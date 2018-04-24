/*
 * Copyright (C) 2016, 2017, 2018  T+A elektroakustik GmbH & Co. KG
 *
 * This file is part of DCPD.
 *
 * DCPD is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 3 as
 * published by the Free Software Foundation.
 *
 * DCPD is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with DCPD.  If not, see <http://www.gnu.org/licenses/>.
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sstream>
#include <array>
#include <cstring>
#include <sys/socket.h>

#include "smartphone_app.hh"
#include "applink.hh"
#include "network_dispatcher.hh"
#include "dbus_common.h"
#include "dbus_iface_deep.h"
#include "actor_id.h"
#include "messages.h"

void Applink::Peer::send_to_queue(int fd, std::string &&command)
{
    std::lock_guard<std::mutex> lock(send_queue_.lock_);
    send_queue_.queue_.emplace_back(command);
    send_queue_.notify_have_outgoing_fn_(fd);
}

bool Applink::Peer::send_one_from_queue_to_peer(int fd)
{
    std::string command;

    {
        std::lock_guard<std::mutex> lock(send_queue_.lock_);

        if(send_queue_.queue_.empty())
            return false;

        command = std::move(send_queue_.queue_.front());
        send_queue_.queue_.pop_front();
    }

    if(command.empty())
        BUG("Ignoring empty applink command in out queue for peer %d", fd);
    else if(fd >= 0)
    {
        if(os_write_from_buffer(command.c_str(), command.size(), fd) < 0)
        {
            msg_error(errno, LOG_ERR, "Sending data to app fd %d failed", fd);
            send_queue_.notify_peer_died_fn_(fd, false);
            return false;
        }
    }

    return true;
}

bool Applink::AppConnections::add_new_peer(int peer_fd)
{
    if(peers_.find(peer_fd) != peers_.end())
    {
        BUG("Tried to add peer fd %d twice", peer_fd);
        return false;
    }

    peers_.emplace(peer_fd, std::unique_ptr<Applink::Peer>(new Applink::Peer(
                                peer_fd, send_queue_filled_notification_fn_,
                                [this] (int fd, bool cleanly_closed)
                                {
                                    close_and_forget_peer(fd);
                                })));

    if(peers_.find(peer_fd) == peers_.end())
    {
        msg_out_of_memory("Applink::Peer");
        return false;
    }

    return true;
}

void Applink::AppConnections::close_and_forget_peer(int peer_fd,
                                                    bool is_registered_with_dispatcher)
{
    log_assert(peers_.find(peer_fd) != peers_.end());

    msg_info("Smartphone direct connection disconnected (fd %d)", peer_fd);

    peers_.erase(peer_fd);

    if(is_registered_with_dispatcher)
        Network::Dispatcher::get_singleton().remove_connection(peer_fd);
    else
        network_close(&peer_fd);
}

/*!
 * Handle incoming connection from the smartphone.
 */
bool Applink::AppConnections::handle_new_peer(int server_fd)
{
    int peer_fd = network_accept_peer_connection(server_fd, true,
                                                 MESSAGE_LEVEL_NORMAL);

    if(peer_fd < 0)
        return false;

    if(!add_new_peer(peer_fd))
    {
        network_close(&peer_fd);
        return false;
    }

    if(!Network::Dispatcher::get_singleton().add_connection(peer_fd,
            std::move(Network::DispatchHandlers(
                [this] (int peer_fd_arg)
                {
                    return peers_[peer_fd_arg]->handle_incoming_data(peer_fd_arg);
                },
                [this] (int peer_fd_arg)
                {
                    handle_peer_died(peer_fd_arg);
                }
            ))))
    {
        close_and_forget_peer(peer_fd, false);
        return false;
    }

    msg_info("Accepted smartphone connection, fd %d", peer_fd);

    return true;
}

void Applink::AppConnections::handle_peer_died(int peer_fd)
{
    close_and_forget_peer(peer_fd);
}

bool Applink::AppConnections::listen(uint16_t port)
{
    if(server_fd_ >= 0)
    {
        BUG("Applink server already running");
        return false;
    }

    const int server_fd = network_create_socket(port, SOMAXCONN);

    if(server_fd < 0)
    {
        msg_error(errno, LOG_ERR, "Failed to open applink server port");
        return false;
    }

    if(!Network::Dispatcher::get_singleton().add_connection(server_fd,
            std::move(Network::DispatchHandlers(
                [this] (int server_fd_arg)
                {
                    return handle_new_peer(server_fd_arg);
                },
                [this] (int server_fd_arg)
                {
                    msg_info("Applink server connection died (fd %d)",
                             server_fd_arg);
                }
            ))))
    {
        return false;
    }

    server_fd_ = server_fd;

    return true;
}

static bool no_airable(const char *why)
{
    if(dbus_get_airable_sec_iface() != nullptr &&
       dbus_get_credentials_read_iface() != nullptr)
        return false;

    BUG("Cannot %s, have no Airable D-Bus proxy", why);

    return true;
}

static bool process_applink_command(const Applink::Command &command,
                                    std::string &answer_for_command)
{
    if(!command.is_request())
    {
        msg_info("Not accepting answers from app.");
        return false;
    }

    const auto *variable = command.get_variable();
    log_assert(variable != nullptr);

    msg_vinfo(MESSAGE_LEVEL_DEBUG, "App request: %s", variable->name);

    log_assert(variable->variable_id >= uint16_t(Applink::Variables::FIRST_SUPPORTED_VARIABLE));
    log_assert(variable->variable_id <= uint16_t(Applink::Variables::LAST_SUPPORTED_VARIABLE));

    const auto id = Applink::Variables(variable->variable_id);

    GError *error = nullptr;
    gchar *answer = nullptr;
    std::ostringstream buffer;

    switch(id)
    {
      case Applink::Variables::AIRABLE_AUTH_URL:
        {
            std::array<char, 16> locale_buffer;
            std::array<char, 64> ipaddress_buffer;

            command.get_parameter(0, locale_buffer);
            command.get_parameter(1, ipaddress_buffer);

            /* we keep requiring the IP address for backward compatibility, but
             * ignore it */
            if(locale_buffer[0] == '\0' || ipaddress_buffer[0] == '\0')
                break;

            if(no_airable("generate authentication URL"))
                break;

            tdbus_airable_call_generate_authentication_url_sync(dbus_get_airable_sec_iface(),
                                                                locale_buffer.data(),
                                                                &answer,
                                                                nullptr, &error);
            if(dbus_common_handle_dbus_error(&error, "Generate Airable auth URL") < 0)
                break;

            Applink::make_answer_for_var(buffer, *variable, { answer });
        }

        break;

      case Applink::Variables::AIRABLE_PASSWORD:
        {
            std::array<char, 128> token_buffer;
            std::array<char, 32>  timestamp_buffer;

            command.get_parameter(0, token_buffer);
            command.get_parameter(1, timestamp_buffer);

            if(token_buffer[0] == '\0' || timestamp_buffer[0] == '\0')
                break;

            if(no_airable("generate password"))
                break;

            tdbus_airable_call_generate_password_sync(dbus_get_airable_sec_iface(),
                                                      token_buffer.data(),
                                                      timestamp_buffer.data(),
                                                      &answer, nullptr, &error);
            if(dbus_common_handle_dbus_error(&error, "Generate Airable password") < 0)
                break;

            Applink::make_answer_for_var(buffer, *variable, { answer });
        }

        break;

      case Applink::Variables::AIRABLE_ROOT_URL:
        if(no_airable("get root URL"))
            break;

        tdbus_airable_call_get_root_url_sync(dbus_get_airable_sec_iface(),
                                             &answer, nullptr, &error);
        if(dbus_common_handle_dbus_error(&error, "Get Airable root URL") < 0)
            break;

        Applink::make_answer_for_var(buffer, *variable, { answer });

        break;

      case Applink::Variables::SERVICE_CREDENTIALS:
        {
            std::array<char, 32> service_id_buffer;

            command.get_parameter(0, service_id_buffer);

            if(service_id_buffer[0] == '\0')
                break;

            if(no_airable("get service credentials"))
                break;

            gchar *password;

            tdbus_credentials_read_call_get_default_credentials_sync(
                dbus_get_credentials_read_iface(),
                service_id_buffer.data(), &answer, &password,
                nullptr, &error);
            if(dbus_common_handle_dbus_error(&error, "Get default credentials") < 0)
                break;

            const char *const is_known =
                (answer[0] != '\0' && password[0] != '\0')
                ? "known"
                : "unknown";

            if(!is_known)
            {
                answer[0] = '\0';
                password[0] = '\0';
            }

            Applink::make_answer_for_var(buffer, *variable,
                                         { service_id_buffer.data(), is_known, answer, password });

            g_free(password);
        }

        break;

      case Applink::Variables::SERVICE_LOGGED_IN:
      case Applink::Variables::SERVICE_LOGGED_OUT:
        msg_vinfo(MESSAGE_LEVEL_DEBUG, "App request for \"%s\" ignored", variable->name);
        break;
    }

    if(answer != nullptr)
        g_free(answer);

    answer_for_command = buffer.str();

    if(answer_for_command.empty())
        BUG("Generated zero length applink answer (%s)", variable->name);

    return true;
}

static void process_applink_answer(const Applink::Command &command)
{
    const auto *variable = command.get_variable();
    log_assert(variable != nullptr);

    msg_vinfo(MESSAGE_LEVEL_DEBUG, "App answer: %s", variable->name);

    log_assert(variable->variable_id >= uint16_t(Applink::Variables::FIRST_SUPPORTED_VARIABLE));
    log_assert(variable->variable_id <= uint16_t(Applink::Variables::LAST_SUPPORTED_VARIABLE));

    const auto id = Applink::Variables(variable->variable_id);

    switch(id)
    {
      case Applink::Variables::AIRABLE_AUTH_URL:
      case Applink::Variables::AIRABLE_PASSWORD:
      case Applink::Variables::AIRABLE_ROOT_URL:
      case Applink::Variables::SERVICE_CREDENTIALS:
        msg_info("App answer ignored");
        break;

      case Applink::Variables::SERVICE_LOGGED_IN:
        {
            std::array<char, 32>  service_id_buffer;
            std::array<char, 128> username_buffer;

            command.get_parameter(0, service_id_buffer);
            command.get_parameter(1, username_buffer);

            msg_vinfo(MESSAGE_LEVEL_TRACE,
                      "App said it logged into \"%s\" with user \"%s\"",
                      service_id_buffer.data(), username_buffer.data());

            if(no_airable("log into service"))
                break;

            tdbus_airable_call_external_service_login_sync(
                dbus_get_airable_sec_iface(), service_id_buffer.data(),
                username_buffer.data(), false,
                ACTOR_ID_SMARTPHONE_APP, nullptr, nullptr);
        }

        break;

      case Applink::Variables::SERVICE_LOGGED_OUT:
        {
            std::array<char, 32>   service_id_buffer;
            std::array<char, 1024> url_buffer;

            command.get_parameter(0, service_id_buffer);
            command.get_parameter(1, url_buffer);

            msg_vinfo(MESSAGE_LEVEL_TRACE,
                      "App said it logged out from \"%s\" using URL \"%s\"",
                      service_id_buffer.data(), url_buffer.data());

            if(no_airable("log out from service"))
                break;

            tdbus_airable_call_external_service_logout_sync(
                dbus_get_airable_sec_iface(), service_id_buffer.data(),
                url_buffer.data(), false, ACTOR_ID_SMARTPHONE_APP, nullptr, nullptr);
        }

        break;
    }
}

bool Applink::Peer::handle_incoming_data(int fd)
{
    msg_vinfo(MESSAGE_LEVEL_DEBUG, "Smartphone app over TCP/IP on fd %d", fd);

    while(true)
    {
        Applink::ParserResult result = Applink::ParserResult::IO_ERROR;
        std::unique_ptr<Applink::Command> command =
            input_buffer_.get_next_command(fd, result);

        std::string answer;

        switch(result)
        {
          case Applink::ParserResult::HAVE_COMMAND:
            log_assert(command != nullptr);
            process_applink_command(*command, answer);

            if(!answer.empty())
                send_to_queue(fd, std::move(answer));

            break;

          case Applink::ParserResult::HAVE_ANSWER:
            log_assert(command != nullptr);
            process_applink_answer(*command);
            break;

          case Applink::ParserResult::IO_ERROR:
            send_queue_.notify_peer_died_fn_(fd, false);
            return true;

          case Applink::ParserResult::EMPTY:
          case Applink::ParserResult::NEED_MORE_DATA:
          case Applink::ParserResult::OUT_OF_MEMORY:
            return true;
        }
    }
}

void Applink::AppConnections::process_out_queue()
{
    if(peers_.empty())
        return;

    decltype(peers_)::iterator next;

    for(auto it(peers_.begin()); it != peers_.end(); it = next)
    {
        next = it;
        ++next;

        while(it->second->send_one_from_queue_to_peer(it->first))
            ;
    }
}

void Applink::AppConnections::send_to_all_peers(std::string &&command)
{
    if(peers_.empty())
        return;

    for(auto &peer : peers_)
        peer.second->send_to_queue(peer.first, std::string(command));
}

void Applink::AppConnections::close()
{
    if(server_fd_ >= 0)
    {
        Network::Dispatcher::get_singleton().remove_connection(server_fd_);
        server_fd_ = -1;
    }

    while(!peers_.empty())
        close_and_forget_peer(peers_.begin()->first);
}
