/*
 * Copyright (C) 2015, 2016, 2018, 2019  T+A elektroakustik GmbH & Co. KG
 *
 * This file is part of DCPD.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "dcpregs_tcptunnel.hh"
#include "registers_priv.hh"
#include "network.h"
#include "network_dispatcher.hh"
#include "messages.h"

#include <sys/socket.h>

#include <memory>
#include <map>
#include <unordered_map>
#include <vector>
#include <limits>

class PeerID
{
  public:
    using IDType = uint8_t;

  private:
    IDType id_;

    static constexpr IDType INVALID   = 0;
    static constexpr IDType BROADCAST = UINT8_MAX;

  public:
    explicit PeerID(): id_(INVALID) {}
    explicit PeerID(IDType id): id_(id) {}

    bool is_valid_peer() const { return id_ != INVALID && id_ != BROADCAST; }
    bool is_valid_for_sending() const { return id_ != INVALID; }
    bool is_broadcast() const { return id_ == BROADCAST; }
    void invalidate() { id_ = INVALID; }
    IDType get_raw_id() const { return id_; }
    bool operator<(const PeerID &other) const { return id_ < other.id_; }

    void increment()
    {
        log_assert(is_valid_peer());
        do { ++id_; } while(!is_valid_peer());
    }
};

class TcpTunnel
{
  public:
    static constexpr size_t MAXIMUM_NUMBER_OF_PEERS = 20;
    static_assert(std::numeric_limits<PeerID::IDType>::max() > MAXIMUM_NUMBER_OF_PEERS,
                  "ID type overflow, add more bits to the ID");

    const uint16_t port_;

  private:
    PeerID next_peer_id_;
    std::map<PeerID, int> peer_id_to_descriptor_;
    std::unordered_map<int, PeerID> peer_descriptor_to_id_;

    int server_fd_;
    bool is_registered_with_dispatcher_;

  public:
    TcpTunnel(const TcpTunnel &) = delete;
    TcpTunnel &operator=(const TcpTunnel &) = delete;

    explicit TcpTunnel(uint16_t port, int server_fd):
        port_(port),
        next_peer_id_(1),
        server_fd_(server_fd),
        is_registered_with_dispatcher_(false)
    {}

    ~TcpTunnel()
    {
        for(const auto &fd_and_id : peer_descriptor_to_id_)
            if(fd_and_id.first >= 0)
                Network::Dispatcher::get_singleton().remove_connection(fd_and_id.first);

        if(is_registered_with_dispatcher_)
            Network::Dispatcher::get_singleton().remove_connection(server_fd_);
        else
            network_close(&server_fd_);
    }

    void set_registered()
    {
        log_assert(!is_registered_with_dispatcher_);
        is_registered_with_dispatcher_ = true;
    }

    PeerID add_peer(int peer_fd)
    {
        log_assert(peer_fd >= 0);

        if(peer_id_to_descriptor_.size() >= MAXIMUM_NUMBER_OF_PEERS)
        {
            msg_error(0, LOG_NOTICE,
                      "Too many client connections, rejecting new connection");
            return PeerID();
        }

        while(peer_id_to_descriptor_.find(next_peer_id_) != peer_id_to_descriptor_.end())
            next_peer_id_.increment();

        peer_id_to_descriptor_[next_peer_id_] = peer_fd;
        peer_descriptor_to_id_[peer_fd] = next_peer_id_;

        auto result = next_peer_id_;
        next_peer_id_.increment();

        return result;
    }

    PeerID get_peer_id(int fd) const
    {
        const auto it = peer_descriptor_to_id_.find(fd);;
        return it != peer_descriptor_to_id_.end() ? it->second : PeerID();
    }

    int get_peer_descriptor(PeerID id) const
    {
        auto it = peer_id_to_descriptor_.find(id);
        return it != peer_id_to_descriptor_.end() ? it->second : -1;
    }

    void close_and_forget_peer(PeerID peer_id,
                               bool is_registered_with_dispatcher = true)
    {
        log_assert(peer_id.is_valid_peer());

        const auto it = peer_id_to_descriptor_.find(peer_id);
        log_assert(it != peer_id_to_descriptor_.end());

        const int peer_fd = it->second;

        if(is_registered_with_dispatcher)
            Network::Dispatcher::get_singleton().remove_connection(peer_fd);
        else
        {
            int temp = peer_fd;
            network_close(&temp);
        }

        peer_id_to_descriptor_.erase(peer_id);
        peer_descriptor_to_id_.erase(peer_fd);
    }

    void for_each_peer(const std::function<void(const TcpTunnel &,PeerID, int)> &apply) const
    {
        for(const auto &p : peer_id_to_descriptor_)
            apply(*this, p.first, p.second);
    }
};

class AllTunnels
{
  public:
    static constexpr size_t MAXIMUM_NUMBER_OF_TUNNELS = 10;

    std::map<uint16_t, std::unique_ptr<TcpTunnel>> tunnels_;

  public:
    AllTunnels(const AllTunnels &) = delete;
    AllTunnels &operator=(const AllTunnels &) = delete;

    explicit AllTunnels() {}

    TcpTunnel *add_tunnel(uint16_t port, int server_fd)
    {
        log_assert(port > 0);
        log_assert(server_fd >= 0);

        if(tunnels_.size() >= MAXIMUM_NUMBER_OF_TUNNELS)
            return nullptr;

        const auto it(tunnels_.find(port));

        if(it != tunnels_.end())
            return nullptr;

        tunnels_.emplace(port, std::make_unique<TcpTunnel>(port, server_fd));

        if(tunnels_[port] == nullptr)
        {
            tunnels_.erase(port);
            msg_out_of_memory("tunnel data");
            return nullptr;
        }

        return tunnels_[port].get();
    }

    const TcpTunnel *get_tunnel_by_port(uint16_t port) const
    {
        return const_cast<AllTunnels *>(this)->get_tunnel_by_port(port);
    }

    TcpTunnel *get_tunnel_by_port(uint16_t port)
    {
        const auto it = tunnels_.find(port);
        return it != tunnels_.end() ? it->second.get() : nullptr;
    }

    bool close_and_forget_tunnel(uint16_t port)
    {
        log_assert(port > 0);

        auto it = tunnels_.find(port);

        if(it == tunnels_.end())
            return false;

        it->second = nullptr;
        tunnels_.erase(port);

        return true;
    }
};

class RegisterStatus
{
  private:
    uint16_t tunnel_port_;
    PeerID peer_id_;

  public:
    RegisterStatus(const RegisterStatus &) = delete;
    RegisterStatus &operator=(const RegisterStatus &) = delete;

    explicit RegisterStatus():
        tunnel_port_(0),
        peer_id_(0)
    {}

    bool is_set() const { return tunnel_port_ != 0 && peer_id_.is_valid_peer(); }

    bool set(uint16_t tunnel_port, PeerID peer_id)
    {
        if(is_set())
        {
            /* read function has not yet processed the previous peer request */
            return false;
        }

        if(tunnel_port == 0 || !peer_id.is_valid_peer())
            return false;

        tunnel_port_ = tunnel_port;
        peer_id_ = peer_id;

        return true;
    }

    void reset()
    {
        tunnel_port_ = 0;
        peer_id_.invalidate();
    }

    uint16_t get_tunnel_port() const { return tunnel_port_; }
    PeerID get_peer_id() const { return peer_id_; }
};

static RegisterStatus register_status;

static bool queue_read_from_peer_event(TcpTunnel *tunnel, int peer_fd)
{
    if(!register_status.set(tunnel->port_, tunnel->get_peer_id(peer_fd)))
        return false;

    Regs::get_data().register_changed_notification_fn(120);

    return true;
}

static bool handle_peer_data(AllTunnels &tunnels, uint16_t tunnel_port,
                             PeerID peer_id, int peer_fd)
{
    auto *tunnel = tunnels.get_tunnel_by_port(tunnel_port);

    if(tunnel == nullptr)
    {
        msg_error(0, LOG_ERR,
                  "Cannot handle data for peer %u on port %u, "
                  "tunnel does not exist",
                  peer_id.get_raw_id(), tunnel_port);
        return false;
    }

    if(!queue_read_from_peer_event(tunnel, peer_fd))
        msg_vinfo(MESSAGE_LEVEL_TRACE,
                  "Queued push-to-slave for data from peer %u on port %u",
                  peer_id.get_raw_id(), tunnel_port);

    return true;
}

static void handle_peer_died(AllTunnels &tunnels, uint16_t tunnel_port,
                             PeerID peer_id, int peer_fd)
{
    auto *tunnel = tunnels.get_tunnel_by_port(tunnel_port);

    if(tunnel == nullptr)
        msg_error(0, LOG_ERR,
                  "Cannot handle disconnect of peer %u on port %u, "
                  "tunnel does not exist",
                  peer_id.get_raw_id(), tunnel_port);
    else if(queue_read_from_peer_event(tunnel, peer_fd))
        msg_info("Peer %u on port %u died, closing connection",
                 peer_id.get_raw_id(), tunnel_port);
}

static bool handle_new_peer(int fd, uint16_t port, AllTunnels &tunnels)
{
    auto *t = tunnels.get_tunnel_by_port(port);

    if(t == nullptr)
    {
        BUG("Tunnel with fd %d unknown, cannot handle new peer", fd);
        network_close(&fd);
        return false;
    }

    msg_info("Connection attempt on port %u", t->port_);

    int peer_fd = network_accept_peer_connection(fd, false,
                                                 MESSAGE_LEVEL_NORMAL);
    if(peer_fd < 0)
        return false;

    const PeerID peer_id = t->add_peer(peer_fd);

    if(!peer_id.is_valid_peer())
    {
        network_close(&peer_fd);
        return false;
    }

    const uint16_t tunnel_port = t->port_;

    if(!Network::Dispatcher::get_singleton().add_connection(peer_fd,
            std::move(Network::DispatchHandlers(
                [&tunnels, tunnel_port, peer_id]
                (int peer_fd_arg)
                {
                    return handle_peer_data(tunnels, tunnel_port,
                                            peer_id, peer_fd_arg);
                },
                [&tunnels, tunnel_port, peer_id]
                (int peer_fd_arg)
                {
                    handle_peer_died(tunnels, tunnel_port,
                                     peer_id, peer_fd_arg);
                }
            ))))
    {
        t->close_and_forget_peer(peer_id, false);
        return false;
    }

    msg_info("Accepted connection on tunnel on port %u, peer %u, fd %d",
             t->port_, peer_id.get_raw_id(), peer_fd);

    return true;
}

static bool send_to_peer(const TcpTunnel &tunnel, PeerID peer_id, int peer_fd,
                         const uint8_t *data, size_t data_length)
{
    if(os_write_from_buffer(data, data_length, peer_fd) < 0)
    {
        msg_error(errno, LOG_ERR,
                  "Sending data to peer %u on port %u failed, closing connection",
                  peer_id.get_raw_id(), tunnel.port_);
        return false;
    }

    msg_vinfo(MESSAGE_LEVEL_TRACE,
              "Sent %zu bytes to network peer %u on port %u",
              data_length, peer_id.get_raw_id(), tunnel.port_);
    return true;
}

static AllTunnels all_tunnels;

static int tunnel_error(const char *what, uint16_t port, const char *why)
{
    msg_error(EINVAL, LOG_ERR,
              "%s TCP tunnel on port %u failed: %s", what, port, why);
    return -1;
}

static int tunnel_error_with_peer(const char *what, uint16_t port,
                                  PeerID peer_id, const char *why)
{
    msg_error(EINVAL, LOG_ERR,
              "%s peer ID %u on TCP tunnel on port %u failed: %s",
              what, peer_id.get_raw_id(), port, why);
    return -1;
}

static int close_tunnel(uint16_t port)
{
    if(!all_tunnels.close_and_forget_tunnel(port))
        return tunnel_error("Close", port, "no active tunnel");

    msg_info("Closed TCP tunnel on port %u", port);

    return 0;
}

static int open_tunnel(uint16_t port)
{
    static const char what_error[] = "Open";

    if(all_tunnels.get_tunnel_by_port(port) != nullptr)
        return tunnel_error(what_error, port, "already open");

    int server_fd = network_create_socket(port, SOMAXCONN);

    if(server_fd < 0)
        return tunnel_error(what_error, port, "socket error");

    TcpTunnel *tunnel = all_tunnels.add_tunnel(port, server_fd);

    if(tunnel == nullptr)
    {
        network_close(&server_fd);
        return tunnel_error(what_error, port,
                            "maximum number of tunnels exceeded");
    }

    if(!Network::Dispatcher::get_singleton().add_connection(server_fd,
            std::move(Network::DispatchHandlers(
                [port] (int server_fd_arg)
                {
                    return handle_new_peer(server_fd_arg, port, all_tunnels);
                },
                [port] (int server_fd_arg)
                {
                    const auto *t = all_tunnels.get_tunnel_by_port(port);

                    if(t != nullptr)
                        BUG("Server connection on port %u died, "
                            "but this event is not handled yet", t->port_);
                    else
                        BUG("Unknown server connection with fd %d died",
                            t->port_);
                }
            ))))
    {
        all_tunnels.close_and_forget_tunnel(port);
        return tunnel_error(what_error, port, "internal error");
    }

    msg_info("Opened TCP tunnel on port %u, fd %d", port, server_fd);
    tunnel->set_registered();

    return 0;
}

int Regs::TCPTunnel::DCP::write_119_tcp_tunnel_control(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 119 handler %p %zu", data, length);

    if(length < 2 || length > 3)
    {
        msg_error(EINVAL, LOG_ERR, "Unexpected command length");
        return -1;
    }

    const uint16_t requested_port = data[0] | (data[1] << 8);

    if(requested_port == 0)
        return tunnel_error("Configure", 0, "port 0 is invalid");

    uint8_t requested_state;

    if(length == 2)
        requested_state = 0;
    else
        requested_state = data[2];

    if(requested_state > 1)
    {
        msg_error(EINVAL, LOG_ERR,
                  "Invalid TCP tunnel state requested, must be 0 or 1");
        return -1;
    }

    if(requested_state == 1)
        return open_tunnel(requested_port);
    else
        return close_tunnel(requested_port);
}

ssize_t Regs::TCPTunnel::DCP::read_120_tcp_tunnel_read(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 120 handler %p %zu", response, length);

    if(length < 4)
    {
        msg_error(EINVAL, LOG_ERR,
                  "Read buffer too small, cannot read anything from peer");
        register_status.reset();
        return -1;
    }

    if(!register_status.is_set())
    {
        msg_vinfo(MESSAGE_LEVEL_IMPORTANT, "No active peer, cannot read data");
        response[0] = response[1] = response[2] = 0;
        return 3;
    }

    TcpTunnel *const tunnel =
        all_tunnels.get_tunnel_by_port(register_status.get_tunnel_port());

    if(tunnel == nullptr)
    {
        BUG("Tunnel on port %u does not exist, cannot read data",
            register_status.get_tunnel_port());
        register_status.reset();
        return -1;
    }

    const int peer_fd =
        tunnel->get_peer_descriptor(register_status.get_peer_id());

    if(peer_fd < 0)
    {
        BUG("No file descriptor for peer %u on port %u",
            register_status.get_peer_id().get_raw_id(),
            register_status.get_tunnel_port());
        register_status.reset();
        return -1;
    }

    response[0] = register_status.get_tunnel_port() & 0xff;
    response[1] = register_status.get_tunnel_port() >> 8;
    response[2] = register_status.get_peer_id().get_raw_id();

    ssize_t len;

    if(network_have_data(peer_fd))
    {
        while(1)
        {
            len = os_read(peer_fd, response + 3, length - 3);
            if(len >= 0 || errno != EINTR)
                break;
        }

        if(len < 0)
        {
            msg_error(errno, LOG_ERR,
                      "Reading data from peer %u failed, closing connection",
                      register_status.get_peer_id().get_raw_id());
            tunnel->close_and_forget_peer(register_status.get_peer_id());
            register_status.reset();
            return -1;
        }

        msg_vinfo(MESSAGE_LEVEL_TRACE,
                  "Read %zd bytes of up to %zu bytes from network peer %u on port %u",
                  len, length - 3, register_status.get_peer_id().get_raw_id(),
                  register_status.get_tunnel_port());
    }
    else
        len = 0;

    if(len == 0)
    {
        msg_info("Peer %u on port %u has no more data, closing connection",
                 register_status.get_peer_id().get_raw_id(),
                 register_status.get_tunnel_port());
        tunnel->close_and_forget_peer(register_status.get_peer_id());
    }

    register_status.reset();

    return len + 3;
}

int Regs::TCPTunnel::DCP::write_121_tcp_tunnel_write(const uint8_t *data, size_t length)
{
    static const char what_error[] = "Write to";

    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 121 handler %p %zu", data, length);

    if(length < 3)
    {
        msg_error(EINVAL, LOG_ERR,
                  "Write buffer too small, cannot send anything to peer");
        return -1;
    }

    const uint16_t requested_port = data[0] | (data[1] << 8);

    if(requested_port == 0)
        return tunnel_error(what_error, 0, "port 0 is invalid");

    const PeerID requested_peer_id(data[2]);

    if(!requested_peer_id.is_valid_for_sending())
        return tunnel_error_with_peer(what_error, requested_port,
                                      requested_peer_id, "invalid peer ID");

    /* skip command header */
    data += 3;
    length -= 3;

    TcpTunnel *const tunnel = all_tunnels.get_tunnel_by_port(requested_port);

    if(tunnel == nullptr)
        return tunnel_error_with_peer(what_error, requested_port,
                                      requested_peer_id, "no active tunnel");

    if(requested_peer_id.is_broadcast())
    {
        std::vector<PeerID> failed;

        if(length > 0)
        {
            unsigned int succeeded = 0;

            tunnel->for_each_peer(
                [data, length, &failed, &succeeded]
                (const TcpTunnel &t, PeerID peer_id, int peer_fd)
                {
                    if(send_to_peer(t, peer_id, peer_fd, data, length))
                        ++succeeded;
                    else
                        failed.push_back(peer_id);
                });

            msg_vinfo(MESSAGE_LEVEL_DIAG,
                      "Sent broadcast message to %u peer%s on port %u, "
                      "%zu failure%s",
                      succeeded, succeeded == 1 ? "" : "s", tunnel->port_,
                      failed.size(), failed.size() == 1 ? "" : "s");
        }
        else
        {
            tunnel->for_each_peer(
                [&failed] (const TcpTunnel &t, PeerID peer_id, int)
                { failed.push_back(peer_id); });
            msg_info("Kicking all %zu peer%s on port %u",
                     failed.size(), failed.size() == 1 ? "" : "s",
                     tunnel->port_);
        }

        for(const auto &peer_id : failed)
            tunnel->close_and_forget_peer(peer_id);

        return 0;
    }
    else
    {
        const int peer_fd = tunnel->get_peer_descriptor(requested_peer_id);

        if(peer_fd < 0)
            return tunnel_error_with_peer(what_error, requested_port,
                                          requested_peer_id, "no such peer");

        if(length > 0 &&
           send_to_peer(*tunnel, requested_peer_id, peer_fd, data, length))
            return 0;

        if(length == 0)
            msg_info("Kicking peer %u on port %u",
                     requested_peer_id.get_raw_id(), tunnel->port_);

        tunnel->close_and_forget_peer(requested_peer_id);
        return length > 0 ? -1 : 0;
    }
}
