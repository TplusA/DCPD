/*
 * Copyright (C) 2016  T+A elektroakustik GmbH & Co. KG
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

#include <sys/socket.h>

#include "smartphone_app.h"
#include "applink.h"
#include "dbus_common.h"
#include "dbus_iface_deep.h"
#include "messages.h"

int appconn_init(struct smartphone_app_connection_data *appconn)
{
    log_assert(appconn != NULL);

    appconn->peer_fd = -1;

    if(applink_connection_init(&appconn->connection) < 0)
    {
        appconn->server_fd = -1;
        return -1;
    }

    if(applink_command_init(&appconn->command) < 0)
    {
        applink_connection_free(&appconn->connection);
        appconn->server_fd = -1;
        return -1;
    }

    /*
     * The port number is ASCII "TB" (meaning T + A) + 1.
     */
    appconn->server_fd = network_create_socket(8466, SOMAXCONN);

    return appconn->server_fd;
}

void appconn_handle_incoming(struct smartphone_app_connection_data *appconn)
{
    int peer_fd = network_accept_peer_connection(appconn->server_fd, true);

    if(peer_fd < 0)
        return;

    if(appconn->peer_fd >= 0)
    {
        network_close(&peer_fd);
        msg_info("Rejected smartphone connection, only single connection supported");
    }
    else
    {
        appconn->peer_fd = peer_fd;
        applink_connection_associate(&appconn->connection, appconn->peer_fd);
        msg_info("Accepted smartphone connection, fd %d", appconn->peer_fd);
    }
}

static ssize_t process_applink_command(const struct ApplinkCommand *command,
                                       char *buffer, size_t buffer_size)
{
    log_assert(command != NULL);
    log_assert(buffer != NULL);

    if(!command->is_request)
    {
        msg_info("Not accepting answers from app.");
        return -1;
    }

    if(buffer_size == 0)
        return -1;

    msg_info("App request: %s", command->variable->name);

    enum ApplinkSupportedVariables id = command->variable->variable_id;

    log_assert(id >= VAR_FIRST_SUPPORTED_VARIABLE);
    log_assert(id <= VAR_LAST_SUPPORTED_VARIABLE);

    ssize_t len = -1;
    GError *error = NULL;
    gchar *answer = NULL;

    switch(id)
    {
      case VAR_AIRABLE_AUTH_URL:
        {
            char locale_buffer[16];
            char ipaddress_buffer[64];

            applink_command_get_parameter(command, 0, locale_buffer, sizeof(locale_buffer));
            applink_command_get_parameter(command, 1, ipaddress_buffer, sizeof(ipaddress_buffer));

            /* we keep requiring the IP address for backward compatibility, but
             * ignore it */
            if(locale_buffer[0] == '\0' || ipaddress_buffer[0] == '\0')
                break;

            tdbus_airable_call_generate_authentication_url_sync(dbus_get_airable_sec_iface(),
                                                                locale_buffer,
                                                                &answer,
                                                                NULL, &error);
            if(dbus_common_handle_dbus_error(&error) < 0)
                break;

            len = applink_make_answer_for_var(buffer, buffer_size,
                                              command->variable, answer);
        }

        break;

      case VAR_AIRABLE_PASSWORD:
        {
            char token_buffer[128];
            char timestamp_buffer[32];

            applink_command_get_parameter(command, 0, token_buffer, sizeof(token_buffer));
            applink_command_get_parameter(command, 1, timestamp_buffer, sizeof(timestamp_buffer));

            if(token_buffer[0] == '\0' || timestamp_buffer[0] == '\0')
                break;

            tdbus_airable_call_generate_password_sync(dbus_get_airable_sec_iface(),
                                                      token_buffer,
                                                      timestamp_buffer,
                                                      &answer, NULL, &error);
            if(dbus_common_handle_dbus_error(&error) < 0)
                break;

            len = applink_make_answer_for_var(buffer, buffer_size,
                                              command->variable, answer);
        }

        break;

      case VAR_AIRABLE_ROOT_URL:
        tdbus_airable_call_get_root_url_sync(dbus_get_airable_sec_iface(),
                                             &answer, NULL, &error);
        if(dbus_common_handle_dbus_error(&error) < 0)
            break;

        len = applink_make_answer_for_var(buffer, buffer_size,
                                          command->variable, answer);

        break;

      case VAR_SERVICE_CREDENTIALS:
        {
            char service_id_buffer[32];

            applink_command_get_parameter(command, 0, service_id_buffer, sizeof(service_id_buffer));

            if(service_id_buffer[0] == '\0')
                break;

            gchar *password;

            tdbus_credentials_read_call_get_default_credentials_sync(
                dbus_get_credentials_read_iface(),
                service_id_buffer, &answer, &password,
                NULL, &error);
            if(dbus_common_handle_dbus_error(&error) < 0)
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

            len = applink_make_answer_for_var(buffer, buffer_size,
                                              command->variable,
                                              service_id_buffer,
                                              is_known,
                                              answer, password);

            g_free(password);
        }

        break;
    }

    if(answer != NULL)
        g_free(answer);

    if(len == 0)
        BUG("Generated zero length applink answer (%s)",
            command->variable->name);

    return len;
}

static void process_and_flush_on_overflow(struct ApplinkCommand *command,
                                          int out_fd, char *const buffer,
                                          const size_t buffer_size,
                                          size_t *buffer_pos)
{
    while(1)
    {
        ssize_t added_bytes =
            process_applink_command(command, buffer + *buffer_pos,
                                    buffer_size - *buffer_pos);

        if(added_bytes >= 0)
        {
            /* good, answer is in output buffer */
            *buffer_pos += added_bytes;
            return;
        }

        /* command wasn't properly processed */
        if(*buffer_pos > 0)
        {
            /* ah, probably a buffer overflow---flush and try again */
            (void)os_write_from_buffer(buffer, *buffer_pos, out_fd);
            *buffer_pos = 0;
        }
        else
        {
            /* overflow of empty buffer, D-Bus error, or something else */
            BUG("Unexpected failure while processing applink command (%s %s)---skipping command",
                command->is_request ? "request for" : "answer to",
                command->variable->name);
            return;
        }
    }
}

void appconn_handle_outgoing(struct smartphone_app_connection_data *appconn,
                             bool can_read_from_peer, bool peer_died)
{
    if(can_read_from_peer)
    {
        log_assert(appconn->peer_fd >= 0);
        msg_info("Smartphone app over TCP/IP");

        bool done = false;

        static char buffer[4096];
        size_t buffer_pos = 0;

        while(!done)
        {
            const enum ApplinkResult result =
                applink_get_next_command(&appconn->connection,
                                         &appconn->command);

            switch(result)
            {
              case APPLINK_RESULT_HAVE_COMMAND:
                process_and_flush_on_overflow(&appconn->command,
                                              appconn->connection.peer_fd,
                                              buffer, sizeof(buffer),
                                              &buffer_pos);
                break;

              case APPLINK_RESULT_IO_ERROR:
                peer_died = true;

                /* fall-through */

              case APPLINK_RESULT_EMPTY:
              case APPLINK_RESULT_NEED_MORE_DATA:
              case APPLINK_RESULT_OUT_OF_MEMORY:
                done = true;
                break;
            }
        }

        if(!peer_died && buffer_pos > 0)
            (void)os_write_from_buffer(buffer, buffer_pos,
                                       appconn->connection.peer_fd);
    }

    if(peer_died)
    {
        if(appconn->peer_fd >= 0)
        {
            msg_info("Smartphone disconnected");
            appconn_close_peer(appconn);
        }
    }
}

void appconn_close_peer(struct smartphone_app_connection_data *appconn)
{
    log_assert(appconn != NULL);

    applink_connection_release(&appconn->connection);
    network_close(&appconn->peer_fd);
}

void appconn_close(struct smartphone_app_connection_data *appconn)
{
    appconn_close_peer(appconn);
    applink_connection_free(&appconn->connection);
    applink_command_free(&appconn->command);
    network_close(&appconn->server_fd);
}
