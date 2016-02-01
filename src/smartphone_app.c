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
#include "messages.h"

int appconn_init(struct smartphone_app_connection_data *appconn)
{
    log_assert(appconn != NULL);

    /*
     * The port number is ASCII "TB" (meaning T + A) + 1.
     */
    appconn->server_fd = network_create_socket(8466, SOMAXCONN);
    appconn->peer_fd = -1;

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
        msg_info("Accepted smartphone connection, fd %d", appconn->peer_fd);
    }
}

void appconn_handle_outgoing(struct smartphone_app_connection_data *appconn,
                             bool can_read_from_peer, bool peer_died)
{
    if(can_read_from_peer)
    {
        log_assert(appconn->peer_fd >= 0);
        msg_info("Smartphone app over TCP/IP");
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

    network_close(&appconn->peer_fd);
}

void appconn_close(struct smartphone_app_connection_data *appconn)
{
    appconn_close_peer(appconn);
    network_close(&appconn->server_fd);
}
