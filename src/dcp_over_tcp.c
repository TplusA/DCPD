/*
 * Copyright (C) 2015, 2016, 2018  T+A elektroakustik GmbH & Co. KG
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

#include "dcp_over_tcp.h"
#include "messages.h"

int dot_init(struct dcp_over_tcp_data *dot)
{
    log_assert(dot != NULL);

    /*
     * The port number is ASCII "TA", meaning T + A.
     *
     * The backlog parameter could be SOMAXCONN instead of the tiny value used
     * here, but this connection is only intended to be used for internal
     * testing purposes and is most probably not going to be heavily loaded.
     */
    dot->server_fd = network_create_socket(8465, 4);
    dot->peer_fd = -1;

    return dot->server_fd;
}

void dot_handle_incoming(struct dcp_over_tcp_data *dot)
{
    int peer_fd = network_accept_peer_connection(dot->server_fd, false,
                                                 MESSAGE_LEVEL_DIAG);

    if(peer_fd < 0)
        return;

    if(dot->peer_fd >= 0)
    {
        network_close(&peer_fd);
        msg_info("Rejected peer connection, only single connection supported");
    }
    else
    {
        dot->peer_fd = peer_fd;
        msg_vinfo(MESSAGE_LEVEL_DIAG,
                  "Accepted peer connection, fd %d", dot->peer_fd);
    }
}

void dot_handle_outgoing(struct dcp_over_tcp_data *dot,
                         bool can_read_from_peer, bool peer_died)
{
    if(can_read_from_peer)
    {
        log_assert(dot->peer_fd >= 0);
        msg_vinfo(MESSAGE_LEVEL_DEBUG, "DCP over TCP/IP");
    }

    if(peer_died)
    {
        if(dot->peer_fd >= 0)
        {
            msg_info("Peer disconnected");
            dot_close_peer(dot);
        }
    }
}

void dot_close_peer(struct dcp_over_tcp_data *dot)
{
    log_assert(dot != NULL);

    network_close(&dot->peer_fd);
}

void dot_close(struct dcp_over_tcp_data *dot)
{
    dot_close_peer(dot);
    network_close(&dot->server_fd);
}
