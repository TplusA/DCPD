/*
 * Copyright (C) 2015  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCP_OVER_TCP_H
#define DCP_OVER_TCP_H

#include "network.h"

/*!
 * A DCP over TCP connection.
 *
 * This is basicaaly a pair of socket file descriptors, one for the server
 * side, and one for the single supported peer. Multiple simultaneous
 * connections are not supported.
 */
struct dcp_over_tcp_data
{
    int server_fd;
    int peer_fd;
};

#ifdef __cplusplus
extern "C" {
#endif

int dot_init(struct dcp_over_tcp_data *dot);
void dot_handle_incoming(struct dcp_over_tcp_data *dot);
void dot_handle_outgoing(struct dcp_over_tcp_data *dot,
                         bool can_read, bool peer_died);
void dot_close_peer(struct dcp_over_tcp_data *dot);
void dot_close(struct dcp_over_tcp_data *dot);

#ifdef __cplusplus
}
#endif

#endif /* !DCP_OVER_TCP_H */
