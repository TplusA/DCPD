/*
 * Copyright (C) 2015, 2016, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCP_OVER_TCP_H
#define DCP_OVER_TCP_H

#include "network.h"

/*!
 * A DCP over TCP connection.
 *
 * This is basically a pair of socket file descriptors, one for the server
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
                         bool can_read_from_peer, bool peer_died);
void dot_close_peer(struct dcp_over_tcp_data *dot);
void dot_close(struct dcp_over_tcp_data *dot);

#ifdef __cplusplus
}
#endif

#endif /* !DCP_OVER_TCP_H */
