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

#ifndef SMARTPHONE_APP_H
#define SMARTPHONE_APP_H

#include "network.h"
#include "applink.h"

/*!
 * A TCP/IP connection to a smartphone.
 *
 * This is basically a pair of socket file descriptors, one for the server
 * side, and one for the single supported peer. Multiple simultaneous
 * connections are not supported.
 */

struct smartphone_app_connection_data
{
    int server_fd;
    int peer_fd;

    struct ApplinkConnection connection;
    struct ApplinkCommand command;
};

#ifdef __cplusplus
extern "C" {
#endif

int appconn_init(struct smartphone_app_connection_data *appconn);
void appconn_handle_incoming(struct smartphone_app_connection_data *appconn);
void appconn_handle_outgoing(struct smartphone_app_connection_data *appconn,
                             bool can_read, bool peer_died);
void appconn_close_peer(struct smartphone_app_connection_data *appconn);
void appconn_close(struct smartphone_app_connection_data *appconn);

#ifdef __cplusplus
}
#endif

#endif /* !SMARTPHONE_APP_H */
