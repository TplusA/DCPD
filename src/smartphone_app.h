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

#include <glib.h>

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

    struct
    {
        GMutex lock;

        struct ApplinkOutputQueue queue;
        void (*notification_fn)(void);
    }
    out_queue;
};

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Initialize connection data and open TCP/IP port for listing.
 *
 * \param appconn
 *     Structure to be initialized.
 *
 * \param send_notification_fn
 *     Function that is called whenever there is a command in the output
 *     command queue.
 */
int appconn_init(struct smartphone_app_connection_data *appconn,
                 void (*send_notification_fn)(void));

/*!
 * Handle incoming connection from the smartphone.
 *
 * This function must be called to accept new connections. It associates the
 * connection structure with the network connection. The connection itself is
 * handled in #appconn_handle_outgoing().
 */
void appconn_handle_incoming(struct smartphone_app_connection_data *appconn);

/*!
 * Handle traffic from and to the smartphone.
 *
 * \param appconn
 *     The connection object associated with a network connection.
 *
 * \param can_read_from_peer
 *     True if the peer is known to have data for us. For each complete command
 *     that can be read from the network connection, an answer is generated and
 *     placed into an output buffer. After having collected all answers, that
 *     buffer is sent as a single network transfer.
 *
 * \param can_send_from_queue
 *     True if there might be commands in the output command queue which should
 *     be processed now.
 *
 * \param peer_died
 *     The peer was determined dead, connection is to be closed cleanly.
 */
void appconn_handle_outgoing(struct smartphone_app_connection_data *appconn,
                             bool can_read_from_peer, bool can_send_from_queue,
                             bool peer_died);

/*!
 * Actively close network connection to the smartphone.
 */
void appconn_close_peer(struct smartphone_app_connection_data *appconn);

/*!
 * Close all connections, including the listening port.
 */
void appconn_close(struct smartphone_app_connection_data *appconn);

#ifdef __cplusplus
}
#endif

#endif /* !SMARTPHONE_APP_H */
