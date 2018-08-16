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

#ifndef NETWORK_H
#define NETWORK_H

#include "messages.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Create a socket, bind it, and listen to it.
 *
 * \param port
 *     TCP port to bind to.
 *
 * \param backlog
 *     Maximum length to which the queue of pending connections for the socket
 *     may grow. This parameter is passed directly to \c listen(2).
 *
 * \returns
 *     File descriptor of the socket, or -1 on error.
 */
int network_create_socket(uint16_t port, int backlog);

/*!
 * Accept incoming connection.
 */
int network_accept_peer_connection(int server_fd, bool non_blocking,
                                   enum MessageVerboseLevel verbose_level);

/*!
 * Check if there is any incoming data on the socket.
 *
 * Uses \c recv() with \c MSG_PEEK to check presence of data.
 */
bool network_have_data(int peer_fd);

/*!
 * Close network socket.
 */
void network_close(int *fd);

#ifdef __cplusplus
}
#endif

#endif /* !NETWORK_H */
