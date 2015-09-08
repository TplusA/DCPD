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

#ifndef NETWORK_DISPATCHER_H
#define NETWORK_DISPATCHER_H

#include <stdlib.h>
#include <poll.h>

/*!
 * \addtogroup network_dispatcher Network connection dispatching
 */
/*!@{*/

/*!
 * Maximum number of connections supported by the network connection
 * dispatcher.
 *
 * We handle connections in a simple, flat array, and linear search is used to
 * find data by fd. This only works well if the maximum number of connections
 * is small, otherwise a hash table or other kind of dictionary would be
 * required.
 */
#define NWDISPATCH_MAX_CONNECTIONS      5U

/*!
 * How to handle registered file descriptors.
 */
struct nwdispatch_iface
{
    int (*const handle_incoming_data)(int fd, void *user_data);
    void (*const connection_died)(int fd, void *user_data);
};

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Function required by unit tests for initializing static data.
 */
void nwdispatch_init(void);

/*!
 * Register a socket file descriptor to be considered in the main loop.
 */
int nwdispatch_register(int fd, const struct nwdispatch_iface *iface,
                        void *user_data);

/*!
 * Unregister a socket file descriptor and close it.
 */
int nwdispatch_unregister_and_close(int fd);

/*!
 * Fill in the registered sockets, up to the specified amount.
 *
 * This function is called from the low level networking code that calls
 * \c poll(2). The \p fds array is part of the array passed to \c poll(2).
 */
size_t nwdispatch_scatter_fds(struct pollfd *fds, size_t count, short events);

/*!
 * Handle events that happened for the registered sockets.
 *
 * This function is called from the low level networking code that calls
 * \c poll(2) after \c poll(2) has returned.
 *
 * \param fds
 *     Array of poll structures (or part of array) as filled by \c poll(2).
 *
 * \param count
 *     Number of fds in the \p fds array.
 *
 * \returns
 *     The number of events that have been processed. Note that there could be
 *     multiple events for the same fd.
 *
 * \attention
 *     The function assumes that \p fds is the same array as passed to
 *     #nwdispatch_scatter_fds() and that no new fds have been registered
 *     between the call of #nwdispatch_scatter_fds() and this function.
 */
size_t nwdispatch_handle_events(const struct pollfd *fds, size_t count);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !NETWORK_DISPATCHER_H */
