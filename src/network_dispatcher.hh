/*
 * Copyright (C) 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef NETWORK_DISPATCHER_HH
#define NETWORK_DISPATCHER_HH

#include "logged_lock.hh"

#include <functional>
#include <unordered_map>

struct pollfd;

namespace Network
{

struct DispatchHandlers
{
    DispatchHandlers(const DispatchHandlers &) = default;
    DispatchHandlers(DispatchHandlers &&) = default;
    DispatchHandlers &operator=(const DispatchHandlers &) = delete;

    const std::function<bool(int fd)> handle_incoming_data;
    const std::function<void(int fd)> connection_died;

    explicit DispatchHandlers(std::function<bool(int fd)> &&handle_incoming,
                              std::function<void(int fd)> &&handle_died):
        handle_incoming_data(std::move(handle_incoming)),
        connection_died(std::move(handle_died))
    {}
};

class Dispatcher
{
  private:
    mutable LoggedLock::RecMutex lock_;
    std::unordered_map<int, DispatchHandlers> connections_;

  public:
    Dispatcher(const Dispatcher &) = delete;
    Dispatcher &operator=(const Dispatcher &) = delete;

    explicit Dispatcher()
    {
        LoggedLock::configure(lock_, "Network::Dispatcher", MESSAGE_LEVEL_DEBUG);
    }

    /*!
     * Function required by unit tests for initializing static data.
     */
    void reset() { connections_.clear(); }

    /*!
     * Register a socket file descriptor to be considered in the main loop.
     */
    bool add_connection(int fd, DispatchHandlers &&handlers);

    bool add_connection(int fd, const DispatchHandlers &handlers)
    {
        return add_connection(fd, std::move(DispatchHandlers(handlers)));
    }

    /*!
     * Unregister a socket file descriptor and close it.
     */
    bool remove_connection(int fd);

    size_t get_number_of_fds() const
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::RecMutex> lock(lock_);
        return connections_.size();
    }

    /*!
     * Handle events which happened for the registered sockets.
     *
     * This function is called from the low level networking code that calls
     * \c poll(2) after \c poll(2) has returned.
     *
     * \param fds
     *     Array of poll structures (or part of array) as filled by \c poll(2).
     *
     * \returns
     *     The number of events that have been processed. Note that there could
     *     be multiple events for the same fd.
     *
     * \attention
     *     The function assumes that \p fds is the same array as passed to
     *     #Network::Dispatcher::scatter_fds() and that no new fds have been
     *     registered between the call of #Network::Dispatcher::scatter_fds()
     *     and this function.
     */
    size_t process(const struct pollfd *fds) const;

    /*!
     * Fill in the registered sockets, up to the specified amount.
     *
     * This function is called from the low level networking code that calls
     * \c poll(2). The \p fds array is part of the array passed to \c poll(2).
     */
    size_t scatter_fds(struct pollfd *fds, short events) const;

    /*!
     * Retrieve reference to global dispatcher instance.
     */
    static Dispatcher &get_singleton();
};

}

#endif /* !NETWORK_DISPATCHER_HH */
