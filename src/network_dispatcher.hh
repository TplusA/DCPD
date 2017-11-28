/*
 * Copyright (C) 2018  T+A elektroakustik GmbH & Co. KG
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

#ifndef NETWORK_DISPATCHER_HH
#define NETWORK_DISPATCHER_HH

#include <mutex>
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
    mutable std::recursive_mutex lock_;
    std::unordered_map<int, DispatchHandlers> connections_;

  public:
    Dispatcher(const Dispatcher &) = delete;
    Dispatcher &operator=(const Dispatcher &) = delete;

    explicit Dispatcher() {}

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
