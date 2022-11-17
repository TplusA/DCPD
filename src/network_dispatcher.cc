/*
 * Copyright (C) 2018, 2019, 2022  T+A elektroakustik GmbH & Co. KG
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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "network_dispatcher.hh"
#include "network.h"
#include "messages.h"

bool Network::Dispatcher::add_connection(int fd, DispatchHandlers &&handlers)
{
    msg_log_assert(fd >= 0);

    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::RecMutex> lock(lock_);

    if(connections_.find(fd) != connections_.end())
    {
        MSG_BUG("Attempted to register already registered fd %d", fd);
        return false;
    }

    connections_.emplace(fd, std::move(handlers));

    return true;
}

bool Network::Dispatcher::remove_connection(int fd)
{
    msg_log_assert(fd >= 0);

    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::RecMutex> lock(lock_);

    auto it(connections_.find(fd));

    if(it == connections_.end())
    {
        MSG_BUG("Attempted to unregister nonexistent fd %d", fd);
        return false;
    }

    int temp = it->first;
    network_close(&temp);

    connections_.erase(fd);

    return true;
}

size_t Network::Dispatcher::process(const struct pollfd *fds) const
{
    msg_log_assert(fds != nullptr);

    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::RecMutex> lock(lock_);

    size_t dispatched = 0;
    const size_t last = connections_.size();

    for(size_t i = 0; i < last; ++i)
    {
        const struct pollfd &event(fds[i]);
        const auto it(connections_.find(event.fd));

        if(it == connections_.end())
            continue;

        bool iter_still_valid = true;

        if((event.revents & POLLIN) != 0)
        {
            if(it->second.handle_incoming_data != nullptr)
                iter_still_valid = it->second.handle_incoming_data(event.fd);

            ++dispatched;
        }

        if((iter_still_valid && event.revents & POLLHUP) != 0)
        {
            if(it->second.connection_died != nullptr)
                it->second.connection_died(event.fd);

            ++dispatched;
        }
    }

    return dispatched;
}

size_t Network::Dispatcher::scatter_fds(struct pollfd *fds, short events) const
{
    msg_log_assert(fds != nullptr);

    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::RecMutex> lock(lock_);

    size_t i = 0;

    for(const auto &it : connections_)
    {
        fds[i].fd = it.first;
        fds[i].events = events;
        ++i;
    }

    return connections_.size();
}

Network::Dispatcher &Network::Dispatcher::get_singleton()
{
    static Dispatcher singleton;
    return singleton;
}
