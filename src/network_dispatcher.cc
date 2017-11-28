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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "network_dispatcher.hh"
#include "network.h"
#include "messages.h"

bool Network::Dispatcher::add_connection(int fd, DispatchHandlers &&handlers)
{
    log_assert(fd >= 0);

    std::lock_guard<std::recursive_mutex> lock(lock_);

    if(connections_.find(fd) != connections_.end())
    {
        BUG("Attempted to register already registered fd %d", fd);
        return false;
    }

    connections_.emplace(fd, std::move(handlers));

    return true;
}

bool Network::Dispatcher::remove_connection(int fd)
{
    log_assert(fd >= 0);

    std::lock_guard<std::recursive_mutex> lock(lock_);

    auto it(connections_.find(fd));

    if(it == connections_.end())
    {
        BUG("Attempted to unregister nonexistent fd %d", fd);
        return false;
    }

    int temp = it->first;
    network_close(&temp);

    connections_.erase(fd);

    return true;
}

size_t Network::Dispatcher::process(const struct pollfd *fds) const
{
    log_assert(fds != nullptr);

    std::lock_guard<std::recursive_mutex> lock(lock_);

    size_t dispatched = 0;
    const size_t last = connections_.size();

    for(size_t i = 0; i < last; ++i)
    {
        const struct pollfd &event(fds[i]);
        const auto it(connections_.find(event.fd));

        if(it == connections_.end())
            continue;

        if((event.revents & POLLIN) != 0)
        {
            if(it->second.handle_incoming_data != nullptr)
                it->second.handle_incoming_data(event.fd);

            ++dispatched;
        }

        if((event.revents & POLLHUP) != 0)
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
    log_assert(fds != nullptr);

    std::lock_guard<std::recursive_mutex> lock(lock_);

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
