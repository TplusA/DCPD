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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <string.h>
#include <stdbool.h>

#include "network_dispatcher.h"
#include "network.h"
#include "messages.h"

struct fd_data
{
    bool is_in_use;
    int fd;
    const struct nwdispatch_iface *iface;
    void *iface_data;
};

static struct fd_data all_fds[NWDISPATCH_MAX_CONNECTIONS];

static struct fd_data *find_fd(int fd)
{
    for(size_t i = 0; i < sizeof(all_fds) / sizeof(all_fds[0]); ++i)
    {
        if(all_fds[i].is_in_use && all_fds[i].fd == fd)
            return &all_fds[i];
    }

    return NULL;
}

static struct fd_data *allocate_fd(void)
{
    for(size_t i = 0; i < sizeof(all_fds) / sizeof(all_fds[0]); ++i)
    {
        if(!all_fds[i].is_in_use)
        {
            all_fds[i].is_in_use = true;
            return &all_fds[i];
        }
    }

    return NULL;
}

void nwdispatch_init(void)
{
    memset(all_fds, 0, sizeof(all_fds));
}

int nwdispatch_register(int fd, const struct nwdispatch_iface *iface,
                        void *user_data)
{
    log_assert(fd >= 0);
    log_assert(iface != NULL);

    if(find_fd(fd) != NULL)
    {
        BUG("Attempted to register already registered fd %d", fd);
        return -1;
    }

    struct fd_data *data = allocate_fd();

    if(data == NULL)
    {
        msg_error(0, LOG_NOTICE, "Maximum number of connections exceeded");
        return -1;
    }

    data->fd = fd;
    data->iface = iface;
    data->iface_data = user_data;

    return 0;
}

int nwdispatch_unregister_and_close(int fd)
{
    log_assert(fd >= 0);

    struct fd_data *data = find_fd(fd);

    if(data == NULL)
    {
        BUG("Attempted to unregister nonexistent fd %d", fd);
        return -1;
    }

    network_close(&data->fd);
    data->is_in_use = false;

    return 0;
}

size_t nwdispatch_scatter_fds(struct pollfd *fds, size_t count, short events)
{
    log_assert(fds != NULL);

    size_t next = 0;

    for(size_t i = 0; i < sizeof(all_fds) / sizeof(all_fds[0]); ++i)
    {
        if(all_fds[i].is_in_use)
        {
            if(next >= count)
            {
                msg_error(0, LOG_NOTICE,
                          "Cannot pass all connections to poll(2), "
                          "target array too small");
                break;
            }

            fds[next].fd = all_fds[i].fd;
            fds[next].events = events;

            ++next;
        }
    }

    if(next < count)
        memset(&fds[next], -1, (count - next) * sizeof(fds[0]));

    return next;
}

size_t nwdispatch_handle_events(const struct pollfd *fds, size_t count)
{
    log_assert(fds != NULL);

    size_t dispatched = 0;
    size_t next = 0;

    for(size_t i = 0; i < count; ++i)
    {
        const struct pollfd *const event = &fds[i];
        const struct fd_data *data;

        for(data = NULL; next < sizeof(all_fds) / sizeof(all_fds[0]); ++next)
        {
            if(all_fds[next].is_in_use && all_fds[next].fd == event->fd)
            {
                data = &all_fds[next++];
                break;
            }
        }

        if(data == NULL)
            break;

        if((event->revents & POLLIN) != 0)
        {
            if(data->iface->handle_incoming_data != NULL)
                data->iface->handle_incoming_data(event->fd, data->iface_data);

            ++dispatched;
        }

        if((event->revents & POLLHUP) != 0)
        {
            if(data->iface->connection_died != NULL)
                data->iface->connection_died(event->fd, data->iface_data);

            ++dispatched;
        }
    }

    return dispatched;
}
