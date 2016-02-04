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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <errno.h>

#include "dynamic_buffer_util.h"
#include "messages.h"

bool dynamic_buffer_fill_from_fd(struct dynamic_buffer *buffer, int in_fd,
                                 bool suppress_warning, const char *what)
{
    log_assert(buffer != NULL);

    while(buffer->pos < buffer->size)
    {
        int ret = os_try_read_to_buffer(buffer->data, buffer->size,
                                        &buffer->pos, in_fd, suppress_warning);

        if(ret == 0)
            return true;

        if(ret < 0)
        {
            msg_error(errno, LOG_CRIT, "Failed reading %s from fd %d",
                      what, in_fd);
            return false;
        }
    }

    return true;
}
