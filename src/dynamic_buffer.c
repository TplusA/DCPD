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

#include <stdlib.h>
#include <errno.h>

#include "dynamic_buffer.h"
#include "messages.h"

void dynamic_buffer_init(struct dynamic_buffer *buffer)
{
    buffer->data = NULL;
    buffer->size = 0;
    buffer->pos = 0;
}

void dynamic_buffer_free(struct dynamic_buffer *buffer)
{
    if(buffer->data == NULL)
        return;

    free(buffer->data);
    dynamic_buffer_init(buffer);
}

bool dynamic_buffer_resize(struct dynamic_buffer *buffer, size_t size)
{
    log_assert(buffer != NULL);
    log_assert(size > 0);

    void *temp = realloc(buffer->data, size);

    if(temp == NULL)
    {
        msg_error(errno, LOG_CRIT,
                  "Failed resizing buffer from %zu to %zu bytes",
                  buffer->size, size);
        return false;
    }

    buffer->data = temp;
    buffer->size = size;

    return true;
}

void dynamic_buffer_clear(struct dynamic_buffer *buffer)
{
    buffer->pos = 0;
}

bool dynamic_buffer_check_space(struct dynamic_buffer *buffer)
{
    if(buffer->pos < buffer->size)
        return true;

    static size_t add_space;

    if(add_space == 0)
        add_space = getpagesize();

    return dynamic_buffer_resize(buffer, buffer->size + add_space);
}

bool dynamic_buffer_is_allocated(const struct dynamic_buffer *buffer)
{
    return buffer->size > 0;
}

bool dynamic_buffer_is_empty(const struct dynamic_buffer *buffer)
{
    return buffer->pos == 0;
}
