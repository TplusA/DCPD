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

#ifndef DYNAMIC_BUFFER_H
#define DYNAMIC_BUFFER_H

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

/*!
 * \addtogroup dynbuffer Dynamically sized buffer
 */
/*!@{*/

struct dynamic_buffer
{
    uint8_t *data;
    size_t size;
    size_t pos;
};

#ifdef __cplusplus
extern "C" {
#endif

void dynamic_buffer_init(struct dynamic_buffer *buffer);
void dynamic_buffer_free(struct dynamic_buffer *buffer);
bool dynamic_buffer_resize(struct dynamic_buffer *buffer, size_t size);
void dynamic_buffer_clear(struct dynamic_buffer *buffer);
bool dynamic_buffer_check_space(struct dynamic_buffer *buffer);
bool dynamic_buffer_is_allocated(const struct dynamic_buffer *buffer);
bool dynamic_buffer_is_empty(const struct dynamic_buffer *buffer);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !DYNAMIC_BUFFER_H */
