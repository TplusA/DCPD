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

#ifndef DYNAMIC_BUFFER_UTIL_H
#define DYNAMIC_BUFFER_UTIL_H

#include <stdbool.h>

#include "dynamic_buffer.h"

/*!
 * \addtogroup dynbuffer
 */
/*!@{*/

#ifdef __cplusplus
extern "C" {
#endif

bool dynamic_buffer_fill_from_fd(struct dynamic_buffer *buffer, int in_fd,
                                 bool suppress_warning, const char *what);
bool dynamic_buffer_printf(struct dynamic_buffer *buffer,
                           const char *format_string, ...)
    __attribute__ ((format (printf, 2, 3)));

#ifdef __cplusplus
}
#endif

/*!@}*/


#endif /* !DYNAMIC_BUFFER_UTIL_H */
