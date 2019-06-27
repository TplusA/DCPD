/*
 * Copyright (C) 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef STRING_TRIM_HH
#define STRING_TRIM_HH

#include <cinttypes>
#include <cstddef>

namespace Utils
{

static inline bool trim_trailing_zero_padding(const uint8_t *data, size_t &length)
{
    while(length > 0 && data[length - 1] == '\0')
        --length;

    return length > 0;
}

}

#endif /* !STRING_TRIM_HH */
