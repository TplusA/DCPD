/*
 * Copyright (C) 2019  T+A elektroakustik GmbH & Co. KG
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
