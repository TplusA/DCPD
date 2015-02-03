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

#ifndef DCPDEFS_H
#define DCPDEFS_H

#include <stdint.h>

/*!
 * \addtogroup registers
 */
/*!@{*/

#define DCP_HEADER_SIZE        4
#define DCP_HEADER_DATA_OFFSET 2

#define DCP_COMMAND_WRITE_REGISTER       0
#define DCP_COMMAND_READ_REGISTER        1
#define DCP_COMMAND_MULTI_WRITE_REGISTER 2
#define DCP_COMMAND_MULTI_READ_REGISTER  3

static inline uint16_t dcp_read_header_data(const uint8_t *src)
{
    return src[0] | (src[1] << 8);
}

static inline void dcp_put_header_data(uint8_t *dest, uint16_t value)
{
    dest[0] = value & 0xff;
    dest[1] = value >> 8;
}

/*!@}*/

#endif /* !DCPDEFS_H */
