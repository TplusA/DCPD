/*
 * Copyright (C) 2015, 2016, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCPDEFS_H
#define DCPDEFS_H

#include <stdint.h>

/*!
 * \addtogroup registers
 */
/*!@{*/

#define DCPSYNC_HEADER_SIZE              6
#define DCPSYNC_SLAVE_SERIAL_INVALID     0x0000
#define DCPSYNC_SLAVE_SERIAL_MIN         0x0001
#define DCPSYNC_SLAVE_SERIAL_MAX         0x7fff
#define DCPSYNC_MASTER_SERIAL_INVALID    0x8000
#define DCPSYNC_MASTER_SERIAL_MIN        0x8001
#define DCPSYNC_MASTER_SERIAL_MAX        0xffff

#define DCP_HEADER_SIZE                  4
#define DCP_HEADER_DATA_OFFSET           2
#define DCP_PACKET_MAX_PAYLOAD_SIZE      256U

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
