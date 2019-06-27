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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "dcpregs_stream_speed.hh"
#include "dbus_iface_deep.h"
#include "messages.h"

#include <cerrno>

static bool parse_speed_factor(const uint8_t *data, size_t length,
                               double &factor)
{
    if(length != 2)
    {
        msg_error(EINVAL, LOG_ERR, "Speed factor length must be 2");
        return false;
    }

    if(data[1] >= 100)
    {
        msg_error(EINVAL, LOG_ERR, "Speed factor invalid fraction part");
        return false;
    }

    factor = data[0];
    factor += double(data[1]) / 100.0;

    if(factor <= 0.0)
    {
        msg_error(EINVAL, LOG_ERR, "Speed factor too small");
        return false;
    }

    return true;
}

static bool parse_absolute_position_ms(const uint8_t *data, size_t length,
                                       uint32_t &position_ms)
{
    if(length != sizeof(position_ms))
    {
        msg_error(EINVAL, LOG_ERR,
                  "Seek position length must be %zu", sizeof(position_ms));
        return false;
    }

    /* little endian */
    position_ms = (uint32_t(data[0]) << 0)  | (uint32_t(data[1]) << 8) |
                  (uint32_t(data[2]) << 16) | (uint32_t(data[3]) << 24);

    return true;
}

int Regs::PlayStream::DCP::write_73_seek_or_set_speed(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 73 handler %p %zu", data, length);

    if(length < 1)
        return -1;

    double factor;
    uint32_t position;

    switch(data[0])
    {
      case 0xc1:
        if(parse_speed_factor(data + 1, length - 1, factor))
        {
            tdbus_dcpd_playback_emit_set_speed(dbus_get_playback_iface(), factor);
            return 0;
        }

        break;

      case 0xc2:
        if(parse_speed_factor(data + 1, length - 1, factor))
        {
            tdbus_dcpd_playback_emit_set_speed(dbus_get_playback_iface(), -factor);
            return 0;
        }

        break;

      case 0xc3:
        tdbus_dcpd_playback_emit_set_speed(dbus_get_playback_iface(), 0.0);
        return 0;

      case 0xc4:
        if(parse_absolute_position_ms(data + 1, length - 1, position))
        {
            /* overflow/underflow impossible, no further checks required */
            tdbus_dcpd_playback_emit_seek(dbus_get_playback_iface(),
                                          position, "ms");
            return 0;
        }

        break;

      default:
        msg_error(EINVAL, LOG_ERR,
                  "Invalid subcommand 0x%02x for register 73", data[0]);
        break;
    }

    return -1;
}
