/*
 * Copyright (C) 2016--2021  T+A elektroakustik GmbH & Co. KG
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

#include "dcpregs_protolevel.hh"
#include "registers.hh"
#include "registers_priv.hh"
#include "messages.h"

#include <cstring>

/*! Number of bytes needed to store a protocol level specification. */
#define SIZE_OF_PROTOCOL_LEVEL_SPEC        3U
#define SIZE_OF_PROTOCOL_LEVEL_RANGE_SPEC  (2U * SIZE_OF_PROTOCOL_LEVEL_SPEC)

enum NegotiationState
{
    NEGOTIATION_NOT_IN_PROGRESS = 0,
    NEGOTIATION_SUCCEEDED,
    NEGOTIATION_FAILED,
};

struct NegotiationStateData
{
    enum NegotiationState state;
    Regs::ProtocolLevel negotiated_level;
};

static bool fill_in_highest_supported_level(const uint8_t *const ranges,
                                            const size_t number_of_ranges,
                                            const Regs::ProtocolLevel *supported,
                                            const size_t number_of_supported_ranges,
                                            Regs::ProtocolLevel *level)
{
    level->code = REGISTER_MK_VERSION(0, 0, 0);

    for(size_t i = 0; i < number_of_ranges; ++i)
    {
        const uint8_t *const range_spec = &ranges[i * SIZE_OF_PROTOCOL_LEVEL_RANGE_SPEC];
        const Regs::ProtocolLevel from =
        {
            REGISTER_MK_VERSION(range_spec[0], range_spec[1], range_spec[2]),
        };
        const Regs::ProtocolLevel to =
        {
            REGISTER_MK_VERSION(range_spec[SIZE_OF_PROTOCOL_LEVEL_SPEC + 0],
                                range_spec[SIZE_OF_PROTOCOL_LEVEL_SPEC + 1],
                                range_spec[SIZE_OF_PROTOCOL_LEVEL_SPEC + 2]),
        };

        if(from.code > to.code)
            continue;

        for(size_t v = 0; v < number_of_supported_ranges * 2; v += 2)
        {
            if(from.code > supported[v + 1].code || to.code < supported[v + 0].code)
                continue;

            const Regs::ProtocolLevel overlap_max =
                (to.code < supported[v + 1].code) ? to : supported[v + 1];

            if(overlap_max.code > level->code)
                *level = overlap_max;
        }
    }

    return (level->code != 0);
}

static size_t copy_protocol_level_to_response(uint8_t *response,
                                              Regs::ProtocolLevel level)
{
    Regs::unpack_protocol_level(level,
                                &response[0], &response[1], &response[2]);

    if(response[0] > 0)
        return SIZE_OF_PROTOCOL_LEVEL_SPEC;

    response[0] = UINT8_MAX;

    return 1;
}

static struct NegotiationStateData global_negotiation_data;

void Regs::DCPVersion::init()
{
    memset(&global_negotiation_data, 0, sizeof(global_negotiation_data));
}

ssize_t Regs::DCPVersion::DCP::read_1_protocol_level(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 1 handler %p %zu", response, length);

    Regs::ProtocolLevel level = {REGISTER_MK_VERSION(0, 0, 0)};

    switch(global_negotiation_data.state)
    {
      case NEGOTIATION_NOT_IN_PROGRESS:
        level = Regs::get_protocol_level();
        break;

      case NEGOTIATION_SUCCEEDED:
        level = global_negotiation_data.negotiated_level;
        break;

      case NEGOTIATION_FAILED:
        break;
    }

    global_negotiation_data.state = NEGOTIATION_NOT_IN_PROGRESS;

    if(length < 3)
    {
        if(length < 1)
            return -1;

        level.code = REGISTER_MK_VERSION(0, 0, 0);
    }

    size_t ret = copy_protocol_level_to_response(response, level);
    return ret;
}

int Regs::DCPVersion::DCP::write_1_protocol_level(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 1 handler %p %zu", data, length);

    const Regs::ProtocolLevel *supported_ranges;
    const size_t number_of_supported_ranges =
        Regs::get_supported_protocol_levels(&supported_ranges);

    if(length == SIZE_OF_PROTOCOL_LEVEL_SPEC)
    {
        Regs::set_protocol_level(data[0], data[1], data[2]);
        global_negotiation_data.state = NEGOTIATION_NOT_IN_PROGRESS;
    }
    else if(fill_in_highest_supported_level(data, length / SIZE_OF_PROTOCOL_LEVEL_RANGE_SPEC,
                                            supported_ranges, number_of_supported_ranges,
                                            &global_negotiation_data.negotiated_level))
        global_negotiation_data.state = NEGOTIATION_SUCCEEDED;
    else
        global_negotiation_data.state = NEGOTIATION_FAILED;

    Regs::get_data().register_changed_notification_fn(1);

    return 0;
}
