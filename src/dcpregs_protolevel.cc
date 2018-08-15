/*
 * Copyright (C) 2016, 2017, 2018  T+A elektroakustik GmbH & Co. KG
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

#include <string.h>

#include "dcpregs_protolevel.hh"
#include "registers.hh"
#include "registers_priv.hh"
#include "messages.h"

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

    /* FIXME: This code does not work with a multiple supported ranges */
    log_assert(number_of_supported_ranges == 1);

    for(size_t i = 0; i < number_of_ranges; ++i)
    {
        const uint8_t *const range_spec = &ranges[i * SIZE_OF_PROTOCOL_LEVEL_RANGE_SPEC];
        const Regs::ProtocolLevel from =
        {
            .code = REGISTER_MK_VERSION(range_spec[0], range_spec[1], range_spec[2]),
        };
        const Regs::ProtocolLevel to =
        {
            .code = REGISTER_MK_VERSION(range_spec[SIZE_OF_PROTOCOL_LEVEL_SPEC + 0],
                                        range_spec[SIZE_OF_PROTOCOL_LEVEL_SPEC + 1],
                                        range_spec[SIZE_OF_PROTOCOL_LEVEL_SPEC + 2]),
        };

        if(from.code > to.code)
            continue;

        if(from.code > supported[1].code || to.code < supported[0].code)
            continue;

        const Regs::ProtocolLevel overlap_max =
            (to.code < supported[1].code) ? to : supported[1];

        if(overlap_max.code > level->code)
            *level = overlap_max;
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

void dcpregs_protocol_level_init(void)
{
    memset(&global_negotiation_data, 0, sizeof(global_negotiation_data));
}

ssize_t dcpregs_read_1_protocol_level(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 1 handler %p %zu", response, length);

    Regs::ProtocolLevel level = { .code = REGISTER_MK_VERSION(0, 0, 0) };

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

int dcpregs_write_1_protocol_level(const uint8_t *data, size_t length)
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

    registers_get_data()->register_changed_notification_fn(1);

    return 0;
}
