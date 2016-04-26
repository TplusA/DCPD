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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <string.h>

#include "dcpregs_protolevel.h"
#include "registers_priv.h"
#include "messages.h"

/*! Number of bytes needed to store a protocol level specification. */
#define SIZE_OF_PROTOCOL_LEVEL_SPEC        3U
#define SIZE_OF_PROTOCOL_LEVEL_RANGE_SPEC  (2U * SIZE_OF_PROTOCOL_LEVEL_SPEC)

struct ProtocolLevel
{
    uint8_t major;
    uint8_t minor;
    uint8_t micro;
};

enum NegotiationState
{
    NEGOTIATION_NOT_IN_PROGRESS = 0,
    NEGOTIATION_SUCCEEDED,
    NEGOTIATION_FAILED,
};

struct NegotiationStateData
{
    enum NegotiationState state;
    struct ProtocolLevel negotiated_level;
};

static bool is_level_below(const uint8_t a_major, const uint8_t a_minor,
                           const uint8_t a_micro,
                           const uint8_t b_major, const uint8_t b_minor,
                           const uint8_t b_micro)
{
    if(a_major < b_major)
        return true;
    else if(a_major > b_major)
        return false;

    if(a_minor < b_minor)
        return true;
    else if(a_minor > b_minor)
        return false;
    else
        return (a_micro < b_micro);
}

static bool fill_in_highest_supported_level(const uint8_t *const ranges,
                                            const size_t number_of_ranges,
                                            const struct ProtocolLevel *supported,
                                            struct ProtocolLevel *level)
{
    level->major = level->minor = level->micro = 0;

    for(size_t i = 0; i < number_of_ranges; ++i)
    {
        const uint8_t *const range_spec = &ranges[i * SIZE_OF_PROTOCOL_LEVEL_RANGE_SPEC];

        if(!is_level_below(supported->major,
                           supported->minor,
                           supported->micro,
                           range_spec[0],
                           range_spec[1],
                           range_spec[2]) &&
           !is_level_below(range_spec[SIZE_OF_PROTOCOL_LEVEL_SPEC + 0],
                           range_spec[SIZE_OF_PROTOCOL_LEVEL_SPEC + 1],
                           range_spec[SIZE_OF_PROTOCOL_LEVEL_SPEC + 2],
                           supported->major,
                           supported->minor,
                           supported->micro))
        {
            *level = *supported;
            return true;
        }
    }

    return false;
}

static size_t copy_protocol_level_to_response(uint8_t *response,
                                              const struct ProtocolLevel *level)
{
    if(level != NULL)
    {
        response[0] = level->major;
        response[1] = level->minor;
        response[2] = level->micro;
        return SIZE_OF_PROTOCOL_LEVEL_SPEC;
    }
    else
    {
        response[0] = UINT8_MAX;
        return 1;
    }
}

static const struct ProtocolLevel global_protocol_level =
{
    .major = 1,
};

static struct NegotiationStateData global_negotiation_data;

void dcpregs_protocol_level_init(void)
{
    memset(&global_negotiation_data, 0, sizeof(global_negotiation_data));
}

ssize_t dcpregs_read_1_protocol_level(uint8_t *response, size_t length)
{
    msg_info("read 1 handler %p %zu", response, length);

    const struct ProtocolLevel *level = NULL;

    switch(global_negotiation_data.state)
    {
      case NEGOTIATION_NOT_IN_PROGRESS:
        level = &global_protocol_level;
        break;

      case NEGOTIATION_SUCCEEDED:
        level = &global_negotiation_data.negotiated_level;
        break;

      case NEGOTIATION_FAILED:
        break;
    }

    global_negotiation_data.state = NEGOTIATION_NOT_IN_PROGRESS;

    if(length < 3)
    {
        if(length < 1)
            return -1;

        level = NULL;
    }

    size_t ret = copy_protocol_level_to_response(response, level);
    return ret;
}

int dcpregs_write_1_protocol_level(const uint8_t *data, size_t length)
{
    msg_info("write 1 handler %p %zu", data, length);

    const size_t number_of_ranges = length / SIZE_OF_PROTOCOL_LEVEL_RANGE_SPEC;

    if(fill_in_highest_supported_level(data, number_of_ranges,
                                       &global_protocol_level,
                                       &global_negotiation_data.negotiated_level))
        global_negotiation_data.state = NEGOTIATION_SUCCEEDED;
    else
        global_negotiation_data.state = NEGOTIATION_FAILED;

    registers_get_data()->register_changed_notification_fn(1);

    return 0;
}
