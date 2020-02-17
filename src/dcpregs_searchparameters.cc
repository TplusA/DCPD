/*
 * Copyright (C) 2016, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#include "dcpregs_searchparameters.hh"
#include "dbus_iface_deep.h"
#include "messages.h"

#include <string.h>

static size_t skip_string(const uint8_t *data, size_t length, size_t pos)
{
    while(pos < length)
    {
        if(data[pos++] == '\0')
            break;
    }

    return pos;
}

static size_t check_and_skip_context_id(const uint8_t *data, size_t length)
{
    size_t pos = skip_string(data, length, 0);

    if(pos <= 1)
    {
        msg_error(0, LOG_ERR, "No search context defined");
        return 0;
    }

    for(size_t i = 0; i < pos; ++i)
    {
        const char ch = data[i];

        if(ch == '=')
        {
            msg_error(0, LOG_ERR, "Invalid characters in search context");
            return 0;
        }
    }

    return pos;
}

/*!
 * Parse query and put all strings into a \c GVariantBuilder.
 *
 * The basic expected format is a context ID (zero-terminated short string)
 * followed by zero-separated strings in the form of "variable=value".
 *
 * Examples:
 * - Initiate search in Internet radios: "radios\0"
 * - Initiate search in all content in current context: "default\0"
 * - Initiate search in current context from current location: "here\0"
 * - Search for "My Query" in Internet radios: "radios\0text0=My Query\0"
 * - Search for "Rock" in albums on Tidal: "tidal\0text0=Rock\0select0=3\0"
 */
static int add_string_pairs_to_variant(GVariantBuilder *builder,
                                       const uint8_t *data, size_t length,
                                       size_t pos)
{
    while(pos < length)
    {
        const size_t next_pos = skip_string(data, length, pos);

        if(next_pos - pos <= 1)
        {
            msg_error(0, LOG_ERR, "Empty query");
            return -1;
        }

        size_t equals_pos = 0;

        for(size_t i = pos; i < next_pos; ++i)
        {
            if(data[i] == '=')
            {
                equals_pos = i;
                break;
            }
        }

        if(equals_pos == 0)
        {
            msg_error(0, LOG_ERR, "Missing assignment in query");
            return -1;
        }
        else if(equals_pos == pos)
        {
            msg_error(0, LOG_ERR, "Missing ID in query");
            return -1;
        }
        else if(equals_pos >= next_pos || next_pos - equals_pos <= 2)
        {
            msg_error(0, LOG_ERR, "Missing value in query");
            return -1;
        }

        char buffer[128];

        if(equals_pos - pos >= sizeof(buffer))
        {
            msg_error(0, LOG_ERR, "Query too long");
            return -1;
        }

        memcpy(buffer, data + pos, equals_pos - pos);
        buffer[equals_pos - pos] = '\0';

        g_variant_builder_add(builder, "(ss)", buffer, data + equals_pos + 1);

        pos = next_pos;
    }

    return 0;
}

int Regs::SearchParams::DCP::write_74_search_parameters(const uint8_t *data,
                                                        size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 74 handler %p %zu", data, length);

    size_t pos = check_and_skip_context_id(data, length);

    if(pos == 0)
        return -1;

    const bool have_search_parameters = (pos < length);

    GVariantBuilder builder;
    g_variant_builder_init(&builder, G_VARIANT_TYPE("a(ss)"));

    if(have_search_parameters &&
       add_string_pairs_to_variant(&builder, data, length, pos) < 0)
    {
        g_variant_builder_clear(&builder);
        return -1;
    }

    if(!have_search_parameters)
    {
        /*
         * This is OK. It means that a search within the specified context
         * should be started. Our UI should react by sending a corresponding
         * XML for that context.
         */
    }

    GVariant *params = g_variant_builder_end(&builder);
    tdbus_dcpd_views_emit_search_parameters(dbus_get_views_iface(),
                                            (const char *)data, params);

    return 0;
}
