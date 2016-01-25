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

#include "dcpregs_playstream.h"
#include "messages.h"

int dcpregs_write_78_start_play_stream_title(const uint8_t *data, size_t length)
{
    msg_info("write 78 handler %p %zu", data, length);
    return -1;
}

int dcpregs_write_79_start_play_stream_url(const uint8_t *data, size_t length)
{
    msg_info("write 79 handler %p %zu", data, length);
    return -1;
}

ssize_t dcpregs_read_79_start_play_stream_url(uint8_t *response, size_t length)
{
    msg_info("read 79 handler %p %zu", response, length);
    return -1;
}

int dcpregs_write_238_next_stream_title(const uint8_t *data, size_t length)
{
    msg_info("write 238 handler %p %zu", data, length);
    return -1;
}

int dcpregs_write_239_next_stream_url(const uint8_t *data, size_t length)
{
    msg_info("write 239 handler %p %zu", data, length);
    return -1;
}

ssize_t dcpregs_read_239_next_stream_url(uint8_t *response, size_t length)
{
    msg_info("read 239 handler %p %zu", response, length);
    return -1;
}

void dcpregs_playstream_start_notification(stream_id_t raw_stream_id)
{
    msg_info("Stream %u has started playing", raw_stream_id);
}

void dcpregs_playstream_stop_notification(void)
{
    msg_info("Streamplayer has stopped");
}
