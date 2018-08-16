/*
 * Copyright (C) 2015, 2016, 2017, 2018  T+A elektroakustik GmbH & Co. KG
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

#include "drcp.h"
#include "messages.h"
#include "os.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

bool drcp_read_size_from_fd(struct dynamic_buffer *buffer, int in_fd,
                            size_t *expected_size, size_t *payload_offset)
{
    size_t token_start_pos = buffer->pos;
    bool expecting_size_header = true;
    bool expecting_size_value = false;
    const char *number_string = NULL;

    while(true)
    {
        const size_t prev_pos = buffer->pos;
        const int read_result =
            os_try_read_to_buffer(buffer->data, buffer->size,
                                  &buffer->pos, in_fd, true);

        if(read_result < 0)
        {
            msg_error(errno, LOG_CRIT, "Reading XML size failed");
            return false;
        }

        if(buffer->pos == prev_pos)
        {
            /* try again later */
            os_sched_yield();
            continue;
        }

        if(expecting_size_header)
        {
            static const char size_header[] = "Size: ";

            if(buffer->pos - token_start_pos >= sizeof(size_header))
            {
                if(memcmp(buffer->data, size_header, sizeof(size_header) - 1) != 0)
                {
                    msg_error(EINVAL, LOG_CRIT, "Invalid input, expected XML size");
                    return false;
                }

                expecting_size_header = false;
                expecting_size_value = true;
                token_start_pos += sizeof(size_header) - 1;
            }
            else
            {
                /* size header is incomplete, need to read more data */
            }
        }

        if(expecting_size_value)
        {
            char *const eol = memchr(buffer->data + token_start_pos, '\n',
                                     buffer->pos - token_start_pos);

            if(eol != NULL)
            {
                expecting_size_value = false;
                number_string = (const char *)buffer->data + token_start_pos;
                *eol = '\0';
                token_start_pos += eol - number_string + 1;
                break;
            }
            else
            {
                /* size field is incomplete, need to read more data */
            }
        }

        os_sched_yield();
    }

    char *endptr;
    unsigned long temp = strtoul(number_string, &endptr, 10);

    if(*endptr != '\0')
    {
        msg_error(EINVAL, LOG_CRIT,
                  "Malformed XML size \"%s\"", number_string);
        return false;
    }

    if(temp > UINT16_MAX || (temp == ULONG_MAX && errno == ERANGE))
    {
        msg_error(ERANGE, LOG_CRIT, "Too large XML size %s", number_string);
        return false;
    }

    *expected_size = temp;
    *payload_offset = token_start_pos;

    return true;
}

void drcp_finish_request(bool is_ok, int out_fd)
{
    static const char ok_result[] = "OK\n";
    static const char error_result[] = "FF\n";

    const uint8_t *result =
        (const uint8_t *)(is_ok ? ok_result : error_result);

    (void)os_write_from_buffer(result, 3, out_fd);
}
