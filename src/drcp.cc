/*
 * Copyright (C) 2015--2019  T+A elektroakustik GmbH & Co. KG
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

#include "drcp.hh"
#include "messages.h"
#include "os.h"

#include <array>
#include <algorithm>
#include <cerrno>

bool Drcp::determine_xml_size(int in_fd, std::string &xml_string, size_t &expected_size)
{
    if(expected_size > 0)
        return true;

    if(!Drcp::read_size_from_fd(in_fd, expected_size, xml_string))
        return false;

    return true;
}

bool Drcp::read_xml(int in_fd, std::string &xml_string, const size_t expected_size)
{
    size_t pos = xml_string.size();

    xml_string.resize(expected_size);

    while(pos < expected_size)
    {
        const size_t old_pos(pos);
        const int ret = os_try_read_to_buffer(&xml_string[0], expected_size,
                                              &pos, in_fd, true);

        if(ret > 0)
            continue;

        xml_string.resize(old_pos);

        if(ret == 0)
            break;
        else
        {
            msg_error(errno, LOG_CRIT, "Failed reading DRCP data from fd %d", in_fd);
            return false;
        }
    }

    return true;
}

bool Drcp::read_size_from_fd(int in_fd, size_t &expected_size,
                             std::string &overhang_buffer)
{
    static const char size_header[] = "Size: ";

    /*
     * A 16 byte buffer is all we need to handle 100% of all valid DRCP
     * transfers. In case the DRCP header is longer than this, we know for sure
     * there must be something wrong and we can error out.
     */
    std::array<char, 16> buffer;
    size_t buffer_pos = 0;

    size_t token_start_pos = 0;
    bool expecting_size_header = true;
    bool expecting_size_value = false;
    const char *number_string;

    while(true)
    {
        const size_t prev_pos = buffer_pos;
        const int read_result =
            os_try_read_to_buffer(buffer.data(), buffer.size(),
                                  &buffer_pos, in_fd, true);

        if(read_result < 0)
        {
            msg_error(errno, LOG_CRIT, "Reading XML size failed");
            return false;
        }

        if(buffer_pos == prev_pos)
        {
            /* try again later */
            os_sched_yield();
            continue;
        }

        if(expecting_size_header)
        {
            if(buffer_pos - token_start_pos >= sizeof(size_header))
            {
                if(!std::equal(size_header, size_header + sizeof(size_header) - 1,
                               buffer.begin()))
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
            const auto &eol(std::find(&buffer[token_start_pos],
                                      &buffer[buffer_pos], '\n'));

            if(eol < &buffer[buffer_pos])
            {
                expecting_size_value = false;
                number_string = &buffer[token_start_pos];
                *eol = '\0';
                token_start_pos += eol - number_string + 1;
                break;
            }
            else if(buffer_pos >= buffer.size())
            {
                msg_error(EINVAL, LOG_CRIT, "DRCP header too long");
                return false;
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

    if(temp > std::numeric_limits<uint16_t>::max() ||
       (temp == std::numeric_limits<unsigned long>::max() && errno == ERANGE))
    {
        msg_error(ERANGE, LOG_CRIT, "Too large XML size %s", number_string);
        return false;
    }

    expected_size = temp;

    overhang_buffer.clear();
    std::copy(&buffer[token_start_pos], &buffer[buffer_pos],
              std::back_inserter(overhang_buffer));

    return true;
}

void Drcp::finish_request(int out_fd, bool is_ok)
{
    static const char ok_result[] = "OK\n";
    static const char error_result[] = "FF\n";
    auto *result(reinterpret_cast<const uint8_t *>(is_ok ? ok_result : error_result));
    (void)os_write_from_buffer(result, 3, out_fd);
}
