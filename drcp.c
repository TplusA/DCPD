#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>

#include "drcp.h"
#include "messages.h"

bool drcp_fill_buffer(struct dynamic_buffer *buffer,
                      const struct fifo_pair *fds)
{
    assert(buffer != NULL);

    while(buffer->pos < buffer->size)
    {
        int ret =fifo_try_read_to_buffer(buffer->data, buffer->size,
                                         &buffer->pos, fds->in_fd);

        if(ret == 0)
            return true;

        if(ret < 0)
        {
            msg_error(errno, LOG_ERR, "Failed reading DRCP data from fd %d", fds->in_fd);
            return false;
        }
    }

    return true;
}

bool drcp_read_size_from_fd(struct dynamic_buffer *buffer,
                            const struct fifo_pair *fds,
                            size_t *expected_size, size_t *payload_offset)
{
    if(fifo_try_read_to_buffer(buffer->data, buffer->size,
                               &buffer->pos, fds->in_fd) < 0)
    {
        msg_error(errno, LOG_CRIT, "Reading XML size failed");
        return false;
    }

    static const char size_header[] = "Size: ";

    if(buffer->pos < sizeof(size_header))
    {
        msg_error(EINVAL, LOG_CRIT, "Too short input, expected XML size");
        return false;
    }

    if(memcmp(buffer->data, size_header, sizeof(size_header) - 1) != 0)
    {
        msg_error(EINVAL, LOG_CRIT, "Invalid input, expected XML size");
        return false;
    }

    uint8_t *const eol = memchr(buffer->data, '\n', buffer->pos);
    if(!eol)
    {
        msg_error(EINVAL, LOG_CRIT, "Incomplete XML size");
        return false;
    }

    *eol = '\0';

    char *endptr;
    const char *number_string =
        (const char *)buffer->data + sizeof(size_header) - 1;
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
    *payload_offset = (eol - buffer->data) + 1;

    return true;
}

void drcp_finish_request(bool is_ok, const struct fifo_pair *fds)
{
    static const char ok_result[] = "OK\n";
    static const char error_result[] = "FF\n";

    const uint8_t *result =
        (const uint8_t *)(is_ok ? ok_result : error_result);

    (void)fifo_write_from_buffer(result, 3, fds->out_fd);
}
