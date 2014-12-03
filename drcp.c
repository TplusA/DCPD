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
#include "os.h"

bool drcp_fill_buffer(struct dynamic_buffer *buffer, int in_fd)
{
    assert(buffer != NULL);

    while(buffer->pos < buffer->size)
    {
        int ret = os_try_read_to_buffer(buffer->data, buffer->size,
                                        &buffer->pos, in_fd);

        if(ret == 0)
            return true;

        if(ret < 0)
        {
            msg_error(errno, LOG_CRIT, "Failed reading DRCP data from fd %d", in_fd);
            return false;
        }
    }

    return true;
}

bool drcp_read_size_from_fd(struct dynamic_buffer *buffer, int in_fd,
                            size_t *expected_size, size_t *payload_offset)
{
    /*
     * FIXME: Stupid timing-based hack.
     *
     * We get partial data from DRCPD because it is writing to its pipe end
     * using several system calls. The code below does not handle this
     * situation very well because it assumes that named pipe read/write
     * operations are atomic (which is true up to a certain size) and that
     * DRCPD is using a single operation for sending data (which is not true,
     * hence the breakage). This hack waits for data to accumulate so that we
     * can be reasonably sure that our read operation looks like the other side
     * has written atomically.
     */
    usleep(50U * 1000U);

    if(os_try_read_to_buffer(buffer->data, buffer->size,
                             &buffer->pos, in_fd) < 0)
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

void drcp_finish_request(bool is_ok, int out_fd)
{
    static const char ok_result[] = "OK\n";
    static const char error_result[] = "FF\n";

    const uint8_t *result =
        (const uint8_t *)(is_ok ? ok_result : error_result);

    (void)os_write_from_buffer(result, 3, out_fd);
}
