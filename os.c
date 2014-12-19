#include <inttypes.h>
#include <stdlib.h>
#include <errno.h>

#include "os.h"
#include "messages.h"

int os_write_from_buffer(const void *src, size_t count, int fd)
{
    const uint8_t *src_ptr = src;

    while(count > 0)
    {
        ssize_t len = os_write(fd, src_ptr, count);

        if(len < 0)
        {
            msg_error(errno, LOG_ERR, "Failed writing to fd %d", fd);
            return -1;
        }

        log_assert((size_t)len <= count);

        src_ptr += len;
        count -= len;
    }

    return 0;
}

int os_try_read_to_buffer(void *dest, size_t count, size_t *dest_pos, int fd)
{
    uint8_t *dest_ptr = dest;

    dest_ptr += *dest_pos;
    count -= *dest_pos;

    int retval = 0;

    while(count > 0)
    {
        const ssize_t len = os_read(fd, dest_ptr, count);

        if(len == 0)
            break;

        if(len < 0)
        {
            retval = (errno == EAGAIN) ? 0 : -1;
            msg_error(errno, LOG_ERR, "Failed reading from fd %d", fd);
            break;
        }

        log_assert((size_t)len <= count);

        dest_ptr += len;
        count -= len;
        *dest_pos += len;
        retval = 1;
    }

    return retval;
}

void os_abort(void)
{
    abort();
}
