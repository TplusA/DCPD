/*
 * Copyright (C) 2015  T+A elektroakustik GmbH & Co. KG
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

#include <inttypes.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "os.h"
#include "messages.h"

int os_write_from_buffer(const void *src, size_t count, int fd)
{
    const uint8_t *src_ptr = src;

    while(count > 0)
    {
        ssize_t len;

        while((len = os_write(fd, src_ptr, count)) == -1 && errno == EINTR)
            ;

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

int os_file_new(const char *filename)
{
    int fd;

    while((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC,
                     S_IRWXU | S_IRWXG | S_IRWXO)) == -1 &&
          errno == EINTR)
        ;

    if(fd < 0)
        msg_error(errno, LOG_ERR, "Failed to create file \"%s\"", filename);

    return fd;
}

static void safe_close_fd(int fd)
{
    (void)fsync(fd);

    int ret;
    while((ret = close(fd)) == -1 && errno == EINTR)
        ;

    if(ret == -1 && errno != EINTR)
        msg_error(errno, LOG_ERR, "Failed to close file descriptor %d", fd);
}

void os_file_close(int fd)
{
    if(fd < 0)
        msg_error(EINVAL, LOG_ERR,
                  "Passed invalid file descriptor to %s()", __func__);
    else
        safe_close_fd(fd);
}

void os_file_delete(const char *filename)
{
    log_assert(filename != NULL);

    if(unlink(filename) < 0)
        msg_error(errno, LOG_ERR, "Failed to delete file \"%s\"", filename);
}

int os_map_file_to_memory(struct os_mapped_file_data *mapped,
                          const char *filename)
{
    log_assert(mapped != NULL);
    log_assert(filename != NULL);

    while((mapped->fd = open(filename, O_RDONLY)) == -1 && errno == EINTR)
        ;

    if(mapped->fd < 0)
    {
        msg_error(errno, LOG_ERR, "Failed to open() file \"%s\"", filename);
        return -1;
    }

    struct stat buf;
    if(fstat(mapped->fd, &buf) < 0)
    {
        msg_error(errno, LOG_ERR, "Failed to fstat() file \"%s\"", filename);
        goto error_exit;
    }

    mapped->length = buf.st_size;

    if(mapped->length == 0)
    {
        msg_error(errno, LOG_ERR, "Refusing to map empty file \"%s\"", filename);
        goto error_exit;
    }

    mapped->ptr =
        mmap(NULL, mapped->length, PROT_READ, MAP_PRIVATE, mapped->fd, 0);

    if(mapped->ptr == MAP_FAILED)
    {
        msg_error(errno, LOG_ERR, "Failed to mmap() file \"%s\"", filename);
        goto error_exit;
    }

    return 0;

error_exit:
    safe_close_fd(mapped->fd);
    mapped->fd = -1;

    return -1;
}

void os_unmap_file(struct os_mapped_file_data *mapped)
{
    log_assert(mapped != NULL);

    if(mapped->fd < 0)
        return;

    (void)munmap(mapped->ptr, mapped->length);

    safe_close_fd(mapped->fd);
    mapped->fd = -1;
}
