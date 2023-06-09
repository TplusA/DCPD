/*
 * Copyright (C) 2015, 2016, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#include "named_pipe.h"
#include "messages.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

int fifo_create_and_open(const char *devname, bool write_not_read)
{
    int ret = mkfifo(devname, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

    if(ret < 0)
    {
        if(errno != EEXIST)
        {
            msg_error(errno, LOG_EMERG,
                      "Failed creating named pipe \"%s\"", devname);
            return -1;
        }
    }

    return fifo_open(devname, write_not_read);
}

int fifo_open(const char *devname, bool write_not_read)
{
    int ret = open(devname, write_not_read ? O_WRONLY : (O_RDONLY | O_NONBLOCK));

    if(ret < 0)
        msg_error(errno, LOG_EMERG,
                  "Failed opening named pipe \"%s\"", devname);
    else
        msg_vinfo(MESSAGE_LEVEL_TRACE, "Opened %sable pipe \"%s\", fd %d",
                  write_not_read ? "writ" : "read", devname, ret);

    return ret;
}

void fifo_close(int *fd)
{
    int ret;

    while((ret = close(*fd)) < 0 && errno == EINTR)
        ;

    if(ret < 0)
        msg_error(errno, LOG_ERR, "Failed closing named pipe fd %d", *fd);

    *fd = -1;
}

void fifo_close_and_delete(int *fd, const char *devname)
{
    fifo_close(fd);

    if(unlink(devname) < 0)
        msg_error(errno, LOG_ERR,
                  "Failed deleting named pipe \"%s\"", devname);
}

bool fifo_reopen(int *fd, const char *devname, bool write_not_read)
{
    fifo_close(fd);
    *fd = fifo_open(devname, write_not_read);
    return *fd >= 0;
}
