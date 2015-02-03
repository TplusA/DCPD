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

#ifndef NAMED_PIPE_H
#define NAMED_PIPE_H

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

struct fifo_pair
{
    int in_fd;
    int out_fd;
};

#ifdef __cplusplus
extern "C" {
#endif

int fifo_create_and_open(const char *devname, bool write_not_read);
int fifo_open(const char *devname, bool write_not_read);
void fifo_close_and_delete(int *fd, const char *devname);
void fifo_close(int *fd);
bool fifo_reopen(int *fd, const char *devname, bool write_not_read);

#ifdef __cplusplus
}
#endif

#endif /* !NAMED_PIPE_H */
