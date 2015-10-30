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

#ifndef OS_H
#define OS_H

#include <unistd.h>

/*!
 * Data for keeping track of memory-mapped files.
 */
struct os_mapped_file_data
{
    int fd;
    void *ptr;
    size_t length;
};

#ifdef __cplusplus
extern "C" {
#endif

extern ssize_t (*os_read)(int fd, void *dest, size_t count);
extern ssize_t (*os_write)(int fd, const void *buf, size_t count);

int os_write_from_buffer(const void *src, size_t count, int fd);
int os_try_read_to_buffer(void *dest, size_t count, size_t *dest_pos, int fd);
void os_abort(void);

int os_file_new(const char *filename);
void os_file_close(int fd);
void os_file_delete(const char *filename);

/*!
 * Flush changes in a directory to storage.
 */
void os_sync_dir(const char *path);

int os_map_file_to_memory(struct os_mapped_file_data *mapped,
                          const char *filename);
void os_unmap_file(struct os_mapped_file_data *mapped);

#ifdef __cplusplus
}
#endif

#endif /* !OS_H */
