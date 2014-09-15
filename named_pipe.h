#ifndef NAMED_PIPE_H
#define NAMED_PIPE_H

#include <stdbool.h>
#include <stdint.h>

int fifo_create_and_open(const char *devname, bool write_not_read);
int fifo_open(const char *devname, bool write_not_read);
void fifo_close_and_delete(int *fd, const char *devname);
void fifo_close(int *fd);
bool fifo_reopen(int *fd, const char *devname, bool write_not_read);
int fifo_write_from_buffer(const uint8_t *src, size_t count, int fd);

#endif /* !NAMED_PIPE_H */
