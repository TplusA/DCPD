#ifndef DRCP_H
#define DRCP_H

#include "named_pipe.h"
#include "dynamic_buffer.h"

bool drcp_fill_buffer(struct dynamic_buffer *buffer,
                      const struct fifo_pair *fds);
bool drcp_read_size_from_fd(struct dynamic_buffer *buffer,
                            const struct fifo_pair *fds,
                            size_t *expected_size, size_t *payload_offset);
void drcp_finish_request(bool is_ok, const struct fifo_pair *fds);

#endif /* !DRCP_H */
