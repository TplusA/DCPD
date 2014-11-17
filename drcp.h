#ifndef DRCP_H
#define DRCP_H

#include "dynamic_buffer.h"

/*!
 * \addtogroup drcp Communication with DRCPD
 */
/*!@{*/

#ifdef __cplusplus
extern "C" {
#endif

bool drcp_fill_buffer(struct dynamic_buffer *buffer, int in_fd);
bool drcp_read_size_from_fd(struct dynamic_buffer *buffer, int in_fd,
                            size_t *expected_size, size_t *payload_offset);
void drcp_finish_request(bool is_ok, int out_fd);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !DRCP_H */
