#ifndef DYNAMIC_BUFFER_H
#define DYNAMIC_BUFFER_H

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

/*!
 * \addtogroup dynbuffer Dynamically sized buffer
 */
/*!@{*/

struct dynamic_buffer
{
    uint8_t *data;
    size_t size;
    size_t pos;
};

void dynamic_buffer_init(struct dynamic_buffer *buffer);
void dynamic_buffer_free(struct dynamic_buffer *buffer);
bool dynamic_buffer_resize(struct dynamic_buffer *buffer, size_t size);
void dynamic_buffer_clear(struct dynamic_buffer *buffer);
bool dynamic_buffer_check_space(struct dynamic_buffer *buffer);
bool dynamic_buffer_is_allocated(const struct dynamic_buffer *buffer);
bool dynamic_buffer_is_empty(const struct dynamic_buffer *buffer);

/*!@}*/

#endif /* !DYNAMIC_BUFFER_H */
