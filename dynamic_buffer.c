#include <config.h>

#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include "dynamic_buffer.h"
#include "messages.h"

void dynamic_buffer_init(struct dynamic_buffer *buffer)
{
    buffer->data = NULL;
    buffer->size = 0;
    buffer->pos = 0;
}

void dynamic_buffer_free(struct dynamic_buffer *buffer)
{
    if(buffer->data == NULL)
        return;

    free(buffer->data);
    dynamic_buffer_init(buffer);
}

bool dynamic_buffer_resize(struct dynamic_buffer *buffer, size_t size)
{
    assert(buffer != NULL);
    assert(size > 0);

    void *temp = realloc(buffer->data, size);

    if(temp == NULL)
    {
        msg_error(errno, LOG_CRIT,
                  "Failed resizing buffer from %zu to %zu bytes",
                  buffer->size, size);
        return false;
    }

    buffer->data = temp;
    buffer->size = size;

    return true;
}

bool dynamic_buffer_is_allocated(const struct dynamic_buffer *buffer)
{
    return buffer->size > 0;
}

bool dynamic_buffer_is_empty(const struct dynamic_buffer *buffer)
{
    return buffer->pos == 0;
}
