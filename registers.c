#include <config.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "registers.h"

static ssize_t request_37_image_version(uint8_t *response, size_t length)
{
    /*
     * FIXME: Hard-coded, wrong version string for testing purposes.
     */
    static const char image_version[] = "1234";

    if(sizeof(image_version) < length)
        length = sizeof(image_version);

    memcpy(response, image_version, length);
    return length;
}

/*!
 * List of implemented DCP registers.
 *
 * \note The entries must be sorted by address for the binary search.
 */
static const struct register_t register_map[] =
{
    {
        /* Image version */
        .address = 37,
        .flags = DCP_REGISTER_FLAG_IS_VARIABLE_LENGTH |
                 DCP_REGISTER_FLAG_IS_CACHEABLE,
        .max_data_size = 20,
        .request_handler = request_37_image_version,
        .response_handler = NULL,
    },
};
