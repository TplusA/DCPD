#include <config.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "registers.h"
#include "messages.h"

static ssize_t read_17_device_status(uint8_t *response, size_t length)
{
    msg_info("read 17 handler %p %zu", response, length);
    assert(length == 2);

    /*
     * FIXME: Hard-coded, wrong status bits for testing purposes.
     */
    response[0] = 0x21;
    response[1] = 0;
    return length;
}

static ssize_t read_37_image_version(uint8_t *response, size_t length)
{
    msg_info("read 37 handler %p %zu", response, length);

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
        /* Device status register */
        .address = 17,
        .flags = DCP_REGISTER_FLAG_IS_CACHEABLE,
        .read_handler = read_17_device_status,
    },
    {
        /* Image version */
        .address = 37,
        .flags = DCP_REGISTER_FLAG_IS_VARIABLE_LENGTH |
                 DCP_REGISTER_FLAG_IS_CACHEABLE,
        .max_data_size = 20,
        .read_handler = read_37_image_version,
    },
};

static int compare_register_address(const void *a, const void *b)
{
    return
        (int)((const struct register_t *)a)->address -
        (int)((const struct register_t *)b)->address;
}

const struct register_t *register_lookup(uint8_t register_number)
{
    static struct register_t key;

    key.address = register_number;

    return bsearch(&key, register_map,
                   sizeof(register_map) / sizeof(register_map[0]),
                   sizeof(register_map[0]), compare_register_address);
}
