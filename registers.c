#include <config.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
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

static ssize_t read_51_mac_address(uint8_t *response, size_t length)
{
    msg_info("read 51 handler %p %zu", response, length);

    /*
     * FIXME: Hard-coded, wrong MAC address string for testing purposes.
     */
    static const char mac_address[] = "12:34:56:78:9A:BC";

    assert(length == sizeof(mac_address));

    memcpy(response, mac_address, sizeof(mac_address));
    return sizeof(mac_address);
}

static int write_51_mac_address(const uint8_t *data, size_t length)
{
    msg_info("write 51 handler %p %zu", data, length);

    if(length != 18)
    {
        msg_error(EINVAL, LOG_ERR, "Unexpected data length %zu", length);
        return -1;
    }

    if(data[17] != '\0')
    {
        msg_error(EINVAL, LOG_ERR,
                  "Received MAC address not zero-terminated");
        return -1;
    }

    msg_info("Received MAC address \"%s\", should validate address and "
             "configure adapter", (const char *)data);

    return 0;
}

static ssize_t read_55_dhcp_enabled(uint8_t *response, size_t length)
{
    msg_info("read 55 handler %p %zu", response, length);
    assert(length == 2);

    response[0] = 0;
    return length;
}

static int write_55_dhcp_enabled(const uint8_t *data, size_t length)
{
    msg_info("write 55 handler %p %zu", data, length);
    assert(length == 2);

    if(data[0] > 1)
    {
        msg_error(EINVAL, LOG_ERR,
                  "Received invalid DHCP configuration parameter 0x%02x",
                  data[0]);
        return -1;
    }

    msg_info("Should %sable DHCP", data[0] == 0 ? "dis" : "en");

    return 0;
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
    {
        /* MAC address */
        .address = 51,
        .flags = DCP_REGISTER_FLAG_IS_VARIABLE_LENGTH |
                 DCP_REGISTER_FLAG_IS_CACHEABLE,
        .max_data_size = 18,
        .read_handler = read_51_mac_address,
        .write_handler = write_51_mac_address,
    },
    {
        /* Enable or disable DHCP */
        .address = 55,
        .flags = DCP_REGISTER_FLAG_IS_CACHEABLE,
        .read_handler = read_55_dhcp_enabled,
        .write_handler = write_55_dhcp_enabled,
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
