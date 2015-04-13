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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "registers.h"
#include "messages.h"

#include "dcpregs_drcp.h"
#include "dcpregs_networking.h"
#include "registers_priv.h"

static ssize_t read_17_device_status(uint8_t *response, size_t length)
{
    msg_info("read 17 handler %p %zu", response, length);
    log_assert(length == 2);

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
static const struct dcp_register_t register_map[] =
{
    {
        /* Device status register */
        .address = 17,
        .max_data_size = 2,
        .read_handler = read_17_device_status,
    },
    {
        /* Image version */
        .address = 37,
        .max_data_size = 20,
        .read_handler = read_37_image_version,
    },
    {
        /* MAC address */
        .address = 51,
        .max_data_size = 18,
        .read_handler = dcpregs_read_51_mac_address,
        .write_handler = dcpregs_write_51_mac_address,
    },
    {
        /* Enable or disable DHCP */
        .address = 55,
        .max_data_size = 1,
        .read_handler = dcpregs_read_55_dhcp_enabled,
        .write_handler = dcpregs_write_55_dhcp_enabled,
    },
    {
        /* DRC protocol */
        .address = 71,
        .max_data_size = 256,
    },
    {
        /* DRC command */
        .address = 72,
        .max_data_size = 1,
        .write_handler = dcpregs_write_drcp_command,
    },
};

static int compare_register_address(const void *a, const void *b)
{
    return
        (int)((const struct dcp_register_t *)a)->address -
        (int)((const struct dcp_register_t *)b)->address;
}

static const char *check_mac_address(const char *mac_address,
                                     size_t required_length, bool is_wired)
{
    if(mac_address == NULL ||
       strlen(mac_address) != required_length)
    {
        /* locally administered address, invalid in the wild */
        return is_wired ? "02:00:00:00:00:00" : "03:00:00:00:00:00";
    }
    else
        return mac_address;
}

static void copy_mac_address(char *dest, size_t dest_size, const char *src)
{
    strncpy(dest, src, dest_size);
    dest[dest_size - 1] = '\0';
}

void register_init(const char *ethernet_mac_address,
                   const char *wlan_mac_address,
                   const char *connman_config_path)
{
    struct register_configuration_t *config = registers_get_nonconst_data();
    struct register_network_interface_t *iface_data;
    const char *temp;

    iface_data = &config->builtin_ethernet_interface;
    iface_data->is_builtin = true;
    iface_data->is_wired = true;
    temp = check_mac_address(ethernet_mac_address,
                             sizeof(iface_data->mac_address_string) - 1,
                             iface_data->is_wired);
    copy_mac_address(iface_data->mac_address_string,
                     sizeof(iface_data->mac_address_string), temp);

    iface_data = &config->builtin_wlan_interface;
    iface_data->is_builtin = true;
    iface_data->is_wired = false;
    temp = check_mac_address(wlan_mac_address,
                             sizeof(iface_data->mac_address_string) - 1,
                             iface_data->is_wired);
    copy_mac_address(iface_data->mac_address_string,
                     sizeof(iface_data->mac_address_string), temp);

    config->active_interface = NULL;
    config->connman_config_path = connman_config_path;
}

const struct dcp_register_t *register_lookup(uint8_t register_number)
{
    static struct dcp_register_t key;

    key.address = register_number;

    return bsearch(&key, register_map,
                   sizeof(register_map) / sizeof(register_map[0]),
                   sizeof(register_map[0]), compare_register_address);
}

static struct register_configuration_t config;

const struct register_configuration_t *registers_get_data(void)
{
    return &config;
}

struct register_configuration_t *registers_get_nonconst_data(void)
{
    return &config;
}
