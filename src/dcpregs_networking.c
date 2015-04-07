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

#include <string.h>
#include <errno.h>

#include "dcpregs_networking.h"
#include "registers_priv.h"
#include "messages.h"

ssize_t dcpregs_read_51_mac_address(uint8_t *response, size_t length)
{
    msg_info("read 51 handler %p %zu", response, length);

    const struct register_configuration_t *config = registers_get_data();

    log_assert(length == sizeof(config->mac_address_string));

    if(length <  sizeof(config->mac_address_string))
        return -1;

    memcpy(response, config->mac_address_string, sizeof(config->mac_address_string));

    return sizeof(config->mac_address_string);
}

int dcpregs_write_51_mac_address(const uint8_t *data, size_t length)
{
    msg_info("write 51 handler %p %zu", data, length);

    const struct register_configuration_t *config = registers_get_data();

    if(length != sizeof(config->mac_address_string))
    {
        msg_error(EINVAL, LOG_ERR, "Unexpected data length %zu", length);
        return -1;
    }

    if(data[sizeof(config->mac_address_string) - 1] != '\0')
    {
        msg_error(EINVAL, LOG_ERR,
                  "Received MAC address not zero-terminated");
        return -1;
    }

    msg_info("Received MAC address \"%s\", should validate address and "
             "configure adapter", (const char *)data);

    return 0;
}

ssize_t dcpregs_read_55_dhcp_enabled(uint8_t *response, size_t length)
{
    msg_info("read 55 handler %p %zu", response, length);
    log_assert(length == 1);

    response[0] = 0;
    return length;
}

int dcpregs_write_55_dhcp_enabled(const uint8_t *data, size_t length)
{
    msg_info("write 55 handler %p %zu", data, length);
    log_assert(length == 1);

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
