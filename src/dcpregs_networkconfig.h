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

#ifndef DCPREGS_NETWORKCONFIG_H
#define DCPREGS_NETWORKCONFIG_H

#include <stdint.h>
#include <unistd.h>

/*!
 * \addtogroup registers
 */
/*!@{*/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Function required by unit tests for initializing static data.
 */
void dcpregs_networking_init(void);

ssize_t dcpregs_read_50_network_status(uint8_t *response, size_t length);

ssize_t dcpregs_read_51_mac_address(uint8_t *response, size_t length);

int dcpregs_write_53_active_ip_profile(const uint8_t *data, size_t length);

int dcpregs_write_54_selected_ip_profile(const uint8_t *data, size_t length);

ssize_t dcpregs_read_55_dhcp_enabled(uint8_t *response, size_t length);
int dcpregs_write_55_dhcp_enabled(const uint8_t *data, size_t length);

ssize_t dcpregs_read_56_ipv4_address(uint8_t *response, size_t length);
int dcpregs_write_56_ipv4_address(const uint8_t *data, size_t length);

ssize_t dcpregs_read_57_ipv4_netmask(uint8_t *response, size_t length);
int dcpregs_write_57_ipv4_netmask(const uint8_t *data, size_t length);

ssize_t dcpregs_read_58_ipv4_gateway(uint8_t *response, size_t length);
int dcpregs_write_58_ipv4_gateway(const uint8_t *data, size_t length);

ssize_t dcpregs_read_62_primary_dns(uint8_t *response, size_t length);
int dcpregs_write_62_primary_dns(const uint8_t *data, size_t length);

ssize_t dcpregs_read_63_secondary_dns(uint8_t *response, size_t length);
int dcpregs_write_63_secondary_dns(const uint8_t *data, size_t length);

ssize_t dcpregs_read_92_wlan_security(uint8_t *response, size_t length);
int dcpregs_write_92_wlan_security(const uint8_t *data, size_t length);

ssize_t dcpregs_read_93_ibss(uint8_t *response, size_t length);
int dcpregs_write_93_ibss(const uint8_t *data, size_t length);

ssize_t dcpregs_read_94_ssid(uint8_t *response, size_t length);
int dcpregs_write_94_ssid(const uint8_t *data, size_t length);

ssize_t dcpregs_read_101_wpa_cipher(uint8_t *response, size_t length);
int dcpregs_write_101_wpa_cipher(const uint8_t *data, size_t length);

ssize_t dcpregs_read_102_passphrase(uint8_t *response, size_t length);
int dcpregs_write_102_passphrase(const uint8_t *data, size_t length);

/*!
 * Report change of networking interfaces.
 *
 * \attention
 *     Called from D-Bus thread, not main context.
 */
void dcpregs_networking_interfaces_changed(void);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !DCPREGS_NETWORKCONFIG_H */
