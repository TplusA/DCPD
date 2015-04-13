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

#ifndef DCPREGS_NETWORKING_H
#define DCPREGS_NETWORKING_H

#include <stdint.h>
#include <unistd.h>

/*!
 * \addtogroup registers
 */
/*!@{*/

#ifdef __cplusplus
extern "C" {
#endif

ssize_t dcpregs_read_51_mac_address(uint8_t *response, size_t length);
int dcpregs_write_51_mac_address(const uint8_t *data, size_t length);
int dcpregs_write_53_active_ip_profile(const uint8_t *data, size_t length);
int dcpregs_write_54_selected_ip_profile(const uint8_t *data, size_t length);
ssize_t dcpregs_read_55_dhcp_enabled(uint8_t *response, size_t length);
int dcpregs_write_55_dhcp_enabled(const uint8_t *data, size_t length);
int dcpregs_write_56_ipv4_address(const uint8_t *data, size_t length);
int dcpregs_write_57_ipv4_netmask(const uint8_t *data, size_t length);
int dcpregs_write_58_ipv4_gateway(const uint8_t *data, size_t length);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !DCPREGS_NETWORKING_H */
