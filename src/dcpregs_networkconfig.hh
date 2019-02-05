/*
 * Copyright (C) 2017, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCPREGS_NETWORKCONFIG_HH
#define DCPREGS_NETWORKCONFIG_HH

#include "network_config_request.hh"

namespace Network { class AccessPointManager; }

/*!
 * \addtogroup registers
 */
/*!@{*/

namespace Regs
{

namespace NetworkConfig
{
/*!
 * Function required by unit tests for initializing static data.
 */
void init();

/*!
 * Function required by unit tests.
 */
void deinit();

void set_primary_technology(Connman::Technology tech);

bool request_configuration_for_mac(Network::ConfigRequest &config_request,
                                   const Connman::Address<Connman::AddressType::MAC> &mac,
                                   Connman::Technology tech,
                                   Network::AccessPointManager &apman);

/*!
 * Report change of networking interfaces.
 *
 * \attention
 *     Called from D-Bus thread, not main context.
 */
void interfaces_changed();

/*!
 * Report system shutdown event.
 *
 * This function blocks until a possibly ongoing rewrite of a configuration
 * file completes and the file has been flushed to storage. Further attempts to
 * update network configuration files are blocked after this function has been
 * called.
 *
 * \attention
 *     Called from D-Bus thread, not main context.
 */
void prepare_for_shutdown();

namespace DCP
{
ssize_t read_50_network_status(uint8_t *response, size_t length);

ssize_t read_51_mac_address(uint8_t *response, size_t length);

int write_53_active_ip_profile(const uint8_t *data, size_t length);

int write_54_selected_ip_profile(const uint8_t *data, size_t length);

ssize_t read_55_dhcp_enabled(uint8_t *response, size_t length);
int write_55_dhcp_enabled(const uint8_t *data, size_t length);

ssize_t read_56_ipv4_address(uint8_t *response, size_t length);
int write_56_ipv4_address(const uint8_t *data, size_t length);

ssize_t read_57_ipv4_netmask(uint8_t *response, size_t length);
int write_57_ipv4_netmask(const uint8_t *data, size_t length);

ssize_t read_58_ipv4_gateway(uint8_t *response, size_t length);
int write_58_ipv4_gateway(const uint8_t *data, size_t length);

ssize_t read_62_primary_dns(uint8_t *response, size_t length);
int write_62_primary_dns(const uint8_t *data, size_t length);

ssize_t read_63_secondary_dns(uint8_t *response, size_t length);
int write_63_secondary_dns(const uint8_t *data, size_t length);

ssize_t read_92_wlan_security(uint8_t *response, size_t length);
int write_92_wlan_security(const uint8_t *data, size_t length);

ssize_t read_93_ibss(uint8_t *response, size_t length);
int write_93_ibss(const uint8_t *data, size_t length);

ssize_t read_94_ssid(uint8_t *response, size_t length);
int write_94_ssid(const uint8_t *data, size_t length);

ssize_t read_101_wpa_cipher(uint8_t *response, size_t length);
int write_101_wpa_cipher(const uint8_t *data, size_t length);

ssize_t read_102_passphrase(uint8_t *response, size_t length);
int write_102_passphrase(const uint8_t *data, size_t length);
}

}

}

/*!@}*/

#endif /* !DCPREGS_NETWORKCONFIG_HH */
