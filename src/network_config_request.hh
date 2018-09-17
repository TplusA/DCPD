/*
 * Copyright (C) 2018  T+A elektroakustik GmbH & Co. KG
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

#ifndef NETWORK_CONFIG_REQUEST_HH
#define NETWORK_CONFIG_REQUEST_HH

#include "connman_address.hh"
#include "maybe.hh"

#include <string>
#include <vector>

namespace Network
{

enum class WPSMode
{
    INVALID,
    NONE,
    DIRECT,
    SCAN,
    ABORT,
};

/*!
 * Network configuration change requests.
 *
 * This is a full set of network configuration, expected to be complete and
 * valid. Proper validation is done when the change request is applied, not
 * when filling it (hence all the public members).
 */
class ConfigRequest
{
  public:
    Maybe<std::string> dhcpv4_mode_;
    Maybe<std::string> ipv4_address_;
    Maybe<std::string> ipv4_netmask_;
    Maybe<std::string> ipv4_gateway_;
    Maybe<std::vector<std::string>> ipv4_dns_servers_;

    Maybe<std::string> wlan_security_mode_;
    Maybe<std::string> wlan_ssid_ascii_;
    Maybe<std::string> wlan_ssid_hex_;
    Maybe<std::string> wlan_wpa_passphrase_ascii_;
    Maybe<std::string> wlan_wpa_passphrase_hex_;

  public:
    ConfigRequest(const ConfigRequest &) = delete;
    ConfigRequest &operator=(const ConfigRequest &) = delete;

    explicit ConfigRequest() {}

    void reset()
    {
        dhcpv4_mode_.set_unknown();
        ipv4_address_.set_unknown();
        ipv4_netmask_.set_unknown();
        ipv4_gateway_.set_unknown();
        ipv4_dns_servers_.set_unknown();
        wlan_security_mode_.set_unknown();
        wlan_ssid_ascii_.set_unknown();
        wlan_ssid_hex_.set_unknown();
        wlan_wpa_passphrase_ascii_.set_unknown();
        wlan_wpa_passphrase_hex_.set_unknown();
    }

    bool empty() const
    {
        return !(dhcpv4_mode_.is_known() ||
                 ipv4_address_.is_known() ||
                 ipv4_netmask_.is_known() ||
                 ipv4_gateway_.is_known() ||
                 ipv4_dns_servers_.is_known() ||
                 wlan_security_mode_.is_known() ||
                 wlan_ssid_ascii_.is_known() ||
                 wlan_ssid_hex_.is_known() ||
                 wlan_wpa_passphrase_ascii_.is_known() ||
                 wlan_wpa_passphrase_hex_.is_known());
    }

    bool is_dhcpv4_mode() const { return dhcpv4_mode_ == "dhcp"; }
};

}

#endif /* !NETWORK_CONFIG_REQUEST_HH */
