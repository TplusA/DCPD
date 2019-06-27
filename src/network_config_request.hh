/*
 * Copyright (C) 2018, 2019  T+A elektroakustik GmbH & Co. KG
 *
 * This file is part of DCPD.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
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
    enum class ApplyWhen
    {
        NEVER,
        ON_AUTO_CONNECT,
        NOW,
    };

    Maybe<ApplyWhen> when_;

    Maybe<std::string> dhcpv4_mode_;
    Maybe<std::string> ipv4_address_;
    Maybe<std::string> ipv4_netmask_;
    Maybe<std::string> ipv4_gateway_;

    Maybe<std::string> dhcpv6_mode_;
    Maybe<std::string> ipv6_address_;
    Maybe<std::string> ipv6_prefix_length_;
    Maybe<std::string> ipv6_gateway_;

    Maybe<std::vector<std::string>> dns_servers_;
    Maybe<std::vector<std::string>> time_servers_;
    Maybe<std::vector<std::string>> domains_;

    Maybe<std::string> proxy_method_;
    Maybe<std::string> proxy_pac_url_;
    Maybe<std::vector<std::string>> proxy_servers_;
    Maybe<std::vector<std::string>> proxy_excluded_;

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
        when_.set_unknown();
        dhcpv4_mode_.set_unknown();
        ipv4_address_.set_unknown();
        ipv4_netmask_.set_unknown();
        ipv4_gateway_.set_unknown();
        dhcpv6_mode_.set_unknown();
        ipv6_address_.set_unknown();
        ipv6_prefix_length_.set_unknown();
        ipv6_gateway_.set_unknown();
        dns_servers_.set_unknown();
        time_servers_.set_unknown();
        domains_.set_unknown();
        proxy_method_.set_unknown();
        proxy_pac_url_.set_unknown();
        proxy_servers_.set_unknown();
        proxy_excluded_.set_unknown();
        wlan_security_mode_.set_unknown();
        wlan_ssid_ascii_.set_unknown();
        wlan_ssid_hex_.set_unknown();
        wlan_wpa_passphrase_ascii_.set_unknown();
        wlan_wpa_passphrase_hex_.set_unknown();
    }

    bool empty() const
    {
        if(!when_.is_known())
            return true;

        return !(dhcpv4_mode_.is_known() ||
                 ipv4_address_.is_known() ||
                 ipv4_netmask_.is_known() ||
                 ipv4_gateway_.is_known() ||
                 dhcpv6_mode_.is_known() ||
                 ipv6_address_.is_known() ||
                 ipv6_prefix_length_.is_known() ||
                 ipv6_gateway_.is_known() ||
                 dns_servers_.is_known() ||
                 time_servers_.is_known() ||
                 domains_.is_known() ||
                 proxy_method_.is_known() ||
                 proxy_pac_url_.is_known() ||
                 proxy_servers_.is_known() ||
                 proxy_excluded_.is_known() ||
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
