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
 * It is necessary to collect all configuration changes in RAM before writing
 * them to file because updating each value immediately would cause pointless
 * file writes and trigger reconfiguration attempts on behalf of Connman.
 *
 * All configuration changes are recorded in a #Network::ConfigRequest object
 * after the client has written a 0 to the \c SELECTED_IP_PROFILE register
 * (DCP register 54). Without this, no changes are recorded. Writing a 0 to the
 * \c SELECTED_IP_PROFILE deletes all requested changes. All configuration
 * changes are applied when the client writes a 0 to the \c ACTIVE_IP_PROFILE
 * register (DCP register 53).
 */
class ConfigRequest
{
  private:
    /*!
     * Networking technology at the time the change request was commenced.
     */
    Connman::Technology selected_technology_;

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

    explicit ConfigRequest():
        selected_technology_(Connman::Technology::UNKNOWN_TECHNOLOGY)
    {}

    void reset(Connman::Technology tech)
    {
        selected_technology_ = tech;
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

    bool is_in_edit_mode() const
    {
        return selected_technology_ != Connman::Technology::UNKNOWN_TECHNOLOGY;
    }

    void cancel()
    {
        selected_technology_ = Connman::Technology::UNKNOWN_TECHNOLOGY;
    }

    bool empty() const
    {
        return !is_in_edit_mode() ||
               !(dhcpv4_mode_.is_known() ||
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

    void switch_technology(Connman::Technology tech)
    {
        if(is_in_edit_mode())
            selected_technology_ = tech;
    }

    Connman::Technology get_selected_technology() const
    {
        return selected_technology_;
    }

    bool is_dhcpv4_mode() const { return dhcpv4_mode_ == "dhcp"; }
};

}

#endif /* !NETWORK_CONFIG_REQUEST_HH */
