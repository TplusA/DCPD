/*
 * Copyright (C) 2017, 2018  T+A elektroakustik GmbH & Co. KG
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

#include "network_device_list.hh"

static void fixup_auto_select_devices(Connman::NetworkDeviceList &devices)
{
    for(auto &d : devices)
        d.second->set_auto_select_for(d.second->technology_,
                                      devices.get_auto_select_mac_address(d.second->technology_));
}

void Connman::NetworkDeviceList::set_auto_select_mac_address(Connman::Technology technology,
                                                             const Connman::Address<Connman::AddressType::MAC> &mac_address)
{
    switch(technology)
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
        break;

      case Connman::Technology::ETHERNET:
        if(auto_select_mac_ethernet_ != mac_address)
        {
            auto_select_mac_ethernet_ = mac_address;
            fixup_auto_select_devices(*this);
        }

        break;

      case Connman::Technology::WLAN:
        if(auto_select_mac_wlan_ != mac_address)
        {
            auto_select_mac_wlan_ = mac_address;
            fixup_auto_select_devices(*this);
        }

        break;
    }
}

const Connman::Address<Connman::AddressType::MAC> &
Connman::NetworkDeviceList::get_auto_select_mac_address(Connman::Technology technology) const
{
    switch(technology)
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
        break;

      case Connman::Technology::ETHERNET:
        return auto_select_mac_ethernet_;

      case Connman::Technology::WLAN:
        return auto_select_mac_wlan_;
    }

    return dummy_device_->mac_address_;
}

bool Connman::NetworkDeviceList::is_auto_select(Connman::Technology technology,
                                                const Connman::Address<Connman::AddressType::MAC> &mac_address) const
{
    switch(technology)
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
        break;

      case Connman::Technology::ETHERNET:
        return !mac_address.empty() && mac_address == auto_select_mac_ethernet_;

      case Connman::Technology::WLAN:
        return !mac_address.empty() && mac_address == auto_select_mac_wlan_;
    }

    return false;
}

static bool process_address(Connman::Technology technology,
                            Connman::Address<Connman::AddressType::MAC> &mac_address)
{
    const auto &addr_string(mac_address.get_string());

    bool failed = (mac_address.empty() ||
                   addr_string.length() != Connman::AddressTraits<Connman::AddressType::MAC>::ADDRESS_STRING_LENGTH);

    if(!failed)
    {
        /* colons must be in correct place */
        for(size_t i = 2; i < Connman::AddressTraits<Connman::AddressType::MAC>::ADDRESS_STRING_LENGTH; i += 3)
        {
            if(addr_string[i] != ':')
            {
                msg_error(0, LOG_ERR, "MAC address wrong format (colons)");
                failed = true;
                break;
            }
        }
    }
    else
        msg_error(0, LOG_ERR, "MAC address length wrong");

    if(!failed)
    {
        /* must have hexadecimal digits in between */
        for(size_t i = 0; i < Connman::AddressTraits<Connman::AddressType::MAC>::ADDRESS_STRING_LENGTH; i += 3)
        {
            if(!isxdigit(addr_string[i]) || !isxdigit(addr_string[i + 1]))
            {
                msg_error(0, LOG_ERR, "MAC address wrong format (digits)");
                failed = true;
                break;
            }
        }
    }

    if(failed)
    {
        /* locally administered address, invalid in the wild */
        switch(technology)
        {
          case Connman::Technology::UNKNOWN_TECHNOLOGY:
            mac_address.set("12:00:00:00:00:00");
            break;

          case Connman::Technology::ETHERNET:
            mac_address.set("22:00:00:00:00:00");
            break;

          case Connman::Technology::WLAN:
            mac_address.set("32:00:00:00:00:00");
            break;
        }

        return false;
    }

    const uint8_t nibble = isdigit(addr_string[1])
        ? addr_string[1] - '0'
        : 10 + (toupper(addr_string[1]) - 'A');

    const bool result = (nibble & 0x02) == 0;

    if(!result)
        msg_error(0, LOG_ERR, "MAC address is locally administered");

    return result;
}

std::shared_ptr<Connman::NetworkDevice>
Connman::NetworkDeviceList::insert(Connman::Technology technology,
                                   Connman::Address<Connman::AddressType::MAC> &&mac_address)
{
    if(!process_address(technology, mac_address))
        return nullptr;

    auto it = devices_.find(mac_address.get_string());

    if(it != devices_.end())
        return it->second;

    const bool is_auto = is_auto_select(technology, mac_address);
    auto &dest = (*this)[mac_address];
    auto dev = std::make_shared<Connman::NetworkDevice>(technology,
                                                        std::move(mac_address),
                                                        true, is_auto);
    dest = dev;

    return dev;
}

struct NetworkDeviceListData
{
    Connman::NetworkDeviceList devices;
    std::recursive_mutex lock;
};

/* a locking wrapper around our global network device list */
static NetworkDeviceListData connman_network_device_list_singleton;

std::pair<const Connman::NetworkDeviceList &, std::unique_lock<std::recursive_mutex>>
Connman::NetworkDeviceList::get_singleton_const()
{
    return std::make_pair(std::cref(connman_network_device_list_singleton.devices),
                          std::move(std::unique_lock<std::recursive_mutex>(connman_network_device_list_singleton.lock)));
}

std::pair<Connman::NetworkDeviceList &, std::unique_lock<std::recursive_mutex>>
Connman::NetworkDeviceList::get_singleton_for_update()
{
    return std::make_pair(std::ref(connman_network_device_list_singleton.devices),
                          std::move(std::unique_lock<std::recursive_mutex>(connman_network_device_list_singleton.lock)));
}
