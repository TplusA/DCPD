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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "network_device_list.hh"

#include <algorithm>

static void fixup_auto_select_devices(Connman::NetworkDeviceList &devices)
{
    for(auto &d : devices)
        d.second->set_auto_select_for(d.second->technology_,
                                      devices.get_auto_select_mac_address(d.second->technology_));
}

void Connman::NetworkDeviceList::copy_from(const NetworkDeviceList &src, Technology filter)
{
    if(filter == Technology::UNKNOWN_TECHNOLOGY)
        devices_ = src.devices_;
    else
    {
        devices_.clear();
        std::copy_if(
            src.devices_.begin(), src.devices_.end(), std::inserter(devices_, devices_.end()),
            [filter]
            (const decltype(devices_)::value_type &kv) -> bool
            {
                return kv.second->technology_ == filter;
            });
    }

    auto_select_mac_ethernet_ = src.auto_select_mac_ethernet_;
    auto_select_mac_wlan_ = src.auto_select_mac_wlan_;
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
    if(mac_address.empty())
    {
        msg_error(0, LOG_ERR, "MAC address empty");

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

    if(Connman::is_locally_administered_mac_address(mac_address))
    {
        msg_error(0, LOG_ERR, "MAC address is locally administered");
        return false;
    }

    return true;
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
    auto dev = std::make_shared<Connman::NetworkDevice>(technology,
                                                        std::move(mac_address),
                                                        true, is_auto);
    devices_.insert({dev->mac_address_.get_string(), dev});

    return dev;
}

struct NetworkDeviceListData
{
    Connman::NetworkDeviceList devices;
    LoggedLock::RecMutex lock;

    NetworkDeviceListData()
    {
        LoggedLock::configure(lock, "NetworkDeviceListData", MESSAGE_LEVEL_DEBUG);
    }
};

/* a locking wrapper around our global network device list */
static NetworkDeviceListData connman_network_device_list_singleton;

std::pair<const Connman::NetworkDeviceList &, LoggedLock::UniqueLock<LoggedLock::RecMutex>>
Connman::NetworkDeviceList::get_singleton_const()
{
    return std::make_pair(std::cref(connman_network_device_list_singleton.devices),
                          std::move(LoggedLock::UniqueLock<LoggedLock::RecMutex>(connman_network_device_list_singleton.lock)));
}

std::pair<Connman::NetworkDeviceList &, LoggedLock::UniqueLock<LoggedLock::RecMutex>>
Connman::NetworkDeviceList::get_singleton_for_update()
{
    return std::make_pair(std::ref(connman_network_device_list_singleton.devices),
                          std::move(LoggedLock::UniqueLock<LoggedLock::RecMutex>(connman_network_device_list_singleton.lock)));
}
