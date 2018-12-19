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

#ifndef NETWORK_DEVICE_LIST_HH
#define NETWORK_DEVICE_LIST_HH

#include "network_device.hh"

#include <map>
#include <memory>
#include <mutex>

namespace Connman
{

class NetworkDeviceList
{
  public:
    using Map = std::map<const std::string, std::shared_ptr<NetworkDevice>>;

  private:
    Map devices_;

    std::shared_ptr<NetworkDevice> dummy_device_;
    std::shared_ptr<NetworkDevice> nullptr_device_;

    Address<AddressType::MAC> auto_select_mac_ethernet_;
    Address<AddressType::MAC> auto_select_mac_wlan_;

  public:
    NetworkDeviceList(const NetworkDeviceList &) = delete;
    NetworkDeviceList &operator=(const NetworkDeviceList &) = delete;

    explicit NetworkDeviceList():
        dummy_device_(std::make_shared<NetworkDevice>(Technology::UNKNOWN_TECHNOLOGY,
                                                      std::move(Address<AddressType::MAC>()),
                                                      false, false))
    {}

    void clear()
    {
        auto_select_mac_ethernet_.unset();
        auto_select_mac_wlan_.unset();
        devices_.clear();
    }

    void copy_from(const NetworkDeviceList &src,
                   Technology filter = Technology::UNKNOWN_TECHNOLOGY);

    void set_auto_select_mac_address(Technology technology,
                                     const Address<AddressType::MAC> &mac_address);
    const Address<AddressType::MAC> &get_auto_select_mac_address(Technology technology) const;

    bool is_auto_select(Technology technology,
                        const Address<AddressType::MAC> &mac_address) const;

    std::shared_ptr<NetworkDevice> insert(Technology technology,
                                          Address<AddressType::MAC> &&mac_address);

    std::shared_ptr<NetworkDevice> operator[](const Address<AddressType::MAC> &mac_address)
    {
        if(mac_address.empty())
            return dummy_device_;

        auto it(devices_.find(mac_address.get_string()));
        return it != devices_.end() ? it->second : nullptr_device_;
    }

    std::shared_ptr<const NetworkDevice> operator[](const Address<AddressType::MAC> &mac_address) const
    {
        return (*const_cast<NetworkDeviceList *>(this))[mac_address];
    }

    Map::const_iterator begin() const { return devices_.begin(); }
    Map::const_iterator end() const { return devices_.end(); }
    Map::iterator begin() { return devices_.begin(); }
    Map::iterator end() { return devices_.end(); }

    static std::pair<const NetworkDeviceList &, std::unique_lock<std::recursive_mutex>>
    get_singleton_const();

    static std::pair<NetworkDeviceList &, std::unique_lock<std::recursive_mutex>>
    get_singleton_for_update();

  private:
    Map::const_iterator find(const std::string &mac_address) const { return devices_.find(mac_address); }
    Map::iterator find(const std::string &mac_address) { return devices_.find(mac_address); }
};

}

#endif /* !NETWORK_DEVICE_LIST_HH */
