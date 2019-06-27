/*
 * Copyright (C) 2017, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef NETWORK_DEVICE_HH
#define NETWORK_DEVICE_HH

#include "connman_address.hh"

namespace Connman
{

class NetworkDevice
{
  public:
    const Technology technology_;
    const Address<AddressType::MAC> mac_address_;
    const bool is_real_;

  private:
    bool is_auto_select_;

  public:
    NetworkDevice(const NetworkDevice &) = delete;
    NetworkDevice &operator=(const NetworkDevice &) = delete;

    explicit NetworkDevice(Technology technology,
                           Address<AddressType::MAC> &&mac_address,
                           bool is_real, bool is_auto_select):
        technology_(technology),
        mac_address_(mac_address),
        is_real_(is_real),
        is_auto_select_(is_auto_select)
    {}

    bool is_auto_selected_device() const { return is_auto_select_; }

    void set_auto_select_for(Technology technology,
                             const Address<AddressType::MAC> &mac_address)
    {
        is_auto_select_ = (technology_ == technology &&
                           mac_address_ == mac_address);
    }
};

}

#endif /* !NETWORK_DEVICE_HH */
