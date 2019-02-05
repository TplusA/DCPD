/*
 * Copyright (C) 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef ACCESSPOINT_MANAGER_HH
#define ACCESSPOINT_MANAGER_HH

#include "accesspoint.hh"
#include "connman_service_list.hh"
#include "network_device_list.hh"

#include <atomic>
#include <mutex>

namespace Network
{

class AccessPointManager
{
  private:
    AccessPoint &ap_;
    std::atomic<AccessPoint::Status> ap_status_;

    mutable std::mutex cache_lock_;
    Connman::NetworkDeviceList cached_network_devices_;
    Connman::ServiceList cached_network_services_;

  public:
    AccessPointManager(const AccessPointManager &) = delete;
    AccessPointManager(AccessPointManager &&) = default;
    AccessPointManager &operator=(const AccessPointManager &) = delete;
    AccessPointManager &operator=(AccessPointManager &&) = default;

    explicit AccessPointManager(AccessPoint &ap);

    void start();

    void register_status_watcher(Network::AccessPoint::StatusFn &&fn)
    {
        ap_.register_status_watcher(std::move(fn));
    }

    bool activate(std::string &&ssid, std::string &&passphrase);
    bool deactivate(AccessPoint::DoneFn &&done = nullptr);
    AccessPoint::Status get_status() const { return ap_status_; }

    std::unique_lock<std::mutex> lock_cached() const { return std::unique_lock<std::mutex>(cache_lock_); }
    const Connman::NetworkDeviceList &get_cached_network_devices() const { return cached_network_devices_; }
    const Connman::ServiceList &get_cached_service_list() const { return cached_network_services_; }

  private:
    void status_watcher(Connman::TechnologyRegistry &reg,
                        Network::AccessPoint::Status old_status,
                        Network::AccessPoint::Status new_status);
};

}

#endif /* !ACCESSPOINT_MANAGER_HH */
