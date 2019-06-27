/*
 * Copyright (C) 2017, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef CONNMAN_SERVICE_LIST_HH
#define CONNMAN_SERVICE_LIST_HH

#include "connman_service.hh"
#include "logged_lock.hh"

#include <map>

namespace Connman
{

class ServiceList
{
  public:
    using Map = std::map<std::string, std::shared_ptr<ServiceBase>>;

  private:
    Map services_;
    size_t number_of_ethernet_services_;
    size_t number_of_wlan_services_;

  public:
    ServiceList(const ServiceList &) = delete;
    ServiceList &operator=(const ServiceList &) = delete;

    explicit ServiceList():
        number_of_ethernet_services_(0),
        number_of_wlan_services_(0)
    {}

    void clear();
    void copy_from(const ServiceList &src,
                   Technology filter = Technology::UNKNOWN_TECHNOLOGY);
    void erase(const std::string &name);
    bool insert(const char *name, ServiceData &&service_data,
                Service<Technology::ETHERNET>::TechDataType &&ethernet_data);
    bool insert(const char *name, ServiceData &&service_data,
                Service<Technology::WLAN>::TechDataType &&wlan_data);
    size_t number_of_services() const;
    size_t number_of_ethernet_services() const { return number_of_ethernet_services_; }
    size_t number_of_wlan_services() const { return number_of_wlan_services_; }

    ServiceBase *operator[](const std::string &name)
    {
        auto it(services_.find(name));
        return it != services_.end() ? it->second.get() : nullptr;
    }

    const ServiceBase *operator[](const std::string &name) const
    {
        return const_cast<ServiceList *>(this)->operator[](name);
    }

    Map::const_iterator find(const std::string &name) const { return services_.find(name); }
    Map::const_iterator begin() const { return services_.begin(); }
    Map::const_iterator end() const { return services_.end(); }
    Map::iterator find(const std::string &name) { return services_.find(name); }
    Map::iterator begin() { return services_.begin(); }
    Map::iterator end() { return services_.end(); }

    using LockedConstSingleton =
        std::pair<const ServiceList &, LoggedLock::UniqueLock<LoggedLock::RecMutex>>;
    using LockedSingleton =
        std::pair<ServiceList &, LoggedLock::UniqueLock<LoggedLock::RecMutex>>;

    static LockedConstSingleton get_singleton_const();
    static LockedSingleton get_singleton_for_update();
};

}

#endif /* !CONNMAN_SERVICE_LIST_HH */
