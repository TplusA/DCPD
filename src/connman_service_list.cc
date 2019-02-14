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

#include "connman_service_list.hh"

#include <algorithm>

void Connman::ServiceList::clear()
{
    services_.clear();
    number_of_ethernet_services_ = 0;
    number_of_wlan_services_ = 0;
}

void Connman::ServiceList::copy_from(const ServiceList &src, Technology filter)
{
    switch(filter)
    {
      case Technology::UNKNOWN_TECHNOLOGY:
        services_ = src.services_;
        number_of_ethernet_services_ = src.number_of_ethernet_services_;
        number_of_wlan_services_ = src.number_of_wlan_services_;
        break;

      case Technology::ETHERNET:
      case Technology::WLAN:
        clear();
        std::copy_if(
            src.services_.begin(), src.services_.end(), std::inserter(services_, services_.end()),
            [filter]
            (const decltype(services_)::value_type &kv) -> bool
            {
                return kv.second->get_technology() == filter;
            });

        if(filter == Technology::ETHERNET)
            number_of_ethernet_services_ = services_.size();
        else
            number_of_wlan_services_ = services_.size();

        break;
    }
}

void Connman::ServiceList::erase(const std::string &name)
{
    auto it(services_.find(name));

    if(it == services_.end())
        return;

    switch(it->second->get_technology())
    {
      case Technology::UNKNOWN_TECHNOLOGY:
        break;

      case Technology::ETHERNET:
        log_assert(number_of_ethernet_services_ > 0);
        --number_of_ethernet_services_;
        break;

      case Technology::WLAN:
        log_assert(number_of_wlan_services_ > 0);
        --number_of_wlan_services_;
        break;
    }

    services_.erase(name);
}

bool Connman::ServiceList::insert(const char *name, ServiceData &&service_data,
                                  Service<Technology::ETHERNET>::TechDataType &&ethernet_data)
{
    if(services_.find(name) != services_.end())
        return false;

    services_[name].reset(new Service<Technology::ETHERNET>(std::move(service_data),
                                                            std::move(ethernet_data)));

    ++number_of_ethernet_services_;

    return true;
}

bool Connman::ServiceList::insert(const char *name, ServiceData &&service_data,
                                  Service<Technology::WLAN>::TechDataType &&wlan_data)
{
    if(services_.find(name) != services_.end())
        return false;

    services_[name].reset(new Service<Technology::WLAN>(std::move(service_data),
                                                        std::move(wlan_data)));

    ++number_of_wlan_services_;

    return true;
}

size_t Connman::ServiceList::number_of_services() const
{
    log_assert(services_.size() == number_of_ethernet_services_ + number_of_wlan_services_);
    return services_.size();
}

struct ServiceListData
{
    Connman::ServiceList services;
    LoggedLock::RecMutex lock;

    ServiceListData()
    {
        LoggedLock::configure(lock, "ServiceListData", MESSAGE_LEVEL_DEBUG);
    }
};

/* a locking wrapper around our global service list */
static ServiceListData connman_service_list_singleton;

Connman::ServiceList::LockedConstSingleton Connman::ServiceList::get_singleton_const()
{
    return std::make_pair(std::cref(connman_service_list_singleton.services),
                          std::move(LoggedLock::UniqueLock<LoggedLock::RecMutex>(connman_service_list_singleton.lock)));
}

Connman::ServiceList::LockedSingleton Connman::ServiceList::get_singleton_for_update()
{
    return std::make_pair(std::ref(connman_service_list_singleton.services),
                          std::move(LoggedLock::UniqueLock<LoggedLock::RecMutex>(connman_service_list_singleton.lock)));
}
