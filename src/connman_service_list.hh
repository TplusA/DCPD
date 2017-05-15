/*
 * Copyright (C) 2017  T+A elektroakustik GmbH & Co. KG
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

#ifndef CONNMAN_SERVICE_LIST_HH
#define CONNMAN_SERVICE_LIST_HH

#include <map>
#include <memory>
#include <mutex>

#include "connman_service.hh"

namespace Connman
{

class ServiceList
{
  public:
    using Map = std::map<std::string, std::unique_ptr<ServiceBase>>;

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

    void clear()
    {
        services_.clear();
        number_of_ethernet_services_ = 0;
        number_of_wlan_services_ = 0;
    }

    void erase(const std::string &name)
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

    bool insert(const char *name, ServiceData &&service_data,
                Service<Technology::ETHERNET>::TechDataType &&ethernet_data,
                bool is_ours)
    {
        if(services_.find(name) != services_.end())
            return false;

        services_[name].reset(new Service<Technology::ETHERNET>(std::move(service_data),
                                                                std::move(ethernet_data),
                                                                is_ours));

        ++number_of_ethernet_services_;

        return true;
    }

    bool insert(const char *name, ServiceData &&service_data,
                Service<Technology::WLAN>::TechDataType &&wlan_data,
                bool is_ours)
    {
        if(services_.find(name) != services_.end())
            return false;

        services_[name].reset(new Service<Technology::WLAN>(std::move(service_data),
                                                            std::move(wlan_data),
                                                            is_ours));

        ++number_of_wlan_services_;

        return true;
    }

    size_t number_of_services() const
    {
        log_assert(services_.size() == number_of_ethernet_services_ + number_of_wlan_services_);
        return services_.size();
    }

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
};

std::pair<const ServiceList &, std::unique_lock<std::recursive_mutex>>
get_service_list_singleton_const();

std::pair<ServiceList &, std::unique_lock<std::recursive_mutex>>
get_service_list_singleton_for_update();

}

#endif /* !CONNMAN_SERVICE_LIST_HH */