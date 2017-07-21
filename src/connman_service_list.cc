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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "connman_service_list.hh"

struct ServiceListData
{
    Connman::ServiceList services;
    std::recursive_mutex lock;
};

/* a locking wrapper around our global service list */
static ServiceListData connman_service_list_singleton;

std::pair<const Connman::ServiceList &, std::unique_lock<std::recursive_mutex>>
Connman::ServiceList::get_singleton_const()
{
    return std::make_pair(std::cref(connman_service_list_singleton.services),
                          std::move(std::unique_lock<std::recursive_mutex>(connman_service_list_singleton.lock)));
}

std::pair<Connman::ServiceList &, std::unique_lock<std::recursive_mutex>>
Connman::ServiceList::get_singleton_for_update()
{
    return std::make_pair(std::ref(connman_service_list_singleton.services),
                          std::move(std::unique_lock<std::recursive_mutex>(connman_service_list_singleton.lock)));
}
