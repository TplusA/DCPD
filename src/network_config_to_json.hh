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

#ifndef NETWORK_CONFIG_TO_JSON_HH
#define NETWORK_CONFIG_TO_JSON_HH

#include "connman_service_list.hh"
#include "network_device_list.hh"

namespace Network
{

std::string configuration_to_json(const Connman::ServiceList &services,
                                  const Connman::NetworkDeviceList &devices,
                                  const std::string &have_version,
                                  bool is_cached, std::string &version);

}

#endif /* !NETWORK_CONFIG_TO_JSON_HH */
