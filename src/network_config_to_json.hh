/*
 * Copyright (C) 2018, 2019  T+A elektroakustik GmbH & Co. KG
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
