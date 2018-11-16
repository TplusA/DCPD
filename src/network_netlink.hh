/*
 * Copyright (C) 2018  T+A elektroakustik GmbH & Co. KG
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

#ifndef NETWORK_NETLINK_HH
#define NETWORK_NETLINK_HH

#include "connman_address.hh"

#include <vector>
#include <string>
#include <tuple>

namespace Network
{

using NetlinkList =
    std::vector<std::tuple<std::string,
                           Connman::Address<Connman::AddressType::MAC>,
                           Connman::Technology>>;

NetlinkList os_get_network_devices();

}

#endif /* !NETWORK_NETLINK_HH */