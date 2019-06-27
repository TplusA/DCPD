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

#ifndef DCPREGS_UPNPSERVER_HH
#define DCPREGS_UPNPSERVER_HH

#include <vector>
#include <cstddef>
#include <cstdint>

/*!
 * \addtogroup registers
 */
/*!@{*/

namespace Regs
{

namespace UPnPServer
{

void connected(bool is_connected);
void set_busy_state(bool is_busy);

namespace DCP
{
int write_89_upnp_server_command(const uint8_t *data, size_t length);
bool read_89_upnp_server_status(std::vector<uint8_t> &buffer);
}

}

}

/*!@}*/

#endif /* !DCPREGS_UPNPSERVER_HH */
