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

#ifndef DCPREGS_UPNPNAME_HH
#define DCPREGS_UPNPNAME_HH

#include <string>

/*!
 * \addtogroup registers
 */
/*!@{*/

namespace Regs
{

namespace UPnPName
{
void init();
void deinit();
void prepare_for_shutdown();
void set_appliance_id(const std::string &appliance);
void set_device_uuid(const std::string &uuid);

namespace DCP
{
ssize_t read_88_upnp_friendly_name(uint8_t *response, size_t length);
int write_88_upnp_friendly_name__v1_0_1(const uint8_t *data, size_t length);
int write_88_upnp_friendly_name__v1_0_6(const uint8_t *data, size_t length);
}

}

}

/*!@}*/

#endif /* !DCPREGS_UPNPNAME_HH */
