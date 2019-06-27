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

#ifndef DCPREGS_APPLIANCE_H
#define DCPREGS_APPLIANCE_H

#include <cinttypes>
#include <cstdlib>

/*!
 * \addtogroup registers
 */
/*!@{*/

namespace Regs
{

namespace Appliance
{

bool init();
void configure();

uint8_t get_standby_state_for_dbus();
bool request_standby_state(uint8_t state, uint8_t &current_state,
                           bool &is_pending);

namespace DCP
{
int write_18_appliance_status(const uint8_t *data, size_t length);
ssize_t read_19_appliance_control(uint8_t *response, size_t length);
ssize_t read_87_appliance_id(uint8_t *response, size_t length);
int write_87_appliance_id(const uint8_t *data, size_t length);
}

}

}

/*!@}*/

#endif /* !DCPREGS_APPLIANCE_H */
