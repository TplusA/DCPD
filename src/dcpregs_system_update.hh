/*
 * Copyright (C) 2020  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCPREGS_SYSTEM_UPDATE_HH
#define DCPREGS_SYSTEM_UPDATE_HH

#include <cstddef>
#include <cstdint>

/*!
 * \addtogroup registers
 */
/*!@{*/

namespace Regs
{

namespace SystemUpdate
{

void init();
bool process_update_request();
static inline unsigned int get_register_protocol_version() { return 0; }

namespace DCP
{
/*!
 * Set Streaming Board update parameters.
 *
 * This interface allows SPI clients to specify which version of the Streaming
 * Board software should run on the device without actually knowing how to
 * install that software version given the device's current state.
 */
int write_211_strbo_update_parameters(const uint8_t *data, size_t length);
}

}

}

/*!@}*/

#endif /* !DCPREGS_SYSTEM_UPDATE_HH */
