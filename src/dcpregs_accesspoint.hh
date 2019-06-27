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

#ifndef DCPREGS_ACCESSPOINT_HH
#define DCPREGS_ACCESSPOINT_HH

#include <vector>
#include <cstddef>
#include <cstdint>

namespace Network { class AccessPointManager; }
namespace Connman { class TechnologyRegistry; }

/*!
 * \addtogroup registers
 */
/*!@{*/

namespace Regs
{

namespace WLANAccessPoint
{
void init(Network::AccessPointManager &apman,
          const Connman::TechnologyRegistry &tech_reg);
void deinit();

namespace DCP
{
int write_107_access_point(const uint8_t *data, size_t length);
bool read_107_access_point(std::vector<uint8_t> &buffer);
}

}

}

/*!@}*/

#endif /* !DCPREGS_ACCESSPOINT_HH */
