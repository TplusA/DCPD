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
