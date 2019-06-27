/*
 * Copyright (C) 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCPREGS_DATETIME_HH
#define DCPREGS_DATETIME_HH

#include <vector>
#include <cstdint>

/*!
 * \addtogroup registers
 */
/*!@{*/

namespace Regs
{
namespace DateTime
{
namespace DCP
{
bool read_207_date_and_time(std::vector<uint8_t> &buffer);
}
}
}

/*!@}*/

#endif /* !DCPREGS_DATETIME_HH */
