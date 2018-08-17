/*
 * Copyright (C) 2016, 2018  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCPREGS_PROTOLEVEL_HH
#define DCPREGS_PROTOLEVEL_HH

#include <cstdint>
#include <cstdlib>

/*!
 * \addtogroup registers
 */
/*!@{*/

namespace Regs
{

namespace DCPVersion
{
/*!
 * Function required by unit tests for initializing static data.
 */
void init();

namespace DCP
{
ssize_t read_1_protocol_level(uint8_t *response, size_t length);
int write_1_protocol_level(const uint8_t *data, size_t length);
}

}

}

/*!@}*/

#endif /* !DCPREGS_PROTOLEVEL_HH */
