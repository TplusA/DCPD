/*
 * Copyright (C) 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCPREGS_AUDIOPATHS_HH
#define DCPREGS_AUDIOPATHS_HH

#include <cinttypes>
#include <cstdlib>
#include <vector>

/*!
 * \addtogroup registers
 */
/*!@{*/

namespace Regs
{

namespace AudioPaths
{

void request_full_from_appliance();

namespace DCP
{
int write_82_audio_path_parameters(const uint8_t *data, size_t length);
bool read_82_audio_path_parameters(std::vector<uint8_t> &buffer);
}

}

}

/*!@}*/

#endif /* !DCPREGS_AUDIOPATHS_HH */
