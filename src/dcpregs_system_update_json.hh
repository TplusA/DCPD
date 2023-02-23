/*
 * Copyright (C) 2020, 2023  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCPREGS_SYSTEM_UPDATE_JSON_HH
#define DCPREGS_SYSTEM_UPDATE_JSON_HH

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch-enum"
#pragma GCC diagnostic ignored "-Wtype-limits"
#include "json.hh"
#pragma GCC diagnostic pop

namespace Regs
{

namespace SystemUpdate
{
nlohmann::json get_update_request();
}

}

#endif /* !DCPREGS_SYSTEM_UPDATE_JSON_HH */
