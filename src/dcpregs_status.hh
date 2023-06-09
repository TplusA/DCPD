/*
 * Copyright (C) 2015, 2018, 2019, 2021  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCPREGS_STATUS_HH
#define DCPREGS_STATUS_HH

/*!
 * \addtogroup registers
 */
/*!@{*/

namespace Regs
{

namespace StrBoStatus
{

void set_ready(bool is_updating, bool force_status_update);
void set_ready_to_shutdown();
void set_reboot_required();
void set_system_update_request_accepted();
void set_system_update_request_rejected();

}

}

/*!@}*/

#endif /* !DCPREGS_STATUS_HH */
