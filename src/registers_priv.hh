/*
 * Copyright (C) 2015, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef REGISTERS_PRIV_HH
#define REGISTERS_PRIV_HH

#include <cinttypes>

namespace Regs
{
/*!
 * \internal
 * DCP registers configuration data.
 */
struct PrivateData
{
    void (*register_changed_notification_fn)(uint8_t reg_number);
};

/*!
 * Get private data.
 */
const PrivateData &get_data();

/*!
 * Get private data for writing.
 */
PrivateData &get_nonconst_data();
}

#endif /* !REGISTERS_PRIV_HH */
