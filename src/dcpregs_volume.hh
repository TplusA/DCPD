/*
 * Copyright (C) 2017, 2018  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCPREGS_VOLUME_HH
#define DCPREGS_VOLUME_HH

#include "dynamic_buffer.h"

/*!
 * \addtogroup registers
 */
/*!@{*/

namespace Regs
{

namespace ApplianceVolumeControl
{

namespace DCP
{
/*!
 * Configure volume control properties or set volume level.
 *
 * This register expects a subcommand code (one byte) followed directly by
 * parameters specific to the subcommand. Note that for exchange of real
 * values, we use the 14-bit fix point representation defined in fixpoint.hh.
 *
 * Subcommands:
 *
 * - Set volume level and mute state (0x00). This subcommand expects 16 bits of
 *   data structured as follows:
 *       Bits    | Meaning
 *       -------:|--------------------------------------
 *       15      | Mute on or off (1 = mute).
 *       14      | Reserved, must be zero.
 *       13...0  | Fix point value for the volume level.
 *
 * - Configure volume control properties (0x01). This subcommand expects the
 *   following parameters:
 *       Offset  | Type       | Meaning
 *       -------:|------------|-----------------------------------------
 *       0       | byte       | Scale (0 = steps, 1 = dB).
 *       1       | fix point  | Minimum value on scale.
 *       3       | fix point  | Maximum value on scale.
 *       5       | fix point  | Minimum step width on scale (for use by Roon client).
 *       7       | fix point  | Dynamic range minimum value, always in dB. Pass NaN if not used or applicable.
 *       9       | fix point  | Dynamic range maximum value, always in dB. Pass NaN if not used or applicable.
 *       11      | fix point  | Initial volume level. Pass NaN if unknown.
 *       13      | byte       | Initial mute state (0 = not muted, 1 = muted, 2 = unknown).
 *
 * - Clear volume control properties (0x02). This subcommand does not expect
 *   any parameters.
 */
int write_64_volume_control(const uint8_t *data, size_t length);

/*!
 * Read out volume level and mute state request.
 *
 * This function serializes a requested mute state and a fix point number to
 * the response buffer. The upper-most bit of the two bytes returned is the
 * requested mute state (1 = muted), the fix point number is a volume level
 * request on the scale configured for the volume control.
 *
 * In case there is no active volume request (spurious read), the function will
 * fail and the response is left empty.
 *
 * Note that the values returned in this register are really only a request to
 * the appliance. The appliance should change the volume and mute state
 * according to the request and write the changed values back to register 64.
 * In case the appliance chooses to ignore the request, it doesn't have to do
 * anything.
 */
ssize_t read_64_volume_control(uint8_t *response, size_t length);
}

}

}

/*!@}*/

#endif /* !DCPREGS_VOLUME_HH */