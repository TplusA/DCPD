/*
 * Copyright (C) 2017  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCPREGS_APPLIANCE_H
#define DCPREGS_APPLIANCE_H

#include <stdint.h>
#include <unistd.h>

/*!
 * \addtogroup registers
 */
/*!@{*/

#ifdef __cplusplus
extern "C" {
#endif

ssize_t dcpregs_read_87_appliance_id(uint8_t *response, size_t length);
int dcpregs_write_87_appliance_id(const uint8_t *data, size_t length);

void dcpregs_appliance_id_configure_appliance(void);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !DCPREGS_APPLIANCE_H */
