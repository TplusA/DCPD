/*
 * Copyright (C) 2015, 2018  T+A elektroakustik GmbH & Co. KG
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

#ifndef REGISTERS_PRIV_HH
#define REGISTERS_PRIV_HH

#include <stdbool.h>

/*!
 * \internal
 * DCP registers configuration data.
 */
struct register_configuration_t
{
    void (*register_changed_notification_fn)(uint8_t reg_number);
};

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Get private data.
 */
const struct register_configuration_t *registers_get_data(void);

/*!
 * Get private data for writing.
 */
struct register_configuration_t *registers_get_nonconst_data(void);

#ifdef __cplusplus
}
#endif

#endif /* !REGISTERS_PRIV_HH */
