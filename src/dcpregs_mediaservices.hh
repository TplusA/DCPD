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

#ifndef DCPREGS_MEDIASERVICES_H
#define DCPREGS_MEDIASERVICES_H

#include "dynamic_buffer.h"

/*!
 * \addtogroup registers
 */
/*!@{*/

#ifdef __cplusplus
extern "C" {
#endif

int dcpregs_write_106_media_service_list(const uint8_t *data, size_t length);
bool dcpregs_read_106_media_service_list(struct dynamic_buffer *buffer);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !DCPREGS_MEDIASERVICES_H */
