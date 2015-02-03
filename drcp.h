/*
 * Copyright (C) 2015  T+A elektroakustik GmbH & Co. KG
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

#ifndef DRCP_H
#define DRCP_H

#include "dynamic_buffer.h"

/*!
 * \addtogroup drcp Communication with DRCPD
 */
/*!@{*/

#ifdef __cplusplus
extern "C" {
#endif

bool drcp_fill_buffer(struct dynamic_buffer *buffer, int in_fd);
bool drcp_read_size_from_fd(struct dynamic_buffer *buffer, int in_fd,
                            size_t *expected_size, size_t *payload_offset);
void drcp_finish_request(bool is_ok, int out_fd);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !DRCP_H */
