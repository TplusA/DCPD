/*
 * Copyright (C) 2016  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCPREGS_PLAYSTREAM_H
#define DCPREGS_PLAYSTREAM_H

#include <stdint.h>
#include <unistd.h>

/*!
 * \addtogroup registers
 */
/*!@{*/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Function required by unit tests for initializing static data.
 */
void dcpregs_playstream_init(void);

/*!
 * Function required by unit tests.
 */
void dcpregs_playstream_deinit(void);

int dcpregs_write_78_start_play_stream_title(const uint8_t *data, size_t length);
int dcpregs_write_79_start_play_stream_url(const uint8_t *data, size_t length);
ssize_t dcpregs_read_79_start_play_stream_url(uint8_t *response, size_t length);
int dcpregs_write_238_next_stream_title(const uint8_t *data, size_t length);
int dcpregs_write_239_next_stream_url(const uint8_t *data, size_t length);
ssize_t dcpregs_read_239_next_stream_url(uint8_t *response, size_t length);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !DCPREGS_PLAYSTREAM_H */
