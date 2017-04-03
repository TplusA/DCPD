/*
 * Copyright (C) 2016, 2017  T+A elektroakustik GmbH & Co. KG
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

#include "stream_id.h"

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

int dcpregs_write_73_seek_or_set_speed(const uint8_t *data, size_t length);
ssize_t dcpregs_read_75_current_stream_title(uint8_t *response, size_t length);
ssize_t dcpregs_read_76_current_stream_url(uint8_t *response, size_t length);
int dcpregs_write_78_start_play_stream_title(const uint8_t *data, size_t length);
int dcpregs_write_79_start_play_stream_url(const uint8_t *data, size_t length);
ssize_t dcpregs_read_79_start_play_stream_url(uint8_t *response, size_t length);
ssize_t dcpregs_read_210_current_cover_art_hash(uint8_t *response, size_t length);
int dcpregs_write_238_next_stream_title(const uint8_t *data, size_t length);
int dcpregs_write_239_next_stream_url(const uint8_t *data, size_t length);
ssize_t dcpregs_read_239_next_stream_url(uint8_t *response, size_t length);

void dcpregs_playstream_set_title_and_url(stream_id_t raw_stream_id,
                                          const char *title, const char *url);
void dcpregs_playstream_start_notification(stream_id_t raw_stream_id,
                                           void *stream_key_variant);
void dcpregs_playstream_stop_notification(void);
void dcpregs_playstream_cover_art_notification(void *stream_key_variant);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !DCPREGS_PLAYSTREAM_H */
