/*
 * Copyright (C) 2017, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCPREGS_PLAYSTREAM_HH
#define DCPREGS_PLAYSTREAM_HH

#include "stream_id.hh"
#include "coverart.hh"

/*!
 * \addtogroup registers
 */
/*!@{*/

namespace Regs
{

namespace PlayStream
{
const CoverArt::PictureProviderIface &get_picture_provider();

void init();
void late_init();
void deinit();

void select_source();
void deselect_source();
void set_title_and_url(ID::Stream stream_id, std::string &&title, std::string &&url);
void start_notification(ID::Stream stream_id, void *stream_key_variant);
void stop_notification();
void cover_art_notification(void *stream_key_variant);

namespace DCP
{
ssize_t read_75_current_stream_title(uint8_t *response, size_t length);
ssize_t read_76_current_stream_url(uint8_t *response, size_t length);
int write_78_start_play_stream_title(const uint8_t *data, size_t length);
int write_79_start_play_stream_url(const uint8_t *data, size_t length);
ssize_t read_79_start_play_stream_url(uint8_t *response, size_t length);
ssize_t read_210_current_cover_art_hash(uint8_t *response, size_t length);
int write_238_next_stream_title(const uint8_t *data, size_t length);
int write_239_next_stream_url(const uint8_t *data, size_t length);
ssize_t read_239_next_stream_url(uint8_t *response, size_t length);
}

}

}

/*!@}*/

#endif /* !DCPREGS_PLAYSTREAM_HH */
