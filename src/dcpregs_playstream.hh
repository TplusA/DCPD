/*
 * Copyright (C) 2017--2023  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCPREGS_PLAYSTREAM_HH
#define DCPREGS_PLAYSTREAM_HH

#include "stream_id.hh"

#include <string>
#include <vector>
#include <memory>

namespace CoverArt { class PictureProviderIface; }

/*!
 * \addtogroup registers
 */
/*!@{*/

namespace Regs
{

namespace PlayStream
{

class StreamingRegistersIface
{
  protected:
    explicit StreamingRegistersIface() = default;

  public:
    StreamingRegistersIface(const StreamingRegistersIface &) = delete;
    StreamingRegistersIface(StreamingRegistersIface &&) = default;
    StreamingRegistersIface &operator=(const StreamingRegistersIface &) = delete;
    StreamingRegistersIface &operator=(StreamingRegistersIface &&) = default;
    virtual ~StreamingRegistersIface() = default;

    virtual void late_init() = 0;
    virtual const CoverArt::PictureProviderIface &get_picture_provider() const = 0;
    virtual void audio_source_selected(bool on_hold) = 0;
    virtual void audio_source_deselected() = 0;
    virtual void set_title_and_url(ID::Stream stream_id, std::string &&title, std::string &&url) = 0;
    virtual void start_notification(ID::Stream stream_id, const char *stream_url, void *stream_key_variant) = 0;
    virtual void stop_notification(ID::Stream stream_id) = 0;
    virtual void stop_notification(ID::Stream stream_id, const char *reason, std::vector<ID::Stream> &&dropped_ids) = 0;
    virtual void drop_notification(ID::Stream stream_id) = 0;
    virtual void cover_art_notification(void *stream_key_variant) = 0;
};

std::unique_ptr<StreamingRegistersIface> mk_streaming_registers();

namespace DCP
{
void init(StreamingRegistersIface &regs);
bool stop_plain_player();
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
