/*
 * Copyright (C) 2019  T+A elektroakustik GmbH & Co. KG
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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "dcpregs_audiopaths.hh"
#include "audiopath_minidsl.hh"
#include "dbus_iface_deep.h"
#include "registers_priv.hh"
#include "logged_lock.hh"
#include "messages.h"

#include <deque>
#include <string>
#include <stdexcept>

enum class AudioPathRequest
{
    GET_FULL_AUDIO_PATH_INFORMATION = 0x00,

    LAST_REQUEST = GET_FULL_AUDIO_PATH_INFORMATION,
};

/*!
 * A queue for audio path requests from the system to the SPI slave.
 *
 * TODO: See also #SlavePushCommandQueue for similar thing; try to DRY up
 */
class AudioPathRequestQueue
{
  private:
    LoggedLock::Mutex lock_;
    std::deque<AudioPathRequest> queue_;

  public:
    AudioPathRequestQueue(const AudioPathRequestQueue &) = delete;
    AudioPathRequestQueue(AudioPathRequestQueue &&) = default;
    AudioPathRequestQueue &operator=(const AudioPathRequestQueue &) = delete;
    AudioPathRequestQueue &operator=(AudioPathRequestQueue &&) = default;

    explicit AudioPathRequestQueue()
    {
        LoggedLock::configure(lock_, "AudioPathRequestQueue", MESSAGE_LEVEL_DEBUG);
    }

    void add(AudioPathRequest request)
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(lock_);
        queue_.push_back(request);
        Regs::get_data().register_changed_notification_fn(82);
    }

    AudioPathRequest take()
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(lock_);

        if(queue_.empty())
        {
            BUG("No request in register 82 read queue");
            throw std::out_of_range("");
        }

        const auto result = queue_.front();
        queue_.pop_front();

        return result;
    }

    void reset()
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(lock_);
        queue_.clear();
    }
};

static AudioPathRequestQueue push_82_queue;

void Regs::AudioPaths::request_full_from_appliance()
{
    push_82_queue.add(AudioPathRequest::GET_FULL_AUDIO_PATH_INFORMATION);
}

int Regs::AudioPaths::DCP::write_82_audio_path_parameters(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 82 handler %p %zu", data, length);

    ::AudioPaths::Parser parser;

    try
    {
        parser.process(data, length);
    }
    catch(const ::AudioPaths::ParserError &e)
    {
        msg_error(0, LOG_ERR,
                  "Failed parsing audio path information passed by "
                  "SPI slave: %s", e.what());
        return -1;
    }

    const auto json(parser.json_string());

    if(!json.empty())
    {
        static const char *const empty[] = { nullptr };
        tdbus_jsonemitter_emit_object(dbus_audiopath_get_config_update_iface(),
                                      json.c_str(), empty);
    }

    return 0;
}

bool Regs::AudioPaths::DCP::read_82_audio_path_parameters(std::vector<uint8_t> &buffer)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 82 handler");

    AudioPathRequest request;

    try
    {
        request = push_82_queue.take();
    }
    catch(const std::out_of_range &e)
    {
        return false;
    }

    switch(request)
    {
      case AudioPathRequest::GET_FULL_AUDIO_PATH_INFORMATION:
        buffer.push_back(uint8_t(AudioPathRequest::GET_FULL_AUDIO_PATH_INFORMATION));
        break;
    }

    return true;
}
