/*
 * Copyright (C) 2019, 2020, 2021  T+A elektroakustik GmbH & Co. KG
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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <glib.h>

#include "plainplayer.hh"
#include "dbus_iface_deep.h"
#include "maybe.hh"
#include "logged_lock.hh"

GVariant *Regs::PlayStream::to_gvariant(const StreamInfo &si)
{
    GVariantBuilder builder;
    g_variant_builder_init(&builder, G_VARIANT_TYPE("a(ss)"));
    g_variant_builder_add(&builder, "(ss)", "artist", si.artist_.c_str());
    g_variant_builder_add(&builder, "(ss)", "album", si.album_.c_str());
    g_variant_builder_add(&builder, "(ss)", "title", si.title_.c_str());
    g_variant_builder_add(&builder, "(ss)", "x-drcpd-title", si.alttrack_.c_str());
    return g_variant_builder_end(&builder);
}

class Player:
    public Regs::PlayStream::PlainPlayer,
    public Regs::PlayStream::PlainPlayerNotifications
{
  public:
    enum State
    {
        DESELECTED,
        DESELECTED_AWAITING_SELECTION,
        STOPPED_REQUESTED,
        STOPPED,
        PLAYING_REQUESTED,
        PLAYING,
        PLAYING_BUT_STOPPED,
    };

  private:
    mutable LoggedLock::Mutex lock_;
    State state_;

    PushStreamFunction push_stream_fn_;

    Maybe<Regs::PlayStream::StreamInfo> current_stream_;
    Maybe<Regs::PlayStream::StreamInfo> next_stream_;

    /*!
     * Keep track of IDs of streams started by app.
     */
    StreamID next_free_stream_id_;

    /*!
     * Currently requested app stream.
     *
     * This is the next app stream already pushed to streamplayer FIFO. It is
     * set after a successful, synchronous push to streamplayer.
     */
    StreamID waiting_for_stream_id_;

    /*!
     * Currently playing app stream.
     *
     * Set when a stream is reported as playing by streamplayer.
     */
    StreamID currently_playing_stream_id_;

    /*!
     * Suppress a BUG log entry when receiving a stop notification for a
     * specific stream while the plain URL source is deselected.
     *
     * After audio source deselection, a stop notification may still be
     * delivered by the stream player. If this happens, then we don't want to
     * see a bug entry in case the stream ID matches the ID we know should be
     * playing; for any other ID, we still emit a bug message.
     */
    StreamID expected_stopping_stream_id_;

  public:
    Player(const Player &) = delete;
    Player(Player &&) = default;
    Player &operator=(const Player &) = delete;
    Player &operator=(Player &&) = default;

    explicit Player():
        state_(State::DESELECTED),
        next_free_stream_id_(StreamID::make()),
        waiting_for_stream_id_(StreamID::make_invalid()),
        currently_playing_stream_id_(StreamID::make_invalid()),
        expected_stopping_stream_id_(StreamID::make_invalid())
    {
        LoggedLock::configure(lock_, "Player", MESSAGE_LEVEL_DEBUG);
    }

    virtual ~Player() = default;

    void activate(const std::function<void()> &request_audio_source) override;
    bool is_active() const override;
    bool start(Regs::PlayStream::StreamInfo &&stream,
               const PushStreamFunction &push_stream) override;
    bool next(Regs::PlayStream::StreamInfo &&stream) override;
    bool stop(const std::function<bool()> &stop_stream) override;
    void audio_source_selected() override;
    void audio_source_deselected() override;
    StartResult started(StreamID stream_id) override;
    StopResult stopped(StreamID stream_id) override;
    StopResult stopped(StreamID stream_id, const char *reason,
                       std::vector<ID::Stream> &&dropped) override;

    const Maybe<Regs::PlayStream::StreamInfo> &get_current_stream_info() const override
    {
        return current_stream_;
    }

    virtual PlainPlayerNotifications &notifications() override
    {
        return *this;
    }

  private:
    void do_start(Regs::PlayStream::StreamInfo &&stream,
                  const PushStreamFunction &push_stream)
    {
        push_stream_fn_ = push_stream;
        current_stream_ = std::move(stream);
        next_stream_.set_unknown();
        waiting_for_stream_id_ = StreamID::make_invalid();
        currently_playing_stream_id_ = StreamID::make_invalid();
        expected_stopping_stream_id_ = StreamID::make_invalid();
    }

    bool do_push_next(MessageVerboseLevel level)
    {
        log_assert(push_stream_fn_ != nullptr);
        log_assert(next_stream_.is_known());

        if(!push_stream_fn_(next_stream_.get(), next_free_stream_id_, false,
                            state_ == State::PLAYING_REQUESTED))
        {
            msg_error(0, LOG_ERR, "Failed pushing next stream %u",
                      next_free_stream_id_.get().get_raw_id());
            return false;
        }

        msg_vinfo(level, "Pushed next stream %u",
                  next_free_stream_id_.get().get_raw_id());
        waiting_for_stream_id_ = next_free_stream_id_;
        ++next_free_stream_id_;
        return true;
    }

  public:
    static const char *state_to_string(Player::State state)
    {
        switch(state)
        {
          case Player::State::DESELECTED: return "DESELECTED";
          case Player::State::DESELECTED_AWAITING_SELECTION: return "DESELECTED_AWAITING_SELECTION";
          case Player::State::STOPPED_REQUESTED: return "STOPPED_REQUESTED";
          case Player::State::STOPPED: return "STOPPED";
          case Player::State::PLAYING_REQUESTED: return "PLAYING_REQUESTED";
          case Player::State::PLAYING: return "PLAYING";
          case Player::State::PLAYING_BUT_STOPPED: return "PLAYING_BUT_STOPPED";
        }

        return "*** UNKNOWN ***";
    }
};

static const char *to_string(Player::State state)
{
    return Player::state_to_string(state);
}

void Player::activate(const std::function<void()> &request_audio_source)
{
    log_assert(request_audio_source != nullptr);

    std::lock_guard<LoggedLock::Mutex> lock(lock_);

    switch(state_)
    {
      case State::DESELECTED:
        request_audio_source();
        state_ = State::DESELECTED_AWAITING_SELECTION;
        break;

      case State::DESELECTED_AWAITING_SELECTION:
      case State::STOPPED_REQUESTED:
      case State::STOPPED:
      case State::PLAYING_REQUESTED:
      case State::PLAYING:
      case State::PLAYING_BUT_STOPPED:
        break;
    }
}

bool Player::is_active() const
{
    std::lock_guard<LoggedLock::Mutex> lock(lock_);

    switch(state_)
    {
      case State::DESELECTED:
        break;

      case State::DESELECTED_AWAITING_SELECTION:
      case State::STOPPED_REQUESTED:
      case State::STOPPED:
      case State::PLAYING_REQUESTED:
      case State::PLAYING:
      case State::PLAYING_BUT_STOPPED:
        return true;
    }

    return false;
}

bool Player::start(Regs::PlayStream::StreamInfo &&stream,
                   const PushStreamFunction &push_stream)
{
    log_assert(push_stream != nullptr);

    std::lock_guard<LoggedLock::Mutex> lock(lock_);

    switch(state_)
    {
      case State::DESELECTED:
        BUG("Attempted to start playback without prior audio source selection");
        break;

      case State::DESELECTED_AWAITING_SELECTION:
        do_start(std::move(stream), push_stream);
        return true;

      case State::STOPPED_REQUESTED:
      case State::STOPPED:
      case State::PLAYING_REQUESTED:
      case State::PLAYING:
      case State::PLAYING_BUT_STOPPED:
        do_start(std::move(stream), push_stream);

        if(!push_stream_fn_(current_stream_.get(), next_free_stream_id_, true,
                            state_ == State::PLAYING_REQUESTED))
            break;

        waiting_for_stream_id_ = next_free_stream_id_;
        ++next_free_stream_id_;
        state_ = State::PLAYING_REQUESTED;
        return true;
    }

    return false;
}

bool Player::next(Regs::PlayStream::StreamInfo &&stream)
{
    std::lock_guard<LoggedLock::Mutex> lock(lock_);

    /*
     * TODO: We should filter next requests based on the URL and the register
     *       by which the URL was passed. In case of 238, we need to ignore
     *       duplicate URLs and avoid incrementing stream IDs. Instead, a
     *       prominent BUG log message should be emitted which states that the
     *       app is buggy because it sends the same information multiple times.
     */
    switch(state_)
    {
      case State::DESELECTED:
        BUG("Attempted to set next stream without prior audio source selection");
        break;

      case State::STOPPED_REQUESTED:
      case State::STOPPED:
        BUG("Attempted to set next stream while stopped%s",
            state_ == State::STOPPED ? "" : " requested");
        break;

      case State::DESELECTED_AWAITING_SELECTION:
      case State::PLAYING_REQUESTED:
        next_stream_ = std::move(stream);
        return true;

      case State::PLAYING:
      case State::PLAYING_BUT_STOPPED:
        next_stream_ = std::move(stream);
        return do_push_next(MESSAGE_LEVEL_DIAG);
    }

    return false;
}

bool Player::stop(const std::function<bool()> &stop_stream)
{
    std::lock_guard<LoggedLock::Mutex> lock(lock_);

    switch(state_)
    {
      case State::DESELECTED:
        break;

      case State::DESELECTED_AWAITING_SELECTION:
        push_stream_fn_ = nullptr;
        next_stream_.set_unknown();
        waiting_for_stream_id_ = StreamID::make_invalid();
        return true;

      case State::STOPPED_REQUESTED:
      case State::STOPPED:
        return true;

      case State::PLAYING_REQUESTED:
      case State::PLAYING:
        if(!stop_stream())
            break;

        state_ = State::STOPPED_REQUESTED;
        return true;

      case State::PLAYING_BUT_STOPPED:
        state_ = State::STOPPED;
        return true;
    }

    return false;
}

void Player::audio_source_selected()
{
    std::lock_guard<LoggedLock::Mutex> lock(lock_);

    switch(state_)
    {
      case State::DESELECTED:
        current_stream_.set_unknown();
        state_ = State::STOPPED;
        break;

      case State::DESELECTED_AWAITING_SELECTION:
        if(current_stream_.is_known() &&
           push_stream_fn_(current_stream_.get(), next_free_stream_id_, true, false))
        {
            waiting_for_stream_id_ = next_free_stream_id_;
            ++next_free_stream_id_;
            state_ = State::PLAYING_REQUESTED;
        }
        else
        {
            current_stream_.set_unknown();
            state_ = State::STOPPED;
        }

        break;

      case State::STOPPED_REQUESTED:
      case State::STOPPED:
      case State::PLAYING_REQUESTED:
      case State::PLAYING:
      case State::PLAYING_BUT_STOPPED:
        BUG("Audio source selected in state %s", to_string(state_));
        break;
    }
}

void Player::audio_source_deselected()
{
    std::lock_guard<LoggedLock::Mutex> lock(lock_);

    switch(state_)
    {
      case State::DESELECTED:
        BUG("Plain URL audio source not selected");
        return;

      case State::DESELECTED_AWAITING_SELECTION:
      case State::STOPPED_REQUESTED:
      case State::STOPPED:
      case State::PLAYING_BUT_STOPPED:
        break;

      case State::PLAYING_REQUESTED:
      case State::PLAYING:
        expected_stopping_stream_id_ = currently_playing_stream_id_;
        break;
    }

    state_ = State::DESELECTED;
}

Regs::PlayStream::PlainPlayerNotifications::StartResult
Player::started(StreamID stream_id)
{
    log_assert(stream_id.get().is_valid());

    std::lock_guard<LoggedLock::Mutex> lock(lock_);

    switch(state_)
    {
      case State::DESELECTED:
      case State::DESELECTED_AWAITING_SELECTION:
      case State::STOPPED_REQUESTED:
      case State::STOPPED:
        BUG("App stream %u started in unexpected state %s",
            stream_id.get().get_raw_id(), to_string(state_));
        break;

      case State::PLAYING_REQUESTED:
      case State::PLAYING:
      case State::PLAYING_BUT_STOPPED:
        if(currently_playing_stream_id_ == stream_id)
            return StartResult::CONTINUE_FROM_PAUSE;

        if(!waiting_for_stream_id_.get().is_valid())
        {
            BUG("App stream %u started while not waiting for any stream",
                stream_id.get().get_raw_id());
            return StartResult::UNEXPECTED_START;
        }

        if(waiting_for_stream_id_ != stream_id)
        {
            msg_info("App stream %u started, but we are waiting for %u",
                     stream_id.get().get_raw_id(),
                     waiting_for_stream_id_.get().get_raw_id());
            return StartResult::UNEXPECTED_STREAM_ID;
        }

        msg_info("Next app stream %u", stream_id.get().get_raw_id());

        waiting_for_stream_id_ = StreamID::make_invalid();
        currently_playing_stream_id_ = stream_id;

        if(state_ == State::PLAYING || state_ == State::PLAYING_BUT_STOPPED)
        {
            current_stream_ = std::move(next_stream_);
            return StartResult::PLAYING_ON;
        }

        state_ = State::PLAYING;

        if(next_stream_.is_known())
            do_push_next(MESSAGE_LEVEL_DIAG);

        return StartResult::STARTED;
    }

    return StartResult::WRONG_STATE;
}

Regs::PlayStream::PlainPlayerNotifications::StopResult
Player::stopped(StreamID stream_id)
{
    switch(state_)
    {
      case State::DESELECTED:
      case State::DESELECTED_AWAITING_SELECTION:
        if(stream_id.get().is_valid() && stream_id != expected_stopping_stream_id_)
            BUG("App stream %u stopped in unexpected state %s",
                stream_id.get().get_raw_id(), to_string(state_));

        return StopResult::PLAYER_NOT_SELECTED;

      case State::STOPPED:
      case State::PLAYING_BUT_STOPPED:
        return StopResult::ALREADY_STOPPED;

      case State::STOPPED_REQUESTED:
        state_ = State::STOPPED;
        push_stream_fn_ = nullptr;
        next_stream_.set_unknown();
        waiting_for_stream_id_ = StreamID::make_invalid();

        /* fall-through */

      case State::PLAYING_REQUESTED:
      case State::PLAYING:
        if(stream_id.get().is_valid() &&
           currently_playing_stream_id_.get().is_valid() &&
           stream_id != currently_playing_stream_id_)
            BUG("App stream %u stopped, but current stream ID should be %u",
                stream_id.get().get_raw_id(),
                currently_playing_stream_id_.get().get_raw_id());

        current_stream_.set_unknown();
        currently_playing_stream_id_ = StreamID::make_invalid();

        if(next_stream_.is_known())
            return do_push_next(MESSAGE_LEVEL_DIAG)
                ? StopResult::PUSHED_NEXT
                : StopResult::PUSH_NEXT_FAILED;

        if(state_ == State::STOPPED)
            return StopResult::STOPPED_AS_REQUESTED;

        state_ = State::PLAYING_BUT_STOPPED;
        return StopResult::STOPPED_EXTERNALLY;
    }

    return StopResult::BAD_STATE;
}

Regs::PlayStream::PlainPlayerNotifications::StopResult
Player::stopped(StreamID stream_id, const char *reason,
                std::vector<ID::Stream> &&dropped)
{
    switch(state_)
    {
      case State::DESELECTED:
      case State::DESELECTED_AWAITING_SELECTION:
      case State::STOPPED_REQUESTED:
      case State::STOPPED:
      case State::PLAYING_BUT_STOPPED:
        /* regular handling */
        return stopped(stream_id);

      case State::PLAYING_REQUESTED:
      case State::PLAYING:
        if(stream_id.get().is_valid() &&
           currently_playing_stream_id_.get().is_valid() &&
           stream_id != currently_playing_stream_id_ &&
           waiting_for_stream_id_.get().is_valid() &&
           stream_id != waiting_for_stream_id_)
        {
            BUG("App stream %u stopped with error, "
                "but current stream ID is %u, waiting for ID %u",
                stream_id.get().get_raw_id(),
                currently_playing_stream_id_.get().get_raw_id(),
                waiting_for_stream_id_.get().get_raw_id());
        }

        msg_error(0, LOG_NOTICE, "Stream %u stopped with error: %s",
                  stream_id.get().get_raw_id(), reason);

        current_stream_.set_unknown();
        currently_playing_stream_id_ = StreamID::make_invalid();

        if(next_stream_.is_known())
            return do_push_next(MESSAGE_LEVEL_NORMAL)
                ? StopResult::PUSHED_NEXT
                : StopResult::PUSH_NEXT_FAILED;

        if(state_ == State::STOPPED)
            return StopResult::STOPPED_AS_REQUESTED;

        state_ = State::PLAYING_BUT_STOPPED;
        return StopResult::STOPPED_BY_FAILURE;
    }

    return StopResult::BAD_STATE;
}

std::unique_ptr<Regs::PlayStream::PlainPlayer> Regs::PlayStream::make_player()
{
    return std::make_unique<Player>();
}
