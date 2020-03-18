/*
 * Copyright (C) 2019, 2020  T+A elektroakustik GmbH & Co. KG
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

#ifndef PLAINPLAYER_HH
#define PLAINPLAYER_HH

#include "stream_id.hh"
#include "maybe.hh"

#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace Regs
{

namespace PlayStream
{

/*!
 * Information about a stream for playing via plain URL audio source.
 */
class StreamInfo
{
  public:
    std::string artist_;
    std::string album_;
    std::string title_;
    std::string alttrack_;
    std::string url_;

    StreamInfo(const StreamInfo &) = delete;
    StreamInfo(StreamInfo &&) = default;
    StreamInfo &operator=(const StreamInfo &) = delete;
    StreamInfo &operator=(StreamInfo &&) = default;

    explicit StreamInfo() = default;

    explicit StreamInfo(std::string &&artist, std::string &&album,
                        std::string &&title, std::string &&alttrack,
                        std::string &&url):
        artist_(artist),
        album_(album),
        title_(title),
        alttrack_(alttrack),
        url_(url)
    {}
};

class PlainPlayerNotifications;

/*!
 * Control interface to plain URL player.
 */
class PlainPlayer
{
  public:
    using StreamID = ::ID::SourcedStream<STREAM_ID_SOURCE_APP>;
    using PushStreamFunction =
        std::function<bool(const StreamInfo &, StreamID, bool, bool)>;

    PlainPlayer(const PlainPlayer &) = delete;
    PlainPlayer(PlainPlayer &&) = default;
    PlainPlayer &operator=(const PlainPlayer &) = delete;
    PlainPlayer &operator=(PlainPlayer &&) = default;

  protected:
    explicit PlainPlayer() = default;

  public:
    virtual ~PlainPlayer() = default;

    /*!
     * Prepare for playing.
     *
     * This function requests activation of the plain URL audio source if it is
     * not active already. Note that audio source activation is only requested
     * by this function, but activation may succeed or fail only much later.
     *
     * Note that there is no direct counterpart to this function for
     * deactivating the player. Deactivation is done simply by switching away
     * from the plain URL audio source to another audio source, in which case
     * the player is reset and its stream information are dropped.
     */
    virtual void activate(const std::function<void()> &request_audio_source) = 0;

    /*!
     * Check whether or not the player is active, i.e., ready to play.
     */
    virtual bool is_active() const = 0;

    /*!
     * Request start playing stream.
     *
     * This function is for playing the given stream, replacing the currently
     * playing stream. It also puts the player into the logical "playing"
     * state and causes the player to forget the next queued stream, if any.
     *
     * If the plain URL audio source is active, then playback should begin very
     * soon after this function has been called. It is safe to call this
     * function if the audio source is not active yet, but has been requested.
     * In this case, the start request will be stored until the audio source
     * has been activated.
     *
     * This function will fail immediately if the plain URL audio source is
     * neither active nor has been requested. That is, this function can only
     * succeed if #Regs::PlayStream::PlainPlayer::activate() has been called
     * beforehand.
     *
     * \returns
     *     True if the stream is accepted for playback and the player was
     *     switched to "playing" state, false in case of any error.
     *
     * \note
     *     The function object \p push_stream may be stored and called later,
     *     after this function has returned. Thus, the caller must ensure
     *     validity of any data captured by and dereferenced inside the
     *     function object
     */
    virtual bool start(StreamInfo &&stream, const PushStreamFunction &push_stream) = 0;

    /*!
     * Put information for next stream.
     *
     * The stream passed to this function will be played after the stream which
     * is currently playing, if any. If the player is not in "playing" mode,
     * then this function will ignore the input and return with an error.
     *
     * Note that there is no queue, but just a single slot for storing
     * information about the next stream. Calling this function multiple times
     * means overwriting this slot, and the last stream set by this function
     * will be played next.
     *
     * This function only works if #Regs::PlayStream::PlainPlayer::start() has
     * been called beforehand.
     *
     * It is not possible to start playing through this function. It is,
     * however, possible to continue playing after the previous stream has
     * stopped because it has ended or because of some error. The logical state
     * of the player will still be "playing" in this case, so it is possible to
     * continue with a next stream even in case the next stream is delivered
     * late. There will, of course, be an audible gap in this case.
     *
     * \returns
     *     True if the stream is accepted, false in case of any error.
     */
    virtual bool next(StreamInfo &&stream) = 0;

    /*!
     * Stop playing and forget streams.
     *
     * This functions instructs the player to stop playback and puts the player
     * into the logical "stopped" state. Any stream information are dropped.
     *
     * This function will fail if the player is not active, i.e., if the plain
     * URL audio source is not selected.
     *
     * \returns
     *     True if the stream is about to stop or has been stopped already,
     *     false in case of any error.
     */
    virtual bool stop(const std::function<bool()> &stop_stream) = 0;

    /*!
     * Return copy of information about currently playing stream, if any.
     */
    virtual const Maybe<Regs::PlayStream::StreamInfo> &get_current_stream_info() const = 0;

    /*!
     * Get reference to notification interface for this player.
     */
    virtual PlainPlayerNotifications &notifications() = 0;
};

/*!
 * Notification interface to plain URL player.
 */
class PlainPlayerNotifications
{
  public:
    PlainPlayerNotifications(const PlainPlayerNotifications &) = delete;
    PlainPlayerNotifications(PlainPlayerNotifications &&) = default;
    PlainPlayerNotifications &operator=(const PlainPlayerNotifications &) = delete;
    PlainPlayerNotifications &operator=(PlainPlayerNotifications &&) = default;

  protected:
    explicit PlainPlayerNotifications() = default;

  public:
    virtual ~PlainPlayerNotifications() = default;

    /*!
     * Plain URL audio source has been selected and can be used.
     */
    virtual void audio_source_selected() = 0;

    /*!
     * Plain URL audio source has been deselected.
     *
     * Communication with the player is forbidden after this function has been
     * called.
     */
    virtual void audio_source_deselected() = 0;

    enum class StartResult
    {
        STARTED,
        PLAYING_ON,
        CONTINUE_FROM_PAUSE,
        UNEXPECTED_START,
        UNEXPECTED_STREAM_ID,
        WRONG_STATE,
        FAILED,
    };

    /*!
     * A new stream has started playing.
     */
    virtual StartResult started(PlainPlayer::StreamID stream_id) = 0;

    enum class StopResult
    {
        STOPPED_AS_REQUESTED,
        STOPPED_EXTERNALLY,
        STOPPED_BY_FAILURE,
        PUSHED_NEXT,
        ALREADY_STOPPED,
        PUSH_NEXT_FAILED,
        PLAYER_NOT_SELECTED,
        BAD_STATE,
    };

    /*!
     * The player has stopped playing.
     */
    virtual StopResult stopped(PlainPlayer::StreamID stream_id) = 0;

    /*!
     * The player has stopped playing with an error.
     */
    virtual StopResult stopped(PlainPlayer::StreamID stream_id,
                               const char *reason,
                               std::vector<ID::Stream> &&dropped) = 0;
};

/*!
 * Create a new plain URL player instance.
 */
std::unique_ptr<PlainPlayer> make_player();

}

}

#endif /* !PLAINPLAYER_HH */
