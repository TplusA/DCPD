/*
 * Copyright (C) 2016, 2017, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#include <glib.h>  /* must be first for #GVariantWrapper */

#include "dcpregs_playstream.hh"
#include "dcpregs_audiosources.hh"
#include "plainplayer.hh"
#include "coverart.hh"
#include "registers_priv.hh"
#include "de_tahifi_artcache_errors.hh"
#include "dbus_common.h"
#include "dbus_iface_deep.h"
#include "logged_lock.hh"

#include <algorithm>

constexpr const char *ArtCache::ReadError::names_[];

static const auto plainurl_register_dump_level = MESSAGE_LEVEL_NORMAL;
static const char app_audio_source_id[] = "strbo.plainurl";

static inline void notify_stream_title_changed()
{
    Regs::get_data().register_changed_notification_fn(75);
}

static inline void notify_stream_url_changed()
{
    Regs::get_data().register_changed_notification_fn(76);
}

static inline void notify_app_playback_stopped()
{
    Regs::get_data().register_changed_notification_fn(79);
}

static inline void notify_ready_for_next_stream_from_slave()
{
    Regs::get_data().register_changed_notification_fn(239);
}

static inline void notify_cover_art_changed()
{
    Regs::get_data().register_changed_notification_fn(210);
}

enum class SendStreamUpdate
{
    NONE,
    TITLE,
    URL_AND_TITLE,
};

enum class StreamStarted
{
    NOT,
    FRESH,
    CONTINUED
};

static void do_notify_stream_info(const SendStreamUpdate update)
{
    switch(update)
    {
      case SendStreamUpdate::NONE:
        msg_vinfo(MESSAGE_LEVEL_DIAG,
                  "Suppress sending title and URL to SPI slave");
        break;

      case SendStreamUpdate::URL_AND_TITLE:
        msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
        notify_stream_title_changed();
        notify_stream_url_changed();
        break;

      case SendStreamUpdate::TITLE:
        msg_vinfo(MESSAGE_LEVEL_DIAG, "Send only new title to SPI slave");
        notify_stream_title_changed();
        break;
    }
}

/*!
 * Contents of register pair 78/79 or 238/239.
 */
class BufferedStreamInfo
{
  private:
    ID::Stream stream_id_;

  public:
    std::string meta_data_;
    std::string url_;

  public:
    BufferedStreamInfo(const BufferedStreamInfo &) = delete;
    BufferedStreamInfo &operator=(const BufferedStreamInfo &) = delete;

    BufferedStreamInfo(BufferedStreamInfo &&src):
        stream_id_(src.stream_id_),
        meta_data_(std::move(src.meta_data_)),
        url_(std::move(src.url_))
    {
        src.stream_id_ = ID::Stream::make_invalid();
    }

    BufferedStreamInfo &operator=(BufferedStreamInfo &&src)
    {
        if(src.stream_id_.is_valid())
        {
            stream_id_ = src.stream_id_;
            meta_data_ = std::move(src.meta_data_);
            url_ = std::move(src.url_);
            src.stream_id_ = ID::Stream::make_invalid();
        }
        else
            clear();

        return *this;
    }

    explicit BufferedStreamInfo():
        stream_id_(ID::Stream::make_invalid())
    {}

    bool is_valid() const { return stream_id_.is_valid(); }

    bool matches_id(const ID::Stream &stream_id) const
    {
        return stream_id.is_valid() && stream_id_ == stream_id;
    }

    SendStreamUpdate diff(const BufferedStreamInfo &other) const
    {
        return determine_send_stream_update(meta_data_ != other.meta_data_,
                                            url_ != other.url_);
    }

    SendStreamUpdate set_full(const ID::Stream &stream_id,
                              std::string &&meta_data, std::string &&url)
    {
        const auto result = set_full(std::move(meta_data), std::move(url));
        stream_id_ = stream_id;
        return result;
    }

    SendStreamUpdate set_full(std::string &&meta_data, std::string &&url)
    {
        const auto update =
            determine_send_stream_update(meta_data_ != meta_data, url_ != url);
        meta_data_ = std::move(meta_data);
        url_ = std::move(url);
        return update;
    }

    SendStreamUpdate clear()
    {
        return clear(ID::Stream::make_invalid());
    }

    SendStreamUpdate clear(const ID::Stream &stream_id)
    {
        const auto update =
            determine_send_stream_update(!meta_data_.empty(), !url_.empty());
        stream_id_ = stream_id;
        meta_data_.clear();
        url_.clear();
        return update;
    }

  private:
    static inline SendStreamUpdate
    determine_send_stream_update(bool title_changed, bool url_changed)
    {
        if(!title_changed && !url_changed)
            return SendStreamUpdate::NONE;

        if(!url_changed)
            return SendStreamUpdate::TITLE;

        return SendStreamUpdate::URL_AND_TITLE;
    }
};

/*!
 * Retrieve cover art for given stream key if necessary and possible.
 *
 * \param stream_key
 *     For which stream key the picture should be retrieved from the cover art
 *     cache.
 *
 * \param picture
 *     Where to put the image data.
 *
 * \returns
 *     True in case the \p picture has changed, false in case it remained
 *     unchanged.
 */
static bool try_retrieve_cover_art(GVariant *stream_key,
                                   CoverArt::Picture &picture)
{
    if(stream_key == nullptr)
        return picture.clear();

    guchar error_code;
    guchar image_priority;
    GError *error = nullptr;

    GVariantWrapper known_hash = picture.get_hash_variant();

    if(known_hash == nullptr)
    {
        GVariantBuilder builder;
        g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));
        known_hash = std::move(GVariantWrapper(g_variant_builder_end(&builder)));
    }

    GVariant *image_hash_variant = nullptr;
    GVariant *image_data_variant = nullptr;

    tdbus_artcache_read_call_get_scaled_image_data_sync(
        dbus_get_artcache_read_iface(), stream_key, "png@120x120",
        GVariantWrapper::get(known_hash),
        &error_code, &image_priority,
        &image_hash_variant, &image_data_variant,
        nullptr, &error);

    if(dbus_common_handle_dbus_error(&error, "Get cover art picture") < 0)
        return picture.clear();

    GVariantWrapper image_hash(image_hash_variant, GVariantWrapper::Transfer::JUST_MOVE);
    GVariantWrapper image_data(image_data_variant, GVariantWrapper::Transfer::JUST_MOVE);

    ArtCache::ReadError read_error(error_code);
    bool retval = false;
    bool should_clear_picture = true;

    switch(read_error.get())
    {
      case ArtCache::ReadError::OK:
        msg_info("Cover art for current stream has not changed");
        should_clear_picture = false;
        break;

      case ArtCache::ReadError::UNCACHED:
        {
            gsize hash_len;
            gconstpointer hash_bytes =
                g_variant_get_fixed_array(GVariantWrapper::get(image_hash),
                                          &hash_len, sizeof(uint8_t));

            gsize image_len;
            gconstpointer image_bytes =
                g_variant_get_fixed_array(GVariantWrapper::get(image_data),
                                          &image_len, sizeof(uint8_t));

            msg_info("Taking new cover art for current stream from cache");

            should_clear_picture = false;
            retval = picture.set(std::move(GVariantWrapper(image_hash)),
                                 static_cast<const uint8_t *>(hash_bytes), hash_len,
                                 std::move(GVariantWrapper(image_data)),
                                 static_cast<const uint8_t *>(image_bytes), image_len);
        }

        break;

      case ArtCache::ReadError::KEY_UNKNOWN:
        msg_info("Cover art for current stream not in cache");
        break;

      case ArtCache::ReadError::BUSY:
        msg_info("Cover art for current stream not ready yet");
        break;

      case ArtCache::ReadError::FORMAT_NOT_SUPPORTED:
      case ArtCache::ReadError::IO_FAILURE:
      case ArtCache::ReadError::INTERNAL:
        msg_error(0, LOG_ERR,
                  "Error retrieving cover art: %s", read_error.to_string());
        break;
    }

    return should_clear_picture ? picture.clear() : retval;
}

class StreamingRegisters:
    public Regs::PlayStream::StreamingRegistersIface,
    public CoverArt::PictureProviderIface
{
  private:
    mutable LoggedLock::Mutex lock_;

    /*!
     * Plain URL player.
     *
     * This handles registers 78, 79, 238, and 239.
     */
    std::unique_ptr<Regs::PlayStream::PlainPlayer> player_;

    /*!
     * The cover art meta data of the currently playing stream, if any.
     *
     * This is for register 210.
     */
    CoverArt::Tracker tracked_stream_key_;
    CoverArt::Picture current_cover_art_;

    /*!
     * Currently playing stream (any kind).
     *
     * This is buffered information for the stream information in registers 75
     * and 76, i.e., these data are returned when these registered are read
     * out. The contained stream ID is also used for filtering updates sent to
     * register 210.
     *
     * Note that this object is meant to handle not only app streams, but any
     * kind of stream playing on any source.
     */
    BufferedStreamInfo stream_info_output_buffer_;

    /*!
     * Write buffer for changes of stream meta data and URL.
     *
     * These data are filled in via D-Bus. Since it is possible for us to
     * receive stream information before the stream has actually started
     * playing (because of multitasking and undeterministic task switching), we
     * need to store the data here and wait for the stream to start before
     * moving it over to StreamingRegisters::stream_info_output_buffer_.
     */
    BufferedStreamInfo stream_info_input_buffer_;

    /*!
     * Write buffer for register 78 and 238.
     *
     * Since meta data and URL are different registers (by stupid design), we
     * need to store what's written to register 78 (or 238) until register 79
     * (or 239) is written in some place and construct the request to the
     * player bit by bit.
     *
     * The first field of the pair is the stream information for the player,
     * the second field is true in case the meta data was written through
     * register 78.
     */
    Maybe<std::pair<Regs::PlayStream::StreamInfo, bool>> play_request_input_buffer_;

  public:
    explicit StreamingRegisters():
        player_(Regs::PlayStream::make_player())
    {
        LoggedLock::configure(lock_, "StreamingRegisters", MESSAGE_LEVEL_DEBUG);
    }

    void late_init() override;

    const CoverArt::PictureProviderIface &get_picture_provider() const override
    {
        return *this;
    }

    void with_current_stream_information(const std::function<void(const BufferedStreamInfo &)> &apply)
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(lock_);
        apply(stream_info_output_buffer_);
    }

    void with_current_cover_art(const std::function<void(const CoverArt::Picture &)> &apply)
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(lock_);
        apply(current_cover_art_);
    }

    void audio_source_selected()
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(lock_);
        player_->notifications().audio_source_selected();
    }

    void audio_source_deselected()
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(lock_);
        player_->notifications().audio_source_deselected();
    }

    /*!
     * Store title and URL for non-app stream.
     *
     * For registers 75 and 76.
     */
    void set_title_and_url(ID::Stream stream_id,
                           std::string &&title, std::string &&url)
    {
        msg_vinfo(MESSAGE_LEVEL_DIAG,
                  "Received explicit title and URL information for stream %u",
                  stream_id.get_raw_id());

        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(lock_);

        log_assert(stream_id.get_source() != STREAM_ID_SOURCE_INVALID);

        if(!Regs::PlayStream::PlainPlayer::StreamID::compatible_with(stream_id))
            store_meta_data_and_url(stream_id, std::move(title), std::move(url));
        else
        {
            BUG("Got title and URL information for app stream ID %u",
                stream_id.get_raw_id());
            BUG("+   Title: \"%s\"", title.c_str());
            BUG("+   URL  : \"%s\"", url.c_str());
        }
    }

    /*!
     * Store meta data written through register 78 in a buffer.
     *
     * The plain URL audio source is requested by this function if not done
     * already. This function must be called before calling
     * #StreamingRegisters::start_first_stream().
     */
    void store_meta_data_for_first_stream(std::string &&artist, std::string &&album,
                                          std::string &&title, std::string &&alttrack)
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(lock_);

        play_request_input_buffer_ =
        {
            Regs::PlayStream::StreamInfo(std::move(artist), std::move(album),
                                         std::move(title), std::move(alttrack), ""),
            true
        };

        player_->activate(
            [] ()
            {
                GVariantDict empty;
                g_variant_dict_init(&empty, nullptr);
                tdbus_aupath_manager_call_request_source(
                    dbus_audiopath_get_manager_iface(), app_audio_source_id,
                    g_variant_dict_end(&empty), nullptr, nullptr, nullptr);
            });
    }

    /*!
     * Store meta data written through register 79 in a buffer.
     *
     * The plain URL audio source is requested by this function if not done
     * already. This function must be called before calling
     * #StreamingRegisters::push_next_stream().
     */
    void store_meta_data_for_next_stream(std::string &&artist, std::string &&album,
                                         std::string &&title, std::string &&alttrack)
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(lock_);

        play_request_input_buffer_ =
        {
            Regs::PlayStream::StreamInfo(std::move(artist), std::move(album),
                                         std::move(title), std::move(alttrack), ""),
            false
        };
    }

    void start_first_stream(std::string &&url)
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(lock_);

        if(!play_request_input_buffer_.is_known() || !play_request_input_buffer_->second)
        {
            msg_error(0, LOG_ERR, "Not starting stream, register 78 wasn't set");
            return;
        }

        play_request_input_buffer_->first.url_ = std::move(url);
        player_->start(
            std::move(play_request_input_buffer_->first),
            [this]
            (const auto &stream_info, auto stream_id,
             bool is_first, bool is_start_requested)
            {
                return do_push_and_start_stream(stream_info, stream_id,
                                                is_first, is_start_requested);
            });
        play_request_input_buffer_.set_unknown();
    }

    void push_next_stream(std::string &&url)
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(lock_);

        if(!play_request_input_buffer_.is_known() || play_request_input_buffer_->second)
        {
            msg_error(0, LOG_ERR, "Not pushing next stream, register 238 wasn't set");
            return;
        }

        play_request_input_buffer_->first.url_ = std::move(url);
        player_->next(std::move(play_request_input_buffer_->first));
        play_request_input_buffer_.set_unknown();
    }

    void stop_playing(const char *reason)
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(lock_);

        const auto stopped = player_->stop(
            [reason] ()
            {
                GError *error = nullptr;
                if(!tdbus_splay_playback_call_stop_sync(
                        dbus_get_streamplayer_playback_iface(),
                        reason, nullptr, &error))
                {
                    msg_error(0, LOG_NOTICE, "Failed stopping stream player");
                    dbus_common_handle_dbus_error(&error, "Stop stream");
                    return false;
                }
                return true;
            });

        if(stopped)
            play_request_input_buffer_.set_unknown();
    }

    /*!
     * React on start of stream.
     */
    void start_notification(ID::Stream stream_id, void *stream_key_variant)
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(lock_);

        const auto app_stream_id =
            Regs::PlayStream::PlainPlayer::StreamID::make_from_generic_id(stream_id);
        bool player_has_matching_meta_data = false;
        bool stream_is_a_new_one = true;
        if(app_stream_id.get().is_valid())
        {
            switch(player_->notifications().started(app_stream_id))
            {
              case Regs::PlayStream::PlainPlayerNotifications::StartResult::STARTED:
              case Regs::PlayStream::PlainPlayerNotifications::StartResult::PLAYING_ON:
                notify_ready_for_next_stream_from_slave();
                player_has_matching_meta_data = true;
                break;

              case Regs::PlayStream::PlainPlayerNotifications::StartResult::CONTINUE_FROM_PAUSE:
                stream_is_a_new_one = false;
                break;

              case Regs::PlayStream::PlainPlayerNotifications::StartResult::UNEXPECTED_START:
              case Regs::PlayStream::PlainPlayerNotifications::StartResult::UNEXPECTED_STREAM_ID:
              case Regs::PlayStream::PlainPlayerNotifications::StartResult::WRONG_STATE:
              case Regs::PlayStream::PlainPlayerNotifications::StartResult::FAILED:
                break;
            }
        }
        else if(player_->is_active())
        {
            BUG("Non-app stream %u started while plain URL player is selected",
                stream_id.get_raw_id());
            player_->notifications().audio_source_deselected();
            notify_app_playback_stopped();
        }

        tracked_stream_key_.set(
            std::move(GVariantWrapper(static_cast<GVariant *>(stream_key_variant),
                                      GVariantWrapper::Transfer::JUST_MOVE)));

        StreamStarted stream_started;
        if(stream_is_a_new_one)
        {
            const auto update =
                set_currently_playing_stream_id(
                    stream_id, stream_started,
                    app_stream_id.get().is_valid() && player_has_matching_meta_data
                    ? player_.get()
                    : nullptr);

            if(update != SendStreamUpdate::NONE || stream_started != StreamStarted::FRESH)
                do_notify_stream_info(update);
        }
        else
        {
            msg_info("Continue with app stream %u", stream_id.get_raw_id());
            stream_started = StreamStarted::NOT;
        }

        GVariant *val = tracked_stream_key_.is_tracking()
            ? GVariantWrapper::get(tracked_stream_key_.get_variant())
            : nullptr;

        if(try_retrieve_cover_art(val, current_cover_art_) ||
           stream_started != StreamStarted::NOT)
            notify_cover_art_changed();
    }

    void stop_notification(ID::Stream stream_id)
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(lock_);

        const auto app_stream_id =
            Regs::PlayStream::PlainPlayer::StreamID::make_from_generic_id(stream_id);

        tracked_stream_key_.clear();
        current_cover_art_.clear();

        const auto stopped_result = player_->notifications().stopped(app_stream_id);
        if(app_stream_id.get().is_valid())
        {
            switch(stopped_result)
            {
              case Regs::PlayStream::PlainPlayerNotifications::StopResult::STOPPED_AS_REQUESTED:
                msg_info("Stream player stopped playing app stream %u (requested)",
                         stream_id.get_raw_id());
                notify_app_playback_stopped();
                break;

              case Regs::PlayStream::PlainPlayerNotifications::StopResult::STOPPED_EXTERNALLY:
                msg_info("Stream player stopped playing app stream %u (external cause)",
                         stream_id.get_raw_id());
                notify_app_playback_stopped();
                break;

              case Regs::PlayStream::PlainPlayerNotifications::StopResult::PUSHED_NEXT:
              case Regs::PlayStream::PlainPlayerNotifications::StopResult::ALREADY_STOPPED:
              case Regs::PlayStream::PlainPlayerNotifications::StopResult::WRONG_STATE:
              case Regs::PlayStream::PlainPlayerNotifications::StopResult::FAILED:
                break;
            }
        }

        const auto update = stream_info_output_buffer_.clear();
        do_notify_stream_info(update);
    }

    void cover_art_notification(void *stream_key_variant)
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(lock_);

        const GVariantWrapper wrapped_val(static_cast<GVariant *>(stream_key_variant),
                                          GVariantWrapper::Transfer::JUST_MOVE);

        const bool has_cover_art_changed =
            tracked_stream_key_.is_tracking(wrapped_val)
            ? try_retrieve_cover_art(GVariantWrapper::get(wrapped_val),
                                     current_cover_art_)
            : false;

        if(has_cover_art_changed)
            notify_cover_art_changed();
    }

    bool copy_picture(CoverArt::Picture &dest) const override
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(lock_);
        dest = current_cover_art_;
        return dest.is_available();
    }

  private:
    /*!
     * Push first or next stream to streamplayer, emit meta data, start if necessary
     */
    bool do_push_and_start_stream(const Regs::PlayStream::StreamInfo &stream_info,
                                  Regs::PlayStream::PlainPlayer::StreamID stream_id,
                                  bool is_first, bool is_start_requested)
    {
        CoverArt::StreamKey stream_key;
        CoverArt::generate_stream_key_for_app(stream_key, stream_info.url_);

        tdbus_dcpd_playback_emit_stream_info(
                dbus_get_playback_iface(), stream_id.get().get_raw_id(),
                stream_info.artist_.c_str(), stream_info.album_.c_str(),
                stream_info.title_.c_str(), stream_info.alttrack_.c_str(),
                stream_info.url_.c_str());

        gboolean fifo_overflow;
        gboolean is_playing;
        GError *error = nullptr;

        if(!tdbus_splay_urlfifo_call_push_sync(
                dbus_get_streamplayer_urlfifo_iface(),
                stream_id.get().get_raw_id(), stream_info.url_.c_str(),
                g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE,
                                          stream_key.key_,
                                          sizeof(stream_key.key_),
                                          sizeof(stream_key.key_[0])),
                0, "ms", 0, "ms",
                is_first ? -2 : 0,
                &fifo_overflow, &is_playing,
                nullptr, &error))
        {
            BUG("Failed pushing stream %u, URL %s to stream player",
                stream_id.get().get_raw_id(), stream_info.url_.c_str());
            dbus_common_handle_dbus_error(&error, "Push stream to player");
            return false;
        }

        if(fifo_overflow)
        {
            BUG("Pushed stream with clear request, got FIFO overflow");
            return false;
        }

        if(!is_playing && !is_start_requested &&
           !tdbus_splay_playback_call_start_sync(dbus_get_streamplayer_playback_iface(),
                                                 nullptr, &error))
        {
            msg_error(0, LOG_NOTICE, "Failed starting stream");
            dbus_common_handle_dbus_error(&error, "Start stream");

            if(!tdbus_splay_urlfifo_call_clear_sync(dbus_get_streamplayer_urlfifo_iface(),
                                                    0, nullptr, nullptr, nullptr,
                                                    nullptr, &error))
            {
                msg_error(0, LOG_NOTICE, "Failed clearing stream player FIFO");
                dbus_common_handle_dbus_error(&error, "Clear URLFIFO");
            }

            return false;
        }

        if(is_first)
            tdbus_dcpd_views_emit_open(dbus_get_views_iface(), "Play");

        return true;
    }

    SendStreamUpdate
    set_currently_playing_stream_id(const ID::Stream &stream_id,
                                    StreamStarted &started,
                                    const Regs::PlayStream::PlainPlayer *const player)
    {
        started = (stream_info_output_buffer_.matches_id(stream_id)
                   ? StreamStarted::NOT
                   : (stream_info_output_buffer_.is_valid()
                      ? StreamStarted::CONTINUED
                      : StreamStarted::FRESH));

        if(!stream_id.is_valid())
        {
            BUG("Got start notification for invalid stream ID %u",
                stream_id.get_raw_id());
            return stream_info_output_buffer_.clear();
        }

        if(started == StreamStarted::NOT)
        {
            BUG("Got repeated start notification for stream %u",
                stream_id.get_raw_id());
            return SendStreamUpdate::NONE;
        }

        if(stream_info_input_buffer_.matches_id(stream_id))
        {
            const auto update =
                stream_info_output_buffer_.diff(stream_info_input_buffer_);
            stream_info_output_buffer_ = std::move(stream_info_input_buffer_);
            return update;
        }

        if(player == nullptr)
            return stream_info_output_buffer_.clear(stream_id);

        const auto &info(player->get_current_stream_info());

        return info.is_known()
            ? stream_info_output_buffer_.set_full(stream_id,
                                                  std::string(info->alttrack_),
                                                  std::string(info->url_))
            : stream_info_output_buffer_.clear(stream_id);
    }

    void store_meta_data_and_url(const ID::Stream &stream_id,
                                 std::string &&title, std::string &&url)
    {
        if(stream_info_output_buffer_.matches_id(stream_id))
        {
            const SendStreamUpdate update = stream_id.is_valid()
                ? stream_info_output_buffer_.set_full(std::move(title), std::move(url))
                : stream_info_output_buffer_.clear();
            do_notify_stream_info(update);
        }
        else
            stream_info_input_buffer_.set_full(stream_id,
                                               std::move(title), std::move(url));
    }
};

std::unique_ptr<Regs::PlayStream::StreamingRegistersIface>
Regs::PlayStream::mk_streaming_registers()
{
    return std::make_unique<StreamingRegisters>();
}

static size_t copy_string_to_slave(const std::string &src,
                                   char *const dest, size_t dest_size)
{
    if(dest_size == 0)
        return 0;

    const size_t len = src.length();
    const size_t count = len < dest_size ? len : dest_size;

    if(count > 0)
        std::copy_n(src.begin(), count, dest);

    return count;
}

static bool copy_string_data(std::string &dest, const uint8_t *src,
                             size_t src_size, const char *what)
{
    dest.clear();

    if(src_size > 0 && src[0] != '\0')
        std::copy_n(src, src_size, std::back_inserter(dest));

    if(dest.empty())
        msg_vinfo(plainurl_register_dump_level, "%s: <empty>", what);

    return !dest.empty();
}

static void dump_meta_data(const std::string &artist, const std::string &album,
                           const std::string &title, const char *what)
{
    if(!msg_is_verbose(plainurl_register_dump_level))
        return;

    msg_vinfo(plainurl_register_dump_level, "%s artist: \"%s\"", what, artist.c_str());
    msg_vinfo(plainurl_register_dump_level, "%s album : \"%s\"", what, album.c_str());
    msg_vinfo(plainurl_register_dump_level, "%s title : \"%s\"", what, title.c_str());
}

static void dump_plain_url(const std::string &url, const char *what)
{
    msg_vinfo(plainurl_register_dump_level, "%s: \"%s\"", what, url.c_str());
}

static void registered_audio_source(GObject *source_object, GAsyncResult *res,
                                    gpointer user_data)
{
    GError *error = nullptr;
    tdbus_aupath_manager_call_register_source_finish(TDBUS_AUPATH_MANAGER(source_object),
                                                     res, &error);
    dbus_common_handle_dbus_error(&error, "Register audio source");

    Regs::AudioSources::fetch_audio_paths();
}

void StreamingRegisters::late_init()
{
    tdbus_aupath_manager_call_register_source(
        dbus_audiopath_get_manager_iface(), app_audio_source_id,
        "Streams pushed by smartphone app", "strbo", "/de/tahifi/Dcpd",
        nullptr, registered_audio_source, this);
}

static std::tuple<std::string, const size_t, const size_t>
tokenize_meta_data(const std::string &src)
{
    std::string dest;
    dest.reserve(src.length() + 1);

    size_t artist = src.length();
    size_t album = src.length();
    size_t idx = 0;

    for(size_t i = 0; i < src.length(); ++i)
    {
        const char ch = src[i];

        if(ch == '\x1d')
        {
            dest.push_back('\0');

            if(idx < 2)
            {
                if(idx == 0)
                    artist = i + 1;
                else
                    album = i + 1;

                ++idx;
            }
        }
        else
            dest.push_back(ch);
    }

    return std::make_tuple(std::move(dest), artist, album);
}

static StreamingRegisters *dcpregs_streaming_registers;

void Regs::PlayStream::DCP::init(StreamingRegistersIface &regs)
{
    dcpregs_streaming_registers = static_cast<StreamingRegisters *>(&regs);
}

ssize_t Regs::PlayStream::DCP::read_75_current_stream_title(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 75 handler %p %zu", response, length);

    size_t result;
    dcpregs_streaming_registers->with_current_stream_information(
        [response, length, &result]
        (const auto &info)
        {
            result = copy_string_to_slave(info.meta_data_, (char *)response, length);
        });
    return result;
}

ssize_t Regs::PlayStream::DCP::read_76_current_stream_url(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 76 handler %p %zu", response, length);

    size_t result;
    dcpregs_streaming_registers->with_current_stream_information(
        [response, length, &result]
        (const auto &info)
        {
            result = copy_string_to_slave(info.url_, (char *)response, length);
        });
    return result;
}

int Regs::PlayStream::DCP::write_78_start_play_stream_title(const uint8_t *data, size_t length)
{
    static const char register_description[] = "First stream meta data (reg 78)";

    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 78 handler %p %zu", data, length);

    std::string meta_data;
    if(!copy_string_data(meta_data, data, length, register_description))
        return -1;

    const auto tokenized(tokenize_meta_data(meta_data));
    const auto d(std::get<0>(tokenized).c_str());
    std::string artist(&d[std::get<1>(tokenized)]);
    std::string album(&d[std::get<2>(tokenized)]);
    std::string title(d);

    dump_meta_data(artist, album, title, register_description);
    dcpregs_streaming_registers->store_meta_data_for_first_stream(
        std::move(artist), std::move(album), std::move(title),
        std::move(meta_data));

    return 0;
}

int Regs::PlayStream::DCP::write_79_start_play_stream_url(const uint8_t *data, size_t length)
{
    static const char register_description[] = "First stream URL (reg 79)";

    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 79 handler %p %zu", data, length);

    std::string url;
    if(copy_string_data(url, data, length, register_description))
    {
        dump_plain_url(url, register_description);
        dcpregs_streaming_registers->start_first_stream(std::move(url));
    }
    else
        dcpregs_streaming_registers->stop_playing("empty URL written to reg 79");

    return 0;
}

ssize_t Regs::PlayStream::DCP::read_79_start_play_stream_url(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 79 handler %p %zu", response, length);
    return 0;
}

int Regs::PlayStream::DCP::write_238_next_stream_title(const uint8_t *data, size_t length)
{
    static const char register_description[] = "Next stream meta data (reg 238)";

    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 238 handler %p %zu", data, length);

    std::string meta_data;
    if(!copy_string_data(meta_data, data, length, register_description))
        return -1;

    const auto tokenized(tokenize_meta_data(meta_data));
    const auto d(std::get<0>(tokenized).c_str());
    std::string artist(&d[std::get<1>(tokenized)]);
    std::string album(&d[std::get<2>(tokenized)]);
    std::string title(d);

    dump_meta_data(artist, album, title, register_description);
    dcpregs_streaming_registers->store_meta_data_for_next_stream(
        std::move(artist), std::move(album), std::move(title),
        std::move(meta_data));

    return 0;
}

int Regs::PlayStream::DCP::write_239_next_stream_url(const uint8_t *data, size_t length)
{
    static const char register_description[] = "Next stream URL (reg 239)";

    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 239 handler %p %zu", data, length);

    std::string url;
    if(copy_string_data(url, data, length, register_description))
    {
        dump_plain_url(url, register_description);
        dcpregs_streaming_registers->push_next_stream(std::move(url));
    }
    else
        APPLIANCE_BUG("Empty URL written to reg 239");

    return 0;
}

ssize_t Regs::PlayStream::DCP::read_239_next_stream_url(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 239 handler %p %zu", response, length);
    return 0;
}

ssize_t Regs::PlayStream::DCP::read_210_current_cover_art_hash(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 210 handler %p %zu", response, length);

    size_t len;
    dcpregs_streaming_registers->with_current_cover_art(
        [response, length, &len] (const auto &cover_art)
        {
            len = cover_art.copy_hash(response, length);
        });

    if(len == 0)
        msg_info("Cover art: Send empty hash to SPI slave");
    else if(len == 16)
        msg_info("Cover art: Send hash to SPI slave: "
                 "%02x%02x%02x%02x%02x%02x%02x%02x"
                 "%02x%02x%02x%02x%02x%02x%02x%02x",
                 response[0], response[1], response[2], response[3],
                 response[4], response[5], response[6], response[7],
                 response[8], response[9], response[10], response[11],
                 response[12], response[13], response[14], response[15]);
    else
        BUG("Cover art: Send %zu hash bytes to SPI slave", len);

    return len;
}
