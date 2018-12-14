/*
 * Copyright (C) 2016, 2017, 2018  T+A elektroakustik GmbH & Co. KG
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
#include "registers_priv.hh"
#include "de_tahifi_artcache_errors.hh"
#include "dbus_common.h"
#include "dbus_iface_deep.h"
#include "messages.h"

#include <mutex>
#include <algorithm>

constexpr const char *ArtCache::ReadError::names_[];

static const auto plainurl_register_dump_level = MESSAGE_LEVEL_NORMAL;

enum class DevicePlaymode
{
    DESELECTED,
    DESELECTED_PLAYING,
    SELECTED_IDLE,
    WAIT_FOR_START_NOTIFICATION,
    WAIT_FOR_STOP_NOTIFICATION_KEEP_SELECTED,
    WAIT_FOR_STOP_NOTIFICATION_FOR_DESELECTION,
    APP_IS_PLAYING,
};

enum class StreamIdType
{
    INVALID,
    NON_APP,
    APP_CURRENT,
    APP_NEXT,
    APP_UNKNOWN,
};

enum class NotifyStreamInfo
{
    UNMODIFIED,
    PENDING,
    OVERWRITTEN_PENDING,
    DEV_NULL,
};

enum class SendStreamUpdate
{
    NONE,
    TITLE,
    URL_AND_TITLE,
};

struct SimplifiedStreamInfo
{
    std::string meta_data;
    std::string url;

    void clear()
    {
        meta_data.clear();
        url.clear();
    }
};

enum class PendingAppRequest
{
    NONE,
    START,
    STOP_KEEP_SELECTED,
};

using AppStreamID = ::ID::SourcedStream<STREAM_ID_SOURCE_APP>;

struct PlayAppStreamData
{
    DevicePlaymode device_playmode;

    /*!
     * Pending request to be considered when app audio source is selected.
     */
    PendingAppRequest pending_request;

  private:
    /*!
     * Keep track of IDs of streams started by app.
     */
    AppStreamID next_free_stream_id_;

    /*!
     * Currently playing app stream.
     *
     * Set when a new stream is sent to streamplayer.
     */
    AppStreamID current_stream_id_;

    /*!
     * Next app stream already pushed to streamplayer FIFO.
     */
    AppStreamID next_stream_id_;

    /*!
     * Stream last pushed to streamplayer.
     */
    AppStreamID last_pushed_stream_id_;

  public:
    /*!
     * Write buffer for registers 78 and 79.
     */
    SimplifiedStreamInfo inbuffer_new_stream;

    /*!
     * Write buffer for registers 238 and 239, next queued app stream.
     */
    SimplifiedStreamInfo inbuffer_next_stream;

    PlayAppStreamData():
        device_playmode(DevicePlaymode::DESELECTED),
        pending_request(PendingAppRequest::NONE),
        next_free_stream_id_(AppStreamID::make_invalid()),
        current_stream_id_(AppStreamID::make_invalid()),
        next_stream_id_(AppStreamID::make_invalid()),
        last_pushed_stream_id_(AppStreamID::make_invalid())
    {}

    void reset()
    {
        device_playmode = DevicePlaymode::DESELECTED;
        pending_request = PendingAppRequest::NONE;
        next_free_stream_id_ = AppStreamID::make();
        current_stream_id_ = AppStreamID::make_invalid();
        next_stream_id_ = AppStreamID::make_invalid();
        last_pushed_stream_id_ = AppStreamID::make_invalid();
        inbuffer_new_stream.clear();
        inbuffer_next_stream.clear();
    }

    void reset_to_idle_mode()
    {
        device_playmode = DevicePlaymode::SELECTED_IDLE;
        pending_request = PendingAppRequest::NONE;
        current_stream_id_ = AppStreamID::make_invalid();
        next_stream_id_ = AppStreamID::make_invalid();
    }

    void reset_to_deselected_mode()
    {
        device_playmode = DevicePlaymode::DESELECTED_PLAYING;
        pending_request = PendingAppRequest::NONE;
        current_stream_id_ = AppStreamID::make_invalid();
        next_stream_id_ = AppStreamID::make_invalid();
    }

    bool is_current_stream(const AppStreamID id) const
    {
        return id.get().is_valid() && id == current_stream_id_;
    }

    bool is_next_stream_in_queue(const AppStreamID id) const
    {
        return id.get().is_valid() && id == next_stream_id_;
    }

    bool is_last_pushed_stream(const AppStreamID id) const
    {
        return id.get().is_valid() && id == last_pushed_stream_id_;
    }

    void queued_stream_notification(AppStreamID stream_id)
    {
        next_stream_id_ = stream_id;
    }

    void restart_notification(AppStreamID stream_id)
    {
        current_stream_id_ = stream_id;
        next_stream_id_ = AppStreamID::make_invalid();
    }

    void playing_next_notification()
    {
        current_stream_id_ = next_stream_id_;
        next_stream_id_ = AppStreamID::make_invalid();
        inbuffer_next_stream.clear();
    }

    void set_last_pushed_stream_id(AppStreamID stream_id)
    {
        last_pushed_stream_id_ = stream_id;
    }

    AppStreamID get_free_stream_id()
    {
        if(!next_free_stream_id_.get().is_valid())
            return AppStreamID::make_invalid();

        while(true)
        {
            const AppStreamID result = next_free_stream_id_;
            ++next_free_stream_id_;

            if(result != current_stream_id_ && result != next_stream_id_)
                return result;
        }
    }

    stream_id_t get_current_stream_raw_id() const
    {
        return current_stream_id_.get().get_raw_id();
    }

    stream_id_t get_next_stream_raw_id() const
    {
        return next_stream_id_.get().get_raw_id();
    }
};

enum class CoverArtDataState
{
    COVER_ART_HAVE_NOTHING,
    COVER_ART_HAVE_TRACKED_STREAM_KEY,
    COVER_ART_PENDING,
    COVER_ART_AVAILABLE,
};

struct PlayAnyStreamData
{
  private:
    /*!
     * The ID that arrived through start/stop notifications.
     */
    ID::Stream currently_playing_stream_;

  public:
    /*!
     * The cover art meta data of the currently playing stream, if any.
     */
    CoverArt::Tracker tracked_stream_key;
    CoverArt::Picture current_cover_art;

    /*!
     * Register values in #PlayAnyStreamData::pending_data are for this ID.
     */
    ID::Stream pending_stream_id;

    /*!
     * Pending stream ID overwritten by new, also pending stream.
     *
     * There can, in fact, be two pending streams if the SPI slave is queuing
     * streams very quickly.
     */
    ID::Stream overwritten_pending_stream_id;

    /*!
     * Buffered information for registers 75 and 76.
     *
     * These information are used when the registers are read out.
     */
    SimplifiedStreamInfo current_stream_information;

    /*!
     * Write buffer for changes to registers 75 and 76.
     */
    SimplifiedStreamInfo pending_data;

    /*!
     * Buffer for changes to registers 75 and 76 while changes are pending.
     */
    SimplifiedStreamInfo overwritten_pending_data;

    PlayAnyStreamData():
        currently_playing_stream_(ID::Stream::make_invalid()),
        pending_stream_id(ID::Stream::make_invalid()),
        overwritten_pending_stream_id(ID::Stream::make_invalid())
    {}

    void reset()
    {
        currently_playing_stream_ = ID::Stream::make_invalid();
        tracked_stream_key.clear();
        current_cover_art.clear();
        pending_stream_id = ID::Stream::make_invalid();
        overwritten_pending_stream_id = ID::Stream::make_invalid();
        current_stream_information.clear();
        pending_data.clear();
        overwritten_pending_data.clear();
    }

    bool is_currently_playing(const ID::Stream &id) const
    {
        return id.is_valid() && id == currently_playing_stream_;
    }

    bool set_currently_playing(const ID::Stream &id)
    {
        if(id == currently_playing_stream_)
            return false;

        currently_playing_stream_ = id;
        return true;
    }
};

static inline bool is_app_mode(const DevicePlaymode mode)
{
    switch(mode)
    {
      case DevicePlaymode::SELECTED_IDLE:
      case DevicePlaymode::WAIT_FOR_START_NOTIFICATION:
      case DevicePlaymode::WAIT_FOR_STOP_NOTIFICATION_KEEP_SELECTED:
      case DevicePlaymode::APP_IS_PLAYING:
        return true;

      case DevicePlaymode::DESELECTED:
      case DevicePlaymode::DESELECTED_PLAYING:
      case DevicePlaymode::WAIT_FOR_STOP_NOTIFICATION_FOR_DESELECTION:
        break;
    }

    return false;
}

static inline bool is_app_mode_and_playing(const DevicePlaymode mode)
{
    return is_app_mode(mode) &&
           mode != DevicePlaymode::WAIT_FOR_STOP_NOTIFICATION_KEEP_SELECTED;
}

static StreamIdType determine_stream_id_type(const ID::Stream &stream_id,
                                             const PlayAppStreamData &data)
{
    const auto id(AppStreamID::make_from_generic_id(stream_id));

    if(!id.get().is_valid())
        return stream_id.is_valid() ? StreamIdType::NON_APP : StreamIdType::INVALID;

    if(data.is_current_stream(id))
        return StreamIdType::APP_CURRENT;
    else if(data.is_next_stream_in_queue(id))
        return StreamIdType::APP_NEXT;
    else
        return StreamIdType::APP_UNKNOWN;
}

static inline SendStreamUpdate
determine_send_stream_update(bool title_changed, bool url_changed)
{
    if(!title_changed && !url_changed)
        return SendStreamUpdate::NONE;

    if(!url_changed)
        return SendStreamUpdate::TITLE;

    return SendStreamUpdate::URL_AND_TITLE;
}

static inline SendStreamUpdate
clear_stream_info(SimplifiedStreamInfo &info)
{
    const auto ret = determine_send_stream_update(!info.meta_data.empty(),
                                                  !info.url.empty());
    info.clear();
    return ret;
}

static inline void notify_app_playback_stopped()
{
    Regs::get_data().register_changed_notification_fn(79);
}

static inline void notify_ready_for_next_stream_from_slave()
{
    Regs::get_data().register_changed_notification_fn(239);
}

static void do_notify_stream_info(PlayAnyStreamData &data,
                                  const NotifyStreamInfo which,
                                  const SendStreamUpdate update)
{
    switch(which)
    {
      case NotifyStreamInfo::UNMODIFIED:
        break;

      case NotifyStreamInfo::PENDING:
        data.current_stream_information = data.pending_data;
        break;

      case NotifyStreamInfo::OVERWRITTEN_PENDING:
        data.current_stream_information = data.overwritten_pending_data;
        break;

      case NotifyStreamInfo::DEV_NULL:
        clear_stream_info(data.current_stream_information);
        break;
    }

    if(which == NotifyStreamInfo::OVERWRITTEN_PENDING)
    {
        clear_stream_info(data.overwritten_pending_data);
        data.overwritten_pending_stream_id = ID::Stream::make_invalid();
    }
    else
    {
        clear_stream_info(data.pending_data);
        data.pending_stream_id = ID::Stream::make_invalid();
    }

    switch(update)
    {
      case SendStreamUpdate::NONE:
        msg_vinfo(MESSAGE_LEVEL_DIAG,
                  "Suppress sending title and URL to SPI slave");
        break;

      case SendStreamUpdate::URL_AND_TITLE:
        msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
        Regs::get_data().register_changed_notification_fn(75);
        Regs::get_data().register_changed_notification_fn(76);
        break;

      case SendStreamUpdate::TITLE:
        msg_vinfo(MESSAGE_LEVEL_DIAG, "Send only new title to SPI slave");
        Regs::get_data().register_changed_notification_fn(75);
        break;
    }
}

static void app_stream_started_playing(PlayAppStreamData &data,
                                       StreamIdType stype, bool is_new_stream)
{
    log_assert(stype == StreamIdType::APP_CURRENT ||
               stype == StreamIdType::APP_NEXT);

    if(!is_app_mode(data.device_playmode))
        BUG("App stream started in unexpected mode %d",
            static_cast<int>(data.device_playmode));

    data.device_playmode = DevicePlaymode::APP_IS_PLAYING;

    if(stype == StreamIdType::APP_NEXT)
        data.playing_next_notification();

    if(is_new_stream)
        notify_ready_for_next_stream_from_slave();
}

static inline void other_stream_started_playing(PlayAppStreamData &data,
                                                bool &switched_to_nonapp_mode)
{
    if(data.device_playmode != DevicePlaymode::DESELECTED &&
       data.device_playmode != DevicePlaymode::DESELECTED_PLAYING)
        switched_to_nonapp_mode = true;

    data.reset_to_deselected_mode();
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

static void unchecked_set_meta_data_and_url(const ID::Stream &stream_id,
                                            const std::string &title,
                                            const std::string &url,
                                            PlayAnyStreamData &any_stream_data)
{
    SimplifiedStreamInfo &dest_info(any_stream_data.is_currently_playing(stream_id)
                                    ? any_stream_data.current_stream_information
                                    : any_stream_data.pending_data);

    any_stream_data.pending_stream_id =
        ((&dest_info == &any_stream_data.pending_data)
         ? stream_id
         : ID::Stream::make_invalid());

    NotifyStreamInfo which;
    SendStreamUpdate update;

    if(stream_id.get_cookie() == STREAM_ID_COOKIE_INVALID)
    {
        update = clear_stream_info(dest_info);
        which = NotifyStreamInfo::DEV_NULL;
    }
    else
    {
        update = determine_send_stream_update(dest_info.meta_data != title,
                                              dest_info.url != url);
        dest_info.meta_data = title;
        dest_info.url = url;
        which = NotifyStreamInfo::UNMODIFIED;
    }

    /* direct update */
    if(any_stream_data.pending_stream_id.get_source() == STREAM_ID_SOURCE_INVALID)
        do_notify_stream_info(any_stream_data, which, update);
}

static void try_notify_pending_stream_info(PlayAnyStreamData &data,
                                           bool switched_to_nonapp_mode)
{
    if(data.pending_stream_id.get_source() != STREAM_ID_SOURCE_INVALID &&
       data.is_currently_playing(data.pending_stream_id))
    {
        do_notify_stream_info(data, NotifyStreamInfo::PENDING,
                              SendStreamUpdate::URL_AND_TITLE);
    }
    else if(data.overwritten_pending_stream_id.get_source() != STREAM_ID_SOURCE_INVALID &&
            data.is_currently_playing(data.overwritten_pending_stream_id))
    {
        do_notify_stream_info(data, NotifyStreamInfo::OVERWRITTEN_PENDING,
                              SendStreamUpdate::URL_AND_TITLE);
    }
    else if(switched_to_nonapp_mode)
    {
        /* In case the mode switched to non-app mode, but the external source
         * has failed to deliver title and URL up to this point, then we need
         * to wipe out the currently stored, outdated information. The external
         * source may send the missing information later in this case. */
        do_notify_stream_info(data, NotifyStreamInfo::DEV_NULL,
                              SendStreamUpdate::URL_AND_TITLE);
    }
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

static void try_start_stream(PlayAppStreamData &data,
                             PlayAnyStreamData &any_stream_data,
                             bool is_restart)
{
    const AppStreamID stream_id(data.get_free_stream_id());

    gboolean fifo_overflow;
    gboolean is_playing;

    const SimplifiedStreamInfo &selected(is_restart
                                         ? data.inbuffer_new_stream
                                         : data.inbuffer_next_stream);

    CoverArt::StreamKey stream_key;
    CoverArt::generate_stream_key_for_app(stream_key, selected.url);

    const auto tokenized(tokenize_meta_data(selected.meta_data));
    const auto token_store(std::get<0>(tokenized).c_str());

    tdbus_dcpd_playback_emit_stream_info(dbus_get_playback_iface(),
                                         stream_id.get().get_raw_id(),
                                         &token_store[std::get<1>(tokenized)],
                                         &token_store[std::get<2>(tokenized)],
                                         token_store,
                                         selected.meta_data.c_str(),
                                         selected.url.c_str());
    GError *error = nullptr;

    if(!tdbus_splay_urlfifo_call_push_sync(dbus_get_streamplayer_urlfifo_iface(),
                                           stream_id.get().get_raw_id(),
                                           selected.url.c_str(),
                                           g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE,
                                                                     stream_key.key_,
                                                                     sizeof(stream_key.key_),
                                                                     sizeof(stream_key.key_[0])),
                                           0, "ms", 0, "ms",
                                           is_restart ? -2 : 0,
                                           &fifo_overflow, &is_playing,
                                           nullptr, &error))
    {
        BUG("Failed pushing stream %u, URL %s to stream player",
            stream_id.get().get_raw_id(), selected.url.c_str());
        dbus_common_handle_dbus_error(&error, "Push stream to player");
        return;
    }

    if(fifo_overflow)
    {
        BUG("Pushed stream with clear request, got FIFO overflow");
        return;
    }

    auto maybe_our_pending_stream_id(AppStreamID::make_from_generic_id(any_stream_data.pending_stream_id));

    if(data.is_last_pushed_stream(maybe_our_pending_stream_id))
    {
        /* slave sent the next stream very quickly after the first stream,
         * didn't receive any start notification from streamplayer yet */
        any_stream_data.overwritten_pending_stream_id = any_stream_data.pending_stream_id;
        any_stream_data.overwritten_pending_data = any_stream_data.pending_data;
    }

    data.set_last_pushed_stream_id(stream_id);

    unchecked_set_meta_data_and_url(stream_id.get(), selected.meta_data,
                                    selected.url, any_stream_data);

    if(!is_playing && data.device_playmode == DevicePlaymode::SELECTED_IDLE)
    {

        if(tdbus_splay_playback_call_start_sync(dbus_get_streamplayer_playback_iface(),
                                                 nullptr, &error))
            data.device_playmode = DevicePlaymode::WAIT_FOR_START_NOTIFICATION;
        else
        {
            msg_error(0, LOG_NOTICE, "Failed starting stream");
            dbus_common_handle_dbus_error(&error, "Start stream");

            data.reset_to_idle_mode();

            if(!tdbus_splay_urlfifo_call_clear_sync(dbus_get_streamplayer_urlfifo_iface(),
                                                    0, nullptr, nullptr, nullptr,
                                                    nullptr, &error))
            {
                msg_error(0, LOG_NOTICE, "Failed clearing stream player FIFO");
                dbus_common_handle_dbus_error(&error, "Clear URLFIFO");
            }

            return;
        }
    }

    if(is_restart)
    {
        data.restart_notification(stream_id);
        tdbus_dcpd_views_emit_open(dbus_get_views_iface(), "Play");
    }
    else
    {
        log_assert(data.device_playmode == DevicePlaymode::WAIT_FOR_START_NOTIFICATION ||
                   data.device_playmode == DevicePlaymode::SELECTED_IDLE ||
                   data.device_playmode == DevicePlaymode::APP_IS_PLAYING);
        data.queued_stream_notification(stream_id);
    }
}

static void try_stop_stream(PlayAppStreamData &data, bool stay_in_app_mode)
{
    data.device_playmode = stay_in_app_mode
        ? DevicePlaymode::WAIT_FOR_STOP_NOTIFICATION_KEEP_SELECTED
        : DevicePlaymode::WAIT_FOR_STOP_NOTIFICATION_FOR_DESELECTION;

    GError *error = nullptr;

    if(!tdbus_splay_playback_call_stop_sync(dbus_get_streamplayer_playback_iface(),
                                            nullptr, &error))
    {
        msg_error(0, LOG_NOTICE, "Failed stopping stream player");
        dbus_common_handle_dbus_error(&error, "Stop stream");
        data.reset_to_idle_mode();
    }
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

static struct
{
    std::mutex lock;

    PlayAppStreamData app;
    PlayAnyStreamData other;
}
play_stream_data;

static const char app_audio_source_id[] = "strbo.plainurl";

void Regs::PlayStream::init()
{
    play_stream_data.app.reset();
    play_stream_data.other.reset();
}

void Regs::PlayStream::late_init()
{
    tdbus_aupath_manager_call_register_source(dbus_audiopath_get_manager_iface(),
                                              app_audio_source_id,
                                              "Streams pushed by smartphone app",
                                              "strbo",
                                              "/de/tahifi/Dcpd",
                                              nullptr,
                                              registered_audio_source, &play_stream_data);
}

void Regs::PlayStream::deinit()
{
    std::lock_guard<std::mutex> lk(play_stream_data.lock);
    play_stream_data.other.tracked_stream_key.clear();
    play_stream_data.other.current_cover_art.clear();
}

static bool parse_speed_factor(const uint8_t *data, size_t length,
                               double &factor)
{
    if(length != 2)
    {
        msg_error(EINVAL, LOG_ERR, "Speed factor length must be 2");
        return false;
    }

    if(data[1] >= 100)
    {
        msg_error(EINVAL, LOG_ERR, "Speed factor invalid fraction part");
        return false;
    }

    factor = data[0];
    factor += double(data[1]) / 100.0;

    if(factor <= 0.0)
    {
        msg_error(EINVAL, LOG_ERR, "Speed factor too small");
        return false;
    }

    return true;
}

static bool parse_absolute_position_ms(const uint8_t *data, size_t length,
                                       uint32_t &position_ms)
{
    if(length != sizeof(position_ms))
    {
        msg_error(EINVAL, LOG_ERR,
                  "Seek position length must be %zu", sizeof(position_ms));
        return false;
    }

    /* little endian */
    position_ms = (uint32_t(data[0]) << 0)  | (uint32_t(data[1]) << 8) |
                  (uint32_t(data[2]) << 16) | (uint32_t(data[3]) << 24);

    return true;
}

int Regs::PlayStream::DCP::write_73_seek_or_set_speed(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 73 handler %p %zu", data, length);

    if(length < 1)
        return -1;

    double factor;
    uint32_t position;

    switch(data[0])
    {
      case 0xc1:
        if(parse_speed_factor(data + 1, length - 1, factor))
        {
            tdbus_dcpd_playback_emit_set_speed(dbus_get_playback_iface(), factor);
            return 0;
        }

        break;

      case 0xc2:
        if(parse_speed_factor(data + 1, length - 1, factor))
        {
            tdbus_dcpd_playback_emit_set_speed(dbus_get_playback_iface(), -factor);
            return 0;
        }

        break;

      case 0xc3:
        tdbus_dcpd_playback_emit_set_speed(dbus_get_playback_iface(), 0.0);
        return 0;

      case 0xc4:
        if(parse_absolute_position_ms(data + 1, length - 1, position))
        {
            /* overflow/underflow impossible, no further checks required */
            tdbus_dcpd_playback_emit_seek(dbus_get_playback_iface(),
                                          position, "ms");
            return 0;
        }

        break;

      default:
        msg_error(EINVAL, LOG_ERR,
                  "Invalid subcommand 0x%02x for register 73", data[0]);
        break;
    }

    return -1;
}

ssize_t Regs::PlayStream::DCP::read_75_current_stream_title(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 75 handler %p %zu", response, length);

    std::lock_guard<std::mutex> lk(play_stream_data.lock);
    return copy_string_to_slave(play_stream_data.other.current_stream_information.meta_data,
                                (char *)response, length);
}

ssize_t Regs::PlayStream::DCP::read_76_current_stream_url(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 76 handler %p %zu", response, length);

    std::lock_guard<std::mutex> lk(play_stream_data.lock);
    return copy_string_to_slave(play_stream_data.other.current_stream_information.url,
                                (char *)response, length);
}

static void dump_plainurl_register_meta_data(const char *what,
                                             const SimplifiedStreamInfo &info)
{
    if(!msg_is_verbose(plainurl_register_dump_level))
        return;

    const auto tokenized(tokenize_meta_data(info.meta_data));
    const auto d(std::get<0>(tokenized).c_str());

    msg_vinfo(plainurl_register_dump_level, "%s artist: \"%s\"", what, &d[std::get<1>(tokenized)]);
    msg_vinfo(plainurl_register_dump_level, "%s album : \"%s\"", what, &d[std::get<2>(tokenized)]);
    msg_vinfo(plainurl_register_dump_level, "%s title : \"%s\"", what, d);
}

static void dump_plainurl_register_url(const char *what,
                                       const SimplifiedStreamInfo &info)
{
    msg_vinfo(plainurl_register_dump_level, "%s: \"%s\"", what, info.url.c_str());
}

int Regs::PlayStream::DCP::write_78_start_play_stream_title(const uint8_t *data, size_t length)
{
    static const char register_description[] = "First stream meta data (reg 78)";

    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 78 handler %p %zu", data, length);

    std::lock_guard<std::mutex> lk(play_stream_data.lock);

    if(!is_app_mode(play_stream_data.app.device_playmode))
    {
        GVariantDict empty;
        g_variant_dict_init(&empty, nullptr);
        tdbus_aupath_manager_call_request_source(dbus_audiopath_get_manager_iface(),
                                                 app_audio_source_id,
                                                 g_variant_dict_end(&empty),
                                                 nullptr, nullptr, nullptr);
    }

    if(copy_string_data(play_stream_data.app.inbuffer_new_stream.meta_data,
                        data, length, register_description))
        dump_plainurl_register_meta_data(register_description,
                                         play_stream_data.app.inbuffer_new_stream);

    return 0;
}

int Regs::PlayStream::DCP::write_79_start_play_stream_url(const uint8_t *data, size_t length)
{
    static const char register_description[] = "First stream URL (reg 79)";

    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 79 handler %p %zu", data, length);

    std::lock_guard<std::mutex> lk(play_stream_data.lock);

    const bool is_in_app_mode = is_app_mode(play_stream_data.app.device_playmode);

    if(is_in_app_mode)
        play_stream_data.app.pending_request = PendingAppRequest::NONE;

    if(copy_string_data(play_stream_data.app.inbuffer_new_stream.url,
                        data, length, register_description))
    {
        dump_plainurl_register_url(register_description,
                                   play_stream_data.app.inbuffer_new_stream);

        /* maybe start playing */
        if(play_stream_data.app.inbuffer_new_stream.meta_data[0] != '\0')
        {
            if(is_in_app_mode)
                try_start_stream(play_stream_data.app, play_stream_data.other,
                                 true);
            else
                play_stream_data.app.pending_request = PendingAppRequest::START;
        }
        else
            msg_error(0, LOG_ERR, "Not starting stream, register 78 still unset");
    }
    else if(is_in_app_mode)
    {
        /* stop command */
        try_stop_stream(play_stream_data.app, true);
    }
    else
        play_stream_data.app.pending_request = PendingAppRequest::STOP_KEEP_SELECTED;

    switch(play_stream_data.app.pending_request)
    {
      case PendingAppRequest::START:
        break;

      case PendingAppRequest::NONE:
      case PendingAppRequest::STOP_KEEP_SELECTED:
        clear_stream_info(play_stream_data.app.inbuffer_new_stream);
        break;
    }

    return 0;
}

ssize_t Regs::PlayStream::DCP::read_79_start_play_stream_url(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 79 handler %p %zu", response, length);
    return 0;
}

ssize_t Regs::PlayStream::DCP::read_210_current_cover_art_hash(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 210 handler %p %zu", response, length);

    std::lock_guard<std::mutex> lk(play_stream_data.lock);

    const size_t len =
        play_stream_data.other.current_cover_art.copy_hash(response, length);

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

int Regs::PlayStream::DCP::write_238_next_stream_title(const uint8_t *data, size_t length)
{
    static const char register_description[] = "Next stream meta data (reg 238)";

    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 238 handler %p %zu", data, length);

    std::lock_guard<std::mutex> lk(play_stream_data.lock);

    if(!is_app_mode(play_stream_data.app.device_playmode))
    {
        BUG("App sets next stream title while not in app mode");
        return 0;
    }

    if(copy_string_data(play_stream_data.app.inbuffer_next_stream.meta_data,
                        data, length, register_description))
        dump_plainurl_register_meta_data(register_description,
                                         play_stream_data.app.inbuffer_next_stream);

    return 0;
}

int Regs::PlayStream::DCP::write_239_next_stream_url(const uint8_t *data, size_t length)
{
    static const char register_description[] = "Next stream URL (reg 239)";

    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 239 handler %p %zu", data, length);

    std::lock_guard<std::mutex> lk(play_stream_data.lock);

    if(!is_app_mode(play_stream_data.app.device_playmode))
    {
        BUG("App sets next URL while not in app mode");
        return 0;
    }

    if(copy_string_data(play_stream_data.app.inbuffer_next_stream.url,
                        data, length, register_description))
    {
        dump_plainurl_register_url(register_description,
                                   play_stream_data.app.inbuffer_next_stream);

        /* maybe send to streamplayer queue */
        if(play_stream_data.app.inbuffer_next_stream.meta_data[0] != '\0')
            try_start_stream(play_stream_data.app, play_stream_data.other,
                             false);
        else
            msg_error(0, LOG_ERR,
                      "Not starting stream, register 238 still unset");
    }
    else
    {
        /* ignore funny writes */
        BUG("App is doing weird stuff");
    }

    clear_stream_info(play_stream_data.app.inbuffer_next_stream);

    return 0;
}

ssize_t Regs::PlayStream::DCP::read_239_next_stream_url(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 239 handler %p %zu", response, length);
    return 0;
}

void Regs::PlayStream::select_source()
{
    std::lock_guard<std::mutex> lk(play_stream_data.lock);

    if(is_app_mode(play_stream_data.app.device_playmode))
    {
        BUG("Already selected");
        return;
    }

    msg_info("Enter app mode");

    play_stream_data.app.device_playmode = DevicePlaymode::SELECTED_IDLE;

    switch(play_stream_data.app.pending_request)
    {
      case PendingAppRequest::NONE:
        break;

      case PendingAppRequest::START:
        msg_vinfo(MESSAGE_LEVEL_DIAG, "Processing pending start request");

        if(play_stream_data.app.inbuffer_new_stream.meta_data[0] != '\0')
        {
            try_start_stream(play_stream_data.app, play_stream_data.other,
                             true);
            clear_stream_info(play_stream_data.app.inbuffer_new_stream);
        }
        else
            BUG("No data available for pending start request");

        break;

      case PendingAppRequest::STOP_KEEP_SELECTED:
        msg_info("Processing pending stop request");
        try_stop_stream(play_stream_data.app, true);
        break;
    }

    play_stream_data.app.pending_request = PendingAppRequest::NONE;
}

void Regs::PlayStream::deselect_source()
{
    std::lock_guard<std::mutex> lk(play_stream_data.lock);

    if(!is_app_mode(play_stream_data.app.device_playmode))
    {
        BUG("Not selected");
        return;
    }

    msg_info("Leave app mode");

    switch(play_stream_data.app.device_playmode)
    {
      case DevicePlaymode::SELECTED_IDLE:
        play_stream_data.app.device_playmode = DevicePlaymode::DESELECTED;
        break;

      case DevicePlaymode::WAIT_FOR_START_NOTIFICATION:
      case DevicePlaymode::APP_IS_PLAYING:
        try_stop_stream(play_stream_data.app, false);
        break;

      case DevicePlaymode::WAIT_FOR_STOP_NOTIFICATION_KEEP_SELECTED:
        play_stream_data.app.device_playmode =
            DevicePlaymode::WAIT_FOR_STOP_NOTIFICATION_FOR_DESELECTION;
        break;

      case DevicePlaymode::DESELECTED:
      case DevicePlaymode::DESELECTED_PLAYING:
      case DevicePlaymode::WAIT_FOR_STOP_NOTIFICATION_FOR_DESELECTION:
        break;
    }
}

void Regs::PlayStream::set_title_and_url(ID::Stream stream_id,
                                         std::string &&title, std::string &&url)
{
    msg_vinfo(MESSAGE_LEVEL_DIAG,
              "Received explicit title and URL information for stream %u",
              stream_id.get_raw_id());

    std::lock_guard<std::mutex> lk(play_stream_data.lock);

    log_assert(stream_id.get_source() != STREAM_ID_SOURCE_INVALID);

    if(!AppStreamID::compatible_with(stream_id))
        unchecked_set_meta_data_and_url(stream_id, title, url,
                                        play_stream_data.other);
    else
    {
        BUG("Got title and URL information for app stream ID %u",
            stream_id.get_raw_id());
        BUG("+   Title: \"%s\"", title.c_str());
        BUG("+   URL  : \"%s\"", url.c_str());
    }
}

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

static inline void notify_cover_art_changed()
{
    Regs::get_data().register_changed_notification_fn(210);
}

/*!
 * React on start of stream.
 *
 * ATTENTION, PLEASE!
 *
 * In case you are wondering why this code does not incorporate the currently
 * selected audio source in any way, but instead relies on a seemingly weired
 * kind of auto-detection of a mysterious "app mode": This code predates
 * explicit audio source and audio path management. Before there were audio
 * paths, there was only a single stream player. Mode switching was done based
 * on stream IDs and start/stop state changes.
 *
 * And this is what's still going on in here. The Roon Ready player generates
 * stream IDs tagged with the Roon ID, so the logic in here detects non-app IDs
 * when seeing them. Code that sends commands directly to the stream player are
 * only sent in app mode, so that there should be no accidental communication
 * with the regular stream player while Roon is active.
 *
 * The mechanisms in here (and in #Regs::PlayStream::stop_notification())
 * operate orthogonal to and completely independent of audio path selection,
 * AND OF COURSE THIS IS A PROBLEM. It currently works, but an adaption to make
 * use of audio source information is required to make this code simpler and
 * also more stable against possible misdetections of app/no-app modes. FIXME.
 */
void Regs::PlayStream::start_notification(ID::Stream stream_id,
                                          void *stream_key_variant)
{
    std::lock_guard<std::mutex> lk(play_stream_data.lock);

    play_stream_data.other.tracked_stream_key.set(
            std::move(GVariantWrapper(static_cast<GVariant *>(stream_key_variant),
                                      GVariantWrapper::Transfer::JUST_MOVE)));

    const StreamIdType stream_id_type =
        determine_stream_id_type(stream_id, play_stream_data.app);

    const bool is_new_stream =
        play_stream_data.other.set_currently_playing(stream_id);

    bool switched_to_nonapp_mode = false;

    switch(stream_id_type)
    {
      case StreamIdType::INVALID:
        BUG("Got start notification for invalid stream ID %u", stream_id.get_raw_id());
        break;

      case StreamIdType::APP_UNKNOWN:
        if(is_app_mode_and_playing(play_stream_data.app.device_playmode))
            msg_error(0, LOG_NOTICE,
                      "Got start notification for unknown app stream ID %u",
                      stream_id.get_raw_id());
        else
            other_stream_started_playing(play_stream_data.app,
                                         switched_to_nonapp_mode);

        break;

      case StreamIdType::APP_CURRENT:
      case StreamIdType::APP_NEXT:
        switch(play_stream_data.app.device_playmode)
        {
          case DevicePlaymode::DESELECTED:
          case DevicePlaymode::DESELECTED_PLAYING:
            BUG("App stream %u started, but audio source not selected",
                stream_id.get_raw_id());

            other_stream_started_playing(play_stream_data.app,
                                         switched_to_nonapp_mode);
            break;

          case DevicePlaymode::SELECTED_IDLE:
          case DevicePlaymode::WAIT_FOR_START_NOTIFICATION:
          case DevicePlaymode::WAIT_FOR_STOP_NOTIFICATION_KEEP_SELECTED:
          case DevicePlaymode::APP_IS_PLAYING:
            msg_info("%s app stream %u",
                     is_new_stream ? "Next" : "Continue with",
                     stream_id.get_raw_id());
            app_stream_started_playing(play_stream_data.app, stream_id_type, is_new_stream);
            break;

          case DevicePlaymode::WAIT_FOR_STOP_NOTIFICATION_FOR_DESELECTION:
            msg_error(0, LOG_NOTICE,
                      "Unexpected start of app stream %u", stream_id.get_raw_id());

            other_stream_started_playing(play_stream_data.app,
                                         switched_to_nonapp_mode);
            break;
        }

        break;

      case StreamIdType::NON_APP:
        if(is_app_mode(play_stream_data.app.device_playmode))
            BUG("Leave app mode: unexpected start of non-app stream %u "
                "(expected next %u or new %u)",
                stream_id.get_raw_id(),
                play_stream_data.app.get_next_stream_raw_id(),
                play_stream_data.app.get_current_stream_raw_id());

        other_stream_started_playing(play_stream_data.app,
                                     switched_to_nonapp_mode);

        if(switched_to_nonapp_mode)
            notify_app_playback_stopped();

        break;
    }

    try_notify_pending_stream_info(play_stream_data.other,
                                   switched_to_nonapp_mode);

    GVariant *val = play_stream_data.other.tracked_stream_key.is_tracking()
        ? GVariantWrapper::get(play_stream_data.other.tracked_stream_key.get_variant())
        : nullptr;

    if(try_retrieve_cover_art(val, play_stream_data.other.current_cover_art) ||
       is_new_stream)
        notify_cover_art_changed();
}

void Regs::PlayStream::stop_notification()
{
    std::lock_guard<std::mutex> lk(play_stream_data.lock);

    play_stream_data.other.tracked_stream_key.clear();
    play_stream_data.other.current_cover_art.clear();

    if(is_app_mode(play_stream_data.app.device_playmode))
    {
        msg_info("App mode: streamplayer has stopped");
        play_stream_data.app.device_playmode = DevicePlaymode::SELECTED_IDLE;
        notify_app_playback_stopped();
    }
    else
        play_stream_data.app.device_playmode = DevicePlaymode::DESELECTED;

    play_stream_data.app.set_last_pushed_stream_id(AppStreamID::make_invalid());
    play_stream_data.other.set_currently_playing(ID::Stream::make_invalid());

    do_notify_stream_info(play_stream_data.other, NotifyStreamInfo::DEV_NULL,
                          SendStreamUpdate::URL_AND_TITLE);
}

void Regs::PlayStream::cover_art_notification(void *stream_key_variant)
{
    std::lock_guard<std::mutex> lk(play_stream_data.lock);

    const GVariantWrapper wrapped_val(static_cast<GVariant *>(stream_key_variant),
                                      GVariantWrapper::Transfer::JUST_MOVE);

    const bool has_cover_art_changed =
        play_stream_data.other.tracked_stream_key.is_tracking(wrapped_val)
        ? try_retrieve_cover_art(GVariantWrapper::get(wrapped_val),
                                 play_stream_data.other.current_cover_art)
        : false;

    if(has_cover_art_changed)
        notify_cover_art_changed();
}

class PictureProvider: public CoverArt::PictureProviderIface
{
  private:
    std::mutex &lock_;
    const CoverArt::Picture &picture_;

  public:
    PictureProvider(const PictureProvider &) = delete;
    PictureProvider &operator=(const PictureProvider &) = delete;

    explicit PictureProvider(std::mutex &lock, const CoverArt::Picture &picture):
        lock_(lock),
        picture_(picture)
    {}

    bool copy_picture(CoverArt::Picture &dest) const override
    {
        std::lock_guard<std::mutex> lk(lock_);
        dest = picture_;

        return dest.is_available();
    }
};

static PictureProvider picture_provider(play_stream_data.lock,
                                        play_stream_data.other.current_cover_art);

const CoverArt::PictureProviderIface &Regs::PlayStream::get_picture_provider()
{
    return picture_provider;
}
