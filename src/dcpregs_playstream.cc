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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <memory>
#include <cstring>
#include <glib.h>

#include "dcpregs_playstream.h"
#include "dcpregs_playstream.hh"
#include "dcpregs_audiosources.h"
#include "registers_priv.h"
#include "coverart.hh"
#include "streamplayer_dbus.h"
#include "artcache_dbus.h"
#include "de_tahifi_artcache_errors.hh"
#include "dbus_common.h"
#include "dbus_iface_deep.h"
#include "messages.h"

constexpr const char *ArtCache::ReadError::names_[];

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
    char meta_data[256 + 1];
    char url[2048 + 1];
};

enum class PendingAppRequest
{
    NONE,
    START,
    STOP_KEEP_SELECTED,
    STOP_FOR_DESELECTION,
};

struct PlayAppStreamData
{
    DevicePlaymode device_playmode;

    /*!
     * Pending request to be considered when app audio source is selected.
     */
    PendingAppRequest pending_request;

    /*!
     * Keep track of IDs of streams started by app.
     */
    stream_id_t next_free_stream_id;

    /*!
     * Currently playing app stream.
     *
     * Set when a new stream is sent to streamplayer.
     */
    stream_id_t current_stream_id;

    /*!
     * Next app stream already pushed to streamplayer FIFO.
     */
    stream_id_t next_stream_id;

    /*!
     * Stream last pushed to streamplayer.
     */
    stream_id_t last_pushed_stream_id;

    /*!
     * Write buffer for registers 78 and 79.
     */
    struct SimplifiedStreamInfo inbuffer_new_stream;

    /*!
     * Write buffer for registers 238 and 239, next queued app stream.
     */
    struct SimplifiedStreamInfo inbuffer_next_stream;
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
    /*!
     * The ID that arrived in through start/stop notifications.
     */
    stream_id_t currently_playing_stream;

    /*!
     * The cover art meta data of the currently playing stream, if any.
     */
    CoverArt::Tracker tracked_stream_key;
    CoverArt::Picture current_cover_art;

    /*!
     * Register values in #PlayAnyStreamData::pending_data are for this ID.
     */
    stream_id_t pending_stream_id;

    /*!
     * Pending stream ID overwritten by new, also pending stream.
     *
     * There can, in fact, be two pending streams if the SPI slave is queuing
     * streams very quickly.
     */
    stream_id_t overwritten_pending_stream_id;

    /*!
     * Buffered information for registers 75 and 76.
     *
     * These information are used when the registers are read out.
     */
    struct SimplifiedStreamInfo current_stream_information;

    /*!
     * Write buffer for changes to registers 75 and 76.
     */
    struct SimplifiedStreamInfo pending_data;

    /*!
     * Buffer for changes to registers 75 and 76 while changes are pending.
     */
    struct SimplifiedStreamInfo overwritten_pending_data;
};

static inline bool is_app_stream(const stream_id_t raw_stream_id)
{
    return (raw_stream_id & STREAM_ID_SOURCE_MASK) == STREAM_ID_SOURCE_APP;
}

static inline bool is_stream_with_valid_source(const stream_id_t raw_stream_id)
{
    return (raw_stream_id & STREAM_ID_SOURCE_MASK) != STREAM_ID_SOURCE_INVALID;
}

static inline bool is_app_stream_and_valid(stream_id_t raw_stream_id)
{
    if(!is_app_stream(raw_stream_id))
        return false;

    raw_stream_id &= STREAM_ID_COOKIE_MASK;

    return (raw_stream_id >= STREAM_ID_COOKIE_MIN &&
            raw_stream_id <= STREAM_ID_COOKIE_MAX);
}

static inline bool is_valid_stream(stream_id_t raw_stream_id)
{
    if(!is_stream_with_valid_source(raw_stream_id))
        return false;

    raw_stream_id &= STREAM_ID_COOKIE_MASK;

    return (raw_stream_id >= STREAM_ID_COOKIE_MIN &&
            raw_stream_id <= STREAM_ID_COOKIE_MAX);
}

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

static StreamIdType determine_stream_id_type(const stream_id_t raw_stream_id,
                                             const struct PlayAppStreamData *data)
{
    const stream_id_t source_id = (raw_stream_id & STREAM_ID_SOURCE_MASK);

    if(source_id == STREAM_ID_SOURCE_INVALID ||
       (raw_stream_id & STREAM_ID_COOKIE_MASK) == STREAM_ID_COOKIE_INVALID)
        return StreamIdType::INVALID;
    else if(source_id != STREAM_ID_SOURCE_APP)
        return StreamIdType::NON_APP;

    if(raw_stream_id == data->current_stream_id)
        return StreamIdType::APP_CURRENT;
    else if(raw_stream_id == data->next_stream_id)
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
clear_stream_info(struct SimplifiedStreamInfo *info)
{
    const SendStreamUpdate ret =
        determine_send_stream_update(info->meta_data[0] != '\0',
                                     info->url[0] != '\0');

    info->meta_data[0] = '\0';
    info->url[0] = '\0';

    return ret;
}

static inline void reset_to_idle_mode(struct PlayAppStreamData *data)
{
    data->device_playmode = DevicePlaymode::SELECTED_IDLE;
    data->pending_request = PendingAppRequest::NONE;
    data->current_stream_id = 0;
    data->next_stream_id = 0;
}

static inline void notify_app_playback_stopped(void)
{
    registers_get_data()->register_changed_notification_fn(79);
}

static inline void notify_ready_for_next_stream_from_slave(void)
{
    registers_get_data()->register_changed_notification_fn(239);
}

static void do_notify_stream_info(struct PlayAnyStreamData *data,
                                  const NotifyStreamInfo which,
                                  const SendStreamUpdate update)
{
    switch(which)
    {
      case NotifyStreamInfo::UNMODIFIED:
        break;

      case NotifyStreamInfo::PENDING:
        data->current_stream_information = data->pending_data;
        break;

      case NotifyStreamInfo::OVERWRITTEN_PENDING:
        data->current_stream_information = data->overwritten_pending_data;
        break;

      case NotifyStreamInfo::DEV_NULL:
        clear_stream_info(&data->current_stream_information);
        break;
    }

    if(which == NotifyStreamInfo::OVERWRITTEN_PENDING)
    {
        clear_stream_info(&data->overwritten_pending_data);
        data->overwritten_pending_stream_id =
            STREAM_ID_SOURCE_INVALID | STREAM_ID_COOKIE_INVALID;
    }
    else
    {
        clear_stream_info(&data->pending_data);
        data->pending_stream_id =
            STREAM_ID_SOURCE_INVALID | STREAM_ID_COOKIE_INVALID;
    }

    switch(update)
    {
      case SendStreamUpdate::NONE:
        msg_vinfo(MESSAGE_LEVEL_DIAG,
                  "Suppress sending title and URL to SPI slave");
        break;

      case SendStreamUpdate::URL_AND_TITLE:
        msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
        registers_get_data()->register_changed_notification_fn(75);
        registers_get_data()->register_changed_notification_fn(76);
        break;

      case SendStreamUpdate::TITLE:
        msg_vinfo(MESSAGE_LEVEL_DIAG, "Send only new title to SPI slave");
        registers_get_data()->register_changed_notification_fn(75);
        break;
    }
}

static void app_stream_started_playing(struct PlayAppStreamData *data,
                                       StreamIdType stype, bool is_new_stream)
{
    log_assert(stype == StreamIdType::APP_CURRENT ||
               stype == StreamIdType::APP_NEXT);

    if(!is_app_mode(data->device_playmode))
        BUG("App stream started in unexpected mode %d",
            static_cast<int>(data->device_playmode));

    data->device_playmode = DevicePlaymode::APP_IS_PLAYING;

    if(stype == StreamIdType::APP_NEXT)
    {
        data->current_stream_id = data->next_stream_id;
        data->next_stream_id = 0;
        clear_stream_info(&data->inbuffer_next_stream);
    }

    if(is_new_stream)
        notify_ready_for_next_stream_from_slave();
}

static inline void other_stream_started_playing(struct PlayAppStreamData *data,
                                                bool *switched_to_nonapp_mode)
{
    if(data->device_playmode != DevicePlaymode::DESELECTED &&
       data->device_playmode != DevicePlaymode::DESELECTED_PLAYING)
        *switched_to_nonapp_mode = true;

    data->device_playmode = DevicePlaymode::DESELECTED_PLAYING;
    data->pending_request = PendingAppRequest::NONE;
    data->current_stream_id = 0;
    data->next_stream_id = 0;
}

static size_t copy_string_to_slave(const char *const __restrict src,
                                   char *const __restrict dest, size_t dest_size)
{
    if(dest_size == 0)
        return 0;

    const size_t len = strlen(src);
    const size_t count = len < dest_size ? len : dest_size;

    if(count > 0)
        memcpy(dest, src, count);

    return count;
}

static bool copy_string_data(char *dest, size_t dest_size,
                             const uint8_t *src, size_t src_size)
{
    if(src_size == 0 || src[0] == '\0' || dest_size <= src_size)
        dest[0] = '\0';
    else
    {
        memcpy(dest, src, src_size);
        dest[src_size] = '\0';
    }

    return dest[0] != '\0';
}

static void strncpy_terminated(char *dest, const char *src, size_t n)
{
    strncpy(dest, src, n);
    dest[n - 1] = '\0';
}

static stream_id_t get_next_stream_id(stream_id_t *const next_free_id)
{
    log_assert(is_app_stream_and_valid(*next_free_id));

    const stream_id_t ret = *next_free_id;

    stream_id_t cookie = ret & STREAM_ID_COOKIE_MASK;

    if(++cookie > STREAM_ID_COOKIE_MAX)
        cookie = STREAM_ID_COOKIE_MIN;

    *next_free_id = STREAM_ID_SOURCE_APP | cookie;

    return ret;
}

static void unchecked_set_meta_data_and_url(const stream_id_t raw_stream_id,
                                            const char *title, const char *url,
                                            struct PlayAnyStreamData *any_stream_data)
{
    struct SimplifiedStreamInfo *const dest_info =
        (raw_stream_id == any_stream_data->currently_playing_stream
         ? &any_stream_data->current_stream_information
         : &any_stream_data->pending_data);

    any_stream_data->pending_stream_id =
        ((dest_info == &any_stream_data->pending_data)
         ? raw_stream_id
         : STREAM_ID_SOURCE_INVALID | STREAM_ID_COOKIE_INVALID);

    NotifyStreamInfo which;
    SendStreamUpdate update;

    if((raw_stream_id & STREAM_ID_COOKIE_MASK) == STREAM_ID_COOKIE_INVALID)
    {
        update = clear_stream_info(dest_info);
        which = NotifyStreamInfo::DEV_NULL;
    }
    else
    {
        update =
            determine_send_stream_update(strcmp(dest_info->meta_data, title) != 0,
                                         strcmp(dest_info->url, url) != 0);

        strncpy_terminated(dest_info->meta_data, title, sizeof(dest_info->meta_data));
        strncpy_terminated(dest_info->url,       url,   sizeof(dest_info->url));
        which = NotifyStreamInfo::UNMODIFIED;
    }

    /* direct update */
    if(!is_stream_with_valid_source(any_stream_data->pending_stream_id))
        do_notify_stream_info(any_stream_data, which, update);
}

static void try_notify_pending_stream_info(struct PlayAnyStreamData *data,
                                           bool switched_to_nonapp_mode)
{
    if(is_stream_with_valid_source(data->pending_stream_id) &&
       data->currently_playing_stream == data->pending_stream_id)
    {
        do_notify_stream_info(data, NotifyStreamInfo::PENDING,
                              SendStreamUpdate::URL_AND_TITLE);
    }
    else if(is_stream_with_valid_source(data->overwritten_pending_stream_id) &&
            data->currently_playing_stream == data->overwritten_pending_stream_id)
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

static void tokenize_meta_data(char *dest, const char *src,
                               const char *(&artist_and_album)[2])
{
    static const char empty[] = "";

    dest[0] = '\0';
    artist_and_album[0] = empty;
    artist_and_album[1] = empty;

    size_t idx = 0;

    for(size_t i = 0; /* nothing */; ++i)
    {
        const char ch = src[i];

        if(ch == '\x1d')
        {
            dest[i] = '\0';

            if(idx < 2)
                artist_and_album[idx++] = &dest[i + 1];
        }
        else
            dest[i] = ch;

        if(ch == '\0')
            break;
    }
}

static void try_start_stream(struct PlayAppStreamData *const data,
                             struct PlayAnyStreamData *any_stream_data,
                             bool is_restart)
{
    stream_id_t stream_id;

    do
    {
        stream_id = get_next_stream_id(&data->next_free_stream_id);
    }
    while(stream_id == data->current_stream_id ||
          stream_id == data->next_stream_id);

    gboolean fifo_overflow;
    gboolean is_playing;

    const char *const meta_data = (is_restart
                                   ? data->inbuffer_new_stream.meta_data
                                   : data->inbuffer_next_stream.meta_data);
    const char *const url = (is_restart
                             ? data->inbuffer_new_stream.url
                             : data->inbuffer_next_stream.url);

    char meta_data_buffer[sizeof(data->inbuffer_new_stream.meta_data)];
    const char *artist_and_album[2];

    CoverArt::StreamKey stream_key;
    CoverArt::generate_stream_key_for_app(stream_key, url);

    tokenize_meta_data(meta_data_buffer, meta_data, artist_and_album);

    tdbus_dcpd_playback_emit_stream_info(dbus_get_playback_iface(), stream_id,
                                         artist_and_album[0],
                                         artist_and_album[1],
                                         meta_data_buffer, meta_data, url);
    GError *error = NULL;

    if(!tdbus_splay_urlfifo_call_push_sync(dbus_get_streamplayer_urlfifo_iface(),
                                           stream_id, url,
                                           g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE,
                                                                     stream_key.key_,
                                                                     sizeof(stream_key.key_),
                                                                     sizeof(stream_key.key_[0])),
                                           0, "ms", 0, "ms",
                                           is_restart ? -2 : 0,
                                           &fifo_overflow, &is_playing,
                                           NULL, &error))
    {
        BUG("Failed pushing stream %u, URL %s to stream player",
            stream_id, url);
        dbus_common_handle_dbus_error(&error, "Push stream to player");
        return;
    }

    if(fifo_overflow)
    {
        BUG("Pushed stream with clear request, got FIFO overflow");
        return;
    }

    if(is_app_stream_and_valid(any_stream_data->pending_stream_id) &&
       any_stream_data->pending_stream_id == data->last_pushed_stream_id)
    {
        /* slave sent the next stream very quickly after the first stream,
         * didn't receive any start notification from streamplayer yet */
        any_stream_data->overwritten_pending_stream_id = any_stream_data->pending_stream_id;
        any_stream_data->overwritten_pending_data = any_stream_data->pending_data;
    }

    data->last_pushed_stream_id = stream_id;

    unchecked_set_meta_data_and_url(stream_id, meta_data, url, any_stream_data);

    if(!is_playing &&
       !tdbus_splay_playback_call_start_sync(dbus_get_streamplayer_playback_iface(),
                                             NULL, &error))
    {
        msg_error(0, LOG_NOTICE, "Failed starting stream");
        dbus_common_handle_dbus_error(&error, "Start stream");

        reset_to_idle_mode(data);

        if(!tdbus_splay_urlfifo_call_clear_sync(dbus_get_streamplayer_urlfifo_iface(),
                                                0, NULL, NULL, NULL,
                                                NULL, &error))
        {
            msg_error(0, LOG_NOTICE, "Failed clearing stream player FIFO");
            dbus_common_handle_dbus_error(&error, "Clear URLFIFO");
        }
    }
    else
    {
        if(is_restart)
        {
            if(!is_playing)
                data->device_playmode = DevicePlaymode::WAIT_FOR_START_NOTIFICATION;

            data->current_stream_id = stream_id;
            data->next_stream_id = 0;

            tdbus_dcpd_views_emit_open(dbus_get_views_iface(), "Play");
        }
        else
        {
            log_assert(data->device_playmode == DevicePlaymode::WAIT_FOR_START_NOTIFICATION ||
                       data->device_playmode == DevicePlaymode::SELECTED_IDLE ||
                       data->device_playmode == DevicePlaymode::APP_IS_PLAYING);
            data->next_stream_id = stream_id;
        }
    }
}

static void try_stop_stream(struct PlayAppStreamData *const data,
                            bool stay_in_app_mode)
{
    data->device_playmode = stay_in_app_mode
        ? DevicePlaymode::WAIT_FOR_STOP_NOTIFICATION_KEEP_SELECTED
        : DevicePlaymode::WAIT_FOR_STOP_NOTIFICATION_FOR_DESELECTION;

    GError *error = NULL;

    if(!tdbus_splay_playback_call_stop_sync(dbus_get_streamplayer_playback_iface(),
                                            NULL, &error))
    {
        msg_error(0, LOG_NOTICE, "Failed stopping stream player");
        dbus_common_handle_dbus_error(&error, "Stop stream");
        reset_to_idle_mode(data);
    }
}

static void registered_audio_source(GObject *source_object, GAsyncResult *res,
                                    gpointer user_data)
{
    GError *error = nullptr;
    tdbus_aupath_manager_call_register_source_finish(TDBUS_AUPATH_MANAGER(source_object),
                                                     res, &error);
    dbus_common_handle_dbus_error(&error, "Register audio source");

    dcpregs_audiosources_fetch_audio_paths();
}

static struct
{
    GMutex lock;

    struct PlayAppStreamData app;
    struct PlayAnyStreamData other;
}
play_stream_data;

static const char app_audio_source_id[] = "strbo.plainurl";

void dcpregs_playstream_init(void)
{
    memset(&play_stream_data, 0, sizeof(play_stream_data));
    g_mutex_init(&play_stream_data.lock);
    play_stream_data.app.next_free_stream_id = STREAM_ID_SOURCE_APP | STREAM_ID_COOKIE_MIN;
}

void dcpregs_playstream_late_init(void)
{
    tdbus_aupath_manager_call_register_source(dbus_audiopath_get_manager_iface(),
                                              app_audio_source_id,
                                              "Streams pushed by smartphone app",
                                              "strbo",
                                              "/de/tahifi/Dcpd",
                                              nullptr,
                                              registered_audio_source, &play_stream_data);
}

void dcpregs_playstream_deinit(void)
{
    g_mutex_lock(&play_stream_data.lock);
    play_stream_data.other.tracked_stream_key.clear();
    play_stream_data.other.current_cover_art.clear();
    g_mutex_unlock(&play_stream_data.lock);

    g_mutex_clear(&play_stream_data.lock);
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

int dcpregs_write_73_seek_or_set_speed(const uint8_t *data, size_t length)
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

ssize_t dcpregs_read_75_current_stream_title(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 75 handler %p %zu", response, length);

    g_mutex_lock(&play_stream_data.lock);

    const ssize_t ret =
        copy_string_to_slave(play_stream_data.other.current_stream_information.meta_data,
                             (char *)response, length);

    g_mutex_unlock(&play_stream_data.lock);

    return ret;
}

ssize_t dcpregs_read_76_current_stream_url(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 76 handler %p %zu", response, length);

    g_mutex_lock(&play_stream_data.lock);

    const ssize_t ret =
        copy_string_to_slave(play_stream_data.other.current_stream_information.url,
                             (char *)response, length);

    g_mutex_unlock(&play_stream_data.lock);

    return ret;
}

int dcpregs_write_78_start_play_stream_title(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 78 handler %p %zu", data, length);

    g_mutex_lock(&play_stream_data.lock);

    if(!is_app_mode(play_stream_data.app.device_playmode))
        tdbus_aupath_manager_call_request_source(dbus_audiopath_get_manager_iface(),
                                                 app_audio_source_id,
                                                 NULL, NULL, NULL);

    (void)copy_string_data(play_stream_data.app.inbuffer_new_stream.meta_data,
                           sizeof(play_stream_data.app.inbuffer_new_stream.meta_data),
                           data, length);

    g_mutex_unlock(&play_stream_data.lock);

    return 0;
}

int dcpregs_write_79_start_play_stream_url(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 79 handler %p %zu", data, length);

    g_mutex_lock(&play_stream_data.lock);

    const bool is_in_app_mode = is_app_mode(play_stream_data.app.device_playmode);

    if(is_in_app_mode)
        play_stream_data.app.pending_request = PendingAppRequest::NONE;

    if(copy_string_data(play_stream_data.app.inbuffer_new_stream.url,
                        sizeof(play_stream_data.app.inbuffer_new_stream.url),
                        data, length))
    {
        /* maybe start playing */
        if(play_stream_data.app.inbuffer_new_stream.meta_data[0] != '\0')
        {
            if(is_in_app_mode)
                try_start_stream(&play_stream_data.app, &play_stream_data.other,
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
        try_stop_stream(&play_stream_data.app, true);
    }
    else
        play_stream_data.app.pending_request = PendingAppRequest::STOP_KEEP_SELECTED;

    switch(play_stream_data.app.pending_request)
    {
      case PendingAppRequest::START:
        break;

      case PendingAppRequest::NONE:
      case PendingAppRequest::STOP_KEEP_SELECTED:
      case PendingAppRequest::STOP_FOR_DESELECTION:
        clear_stream_info(&play_stream_data.app.inbuffer_new_stream);
        break;
    }

    g_mutex_unlock(&play_stream_data.lock);

    return 0;
}

ssize_t dcpregs_read_79_start_play_stream_url(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 79 handler %p %zu", response, length);
    return 0;
}

ssize_t dcpregs_read_210_current_cover_art_hash(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 210 handler %p %zu", response, length);

    g_mutex_lock(&play_stream_data.lock);

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

    g_mutex_unlock(&play_stream_data.lock);

    return len;
}

int dcpregs_write_238_next_stream_title(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 238 handler %p %zu", data, length);

    g_mutex_lock(&play_stream_data.lock);

    if(!is_app_mode(play_stream_data.app.device_playmode))
        BUG("App sets next stream title while not in app mode");
    else
        (void)copy_string_data(play_stream_data.app.inbuffer_next_stream.meta_data,
                               sizeof(play_stream_data.app.inbuffer_next_stream.meta_data),
                               data, length);

    g_mutex_unlock(&play_stream_data.lock);

    return 0;
}

int dcpregs_write_239_next_stream_url(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 239 handler %p %zu", data, length);

    g_mutex_lock(&play_stream_data.lock);

    if(!is_app_mode(play_stream_data.app.device_playmode))
        BUG("App sets next URL while not in app mode");
    else
    {
        if(copy_string_data(play_stream_data.app.inbuffer_next_stream.url,
                            sizeof(play_stream_data.app.inbuffer_next_stream.url),
                            data, length))
        {
            /* maybe send to streamplayer queue */
            if(play_stream_data.app.inbuffer_next_stream.meta_data[0] != '\0')
                try_start_stream(&play_stream_data.app, &play_stream_data.other,
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

        clear_stream_info(&play_stream_data.app.inbuffer_next_stream);
    }

    g_mutex_unlock(&play_stream_data.lock);

    return 0;
}

ssize_t dcpregs_read_239_next_stream_url(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 239 handler %p %zu", response, length);
    return 0;
}

void dcpregs_playstream_select_source(void)
{
    g_mutex_lock(&play_stream_data.lock);

    if(is_app_mode(play_stream_data.app.device_playmode))
        BUG("Already selected");
    else
    {
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
                try_start_stream(&play_stream_data.app, &play_stream_data.other,
                                 true);
                clear_stream_info(&play_stream_data.app.inbuffer_new_stream);
            }
            else
                BUG("No data available for pending start request");

            break;

          case PendingAppRequest::STOP_KEEP_SELECTED:
            msg_info("Processing pending stop request");
            try_stop_stream(&play_stream_data.app, true);
            break;

          case PendingAppRequest::STOP_FOR_DESELECTION:
            msg_info("Processing pending stop request and leaving app mode");
            try_stop_stream(&play_stream_data.app, false);
            break;
        }

        play_stream_data.app.pending_request = PendingAppRequest::NONE;
    }

    g_mutex_unlock(&play_stream_data.lock);
}

void dcpregs_playstream_deselect_source(void)
{
    g_mutex_lock(&play_stream_data.lock);

    if(!is_app_mode(play_stream_data.app.device_playmode))
        BUG("Not selected");
    else
    {
        msg_info("Leave app mode");

        switch(play_stream_data.app.device_playmode)
        {
          case DevicePlaymode::SELECTED_IDLE:
            play_stream_data.app.device_playmode = DevicePlaymode::DESELECTED;
            break;

          case DevicePlaymode::WAIT_FOR_START_NOTIFICATION:
          case DevicePlaymode::APP_IS_PLAYING:
            try_stop_stream(&play_stream_data.app, false);
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

    g_mutex_unlock(&play_stream_data.lock);
}

void dcpregs_playstream_set_title_and_url(stream_id_t raw_stream_id,
                                          const char *title, const char *url)
{
    msg_vinfo(MESSAGE_LEVEL_DIAG,
              "Received explicit title and URL information for stream %u",
              raw_stream_id);

    g_mutex_lock(&play_stream_data.lock);

    log_assert((raw_stream_id & STREAM_ID_SOURCE_MASK) != STREAM_ID_SOURCE_INVALID);
    log_assert(title != NULL);
    log_assert(url != NULL);

    if(!is_app_stream(raw_stream_id))
        unchecked_set_meta_data_and_url(raw_stream_id, title, url,
                                        &play_stream_data.other);
    else
    {
        BUG("Got title and URL information for app stream ID %u",
            raw_stream_id);
        BUG("+   Title: \"%s\"", title);
        BUG("+   URL  : \"%s\"", url);
    }

    g_mutex_unlock(&play_stream_data.lock);
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
        NULL, &error);

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
    registers_get_data()->register_changed_notification_fn(210);
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
 * The mechanisms in here (and in #dcpregs_playstream_stop_notification())
 * operate orthogonal to and completely independent of audio path selection,
 * AND OF COURSE THIS IS A PROBLEM. It currently works, but an adaption to make
 * use of audio source information is required to make this code simpler and
 * also more stable against possible misdetections of app/no-app modes.
 */
void dcpregs_playstream_start_notification(stream_id_t raw_stream_id,
                                           void *stream_key_variant)
{
    g_mutex_lock(&play_stream_data.lock);

    play_stream_data.other.tracked_stream_key.set(
            std::move(GVariantWrapper(static_cast<GVariant *>(stream_key_variant),
                                      GVariantWrapper::Transfer::JUST_MOVE)));

    const StreamIdType stream_id_type =
        determine_stream_id_type(raw_stream_id, &play_stream_data.app);

    const bool is_new_stream =
        play_stream_data.other.currently_playing_stream != raw_stream_id;

    play_stream_data.other.currently_playing_stream = raw_stream_id;

    bool switched_to_nonapp_mode = false;

    switch(stream_id_type)
    {
      case StreamIdType::INVALID:
        BUG("Got start notification for invalid stream ID %u", raw_stream_id);
        break;

      case StreamIdType::APP_UNKNOWN:
        if(is_app_mode_and_playing(play_stream_data.app.device_playmode))
            msg_error(0, LOG_NOTICE,
                      "Got start notification for unknown app stream ID %u",
                      raw_stream_id);
        else
            other_stream_started_playing(&play_stream_data.app,
                                         &switched_to_nonapp_mode);

        break;

      case StreamIdType::APP_CURRENT:
      case StreamIdType::APP_NEXT:
        switch(play_stream_data.app.device_playmode)
        {
          case DevicePlaymode::DESELECTED:
          case DevicePlaymode::DESELECTED_PLAYING:
            BUG("App stream %u started, but audio source not selected",
                raw_stream_id);

            other_stream_started_playing(&play_stream_data.app,
                                         &switched_to_nonapp_mode);
            break;

          case DevicePlaymode::SELECTED_IDLE:
          case DevicePlaymode::WAIT_FOR_START_NOTIFICATION:
          case DevicePlaymode::WAIT_FOR_STOP_NOTIFICATION_KEEP_SELECTED:
          case DevicePlaymode::APP_IS_PLAYING:
            msg_info("%s app stream %u",
                     is_new_stream ? "Next" : "Continue with", raw_stream_id);
            app_stream_started_playing(&play_stream_data.app, stream_id_type, is_new_stream);
            break;

          case DevicePlaymode::WAIT_FOR_STOP_NOTIFICATION_FOR_DESELECTION:
            msg_error(0, LOG_NOTICE,
                      "Unexpected start of app stream %u", raw_stream_id);

            other_stream_started_playing(&play_stream_data.app,
                                         &switched_to_nonapp_mode);
            break;
        }

        break;

      case StreamIdType::NON_APP:
        if(is_app_mode(play_stream_data.app.device_playmode))
            BUG("Leave app mode: unexpected start of non-app stream %u "
                "(expected next %u or new %u)",
                raw_stream_id,
                play_stream_data.app.next_stream_id,
                play_stream_data.app.current_stream_id);

        other_stream_started_playing(&play_stream_data.app,
                                     &switched_to_nonapp_mode);

        if(switched_to_nonapp_mode)
            notify_app_playback_stopped();

        break;
    }

    try_notify_pending_stream_info(&play_stream_data.other,
                                   switched_to_nonapp_mode);

    GVariant *val = play_stream_data.other.tracked_stream_key.is_tracking()
        ? GVariantWrapper::get(play_stream_data.other.tracked_stream_key.get_variant())
        : nullptr;

    if(try_retrieve_cover_art(val, play_stream_data.other.current_cover_art) ||
       is_new_stream)
        notify_cover_art_changed();

    g_mutex_unlock(&play_stream_data.lock);
}

void dcpregs_playstream_stop_notification(void)
{
    g_mutex_lock(&play_stream_data.lock);

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

    play_stream_data.app.last_pushed_stream_id =
        STREAM_ID_SOURCE_INVALID | STREAM_ID_COOKIE_INVALID;

    play_stream_data.other.currently_playing_stream =
        STREAM_ID_SOURCE_INVALID | STREAM_ID_COOKIE_INVALID;

    do_notify_stream_info(&play_stream_data.other, NotifyStreamInfo::DEV_NULL,
                          SendStreamUpdate::URL_AND_TITLE);

    g_mutex_unlock(&play_stream_data.lock);
}

void dcpregs_playstream_cover_art_notification(void *stream_key_variant)
{
    g_mutex_lock(&play_stream_data.lock);

    const GVariantWrapper wrapped_val(static_cast<GVariant *>(stream_key_variant),
                                      GVariantWrapper::Transfer::JUST_MOVE);

    const bool has_cover_art_changed =
        play_stream_data.other.tracked_stream_key.is_tracking(wrapped_val)
        ? try_retrieve_cover_art(GVariantWrapper::get(wrapped_val),
                                 play_stream_data.other.current_cover_art)
        : false;

    if(has_cover_art_changed)
        notify_cover_art_changed();

    g_mutex_unlock(&play_stream_data.lock);
}

class PictureProvider: public CoverArt::PictureProviderIface
{
  private:
    GMutex &lock_;
    const CoverArt::Picture &picture_;

  public:
    PictureProvider(const PictureProvider &) = delete;
    PictureProvider &operator=(const PictureProvider &) = delete;

    explicit PictureProvider(GMutex &lock, const CoverArt::Picture &picture):
        lock_(lock),
        picture_(picture)
    {}

    bool copy_picture(CoverArt::Picture &dest) const override
    {
        g_mutex_lock(&lock_);
        dest = picture_;
        g_mutex_unlock(&lock_);

        return dest.is_available();
    }
};

static PictureProvider picture_provider(play_stream_data.lock,
                                        play_stream_data.other.current_cover_art);

const CoverArt::PictureProviderIface &dcpregs_playstream_get_picture_provider()
{
    return picture_provider;
}
