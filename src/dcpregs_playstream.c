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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <string.h>

#include "dcpregs_playstream.h"
#include "registers_priv.h"
#include "streamplayer_dbus.h"
#include "dbus_common.h"
#include "dbus_iface_deep.h"
#include "messages.h"

enum DevicePlaymode
{
    DEVICE_PLAYMODE_IDLE,
    DEVICE_PLAYMODE_WAIT_FOR_START_NOTIFICATION,
    DEVICE_PLAYMODE_WAIT_FOR_STOP_NOTIFICATION,
    DEVICE_PLAYMODE_APP_IS_PLAYING,
    DEVICE_PLAYMODE_OTHER_IS_PLAYING,
};

enum StreamIdType
{
    STREAM_ID_TYPE_INVALID,
    STREAM_ID_TYPE_NON_APP,
    STREAM_ID_TYPE_APP_CURRENT,
    STREAM_ID_TYPE_APP_NEXT,
    STREAM_ID_TYPE_APP_UNKNOWN,
};

enum NotifyStreamInfo
{
    NOTIFY_STREAM_INFO_UNMODIFIED,
    NOTIFY_STREAM_INFO_PENDING,
    NOTIFY_STREAM_INFO_OVERWRITTEN_PENDING,
    NOTIFY_STREAM_INFO_DEV_NULL,
};

struct SimplifiedStreamInfo
{
    char meta_data[256 + 1];
    char url[512 + 1];
};

struct PlayAppStreamData
{
    enum DevicePlaymode device_playmode;

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

struct PlayAnyStreamData
{
    /*!
     * The ID that arrived in through start/stop notifications.
     */
    stream_id_t currently_playing_stream;

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

static inline bool is_our_stream(const stream_id_t raw_stream_id)
{
    return (raw_stream_id & STREAM_ID_SOURCE_MASK) == STREAM_ID_SOURCE_APP;
}

static inline bool is_stream_with_valid_source(const stream_id_t raw_stream_id)
{
    return (raw_stream_id & STREAM_ID_SOURCE_MASK) != STREAM_ID_SOURCE_INVALID;
}

static inline bool is_our_stream_and_valid(stream_id_t raw_stream_id)
{
    if(!is_our_stream(raw_stream_id))
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

static inline bool is_app_mode(const enum DevicePlaymode mode)
{
    switch(mode)
    {
      case DEVICE_PLAYMODE_WAIT_FOR_START_NOTIFICATION:
      case DEVICE_PLAYMODE_WAIT_FOR_STOP_NOTIFICATION:
      case DEVICE_PLAYMODE_APP_IS_PLAYING:
        return true;

      case DEVICE_PLAYMODE_IDLE:
      case DEVICE_PLAYMODE_OTHER_IS_PLAYING:
        break;
    }

    return false;
}

static inline bool is_app_mode_and_playing(const enum DevicePlaymode mode)
{
    return is_app_mode(mode) && mode != DEVICE_PLAYMODE_WAIT_FOR_STOP_NOTIFICATION;
}

static enum StreamIdType determine_stream_id_type(const stream_id_t raw_stream_id,
                                                  const struct PlayAppStreamData *data)
{
    const stream_id_t source_id = (raw_stream_id & STREAM_ID_SOURCE_MASK);

    if(source_id == STREAM_ID_SOURCE_INVALID ||
       (raw_stream_id & STREAM_ID_COOKIE_MASK) == STREAM_ID_COOKIE_INVALID)
        return STREAM_ID_TYPE_INVALID;
    else if(source_id != STREAM_ID_SOURCE_APP)
        return STREAM_ID_TYPE_NON_APP;

    if(raw_stream_id == data->current_stream_id)
        return STREAM_ID_TYPE_APP_CURRENT;
    else if(raw_stream_id == data->next_stream_id)
        return STREAM_ID_TYPE_APP_NEXT;
    else
        return STREAM_ID_TYPE_APP_UNKNOWN;
}

static inline void clear_stream_info(struct SimplifiedStreamInfo *info)
{
    info->meta_data[0] = '\0';
    info->url[0] = '\0';
}

static inline void reset_to_idle_mode(struct PlayAppStreamData *data)
{
    data->device_playmode = DEVICE_PLAYMODE_IDLE;
    data->current_stream_id = 0;
    data->next_stream_id = 0;
}

static inline void notify_leave_app_mode(void)
{
    registers_get_data()->register_changed_notification_fn(79);
}

static inline void notify_ready_for_next_stream_from_slave(void)
{
    registers_get_data()->register_changed_notification_fn(239);
}

static void do_notify_stream_info(struct PlayAnyStreamData *data,
                                  const enum NotifyStreamInfo which)
{
    switch(which)
    {
      case NOTIFY_STREAM_INFO_UNMODIFIED:
        break;

      case NOTIFY_STREAM_INFO_PENDING:
        data->current_stream_information = data->pending_data;
        break;

      case NOTIFY_STREAM_INFO_OVERWRITTEN_PENDING:
        data->current_stream_information = data->overwritten_pending_data;
        break;

      case NOTIFY_STREAM_INFO_DEV_NULL:
        clear_stream_info(&data->current_stream_information);
        break;
    }

    if(which == NOTIFY_STREAM_INFO_OVERWRITTEN_PENDING)
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

    registers_get_data()->register_changed_notification_fn(75);
    registers_get_data()->register_changed_notification_fn(76);
}

static void app_stream_started_playing(struct PlayAppStreamData *data,
                                       enum StreamIdType stype,
                                       bool is_new_stream)
{
    log_assert(stype == STREAM_ID_TYPE_APP_CURRENT ||
               stype == STREAM_ID_TYPE_APP_NEXT);

    switch(data->device_playmode)
    {
      case DEVICE_PLAYMODE_IDLE:
      case DEVICE_PLAYMODE_WAIT_FOR_STOP_NOTIFICATION:
        BUG("App stream started in unexpected mode %d", data->device_playmode);
        break;

      case DEVICE_PLAYMODE_WAIT_FOR_START_NOTIFICATION:
      case DEVICE_PLAYMODE_APP_IS_PLAYING:
      case DEVICE_PLAYMODE_OTHER_IS_PLAYING:
        break;
    }

    data->device_playmode = DEVICE_PLAYMODE_APP_IS_PLAYING;

    if(stype == STREAM_ID_TYPE_APP_NEXT)
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
    if(data->device_playmode != DEVICE_PLAYMODE_IDLE &&
       data->device_playmode != DEVICE_PLAYMODE_OTHER_IS_PLAYING)
        *switched_to_nonapp_mode = true;

    data->device_playmode = DEVICE_PLAYMODE_OTHER_IS_PLAYING;
    data->current_stream_id = 0;
    data->next_stream_id = 0;
}

static size_t copy_string_to_slave(const char *const restrict src,
                                   char *const restrict dest, size_t dest_size)
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
    log_assert(is_our_stream_and_valid(*next_free_id));

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

    enum NotifyStreamInfo which;

    if((raw_stream_id & STREAM_ID_COOKIE_MASK) == STREAM_ID_COOKIE_INVALID)
    {
        clear_stream_info(dest_info);
        which = NOTIFY_STREAM_INFO_DEV_NULL;
    }
    else
    {
        strncpy_terminated(dest_info->meta_data, title, sizeof(dest_info->meta_data));
        strncpy_terminated(dest_info->url,   url,   sizeof(dest_info->url));
        which = NOTIFY_STREAM_INFO_UNMODIFIED;
    }

    /* direct update */
    if(!is_stream_with_valid_source(any_stream_data->pending_stream_id))
        do_notify_stream_info(any_stream_data, which);
}

static void try_notify_pending_stream_info(struct PlayAnyStreamData *data,
                                           bool switched_to_nonapp_mode)
{
    if(is_stream_with_valid_source(data->pending_stream_id) &&
       data->currently_playing_stream == data->pending_stream_id)
    {
        do_notify_stream_info(data, NOTIFY_STREAM_INFO_PENDING);
    }
    else if(is_stream_with_valid_source(data->overwritten_pending_stream_id) &&
       data->currently_playing_stream == data->overwritten_pending_stream_id)
    {
        do_notify_stream_info(data, NOTIFY_STREAM_INFO_OVERWRITTEN_PENDING);
    }
    else if(switched_to_nonapp_mode)
    {
        /* In case the mode switched to non-app mode, but the external source
         * has failed to deliver title and URL up to this point, then we need
         * to wipe out the currently stored, outdated information. The external
         * source may send the missing information later in this case. */
        do_notify_stream_info(data, NOTIFY_STREAM_INFO_DEV_NULL);
    }
}

static void tokenize_meta_data(char *dest, const char *src,
                               const char *artist_and_album[static 2])
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

    tokenize_meta_data(meta_data_buffer, meta_data, artist_and_album);

    tdbus_dcpd_playback_emit_stream_info(dbus_get_playback_iface(), stream_id,
                                         artist_and_album[0],
                                         artist_and_album[1],
                                         meta_data_buffer, meta_data, url);
    GError *error = NULL;

    if(!tdbus_splay_urlfifo_call_push_sync(dbus_get_streamplayer_urlfifo_iface(),
                                           stream_id, url,
                                           0, "ms", 0, "ms",
                                           is_restart ? -2 : 0,
                                           &fifo_overflow, &is_playing,
                                           NULL, &error))
    {
        BUG("Failed pushing stream %u, URL %s to stream player",
            stream_id, url);
        dbus_common_handle_dbus_error(&error);
        return;
    }

    if(fifo_overflow)
    {
        BUG("Pushed stream with clear request, got FIFO overflow");
        return;
    }

    if(is_our_stream_and_valid(any_stream_data->pending_stream_id) &&
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
        dbus_common_handle_dbus_error(&error);

        reset_to_idle_mode(data);

        if(!tdbus_splay_urlfifo_call_clear_sync(dbus_get_streamplayer_urlfifo_iface(),
                                                0, NULL, NULL, NULL,
                                                NULL, &error))
        {
            msg_error(0, LOG_NOTICE, "Failed clearing stream player FIFO");
            dbus_common_handle_dbus_error(&error);
        }
    }
    else
    {
        if(is_restart)
        {
            if(!is_playing)
                data->device_playmode = DEVICE_PLAYMODE_WAIT_FOR_START_NOTIFICATION;

            data->current_stream_id = stream_id;
            data->next_stream_id = 0;

            tdbus_dcpd_views_emit_open(dbus_get_views_iface(), "Play");
        }
        else
        {
            log_assert(data->device_playmode == DEVICE_PLAYMODE_WAIT_FOR_START_NOTIFICATION ||
                       data->device_playmode == DEVICE_PLAYMODE_APP_IS_PLAYING);
            data->next_stream_id = stream_id;
        }
    }
}

static struct
{
    GMutex lock;

    struct PlayAppStreamData app;
    struct PlayAnyStreamData other;
}
play_stream_data =
{
    .app =
    {
        .next_free_stream_id = STREAM_ID_SOURCE_APP | STREAM_ID_COOKIE_MIN,
    },
};

void dcpregs_playstream_init(void)
{
    memset(&play_stream_data, 0, sizeof(play_stream_data));
    play_stream_data.app.next_free_stream_id = STREAM_ID_SOURCE_APP | STREAM_ID_COOKIE_MIN;
}

void dcpregs_playstream_deinit(void)
{
    g_mutex_clear(&play_stream_data.lock);
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

    if(copy_string_data(play_stream_data.app.inbuffer_new_stream.url,
                        sizeof(play_stream_data.app.inbuffer_new_stream.url),
                        data, length))
    {
        /* maybe start playing */
        if(play_stream_data.app.inbuffer_new_stream.meta_data[0] != '\0')
            try_start_stream(&play_stream_data.app, &play_stream_data.other,
                             true);
        else
            msg_error(0, LOG_ERR, "Not starting stream, register 78 still unset");
    }
    else if(is_app_mode(play_stream_data.app.device_playmode))
    {
        /* stop command */
        play_stream_data.app.device_playmode = DEVICE_PLAYMODE_WAIT_FOR_STOP_NOTIFICATION;

        GError *error = NULL;

        if(!tdbus_splay_playback_call_stop_sync(dbus_get_streamplayer_playback_iface(),
                                                NULL, &error))
        {
            msg_error(0, LOG_NOTICE, "Failed stopping stream player");
            dbus_common_handle_dbus_error(&error);
            reset_to_idle_mode(&play_stream_data.app);
        }
    }

    clear_stream_info(&play_stream_data.app.inbuffer_new_stream);

    g_mutex_unlock(&play_stream_data.lock);

    return 0;
}

ssize_t dcpregs_read_79_start_play_stream_url(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 79 handler %p %zu", response, length);
    return 0;
}

int dcpregs_write_238_next_stream_title(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 238 handler %p %zu", data, length);

    g_mutex_lock(&play_stream_data.lock);

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

    if(copy_string_data(play_stream_data.app.inbuffer_next_stream.url,
                        sizeof(play_stream_data.app.inbuffer_next_stream.url),
                        data, length))
    {
        switch(play_stream_data.app.device_playmode)
        {
          case DEVICE_PLAYMODE_IDLE:
          case DEVICE_PLAYMODE_WAIT_FOR_STOP_NOTIFICATION:
          case DEVICE_PLAYMODE_OTHER_IS_PLAYING:
            msg_error(0, LOG_ERR,
                      "Can't queue next stream, didn't receive a start stream");
            break;

          case DEVICE_PLAYMODE_WAIT_FOR_START_NOTIFICATION:
          case DEVICE_PLAYMODE_APP_IS_PLAYING:
            /* maybe send to streamplayer queue */
            if(play_stream_data.app.inbuffer_next_stream.meta_data[0] != '\0')
                try_start_stream(&play_stream_data.app, &play_stream_data.other,
                                 false);
            else
                msg_error(0, LOG_ERR,
                          "Not starting stream, register 238 still unset");

            break;
        }
    }
    else
    {
        /* ignore funny writes */
    }

    clear_stream_info(&play_stream_data.app.inbuffer_next_stream);

    g_mutex_unlock(&play_stream_data.lock);

    return 0;
}

ssize_t dcpregs_read_239_next_stream_url(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 239 handler %p %zu", response, length);
    return 0;
}

void dcpregs_playstream_set_title_and_url(stream_id_t raw_stream_id,
                                          const char *title, const char *url)
{
    g_mutex_lock(&play_stream_data.lock);

    log_assert((raw_stream_id & STREAM_ID_SOURCE_MASK) != STREAM_ID_SOURCE_INVALID);
    log_assert(title != NULL);
    log_assert(url != NULL);

    if(!is_our_stream(raw_stream_id))
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

void dcpregs_playstream_start_notification(stream_id_t raw_stream_id)
{
    g_mutex_lock(&play_stream_data.lock);

    const enum StreamIdType stream_id_type =
        determine_stream_id_type(raw_stream_id, &play_stream_data.app);

    const bool is_new_stream =
        play_stream_data.other.currently_playing_stream != raw_stream_id;

    play_stream_data.other.currently_playing_stream = raw_stream_id;

    bool switched_to_nonapp_mode = false;

    switch(stream_id_type)
    {
      case STREAM_ID_TYPE_INVALID:
        BUG("Got start notification for invalid stream ID %u", raw_stream_id);
        break;

      case STREAM_ID_TYPE_APP_UNKNOWN:
        if(is_app_mode_and_playing(play_stream_data.app.device_playmode))
            msg_error(0, LOG_NOTICE,
                      "Got start notification for unknown app stream ID %u",
                      raw_stream_id);
        else
            other_stream_started_playing(&play_stream_data.app,
                                         &switched_to_nonapp_mode);

        break;

      case STREAM_ID_TYPE_APP_CURRENT:
      case STREAM_ID_TYPE_APP_NEXT:
        switch(play_stream_data.app.device_playmode)
        {
          case DEVICE_PLAYMODE_WAIT_FOR_START_NOTIFICATION:
            msg_info("Enter app mode: started stream %u", raw_stream_id);
            app_stream_started_playing(&play_stream_data.app, stream_id_type, is_new_stream);
            break;

          case DEVICE_PLAYMODE_OTHER_IS_PLAYING:
            msg_info("Switch to app mode: continue with stream %u",
                     raw_stream_id);
            app_stream_started_playing(&play_stream_data.app, stream_id_type, is_new_stream);
            break;

          case DEVICE_PLAYMODE_APP_IS_PLAYING:
            msg_info("%s app stream %u",
                     is_new_stream ? "Next" : "Continue with", raw_stream_id);
            app_stream_started_playing(&play_stream_data.app, stream_id_type, is_new_stream);
            break;

          case DEVICE_PLAYMODE_IDLE:
          case DEVICE_PLAYMODE_WAIT_FOR_STOP_NOTIFICATION:
            msg_error(0, LOG_NOTICE,
                      "Unexpected start of app stream %u", raw_stream_id);

            other_stream_started_playing(&play_stream_data.app,
                                         &switched_to_nonapp_mode);
            break;
        }

        break;

      case STREAM_ID_TYPE_NON_APP:
        if(is_app_mode(play_stream_data.app.device_playmode))
        {
            msg_error(0, LOG_NOTICE,
                      "Leave app mode: unexpected start of non-app stream %u "
                      "(expected next %u or new %u)",
                      raw_stream_id,
                      play_stream_data.app.next_stream_id,
                      play_stream_data.app.current_stream_id);
            notify_leave_app_mode();
        }

        other_stream_started_playing(&play_stream_data.app,
                                     &switched_to_nonapp_mode);

        break;
    }

    try_notify_pending_stream_info(&play_stream_data.other,
                                   switched_to_nonapp_mode);

    g_mutex_unlock(&play_stream_data.lock);
}

void dcpregs_playstream_stop_notification(void)
{
    g_mutex_lock(&play_stream_data.lock);

    if(is_app_mode(play_stream_data.app.device_playmode))
    {
        msg_info("Leave app mode: streamplayer has stopped");
        notify_leave_app_mode();
    }

    play_stream_data.app.device_playmode = DEVICE_PLAYMODE_IDLE;
    play_stream_data.app.last_pushed_stream_id =
        STREAM_ID_SOURCE_INVALID | STREAM_ID_COOKIE_INVALID;

    play_stream_data.other.currently_playing_stream =
        STREAM_ID_SOURCE_INVALID | STREAM_ID_COOKIE_INVALID;

    do_notify_stream_info(&play_stream_data.other, NOTIFY_STREAM_INFO_DEV_NULL);

    g_mutex_unlock(&play_stream_data.lock);
}
