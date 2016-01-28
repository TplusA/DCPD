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

struct SimplifiedStreamInfo
{
    char title[129];
    char url[513];
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
     * Write buffer for registers 78 and 79.
     */
    struct SimplifiedStreamInfo inbuffer_new_stream;

    /*!
     * Write buffer for registers 238 and 239, next queued app stream.
     */
    struct SimplifiedStreamInfo inbuffer_next_stream;
};

static inline bool is_our_stream(const stream_id_t raw_stream_id)
{
    return (raw_stream_id & STREAM_ID_SOURCE_MASK) == STREAM_ID_SOURCE_APP;
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
    info->title[0] = '\0';
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

static void app_stream_started_playing(struct PlayAppStreamData *data,
                                       enum StreamIdType stype)
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

    notify_ready_for_next_stream_from_slave();
}

static inline void other_stream_started_playing(struct PlayAppStreamData *data)
{
    data->device_playmode = DEVICE_PLAYMODE_OTHER_IS_PLAYING;
    data->current_stream_id = 0;
    data->next_stream_id = 0;
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

static stream_id_t get_next_stream_id(stream_id_t *const next_free_id)
{
    log_assert((*next_free_id & STREAM_ID_SOURCE_MASK) == STREAM_ID_SOURCE_APP);
    log_assert((*next_free_id & STREAM_ID_COOKIE_MASK) >= STREAM_ID_COOKIE_MIN);
    log_assert((*next_free_id & STREAM_ID_COOKIE_MASK) <= STREAM_ID_COOKIE_MAX);

    const stream_id_t ret = *next_free_id;

    stream_id_t cookie = ret & STREAM_ID_COOKIE_MASK;

    if(++cookie > STREAM_ID_COOKIE_MAX)
        cookie = STREAM_ID_COOKIE_MIN;

    *next_free_id = STREAM_ID_SOURCE_APP | cookie;

    return ret;
}

static void try_start_stream(struct PlayAppStreamData *const data,
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

    const char *const url = (is_restart
                             ? data->inbuffer_new_stream.url
                             : data->inbuffer_next_stream.url);

    if(!tdbus_splay_urlfifo_call_push_sync(dbus_get_streamplayer_urlfifo_iface(),
                                           stream_id, url,
                                           0, "ms", 0, "ms",
                                           is_restart ? -2 : 0,
                                           &fifo_overflow, &is_playing,
                                           NULL, NULL))
        return;

    if(fifo_overflow)
    {
        BUG("Pushed stream with clear request, got FIFO overflow");
        return;
    }

    if(!is_playing &&
       !tdbus_splay_playback_call_start_sync(dbus_get_streamplayer_playback_iface(),
                                             NULL, NULL))
    {
        reset_to_idle_mode(data);
        tdbus_splay_urlfifo_call_clear_sync(dbus_get_streamplayer_urlfifo_iface(),
                                            0, NULL, NULL, NULL,
                                            NULL, NULL);
    }
    else
    {
        if(is_restart)
        {
            if(!is_playing)
                data->device_playmode = DEVICE_PLAYMODE_WAIT_FOR_START_NOTIFICATION;

            data->current_stream_id = stream_id;
            data->next_stream_id = 0;
        }
        else
        {
            log_assert(data->device_playmode == DEVICE_PLAYMODE_WAIT_FOR_START_NOTIFICATION ||
                       data->device_playmode == DEVICE_PLAYMODE_APP_IS_PLAYING);
            data->next_stream_id = stream_id;
        }
    }
}

static struct PlayAppStreamData play_app_stream_data =
{
    .next_free_stream_id = STREAM_ID_SOURCE_APP | STREAM_ID_COOKIE_MIN,
};

void dcpregs_playstream_init(void)
{
    memset(&play_app_stream_data, 0, sizeof(play_app_stream_data));
    play_app_stream_data.next_free_stream_id = STREAM_ID_SOURCE_APP | STREAM_ID_COOKIE_MIN;
}

void dcpregs_playstream_deinit(void) {}

int dcpregs_write_78_start_play_stream_title(const uint8_t *data, size_t length)
{
    msg_info("write 78 handler %p %zu", data, length);

    (void)copy_string_data(play_app_stream_data.inbuffer_new_stream.title,
                           sizeof(play_app_stream_data.inbuffer_new_stream.title),
                           data, length);

    return 0;
}

int dcpregs_write_79_start_play_stream_url(const uint8_t *data, size_t length)
{
    msg_info("write 79 handler %p %zu", data, length);

    if(copy_string_data(play_app_stream_data.inbuffer_new_stream.url,
                        sizeof(play_app_stream_data.inbuffer_new_stream.url),
                        data, length))
    {
        /* maybe start playing */
        if(play_app_stream_data.inbuffer_new_stream.title[0] != '\0')
            try_start_stream(&play_app_stream_data, true);
        else
            msg_error(0, LOG_ERR, "Not starting stream, register 78 still unset");
    }
    else if(is_app_mode(play_app_stream_data.device_playmode))
    {
        /* stop command */
        play_app_stream_data.device_playmode = DEVICE_PLAYMODE_WAIT_FOR_STOP_NOTIFICATION;

        if(!tdbus_splay_playback_call_stop_sync(dbus_get_streamplayer_playback_iface(),
                                                NULL, NULL))
            reset_to_idle_mode(&play_app_stream_data);
    }

    clear_stream_info(&play_app_stream_data.inbuffer_new_stream);

    return 0;
}

ssize_t dcpregs_read_79_start_play_stream_url(uint8_t *response, size_t length)
{
    msg_info("read 79 handler %p %zu", response, length);
    return 0;
}

int dcpregs_write_238_next_stream_title(const uint8_t *data, size_t length)
{
    msg_info("write 238 handler %p %zu", data, length);

    (void)copy_string_data(play_app_stream_data.inbuffer_next_stream.title,
                           sizeof(play_app_stream_data.inbuffer_next_stream.title),
                           data, length);

    return 0;
}

int dcpregs_write_239_next_stream_url(const uint8_t *data, size_t length)
{
    msg_info("write 239 handler %p %zu", data, length);

    if(copy_string_data(play_app_stream_data.inbuffer_next_stream.url,
                        sizeof(play_app_stream_data.inbuffer_next_stream.url),
                        data, length))
    {
        switch(play_app_stream_data.device_playmode)
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
            if(play_app_stream_data.inbuffer_next_stream.title[0] != '\0')
                try_start_stream(&play_app_stream_data, false);
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

    clear_stream_info(&play_app_stream_data.inbuffer_next_stream);

    return 0;
}

ssize_t dcpregs_read_239_next_stream_url(uint8_t *response, size_t length)
{
    msg_info("read 239 handler %p %zu", response, length);
    return -1;
}

void dcpregs_playstream_start_notification(stream_id_t raw_stream_id)
{
    const enum StreamIdType stream_id_type =
        determine_stream_id_type(raw_stream_id, &play_app_stream_data);

    switch(stream_id_type)
    {
      case STREAM_ID_TYPE_INVALID:
        BUG("Got start notification for invalid stream ID %u", raw_stream_id);
        break;

      case STREAM_ID_TYPE_APP_UNKNOWN:
        if(is_app_mode_and_playing(play_app_stream_data.device_playmode))
            msg_error(0, LOG_NOTICE,
                      "Got start notification for unknown app stream ID %u",
                      raw_stream_id);
        else
            other_stream_started_playing(&play_app_stream_data);

        break;

      case STREAM_ID_TYPE_APP_CURRENT:
      case STREAM_ID_TYPE_APP_NEXT:
        switch(play_app_stream_data.device_playmode)
        {
          case DEVICE_PLAYMODE_WAIT_FOR_START_NOTIFICATION:
            msg_info("Enter app mode: started stream %u", raw_stream_id);
            app_stream_started_playing(&play_app_stream_data, stream_id_type);
            break;

          case DEVICE_PLAYMODE_OTHER_IS_PLAYING:
            msg_info("Switch to app mode: continue with stream %u",
                     raw_stream_id);
            app_stream_started_playing(&play_app_stream_data, stream_id_type);
            break;

          case DEVICE_PLAYMODE_APP_IS_PLAYING:
            msg_info("Next app stream %u", raw_stream_id);
            app_stream_started_playing(&play_app_stream_data, stream_id_type);
            break;

          case DEVICE_PLAYMODE_IDLE:
          case DEVICE_PLAYMODE_WAIT_FOR_STOP_NOTIFICATION:
            msg_error(0, LOG_NOTICE,
                      "Unexpected start of app stream %u", raw_stream_id);

            other_stream_started_playing(&play_app_stream_data);
            break;
        }

        break;

      case STREAM_ID_TYPE_NON_APP:
        if(is_app_mode(play_app_stream_data.device_playmode))
        {
            msg_error(0, LOG_NOTICE,
                      "Leave app mode: unexpected start of non-app stream %u "
                      "(expected next %u or new %u)",
                      raw_stream_id,
                      play_app_stream_data.next_stream_id,
                      play_app_stream_data.current_stream_id);
            notify_leave_app_mode();
        }

        other_stream_started_playing(&play_app_stream_data);

        break;
    }
}

void dcpregs_playstream_stop_notification(void)
{
    if(is_app_mode(play_app_stream_data.device_playmode))
    {
        msg_info("Leave app mode: streamplayer has stopped");
        notify_leave_app_mode();
    }

    play_app_stream_data.device_playmode = DEVICE_PLAYMODE_IDLE;
}
