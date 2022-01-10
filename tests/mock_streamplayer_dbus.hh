/*
 * Copyright (C) 2016--2019, 2021, 2022  T+A elektroakustik GmbH & Co. KG
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

#ifndef MOCK_STREAMPLAYER_DBUS_HH
#define MOCK_STREAMPLAYER_DBUS_HH

#include "de_tahifi_streamplayer.h"
#include "md5.hh"
#include "mock_expectation.hh"

class MockStreamplayerDBus
{
  public:
    MockStreamplayerDBus(const MockStreamplayerDBus &) = delete;
    MockStreamplayerDBus &operator=(const MockStreamplayerDBus &) = delete;

    class Expectation;
    typedef MockExpectationsTemplate<Expectation> MockExpectations;
    MockExpectations *expectations_;

    explicit MockStreamplayerDBus();
    ~MockStreamplayerDBus();

    void init();
    void check() const;

    void expect_tdbus_splay_urlfifo_call_clear_sync(gboolean retval, tdbussplayURLFIFO *object, gint16 arg_keep_first_n_entries, guint expected_out_playing_id = UINT32_MAX, const uint16_t *expected_out_queued_ids = nullptr, size_t expected_out_queued_ids_size = 0, const uint16_t *expected_out_removed_ids = nullptr, size_t expected_out_removed_ids_size = 0);
    void expect_tdbus_splay_urlfifo_call_next_sync(gboolean retval, tdbussplayURLFIFO *object);
    void expect_tdbus_splay_urlfifo_call_push_sync(gboolean retval, tdbussplayURLFIFO *object, guint16 arg_stream_id, const gchar *arg_stream_url, const MD5::Hash &arg_stream_key, gint64 arg_start_position, const gchar *arg_start_units, gint64 arg_stop_position, const gchar *arg_stop_units, gint16 arg_keep_first_n_entries, GVariant *arg_meta_data, gboolean expected_out_fifo_overflow, gboolean expected_out_is_playing);

    void expect_tdbus_splay_playback_call_start_sync(gboolean retval, tdbussplayPlayback *object, const gchar *arg_reason);
    void expect_tdbus_splay_playback_call_stop_sync(gboolean retval, tdbussplayPlayback *object, const gchar *arg_reason);
    void expect_tdbus_splay_playback_call_pause_sync(gboolean retval, tdbussplayPlayback *object, const gchar *arg_reason);
    void expect_tdbus_splay_playback_call_seek_sync(gboolean retval, tdbussplayPlayback *object, gint64 arg_position, const gchar *arg_position_units);
};

extern MockStreamplayerDBus *mock_streamplayer_dbus_singleton;

#endif /* !MOCK_STREAMPLAYER_DBUS_HH */
