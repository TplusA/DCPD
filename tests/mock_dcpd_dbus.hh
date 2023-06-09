/*
 * Copyright (C) 2015, 2016, 2017, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef MOCK_DCPD_DBUS_HH
#define MOCK_DCPD_DBUS_HH

#include "de_tahifi_dcpd.h"
#include "mock_expectation.hh"

class MockDcpdDBus
{
  public:
    MockDcpdDBus(const MockDcpdDBus &) = delete;
    MockDcpdDBus &operator=(const MockDcpdDBus &) = delete;

    class Expectation;
    typedef MockExpectationsTemplate<Expectation> MockExpectations;
    MockExpectations *expectations_;

    bool ignore_all_;

    explicit MockDcpdDBus();
    ~MockDcpdDBus();

    void init();
    void check() const;

    void expect_tdbus_dcpd_playback_emit_start(tdbusdcpdPlayback *object);
    void expect_tdbus_dcpd_playback_emit_stop(tdbusdcpdPlayback *object);
    void expect_tdbus_dcpd_playback_emit_pause(tdbusdcpdPlayback *object);
    void expect_tdbus_dcpd_playback_emit_next(tdbusdcpdPlayback *object);
    void expect_tdbus_dcpd_playback_emit_previous(tdbusdcpdPlayback *object);
    void expect_tdbus_dcpd_playback_emit_resume(tdbusdcpdPlayback *object);
    void expect_tdbus_dcpd_playback_emit_set_speed(tdbusdcpdPlayback *object, gdouble arg_speed);
    void expect_tdbus_dcpd_playback_emit_seek(tdbusdcpdPlayback *object, gint64 arg_position, const gchar *arg_position_units);
    void expect_tdbus_dcpd_playback_emit_repeat_mode_toggle(tdbusdcpdPlayback *object);
    void expect_tdbus_dcpd_playback_emit_shuffle_mode_toggle(tdbusdcpdPlayback *object);
    void expect_tdbus_dcpd_playback_emit_stream_info(tdbusdcpdPlayback *object, guint16 arg_stream_id, const gchar *arg_artist, const gchar *arg_album, const gchar *arg_title, const gchar *arg_alttrack, const gchar *arg_url);
    void expect_tdbus_dcpd_playback_call_set_stream_info(gboolean ret, tdbusdcpdPlayback *proxy, guint16 arg_stream_id, const gchar *arg_title, const gchar *arg_url);
    void expect_tdbus_dcpd_views_emit_open(tdbusdcpdViews *object, const gchar *arg_view_name);
    void expect_tdbus_dcpd_views_emit_toggle(tdbusdcpdViews *object, const gchar *arg_view_name_back, const gchar *arg_view_name_forth);
    void expect_tdbus_dcpd_views_emit_search_parameters(tdbusdcpdViews *object, const gchar *arg_context, const char **key_value_table);
    void expect_tdbus_dcpd_list_navigation_emit_level_up(tdbusdcpdListNavigation *object);
    void expect_tdbus_dcpd_list_navigation_emit_level_down(tdbusdcpdListNavigation *object);
    void expect_tdbus_dcpd_list_navigation_emit_move_lines(tdbusdcpdListNavigation *object, gint arg_count);
    void expect_tdbus_dcpd_list_navigation_emit_move_pages(tdbusdcpdListNavigation *object, gint arg_count);
    void expect_tdbus_dcpd_list_item_emit_add_to_list(tdbusdcpdListItem *object, const gchar *arg_category, guint16 arg_index);
    void expect_tdbus_dcpd_list_item_emit_remove_from_list(tdbusdcpdListItem *object, const gchar *arg_category, guint16 arg_index);
};

extern MockDcpdDBus *mock_dcpd_dbus_singleton;

#endif /* !MOCK_DCPD_DBUS_HH */
