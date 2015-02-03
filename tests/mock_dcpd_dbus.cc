/*
 * Copyright (C) 2015  T+A elektroakustik GmbH & Co. KG
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

#include <cppcutter.h>

#include "mock_dcpd_dbus.hh"

enum class DBusFn
{
    playback_emit_start,
    playback_emit_stop,
    playback_emit_pause,
    playback_emit_next,
    playback_emit_previous,
    playback_emit_fast_forward,
    playback_emit_fast_rewind,
    playback_emit_fast_wind_stop,
    playback_emit_fast_wind_set_factor,
    playback_emit_repeat_mode_toggle,
    playback_emit_shuffle_mode_toggle,
    views_emit_open,
    views_emit_toggle,
    list_navigation_emit_level_up,
    list_navigation_emit_level_down,
    list_navigation_emit_move_lines,
    list_navigation_emit_move_pages,
    list_item_emit_add_to_list,
    list_item_emit_remove_from_list,

    first_valid_dbus_fn_id = playback_emit_start,
    last_valid_dbus_fn_id = list_item_emit_remove_from_list,
};

static std::ostream &operator<<(std::ostream &os, const DBusFn id)
{
    if(id < DBusFn::first_valid_dbus_fn_id ||
       id > DBusFn::last_valid_dbus_fn_id)
    {
        os << "INVALID";
        return os;
    }

    switch(id)
    {
      case DBusFn::playback_emit_start:
        os << "playback_emit_start";
        break;

      case DBusFn::playback_emit_stop:
        os << "playback_emit_stop";
        break;

      case DBusFn::playback_emit_pause:
        os << "playback_emit_pause";
        break;

      case DBusFn::playback_emit_next:
        os << "playback_emit_next";
        break;

      case DBusFn::playback_emit_previous:
        os << "playback_emit_previous";
        break;

      case DBusFn::playback_emit_fast_forward:
        os << "playback_emit_fast_forward";
        break;

      case DBusFn::playback_emit_fast_rewind:
        os << "playback_emit_fast_rewind";
        break;

      case DBusFn::playback_emit_fast_wind_stop:
        os << "playback_emit_fast_wind_stop";
        break;

      case DBusFn::playback_emit_fast_wind_set_factor:
        os << "playback_emit_fast_wind_set_factor";
        break;

      case DBusFn::playback_emit_repeat_mode_toggle:
        os << "playback_emit_repeat_mode_toggle";
        break;

      case DBusFn::playback_emit_shuffle_mode_toggle:
        os << "playback_emit_shuffle_mode_toggle";
        break;

      case DBusFn::views_emit_open:
        os << "views_emit_open";
        break;

      case DBusFn::views_emit_toggle:
        os << "views_emit_toggle";
        break;

      case DBusFn::list_navigation_emit_level_up:
        os << "list_navigation_emit_level_up";
        break;

      case DBusFn::list_navigation_emit_level_down:
        os << "list_navigation_emit_level_down";
        break;

      case DBusFn::list_navigation_emit_move_lines:
        os << "list_navigation_emit_move_lines";
        break;

      case DBusFn::list_navigation_emit_move_pages:
        os << "list_navigation_emit_move_pages";
        break;

      case DBusFn::list_item_emit_add_to_list:
        os << "list_item_emit_add_to_list";
        break;

      case DBusFn::list_item_emit_remove_from_list:
        os << "list_item_emit_remove_from_list";
        break;
    }

    os << "()";

    return os;
}

class MockDcpdDBus::Expectation
{
  public:
    const DBusFn function_id_;

    const void *dbus_object_;
    const gdouble arg_factor_;
    const gint arg_count_;
    const guint16 arg_index_;
    std::string arg_name_a_;
    std::string arg_name_b_;

    Expectation(const Expectation &) = delete;
    Expectation &operator=(const Expectation &) = delete;

    explicit Expectation(DBusFn id, tdbusdcpdPlayback *dbus_object,
                         gdouble fast_wind_factor = 0.0):
        function_id_(id),
        dbus_object_(static_cast<void *>(dbus_object)),
        arg_factor_(fast_wind_factor),
        arg_count_(0),
        arg_index_(0)
    {}

    explicit Expectation(DBusFn id, tdbusdcpdViews *dbus_object,
                         const char *name_a, const char *name_b = ""):
        function_id_(id),
        dbus_object_(static_cast<void *>(dbus_object)),
        arg_factor_(0.0),
        arg_count_(0),
        arg_index_(0),
        arg_name_a_(name_a),
        arg_name_b_(name_b)
    {}

    explicit Expectation(DBusFn id, tdbusdcpdListNavigation *dbus_object,
                         gint count = 0):
        function_id_(id),
        dbus_object_(static_cast<void *>(dbus_object)),
        arg_factor_(0.0),
        arg_count_(count),
        arg_index_(0)
    {}

    explicit Expectation(DBusFn id, tdbusdcpdListItem *dbus_object,
                         const char *category, guint16 idx):
        function_id_(id),
        dbus_object_(static_cast<void *>(dbus_object)),
        arg_factor_(0.0),
        arg_count_(0),
        arg_index_(idx),
        arg_name_a_(category)
    {}

    Expectation(Expectation &&) = default;
};


MockDcpdDBus::MockDcpdDBus():
    ignore_all_(false)
{
    expectations_ = new MockExpectations();
}

MockDcpdDBus::~MockDcpdDBus()
{
    delete expectations_;
}

void MockDcpdDBus::init()
{
    cppcut_assert_not_null(expectations_);
    expectations_->init();
}

void MockDcpdDBus::check() const
{
    cppcut_assert_not_null(expectations_);
    expectations_->check();
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_start(tdbusdcpdPlayback *object)
{
    expectations_->add(Expectation(DBusFn::playback_emit_start, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_stop(tdbusdcpdPlayback *object)
{
    expectations_->add(Expectation(DBusFn::playback_emit_stop, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_pause(tdbusdcpdPlayback *object)
{
    expectations_->add(Expectation(DBusFn::playback_emit_pause, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_next(tdbusdcpdPlayback *object)
{
    expectations_->add(Expectation(DBusFn::playback_emit_next, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_previous(tdbusdcpdPlayback *object)
{
    expectations_->add(Expectation(DBusFn::playback_emit_previous, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_fast_forward(tdbusdcpdPlayback *object)
{
    expectations_->add(Expectation(DBusFn::playback_emit_fast_forward, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_fast_rewind(tdbusdcpdPlayback *object)
{
    expectations_->add(Expectation(DBusFn::playback_emit_fast_rewind, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_fast_wind_stop(tdbusdcpdPlayback *object)
{
    expectations_->add(Expectation(DBusFn::playback_emit_fast_wind_stop, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_fast_wind_set_factor(tdbusdcpdPlayback *object, gdouble arg_speed)
{
    expectations_->add(Expectation(DBusFn::playback_emit_fast_wind_set_factor, object, arg_speed));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_repeat_mode_toggle(tdbusdcpdPlayback *object)
{
    expectations_->add(Expectation(DBusFn::playback_emit_repeat_mode_toggle, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_shuffle_mode_toggle(tdbusdcpdPlayback *object)
{
    expectations_->add(Expectation(DBusFn::playback_emit_shuffle_mode_toggle, object));
}


void MockDcpdDBus::expect_tdbus_dcpd_views_emit_open(tdbusdcpdViews *object, const gchar *arg_view_name)
{
    expectations_->add(Expectation(DBusFn::views_emit_open, object, arg_view_name));
}

void MockDcpdDBus::expect_tdbus_dcpd_views_emit_toggle(tdbusdcpdViews *object, const gchar *arg_view_name_back, const gchar *arg_view_name_forth)
{
    expectations_->add(Expectation(DBusFn::views_emit_toggle, object, arg_view_name_back, arg_view_name_forth));
}


void MockDcpdDBus::expect_tdbus_dcpd_list_navigation_emit_level_up(tdbusdcpdListNavigation *object)
{
    expectations_->add(Expectation(DBusFn::list_navigation_emit_level_up, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_list_navigation_emit_level_down(tdbusdcpdListNavigation *object)
{
    expectations_->add(Expectation(DBusFn::list_navigation_emit_level_down, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_list_navigation_emit_move_lines(tdbusdcpdListNavigation *object, gint arg_count)
{
    expectations_->add(Expectation(DBusFn::list_navigation_emit_move_lines, object, arg_count));
}

void MockDcpdDBus::expect_tdbus_dcpd_list_navigation_emit_move_pages(tdbusdcpdListNavigation *object, gint arg_count)
{
    expectations_->add(Expectation(DBusFn::list_navigation_emit_move_pages, object, arg_count));
}


void MockDcpdDBus::expect_tdbus_dcpd_list_item_emit_add_to_list(tdbusdcpdListItem *object, const gchar *arg_category, guint16 arg_index)
{
    expectations_->add(Expectation(DBusFn::list_item_emit_add_to_list, object, arg_category, arg_index));
}

void MockDcpdDBus::expect_tdbus_dcpd_list_item_emit_remove_from_list(tdbusdcpdListItem *object, const gchar *arg_category, guint16 arg_index)
{
    expectations_->add(Expectation(DBusFn::list_item_emit_remove_from_list, object, arg_category, arg_index));
}


MockDcpdDBus *mock_dcpd_dbus_singleton = nullptr;

void tdbus_dcpd_playback_emit_start(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::playback_emit_start);
    cppcut_assert_equal(expect.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_stop(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::playback_emit_stop);
    cppcut_assert_equal(expect.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_pause(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::playback_emit_pause);
    cppcut_assert_equal(expect.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_next(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::playback_emit_next);
    cppcut_assert_equal(expect.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_previous(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::playback_emit_previous);
    cppcut_assert_equal(expect.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_fast_forward(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::playback_emit_fast_forward);
    cppcut_assert_equal(expect.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_fast_rewind(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::playback_emit_fast_rewind);
    cppcut_assert_equal(expect.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_fast_wind_stop(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::playback_emit_fast_wind_stop);
    cppcut_assert_equal(expect.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_fast_wind_set_factor(tdbusdcpdPlayback *object, gdouble arg_speed)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::playback_emit_fast_wind_set_factor);
    cppcut_assert_equal(expect.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_repeat_mode_toggle(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::playback_emit_repeat_mode_toggle);
    cppcut_assert_equal(expect.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_shuffle_mode_toggle(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::playback_emit_shuffle_mode_toggle);
    cppcut_assert_equal(expect.dbus_object_, static_cast<void *>(object));
}


void tdbus_dcpd_views_emit_open(tdbusdcpdViews *object, const gchar *arg_view_name)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::views_emit_open);
    cppcut_assert_equal(expect.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.arg_name_a_, std::string(arg_view_name));
}

void tdbus_dcpd_views_emit_toggle(tdbusdcpdViews *object, const gchar *arg_view_name_back, const gchar *arg_view_name_forth)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::views_emit_toggle);
    cppcut_assert_equal(expect.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.arg_name_a_, std::string(arg_view_name_back));
    cppcut_assert_equal(expect.arg_name_b_, std::string(arg_view_name_forth));
}


void tdbus_dcpd_list_navigation_emit_level_up(tdbusdcpdListNavigation *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::list_navigation_emit_level_up);
    cppcut_assert_equal(expect.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_list_navigation_emit_level_down(tdbusdcpdListNavigation *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::list_navigation_emit_level_down);
    cppcut_assert_equal(expect.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_list_navigation_emit_move_lines(tdbusdcpdListNavigation *object, gint arg_count)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::list_navigation_emit_move_lines);
    cppcut_assert_equal(expect.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.arg_count_, arg_count);
}

void tdbus_dcpd_list_navigation_emit_move_pages(tdbusdcpdListNavigation *object, gint arg_count)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::list_navigation_emit_move_pages);
    cppcut_assert_equal(expect.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.arg_count_, arg_count);
}


void tdbus_dcpd_list_item_emit_add_to_list(tdbusdcpdListItem *object, const gchar *arg_category, guint16 arg_index)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::list_item_emit_add_to_list);
    cppcut_assert_equal(expect.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.arg_name_a_, std::string(arg_category));
    cppcut_assert_equal(expect.arg_index_, arg_index);
}

void tdbus_dcpd_list_item_emit_remove_from_list(tdbusdcpdListItem *object, const gchar *arg_category, guint16 arg_index)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::list_item_emit_remove_from_list);
    cppcut_assert_equal(expect.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.arg_name_a_, std::string(arg_category));
    cppcut_assert_equal(expect.arg_index_, arg_index);
}
