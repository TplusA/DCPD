/*
 * Copyright (C) 2015, 2016  T+A elektroakustik GmbH & Co. KG
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
    views_emit_search_parameters,
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

      case DBusFn::views_emit_search_parameters:
        os << "views_emit_search_parameters";
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
    struct Data
    {
        const DBusFn function_id_;

        void *dbus_object_;
        gdouble arg_factor_;
        gint arg_count_;
        guint16 arg_index_;
        std::string arg_name_a_;
        std::string arg_name_b_;
        const char **key_value_table_;

        explicit Data(DBusFn fn):
            function_id_(fn),
            dbus_object_(nullptr),
            arg_factor_(23.42),
            arg_count_(987),
            arg_index_(9000),
            key_value_table_(nullptr)
        {}
    };

    const Data d;

  private:
    /* writable reference for simple ctor code */
    Data &data_ = *const_cast<Data *>(&d);

  public:
    Expectation(const Expectation &) = delete;
    Expectation &operator=(const Expectation &) = delete;

    explicit Expectation(DBusFn id, tdbusdcpdPlayback *dbus_object,
                         gdouble fast_wind_factor = 0.0):
        d(id)
    {
        data_.dbus_object_ = static_cast<void *>(dbus_object);
        data_.arg_factor_ = fast_wind_factor;
    }

    explicit Expectation(DBusFn id, tdbusdcpdViews *dbus_object,
                         const char *name_a, const char *name_b = ""):
        d(id)
    {
        data_.dbus_object_ = static_cast<void *>(dbus_object);
        data_.arg_name_a_ = name_a;
        data_.arg_name_b_ = name_b;
    }

    explicit Expectation(DBusFn id, tdbusdcpdViews *dbus_object,
                         const char *context, const char **key_value_table):
        d(id)
    {
        data_.dbus_object_ = static_cast<void *>(dbus_object);
        data_.arg_name_a_ = context;
        data_.key_value_table_ = key_value_table;
    }

    explicit Expectation(DBusFn id, tdbusdcpdListNavigation *dbus_object,
                         gint count = 0):
        d(id)
    {
        data_.dbus_object_ = static_cast<void *>(dbus_object);
        data_.arg_count_ = count;
    }

    explicit Expectation(DBusFn id, tdbusdcpdListItem *dbus_object,
                         const char *category, guint16 idx):
        d(id)
    {
        data_.dbus_object_ = static_cast<void *>(dbus_object);
        data_.arg_index_ = idx;
        data_.arg_name_a_ = category;
    }

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

void MockDcpdDBus::expect_tdbus_dcpd_views_emit_search_parameters(tdbusdcpdViews *object, const gchar *arg_context, const char **key_value_table)
{
    expectations_->add(Expectation(DBusFn::views_emit_search_parameters, object, arg_context, key_value_table));
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

    cppcut_assert_equal(expect.d.function_id_, DBusFn::playback_emit_start);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_stop(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DBusFn::playback_emit_stop);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_pause(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DBusFn::playback_emit_pause);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_next(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DBusFn::playback_emit_next);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_previous(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DBusFn::playback_emit_previous);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_fast_forward(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DBusFn::playback_emit_fast_forward);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_fast_rewind(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DBusFn::playback_emit_fast_rewind);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_fast_wind_stop(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DBusFn::playback_emit_fast_wind_stop);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_fast_wind_set_factor(tdbusdcpdPlayback *object, gdouble arg_speed)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DBusFn::playback_emit_fast_wind_set_factor);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_repeat_mode_toggle(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DBusFn::playback_emit_repeat_mode_toggle);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_shuffle_mode_toggle(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DBusFn::playback_emit_shuffle_mode_toggle);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}


void tdbus_dcpd_views_emit_open(tdbusdcpdViews *object, const gchar *arg_view_name)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DBusFn::views_emit_open);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.d.arg_name_a_, std::string(arg_view_name));
}

void tdbus_dcpd_views_emit_toggle(tdbusdcpdViews *object, const gchar *arg_view_name_back, const gchar *arg_view_name_forth)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DBusFn::views_emit_toggle);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.d.arg_name_a_, std::string(arg_view_name_back));
    cppcut_assert_equal(expect.d.arg_name_b_, std::string(arg_view_name_forth));
}

void tdbus_dcpd_views_emit_search_parameters(tdbusdcpdViews *object, const gchar *arg_context, GVariant *arg_query)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DBusFn::views_emit_search_parameters);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.d.arg_name_a_, std::string(arg_context));
    cppcut_assert_not_null(arg_query);

    GVariantIter iter;

    const size_t number_of_parameters = g_variant_iter_init(&iter, arg_query);

    if(number_of_parameters == 0)
        cppcut_assert_null(expect.d.key_value_table_);
    else
    {
        cppcut_assert_not_null(expect.d.key_value_table_);

        const gchar *varname;
        const gchar *value;
        size_t i = 0;

        while(g_variant_iter_next(&iter, "(&s&s)", &varname, &value))
        {
            cppcut_assert_equal(expect.d.key_value_table_[i], varname);
            cppcut_assert_equal(expect.d.key_value_table_[i + 1], value);

            i += 2;
        }

        cppcut_assert_null(expect.d.key_value_table_[i]);
        cppcut_assert_equal(i, number_of_parameters * 2);
    }

    g_variant_unref(arg_query);
}


void tdbus_dcpd_list_navigation_emit_level_up(tdbusdcpdListNavigation *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DBusFn::list_navigation_emit_level_up);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_list_navigation_emit_level_down(tdbusdcpdListNavigation *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DBusFn::list_navigation_emit_level_down);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_list_navigation_emit_move_lines(tdbusdcpdListNavigation *object, gint arg_count)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DBusFn::list_navigation_emit_move_lines);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.d.arg_count_, arg_count);
}

void tdbus_dcpd_list_navigation_emit_move_pages(tdbusdcpdListNavigation *object, gint arg_count)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DBusFn::list_navigation_emit_move_pages);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.d.arg_count_, arg_count);
}


void tdbus_dcpd_list_item_emit_add_to_list(tdbusdcpdListItem *object, const gchar *arg_category, guint16 arg_index)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DBusFn::list_item_emit_add_to_list);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.d.arg_name_a_, std::string(arg_category));
    cppcut_assert_equal(expect.d.arg_index_, arg_index);
}

void tdbus_dcpd_list_item_emit_remove_from_list(tdbusdcpdListItem *object, const gchar *arg_category, guint16 arg_index)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DBusFn::list_item_emit_remove_from_list);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.d.arg_name_a_, std::string(arg_category));
    cppcut_assert_equal(expect.d.arg_index_, arg_index);
}
