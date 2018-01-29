/*
 * Copyright (C) 2015, 2016, 2017, 2018  T+A elektroakustik GmbH & Co. KG
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
#include <string>

#include "mock_dcpd_dbus.hh"

enum class DcpdDBusFn
{
    playback_emit_start,
    playback_emit_stop,
    playback_emit_pause,
    playback_emit_next,
    playback_emit_previous,
    playback_emit_resume,
    playback_emit_set_speed,
    playback_emit_seek,
    playback_emit_repeat_mode_toggle,
    playback_emit_shuffle_mode_toggle,
    playback_emit_stream_info,
    playback_call_set_stream_info,
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

static std::ostream &operator<<(std::ostream &os, const DcpdDBusFn id)
{
    if(id < DcpdDBusFn::first_valid_dbus_fn_id ||
       id > DcpdDBusFn::last_valid_dbus_fn_id)
    {
        os << "INVALID";
        return os;
    }

    switch(id)
    {
      case DcpdDBusFn::playback_emit_start:
        os << "playback_emit_start";
        break;

      case DcpdDBusFn::playback_emit_stop:
        os << "playback_emit_stop";
        break;

      case DcpdDBusFn::playback_emit_pause:
        os << "playback_emit_pause";
        break;

      case DcpdDBusFn::playback_emit_next:
        os << "playback_emit_next";
        break;

      case DcpdDBusFn::playback_emit_previous:
        os << "playback_emit_previous";
        break;

      case DcpdDBusFn::playback_emit_resume:
        os << "playback_emit_resume";
        break;

      case DcpdDBusFn::playback_emit_set_speed:
        os << "playback_emit_set_speed";
        break;

      case DcpdDBusFn::playback_emit_seek:
        os << "playback_emit_seek";
        break;

      case DcpdDBusFn::playback_emit_repeat_mode_toggle:
        os << "playback_emit_repeat_mode_toggle";
        break;

      case DcpdDBusFn::playback_emit_shuffle_mode_toggle:
        os << "playback_emit_shuffle_mode_toggle";
        break;

      case DcpdDBusFn::playback_emit_stream_info:
        os << "playback_emit_stream_info";
        break;

      case DcpdDBusFn::playback_call_set_stream_info:
        os << "playback_call_set_stream_info";
        break;

      case DcpdDBusFn::views_emit_open:
        os << "views_emit_open";
        break;

      case DcpdDBusFn::views_emit_toggle:
        os << "views_emit_toggle";
        break;

      case DcpdDBusFn::views_emit_search_parameters:
        os << "views_emit_search_parameters";
        break;

      case DcpdDBusFn::list_navigation_emit_level_up:
        os << "list_navigation_emit_level_up";
        break;

      case DcpdDBusFn::list_navigation_emit_level_down:
        os << "list_navigation_emit_level_down";
        break;

      case DcpdDBusFn::list_navigation_emit_move_lines:
        os << "list_navigation_emit_move_lines";
        break;

      case DcpdDBusFn::list_navigation_emit_move_pages:
        os << "list_navigation_emit_move_pages";
        break;

      case DcpdDBusFn::list_item_emit_add_to_list:
        os << "list_item_emit_add_to_list";
        break;

      case DcpdDBusFn::list_item_emit_remove_from_list:
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
        const DcpdDBusFn function_id_;

        void *dbus_object_;
        gdouble arg_factor_;
        gint arg_count_;
        guint16 arg_index_;
        gint64 arg_position_;
        std::string arg_name_a_;
        std::string arg_name_b_;
        std::string arg_name_c_;
        std::string arg_name_d_;
        std::string arg_name_e_;
        const char **key_value_table_;
        gboolean ret_bool_;

        explicit Data(DcpdDBusFn fn):
            function_id_(fn),
            dbus_object_(nullptr),
            arg_factor_(23.42),
            arg_count_(987),
            arg_index_(9000),
            arg_position_(-987654321),
            key_value_table_(nullptr),
            ret_bool_(false)
        {}
    };

    const Data d;

  private:
    /* writable reference for simple ctor code */
    Data &data_ = *const_cast<Data *>(&d);

  public:
    Expectation(const Expectation &) = delete;
    Expectation &operator=(const Expectation &) = delete;

    explicit Expectation(DcpdDBusFn id, tdbusdcpdPlayback *dbus_object,
                         gdouble fast_wind_factor = 0.0):
        d(id)
    {
        data_.dbus_object_ = static_cast<void *>(dbus_object);
        data_.arg_factor_ = fast_wind_factor;
    }

    explicit Expectation(DcpdDBusFn id, tdbusdcpdPlayback *dbus_object,
                         gint64 position, const gchar *position_units):
        d(DcpdDBusFn::playback_emit_seek)
    {
        data_.dbus_object_ = static_cast<void *>(dbus_object);
        data_.arg_position_ = position;
        data_.arg_name_a_ = position_units;
    }

    explicit Expectation(tdbusdcpdPlayback *dbus_object,
                         guint16 stream_id, const char *artist,
                         const char *album, const char *title,
                         const char *alttrack, const char *url):
        d(DcpdDBusFn::playback_emit_stream_info)
    {
        data_.dbus_object_ = static_cast<void *>(dbus_object);
        data_.arg_index_ = stream_id;
        data_.arg_name_a_ = artist;
        data_.arg_name_b_ = album;
        data_.arg_name_c_ = title;
        data_.arg_name_d_ = alttrack;
        data_.arg_name_e_ = url;
    }

    explicit Expectation(gboolean ret, tdbusdcpdPlayback *dbus_object,
                         guint16 stream_id, const char *title,
                         const char *url):
        d(DcpdDBusFn::playback_call_set_stream_info)
    {
        data_.dbus_object_ = static_cast<void *>(dbus_object);
        data_.ret_bool_ = ret;
        data_.arg_index_ = stream_id;
        data_.arg_name_a_ = title;
        data_.arg_name_b_ = url;
    }

    explicit Expectation(DcpdDBusFn id, tdbusdcpdViews *dbus_object,
                         const char *name_a, const char *name_b = ""):
        d(id)
    {
        data_.dbus_object_ = static_cast<void *>(dbus_object);
        data_.arg_name_a_ = name_a;
        data_.arg_name_b_ = name_b;
    }

    explicit Expectation(DcpdDBusFn id, tdbusdcpdViews *dbus_object,
                         const char *context, const char **key_value_table):
        d(id)
    {
        data_.dbus_object_ = static_cast<void *>(dbus_object);
        data_.arg_name_a_ = context;
        data_.key_value_table_ = key_value_table;
    }

    explicit Expectation(DcpdDBusFn id, tdbusdcpdListNavigation *dbus_object,
                         gint count = 0):
        d(id)
    {
        data_.dbus_object_ = static_cast<void *>(dbus_object);
        data_.arg_count_ = count;
    }

    explicit Expectation(DcpdDBusFn id, tdbusdcpdListItem *dbus_object,
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
    expectations_->add(Expectation(DcpdDBusFn::playback_emit_start, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_stop(tdbusdcpdPlayback *object)
{
    expectations_->add(Expectation(DcpdDBusFn::playback_emit_stop, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_pause(tdbusdcpdPlayback *object)
{
    expectations_->add(Expectation(DcpdDBusFn::playback_emit_pause, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_next(tdbusdcpdPlayback *object)
{
    expectations_->add(Expectation(DcpdDBusFn::playback_emit_next, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_previous(tdbusdcpdPlayback *object)
{
    expectations_->add(Expectation(DcpdDBusFn::playback_emit_previous, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_resume(tdbusdcpdPlayback *object)
{
    expectations_->add(Expectation(DcpdDBusFn::playback_emit_resume, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_set_speed(tdbusdcpdPlayback *object, gdouble arg_speed)
{
    expectations_->add(Expectation(DcpdDBusFn::playback_emit_set_speed, object, arg_speed));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_seek(tdbusdcpdPlayback *object, gint64 arg_position, const gchar *arg_position_units)
{
    expectations_->add(Expectation(DcpdDBusFn::playback_emit_seek, object, arg_position, arg_position_units));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_repeat_mode_toggle(tdbusdcpdPlayback *object)
{
    expectations_->add(Expectation(DcpdDBusFn::playback_emit_repeat_mode_toggle, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_shuffle_mode_toggle(tdbusdcpdPlayback *object)
{
    expectations_->add(Expectation(DcpdDBusFn::playback_emit_shuffle_mode_toggle, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_emit_stream_info(tdbusdcpdPlayback *object, guint16 arg_stream_id, const gchar *arg_artist, const gchar *arg_album, const gchar *arg_title, const gchar *arg_alttrack, const gchar *arg_url)
{
    expectations_->add(Expectation(object, arg_stream_id, arg_artist, arg_album, arg_title, arg_alttrack, arg_url));
}

void MockDcpdDBus::expect_tdbus_dcpd_playback_call_set_stream_info(gboolean ret, tdbusdcpdPlayback *proxy, guint16 arg_stream_id, const gchar *arg_title, const gchar *arg_url)
{
    expectations_->add(Expectation(ret, proxy, arg_stream_id, arg_title, arg_url));
}


void MockDcpdDBus::expect_tdbus_dcpd_views_emit_open(tdbusdcpdViews *object, const gchar *arg_view_name)
{
    expectations_->add(Expectation(DcpdDBusFn::views_emit_open, object, arg_view_name));
}

void MockDcpdDBus::expect_tdbus_dcpd_views_emit_toggle(tdbusdcpdViews *object, const gchar *arg_view_name_back, const gchar *arg_view_name_forth)
{
    expectations_->add(Expectation(DcpdDBusFn::views_emit_toggle, object, arg_view_name_back, arg_view_name_forth));
}

void MockDcpdDBus::expect_tdbus_dcpd_views_emit_search_parameters(tdbusdcpdViews *object, const gchar *arg_context, const char **key_value_table)
{
    expectations_->add(Expectation(DcpdDBusFn::views_emit_search_parameters, object, arg_context, key_value_table));
}


void MockDcpdDBus::expect_tdbus_dcpd_list_navigation_emit_level_up(tdbusdcpdListNavigation *object)
{
    expectations_->add(Expectation(DcpdDBusFn::list_navigation_emit_level_up, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_list_navigation_emit_level_down(tdbusdcpdListNavigation *object)
{
    expectations_->add(Expectation(DcpdDBusFn::list_navigation_emit_level_down, object));
}

void MockDcpdDBus::expect_tdbus_dcpd_list_navigation_emit_move_lines(tdbusdcpdListNavigation *object, gint arg_count)
{
    expectations_->add(Expectation(DcpdDBusFn::list_navigation_emit_move_lines, object, arg_count));
}

void MockDcpdDBus::expect_tdbus_dcpd_list_navigation_emit_move_pages(tdbusdcpdListNavigation *object, gint arg_count)
{
    expectations_->add(Expectation(DcpdDBusFn::list_navigation_emit_move_pages, object, arg_count));
}


void MockDcpdDBus::expect_tdbus_dcpd_list_item_emit_add_to_list(tdbusdcpdListItem *object, const gchar *arg_category, guint16 arg_index)
{
    expectations_->add(Expectation(DcpdDBusFn::list_item_emit_add_to_list, object, arg_category, arg_index));
}

void MockDcpdDBus::expect_tdbus_dcpd_list_item_emit_remove_from_list(tdbusdcpdListItem *object, const gchar *arg_category, guint16 arg_index)
{
    expectations_->add(Expectation(DcpdDBusFn::list_item_emit_remove_from_list, object, arg_category, arg_index));
}


MockDcpdDBus *mock_dcpd_dbus_singleton = nullptr;

void tdbus_dcpd_playback_emit_start(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::playback_emit_start);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_stop(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::playback_emit_stop);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_pause(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::playback_emit_pause);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_next(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::playback_emit_next);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_previous(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::playback_emit_previous);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_resume(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::playback_emit_resume);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_set_speed(tdbusdcpdPlayback *object, gdouble arg_speed_factor)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::playback_emit_set_speed);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
    cut_assert(expect.d.arg_factor_ <= arg_speed_factor &&
               expect.d.arg_factor_ >= arg_speed_factor);
}

void tdbus_dcpd_playback_emit_seek(tdbusdcpdPlayback *object, gint64 arg_position,
                                   const gchar *arg_position_units)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::playback_emit_seek);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.d.arg_position_, arg_position);
    cppcut_assert_equal(expect.d.arg_name_a_, std::string(arg_position_units));
}

void tdbus_dcpd_playback_emit_repeat_mode_toggle(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::playback_emit_repeat_mode_toggle);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_shuffle_mode_toggle(tdbusdcpdPlayback *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::playback_emit_shuffle_mode_toggle);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_playback_emit_stream_info(tdbusdcpdPlayback *object, guint16 arg_stream_id, const gchar *arg_artist, const gchar *arg_album, const gchar *arg_title, const gchar *arg_alttrack, const gchar *arg_url)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::playback_emit_stream_info);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.d.arg_index_, arg_stream_id);
    cppcut_assert_equal(expect.d.arg_name_a_, std::string(arg_artist));
    cppcut_assert_equal(expect.d.arg_name_b_, std::string(arg_album));
    cppcut_assert_equal(expect.d.arg_name_c_, std::string(arg_title));
    cppcut_assert_equal(expect.d.arg_name_d_, std::string(arg_alttrack));
    cppcut_assert_equal(expect.d.arg_name_e_, std::string(arg_url));
}

gboolean tdbus_dcpd_playback_call_set_stream_info_sync(tdbusdcpdPlayback *proxy, guint16 arg_stream_id, const gchar *arg_title, const gchar *arg_url, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::playback_call_set_stream_info);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(proxy));
    cppcut_assert_equal(expect.d.arg_index_, arg_stream_id);
    cppcut_assert_equal(expect.d.arg_name_a_, std::string(arg_title));
    cppcut_assert_equal(expect.d.arg_name_b_, std::string(arg_url));

    if(error != NULL)
        *error = NULL;

    return expect.d.ret_bool_;
}

void tdbus_dcpd_views_emit_open(tdbusdcpdViews *object, const gchar *arg_view_name)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::views_emit_open);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.d.arg_name_a_, std::string(arg_view_name));
}

void tdbus_dcpd_views_emit_toggle(tdbusdcpdViews *object, const gchar *arg_view_name_back, const gchar *arg_view_name_forth)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::views_emit_toggle);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.d.arg_name_a_, std::string(arg_view_name_back));
    cppcut_assert_equal(expect.d.arg_name_b_, std::string(arg_view_name_forth));
}

void tdbus_dcpd_views_emit_search_parameters(tdbusdcpdViews *object, const gchar *arg_context, GVariant *arg_query)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::views_emit_search_parameters);
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

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::list_navigation_emit_level_up);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_list_navigation_emit_level_down(tdbusdcpdListNavigation *object)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::list_navigation_emit_level_down);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
}

void tdbus_dcpd_list_navigation_emit_move_lines(tdbusdcpdListNavigation *object, gint arg_count)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::list_navigation_emit_move_lines);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.d.arg_count_, arg_count);
}

void tdbus_dcpd_list_navigation_emit_move_pages(tdbusdcpdListNavigation *object, gint arg_count)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::list_navigation_emit_move_pages);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.d.arg_count_, arg_count);
}


void tdbus_dcpd_list_item_emit_add_to_list(tdbusdcpdListItem *object, const gchar *arg_category, guint16 arg_index)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::list_item_emit_add_to_list);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.d.arg_name_a_, std::string(arg_category));
    cppcut_assert_equal(expect.d.arg_index_, arg_index);
}

void tdbus_dcpd_list_item_emit_remove_from_list(tdbusdcpdListItem *object, const gchar *arg_category, guint16 arg_index)
{
    const auto &expect(mock_dcpd_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, DcpdDBusFn::list_item_emit_remove_from_list);
    cppcut_assert_equal(expect.d.dbus_object_, static_cast<void *>(object));
    cppcut_assert_equal(expect.d.arg_name_a_, std::string(arg_category));
    cppcut_assert_equal(expect.d.arg_index_, arg_index);
}
