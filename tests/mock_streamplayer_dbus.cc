/*
 * Copyright (C) 2016, 2017, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <vector>
#include <algorithm>
#include <cppcutter.h>

#include "mock_streamplayer_dbus.hh"

#include "stream_id.hh"

enum class StreamplayerFn
{
    urlfifo_call_clear,
    urlfifo_call_next,
    urlfifo_call_push,
    playback_call_start,
    playback_call_stop,
    playback_call_pause,
    playback_call_seek,

    first_valid_streamplayer_fn_id = urlfifo_call_clear,
    last_valid_streamplayer_fn_id = playback_call_seek,
};

static std::ostream &operator<<(std::ostream &os, const StreamplayerFn id)
{
    if(id < StreamplayerFn::first_valid_streamplayer_fn_id ||
       id > StreamplayerFn::last_valid_streamplayer_fn_id)
    {
        os << "INVALID";
        return os;
    }

    switch(id)
    {
      case StreamplayerFn::urlfifo_call_clear:
        os << "urlfifo_call_clear";
        break;

      case StreamplayerFn::urlfifo_call_next:
        os << "urlfifo_call_next";
        break;

      case StreamplayerFn::urlfifo_call_push:
        os << "urlfifo_call_push";
        break;

      case StreamplayerFn::playback_call_start:
        os << "playback_call_start";
        break;

      case StreamplayerFn::playback_call_stop:
        os << "playback_call_stop";
        break;

      case StreamplayerFn::playback_call_pause:
        os << "playback_call_pause";
        break;

      case StreamplayerFn::playback_call_seek:
        os << "playback_call_seek";
        break;
    }

    os << "()";

    return os;
}

class MockStreamplayerDBus::Expectation
{
  public:
    struct Data
    {
        const StreamplayerFn function_id_;

        bool ret_bool_;
        bool ret_overflow_;
        bool ret_is_playing_;
        ID::Stream ret_playing_id_;
        std::vector<stream_id_t> ret_queued_ids_;
        std::vector<stream_id_t> ret_removed_ids_;

        void *arg_object_;
        ID::Stream arg_stream_id_;
        bool is_arg_stream_key_set_;
        MD5::Hash arg_stream_key_;
        std::string arg_string_;
        int64_t arg_start_pos_;
        const char *arg_start_pos_units_;
        int64_t arg_stop_pos_;
        const char *arg_stop_pos_units_;
        int16_t arg_keep_first_n_;

        explicit Data(StreamplayerFn fn):
            function_id_(fn),
            ret_bool_(false),
            ret_overflow_(false),
            ret_is_playing_(false),
            ret_playing_id_(ID::Stream::make_invalid()),
            arg_object_(nullptr),
            arg_stream_id_(ID::Stream::make_invalid()),
            is_arg_stream_key_set_(false),
            arg_stream_key_{0},
            arg_start_pos_(-11111),
            arg_stop_pos_(-22222),
            arg_keep_first_n_(-10)
        {}
    };

    const Data d;

  private:
    /* writable reference for simple ctor code */
    Data &data_ = *const_cast<Data *>(&d);

  public:
    Expectation(const Expectation &) = delete;
    Expectation &operator=(const Expectation &) = delete;

    explicit Expectation(StreamplayerFn fn, bool retval, tdbussplayURLFIFO *object):
        d(fn)
    {
        data_.ret_bool_ = retval;
        data_.arg_object_ = static_cast<void *>(object);
    }

    explicit Expectation(StreamplayerFn fn, bool retval, tdbussplayPlayback *object):
        d(fn)
    {
        data_.ret_bool_ = retval;
        data_.arg_object_ = static_cast<void *>(object);
    }

    explicit Expectation(StreamplayerFn fn, bool retval, tdbussplayPlayback *object,
                         const char *reason):
        d(fn)
    {
        data_.ret_bool_ = retval;
        data_.arg_object_ = static_cast<void *>(object);
        cppcut_assert_not_null(reason);
        data_.arg_string_ = reason;
    }

    explicit Expectation(gboolean retval, tdbussplayURLFIFO *object,
                         gint16 arg_keep_first_n_entries,
                         guint expected_out_playing_id,
                         const uint16_t *expected_out_queued_ids, size_t expected_out_queued_ids_size,
                         const uint16_t *expected_out_removed_ids, size_t expected_out_removed_ids_size):
        Expectation(StreamplayerFn::urlfifo_call_clear, retval, object)
    {
        data_.arg_keep_first_n_ = arg_keep_first_n_entries;
        data_.ret_playing_id_ = ID::Stream::make_from_raw_id(expected_out_playing_id);

        if(expected_out_queued_ids != nullptr && expected_out_queued_ids_size > 0)
            std::copy(expected_out_queued_ids,
                      expected_out_queued_ids + expected_out_queued_ids_size,
                      std::back_inserter(data_.ret_queued_ids_));

        if(expected_out_removed_ids != nullptr && expected_out_removed_ids_size > 0)
            std::copy(expected_out_removed_ids,
                      expected_out_removed_ids + expected_out_removed_ids_size,
                      std::back_inserter(data_.ret_removed_ids_));
    }

    explicit Expectation(gboolean retval, tdbussplayURLFIFO *object,
                         guint16 arg_stream_id, const gchar *arg_stream_url,
                         const MD5::Hash &stream_key,
                         gint64 arg_start_position, const gchar *arg_start_units,
                         gint64 arg_stop_position, const gchar *arg_stop_units,
                         gint16 arg_keep_first_n_entries,
                         gboolean expected_out_fifo_overflow,
                         gboolean expected_out_is_playing):
        Expectation(StreamplayerFn::urlfifo_call_push, retval, object)
    {
        data_.arg_stream_id_ = ID::Stream::make_from_raw_id(arg_stream_id);
        data_.arg_stream_key_ = stream_key;
        data_.is_arg_stream_key_set_ = true;
        data_.arg_string_ = arg_stream_url;
        data_.arg_start_pos_ = arg_start_position;
        data_.arg_start_pos_units_ = arg_start_units;
        data_.arg_stop_pos_ = arg_stop_position;
        data_.arg_stop_pos_units_ = arg_stop_units;
        data_.arg_keep_first_n_ = arg_keep_first_n_entries;
        data_.ret_overflow_ = expected_out_fifo_overflow;
        data_.ret_is_playing_ = expected_out_is_playing;
    }

    explicit Expectation(gboolean retval, tdbussplayPlayback *object,
                         gint64 arg_position, const gchar *arg_position_units):
        Expectation(StreamplayerFn::playback_call_seek, retval, object)
    {
        data_.arg_start_pos_ = arg_position;
        data_.arg_start_pos_units_ = arg_position_units;
    }

    Expectation(Expectation &&) = default;
};

MockStreamplayerDBus::MockStreamplayerDBus()
{
    expectations_ = new MockExpectations();
}

MockStreamplayerDBus::~MockStreamplayerDBus()
{
    delete expectations_;
}

void MockStreamplayerDBus::init()
{
    cppcut_assert_not_null(expectations_);
    expectations_->init();
}

void MockStreamplayerDBus::check() const
{
    cppcut_assert_not_null(expectations_);
    expectations_->check();
}

void MockStreamplayerDBus::expect_tdbus_splay_urlfifo_call_clear_sync(gboolean retval, tdbussplayURLFIFO *object, gint16 arg_keep_first_n_entries, guint expected_out_playing_id, const uint16_t *expected_out_queued_ids, size_t expected_out_queued_ids_size, const uint16_t *expected_out_removed_ids, size_t expected_out_removed_ids_size)
{
    expectations_->add(Expectation(retval, object, arg_keep_first_n_entries, expected_out_playing_id, expected_out_queued_ids, expected_out_queued_ids_size, expected_out_removed_ids, expected_out_removed_ids_size));
}

void MockStreamplayerDBus::expect_tdbus_splay_urlfifo_call_next_sync(gboolean retval, tdbussplayURLFIFO *object)
{
    expectations_->add(Expectation(StreamplayerFn::urlfifo_call_next, retval, object));
}

void MockStreamplayerDBus::expect_tdbus_splay_urlfifo_call_push_sync(gboolean retval, tdbussplayURLFIFO *object, guint16 arg_stream_id, const gchar *arg_stream_url, const MD5::Hash &arg_stream_key, gint64 arg_start_position, const gchar *arg_start_units, gint64 arg_stop_position, const gchar *arg_stop_units, gint16 arg_keep_first_n_entries, gboolean expected_out_fifo_overflow, gboolean expected_out_is_playing)
{
    expectations_->add(Expectation(retval, object, arg_stream_id, arg_stream_url, arg_stream_key, arg_start_position, arg_start_units, arg_stop_position, arg_stop_units, arg_keep_first_n_entries, expected_out_fifo_overflow, expected_out_is_playing));
}

void MockStreamplayerDBus::expect_tdbus_splay_playback_call_start_sync(gboolean retval, tdbussplayPlayback *object)
{
    expectations_->add(Expectation(StreamplayerFn::playback_call_start, retval, object));
}

void MockStreamplayerDBus::expect_tdbus_splay_playback_call_stop_sync(gboolean retval, tdbussplayPlayback *object, const char *arg_reason)
{
    expectations_->add(Expectation(StreamplayerFn::playback_call_stop, retval, object, arg_reason));
}

void MockStreamplayerDBus::expect_tdbus_splay_playback_call_pause_sync(gboolean retval, tdbussplayPlayback *object)
{
    expectations_->add(Expectation(StreamplayerFn::playback_call_pause, retval, object));
}

void MockStreamplayerDBus::expect_tdbus_splay_playback_call_seek_sync(gboolean retval, tdbussplayPlayback *object, gint64 arg_position, const gchar *arg_position_units)
{
    expectations_->add(Expectation(retval, object, arg_position, arg_position_units));
}


MockStreamplayerDBus *mock_streamplayer_dbus_singleton = nullptr;

gboolean tdbus_splay_urlfifo_call_clear_sync(tdbussplayURLFIFO *proxy, gint16 arg_keep_first_n_entries, guint *out_playing_id, GVariant **out_queued_ids, GVariant **out_removed_ids, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_streamplayer_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, StreamplayerFn::urlfifo_call_clear);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));
    cppcut_assert_equal(expect.d.arg_keep_first_n_, arg_keep_first_n_entries);

    if(out_playing_id != NULL)
        *out_playing_id = expect.d.ret_playing_id_.get_raw_id();

    if(out_queued_ids != NULL)
        cut_fail("returning queued IDs as GVariant not implemented yet");

    if(out_removed_ids != NULL)
        cut_fail("returning removed IDs as GVariant not implemented yet");

    if(error != NULL)
        *error = NULL;

    return expect.d.ret_bool_;
}

gboolean tdbus_splay_urlfifo_call_next_sync(tdbussplayURLFIFO *proxy, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_streamplayer_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, StreamplayerFn::urlfifo_call_next);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));

    if(error != NULL)
        *error = NULL;

    return expect.d.ret_bool_;
}

gboolean tdbus_splay_urlfifo_call_push_sync(tdbussplayURLFIFO *proxy, guint16 arg_stream_id, const gchar *arg_stream_url, GVariant *arg_stream_key, gint64 arg_start_position, const gchar *arg_start_units, gint64 arg_stop_position, const gchar *arg_stop_units, gint16 arg_keep_first_n_entries, gboolean *out_fifo_overflow, gboolean *out_is_playing, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_streamplayer_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, StreamplayerFn::urlfifo_call_push);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));
    cppcut_assert_equal(expect.d.arg_stream_id_, ID::Stream::make_from_raw_id(arg_stream_id));
    cppcut_assert_equal(expect.d.arg_string_.c_str(), arg_stream_url);
    cppcut_assert_equal(expect.d.arg_start_pos_, arg_start_position);
    cppcut_assert_equal(expect.d.arg_start_pos_units_, arg_start_units);
    cppcut_assert_equal(expect.d.arg_stop_pos_, arg_start_position);
    cppcut_assert_equal(expect.d.arg_stop_pos_units_, arg_stop_units);
    cppcut_assert_equal(expect.d.arg_keep_first_n_, arg_keep_first_n_entries);

    gsize stream_key_len;
    gconstpointer stream_key_data =
        g_variant_get_fixed_array(arg_stream_key, &stream_key_len,
                                  sizeof(uint8_t));

    cut_assert_true(expect.d.is_arg_stream_key_set_);
    cut_assert_equal_memory(expect.d.arg_stream_key_.data(), expect.d.arg_stream_key_.size(),
                            stream_key_data, stream_key_len);

    cut_assert_true(g_variant_is_floating(arg_stream_key));
    g_variant_unref(arg_stream_key);

    if(out_fifo_overflow != NULL)
        *out_fifo_overflow = expect.d.ret_overflow_;

    if(out_is_playing != NULL)
        *out_is_playing = expect.d.ret_is_playing_;

    if(error != NULL)
        *error = NULL;

    return expect.d.ret_bool_;
}

gboolean tdbus_splay_playback_call_start_sync(tdbussplayPlayback *proxy, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_streamplayer_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, StreamplayerFn::playback_call_start);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));

    if(error != NULL)
        *error = NULL;

    return expect.d.ret_bool_;
}

gboolean tdbus_splay_playback_call_stop_sync(tdbussplayPlayback *proxy, const gchar *arg_reason, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_streamplayer_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, StreamplayerFn::playback_call_stop);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));
    cppcut_assert_not_null(arg_reason);
    cut_assert_false(expect.d.arg_string_.empty());
    cppcut_assert_equal(expect.d.arg_string_.c_str(), arg_reason);

    if(error != NULL)
        *error = NULL;

    return expect.d.ret_bool_;
}

gboolean tdbus_splay_playback_call_pause_sync(tdbussplayPlayback *proxy, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_streamplayer_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, StreamplayerFn::playback_call_pause);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));

    if(error != NULL)
        *error = NULL;

    return expect.d.ret_bool_;
}

gboolean tdbus_splay_playback_call_seek_sync(tdbussplayPlayback *proxy, gint64 arg_position, const gchar *arg_position_units, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_streamplayer_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, StreamplayerFn::playback_call_seek);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));
    cppcut_assert_equal(expect.d.arg_start_pos_, arg_position);
    cppcut_assert_equal(expect.d.arg_start_pos_units_, arg_position_units);

    if(error != NULL)
        *error = NULL;

    return expect.d.ret_bool_;
}
