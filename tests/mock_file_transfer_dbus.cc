/*
 * Copyright (C) 2015, 2019  T+A elektroakustik GmbH & Co. KG
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

#include <cppcutter.h>

#include "mock_file_transfer_dbus.hh"

enum class FileTransferFn
{
    call_download,
    call_cancel,

    first_valid_file_transfer_fn_id = call_download,
    last_valid_file_transfer_fn_id = call_cancel,
};

static std::ostream &operator<<(std::ostream &os, const FileTransferFn id)
{
    if(id < FileTransferFn::first_valid_file_transfer_fn_id ||
       id > FileTransferFn::last_valid_file_transfer_fn_id)
    {
        os << "INVALID";
        return os;
    }

    switch(id)
    {
      case FileTransferFn::call_download:
        os << "call_download";
        break;

      case FileTransferFn::call_cancel:
        os << "call_cancel";
        break;
    }

    os << "()";

    return os;
}

class MockFileTransferDBus::Expectation
{
  public:
    const FileTransferFn function_id_;

    gboolean ret_bool_;
    guint ret_id_;
    const tdbusFileTransfer *dbus_object_;
    const std::string arg_url_;
    guint arg_ticks_;
    guint arg_id_;

    Expectation(const Expectation &) = delete;
    Expectation &operator=(const Expectation &) = delete;

    explicit Expectation(FileTransferFn id, gboolean ret_bool, guint ret_id,
                         tdbusFileTransfer *dbus_object, const char *url, guint ticks):
        function_id_(id),
        ret_bool_(ret_bool),
        ret_id_(ret_id),
        dbus_object_(dbus_object),
        arg_url_(url),
        arg_ticks_(ticks),
        arg_id_(12345)
    {}

    explicit Expectation(FileTransferFn id, gboolean ret_bool,
                         tdbusFileTransfer *dbus_object, guint arg_id):
        function_id_(id),
        ret_bool_(ret_bool),
        ret_id_(12345),
        dbus_object_(dbus_object),
        arg_url_(""),
        arg_ticks_(12345),
        arg_id_(arg_id)
    {}

    Expectation(Expectation &&) = default;
};


MockFileTransferDBus::MockFileTransferDBus()
{
    expectations_ = new MockExpectations();
}

MockFileTransferDBus::~MockFileTransferDBus()
{
    delete expectations_;
}

void MockFileTransferDBus::init()
{
    cppcut_assert_not_null(expectations_);
    expectations_->init();
}

void MockFileTransferDBus::check() const
{
    cppcut_assert_not_null(expectations_);
    expectations_->check();
}

void MockFileTransferDBus::expect_tdbus_file_transfer_call_download_sync(
    gboolean retval, guint ret_id, tdbusFileTransfer *object,
    const gchar *url, guint ticks)
{
    expectations_->add(Expectation(FileTransferFn::call_download,
                                   retval, ret_id, object, url, ticks));
}

void MockFileTransferDBus::expect_tdbus_file_transfer_call_cancel_sync(
    gboolean retval, tdbusFileTransfer *object, guint arg_id)
{
    expectations_->add(Expectation(FileTransferFn::call_cancel,
                                   retval, object, arg_id));
}


MockFileTransferDBus *mock_file_transfer_dbus_singleton = nullptr;

gboolean tdbus_file_transfer_call_download_sync(tdbusFileTransfer *proxy, const gchar *arg_url, guint arg_ticks, guint *out_id, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_file_transfer_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, FileTransferFn::call_download);
    cppcut_assert_equal(expect.dbus_object_, proxy);
    cppcut_assert_equal(expect.arg_url_, std::string(arg_url));
    cppcut_assert_equal(expect.arg_ticks_, arg_ticks);
    cppcut_assert_not_null(out_id);

    *out_id = expect.ret_id_;

    if(error != nullptr)
        *error = nullptr;

    return expect.ret_bool_;
}

gboolean tdbus_file_transfer_call_cancel_sync(tdbusFileTransfer *proxy, guint arg_id, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_file_transfer_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, FileTransferFn::call_cancel);
    cppcut_assert_equal(expect.dbus_object_, proxy);
    cppcut_assert_equal(expect.arg_id_, arg_id);

    if(error != nullptr)
        *error = nullptr;

    return expect.ret_bool_;
}
