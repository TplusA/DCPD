/*
 * Copyright (C) 2015--2019  T+A elektroakustik GmbH & Co. KG
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

#include "mock_dbus_iface.hh"

enum class DBusIfaceFn
{
    setup,
    shutdown,
    get_playback_iface,
    get_views_iface,
    get_list_navigation_iface,
    get_list_item_iface,
    get_audiopath_manager_iface,
    get_file_transfer_iface,
    get_streamplayer_urlfifo_iface,
    get_streamplayer_playback_iface,
    get_airable_sec_iface,
    get_artcache_read_iface,
    get_credentials_read_iface,
    get_credentials_write_iface,
    get_logind_manager_iface,

    first_valid_dbus_fn_id = setup,
    last_valid_dbus_fn_id = get_logind_manager_iface,
};

static std::ostream &operator<<(std::ostream &os, const DBusIfaceFn id)
{
    if(id < DBusIfaceFn::first_valid_dbus_fn_id ||
       id > DBusIfaceFn::last_valid_dbus_fn_id)
    {
        os << "INVALID";
        return os;
    }

    switch(id)
    {
      case DBusIfaceFn::setup:
        os << "setup";
        break;

      case DBusIfaceFn::shutdown:
        os << "shutdown";
        break;

      case DBusIfaceFn::get_playback_iface:
        os << "get_playback_iface";
        break;

      case DBusIfaceFn::get_views_iface:
        os << "get_views_iface";
        break;

      case DBusIfaceFn::get_list_navigation_iface:
        os << "get_list_navigation_iface";
        break;

      case DBusIfaceFn::get_list_item_iface:
        os << "get_list_item_iface";
        break;

      case DBusIfaceFn::get_audiopath_manager_iface:
        os << "get_audiopath_manager_iface";
        break;

      case DBusIfaceFn::get_file_transfer_iface:
        os << "get_file_transfer_iface";
        break;

      case DBusIfaceFn::get_streamplayer_urlfifo_iface:
        os << "get_streamplayer_urlfifo_iface";
        break;

      case DBusIfaceFn::get_streamplayer_playback_iface:
        os << "get_streamplayer_playback_iface";
        break;

      case DBusIfaceFn::get_airable_sec_iface:
        os << "get_airable_sec_iface";
        break;

      case DBusIfaceFn::get_artcache_read_iface:
        os << "get_artcache_read_iface";
        break;

      case DBusIfaceFn::get_credentials_read_iface:
        os << "get_credentials_read_iface";
        break;

      case DBusIfaceFn::get_credentials_write_iface:
        os << "get_credentials_write_iface";
        break;

      case DBusIfaceFn::get_logind_manager_iface:
        os << "get_logind_manager_iface";
        break;
    }

    os << "()";

    return os;
}

class MockDBusIface::Expectation
{
  public:
    const DBusIfaceFn function_id_;

    void *const ret_dbus_object_;
    const int ret_code_;
    const bool arg_connect_to_session_bus_;
    const bool arg_with_connman_;

    Expectation(const Expectation &) = delete;
    Expectation &operator=(const Expectation &) = delete;

    explicit Expectation(DBusIfaceFn id):
        function_id_(id),
        ret_dbus_object_(nullptr),
        ret_code_(0),
        arg_connect_to_session_bus_(false),
        arg_with_connman_(false)
    {}

    explicit Expectation(DBusIfaceFn id, int ret,
                         bool connect_to_session_bus, bool with_connman):
        function_id_(id),
        ret_dbus_object_(nullptr),
        ret_code_(ret),
        arg_connect_to_session_bus_(connect_to_session_bus),
        arg_with_connman_(with_connman)
    {}

    explicit Expectation(tdbusdcpdPlayback *ret_object):
        function_id_(DBusIfaceFn::get_playback_iface),
        ret_dbus_object_(static_cast<void *>(ret_object)),
        ret_code_(0),
        arg_connect_to_session_bus_(false),
        arg_with_connman_(false)
    {}

    explicit Expectation(tdbusdcpdViews *ret_object):
        function_id_(DBusIfaceFn::get_views_iface),
        ret_dbus_object_(static_cast<void *>(ret_object)),
        ret_code_(0),
        arg_connect_to_session_bus_(false),
        arg_with_connman_(false)
    {}

    explicit Expectation(tdbusdcpdListNavigation *ret_object):
        function_id_(DBusIfaceFn::get_list_navigation_iface),
        ret_dbus_object_(static_cast<void *>(ret_object)),
        ret_code_(0),
        arg_connect_to_session_bus_(false),
        arg_with_connman_(false)
    {}

    explicit Expectation(tdbusdcpdListItem *ret_object):
        function_id_(DBusIfaceFn::get_list_item_iface),
        ret_dbus_object_(static_cast<void *>(ret_object)),
        ret_code_(0),
        arg_connect_to_session_bus_(false),
        arg_with_connman_(false)
    {}

    explicit Expectation(tdbusFileTransfer *ret_object):
        function_id_(DBusIfaceFn::get_file_transfer_iface),
        ret_dbus_object_(static_cast<void *>(ret_object)),
        ret_code_(0),
        arg_connect_to_session_bus_(false),
        arg_with_connman_(false)
    {}

    explicit Expectation(tdbussplayURLFIFO *ret_object):
        function_id_(DBusIfaceFn::get_streamplayer_urlfifo_iface),
        ret_dbus_object_(static_cast<void *>(ret_object)),
        ret_code_(0),
        arg_connect_to_session_bus_(false),
        arg_with_connman_(false)
    {}

    explicit Expectation(tdbussplayPlayback *ret_object):
        function_id_(DBusIfaceFn::get_streamplayer_playback_iface),
        ret_dbus_object_(static_cast<void *>(ret_object)),
        ret_code_(0),
        arg_connect_to_session_bus_(false),
        arg_with_connman_(false)
    {}

    explicit Expectation(tdbusAirable *ret_object):
        function_id_(DBusIfaceFn::get_airable_sec_iface),
        ret_dbus_object_(static_cast<void *>(ret_object)),
        ret_code_(0),
        arg_connect_to_session_bus_(false),
        arg_with_connman_(false)
    {}

    explicit Expectation(tdbusartcacheRead *ret_object):
        function_id_(DBusIfaceFn::get_artcache_read_iface),
        ret_dbus_object_(static_cast<void *>(ret_object)),
        ret_code_(0),
        arg_connect_to_session_bus_(false),
        arg_with_connman_(false)
    {}

    explicit Expectation(tdbusaupathManager *ret_object):
        function_id_(DBusIfaceFn::get_audiopath_manager_iface),
        ret_dbus_object_(static_cast<void *>(ret_object)),
        ret_code_(0),
        arg_connect_to_session_bus_(false),
        arg_with_connman_(false)
    {}

    explicit Expectation(tdbuscredentialsRead *ret_object):
        function_id_(DBusIfaceFn::get_credentials_read_iface),
        ret_dbus_object_(static_cast<void *>(ret_object)),
        ret_code_(0),
        arg_connect_to_session_bus_(false),
        arg_with_connman_(false)
    {}

    explicit Expectation(tdbuscredentialsWrite *ret_object):
        function_id_(DBusIfaceFn::get_credentials_write_iface),
        ret_dbus_object_(static_cast<void *>(ret_object)),
        ret_code_(0),
        arg_connect_to_session_bus_(false),
        arg_with_connman_(false)
    {}

    explicit Expectation(tdbuslogindManager *ret_object):
        function_id_(DBusIfaceFn::get_logind_manager_iface),
        ret_dbus_object_(static_cast<void *>(ret_object)),
        ret_code_(0),
        arg_connect_to_session_bus_(false),
        arg_with_connman_(false)
    {}

    Expectation(Expectation &&) = default;
};

MockDBusIface::MockDBusIface():
    ignore_all_(false)
{
    expectations_ = new MockExpectations();
}

MockDBusIface::~MockDBusIface()
{
    delete expectations_;
}

void MockDBusIface::init()
{
    cppcut_assert_not_null(expectations_);
    expectations_->init();
}

void MockDBusIface::check() const
{
    cppcut_assert_not_null(expectations_);
    expectations_->check();
}


void MockDBusIface::expect_dbus_setup(int ret, bool connect_to_session_bus, bool with_connman)
{
    expectations_->add(Expectation(DBusIfaceFn::setup, ret, connect_to_session_bus, with_connman));
}

void MockDBusIface::expect_dbus_shutdown()
{
    expectations_->add(Expectation(DBusIfaceFn::shutdown));
}


void MockDBusIface::expect_dbus_get_playback_iface(tdbusdcpdPlayback *ret)
{
    expectations_->add(Expectation(ret));
}

void MockDBusIface::expect_dbus_get_views_iface(tdbusdcpdViews *ret)
{
    expectations_->add(Expectation(ret));
}

void MockDBusIface::expect_dbus_get_list_navigation_iface(tdbusdcpdListNavigation *ret)
{
    expectations_->add(Expectation(ret));
}

void MockDBusIface::expect_dbus_get_list_item_iface(tdbusdcpdListItem *ret)
{
    expectations_->add(Expectation(ret));
}

void MockDBusIface::expect_dbus_get_file_transfer_iface(tdbusFileTransfer *ret)
{
    expectations_->add(Expectation(ret));
}

void MockDBusIface::expect_dbus_get_streamplayer_urlfifo_iface(tdbussplayURLFIFO *ret)
{
    expectations_->add(Expectation(ret));
}

void MockDBusIface::expect_dbus_get_streamplayer_playback_iface(tdbussplayPlayback *ret)
{
    expectations_->add(Expectation(ret));
}

void MockDBusIface::expect_dbus_get_airable_sec_iface(tdbusAirable *ret)
{
    expectations_->add(Expectation(ret));
}

void MockDBusIface::expect_dbus_get_artcache_read_iface(tdbusartcacheRead *ret)
{
    expectations_->add(Expectation(ret));
}

void MockDBusIface::expect_dbus_get_audiopath_manager_iface(tdbusaupathManager *ret)
{
    expectations_->add(Expectation(ret));
}

void MockDBusIface::expect_dbus_get_credentials_read_iface(tdbuscredentialsRead *ret)
{
    expectations_->add(Expectation(ret));
}

void MockDBusIface::expect_dbus_get_credentials_write_iface(tdbuscredentialsWrite *ret)
{
    expectations_->add(Expectation(ret));
}

void MockDBusIface::expect_dbus_get_logind_manager_iface(tdbuslogindManager *ret)
{
    expectations_->add(Expectation(ret));
}


MockDBusIface *mock_dbus_iface_singleton = nullptr;

int dbus_setup(bool connect_to_session_bus, bool with_connman)
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusIfaceFn::setup);
    cppcut_assert_equal(expect.arg_connect_to_session_bus_, connect_to_session_bus);
    cppcut_assert_equal(expect.arg_with_connman_, with_connman);
    return expect.ret_code_;
}

void dbus_shutdown()
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusIfaceFn::shutdown);
}

tdbusdcpdPlayback *dbus_get_playback_iface()
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusIfaceFn::get_playback_iface);
    return static_cast<tdbusdcpdPlayback *>(expect.ret_dbus_object_);
}

tdbusdcpdViews *dbus_get_views_iface()
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusIfaceFn::get_views_iface);
    return static_cast<tdbusdcpdViews *>(expect.ret_dbus_object_);
}

tdbusdcpdListNavigation *dbus_get_list_navigation_iface()
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusIfaceFn::get_list_navigation_iface);
    return static_cast<tdbusdcpdListNavigation *>(expect.ret_dbus_object_);
}

tdbusdcpdListItem *dbus_get_list_item_iface()
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusIfaceFn::get_list_item_iface);
    return static_cast<tdbusdcpdListItem *>(expect.ret_dbus_object_);
}

tdbusaupathManager *dbus_audiopath_get_manager_iface()
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusIfaceFn::get_audiopath_manager_iface);
    return static_cast<tdbusaupathManager *>(expect.ret_dbus_object_);
}

tdbusFileTransfer *dbus_get_file_transfer_iface()
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusIfaceFn::get_file_transfer_iface);
    return static_cast<tdbusFileTransfer *>(expect.ret_dbus_object_);
}

tdbussplayURLFIFO *dbus_get_streamplayer_urlfifo_iface()
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusIfaceFn::get_streamplayer_urlfifo_iface);
    return static_cast<tdbussplayURLFIFO *>(expect.ret_dbus_object_);
}

tdbussplayPlayback *dbus_get_streamplayer_playback_iface()
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusIfaceFn::get_streamplayer_playback_iface);
    return static_cast<tdbussplayPlayback *>(expect.ret_dbus_object_);
}

tdbusAirable *dbus_get_airable_sec_iface()
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusIfaceFn::get_airable_sec_iface);
    return static_cast<tdbusAirable *>(expect.ret_dbus_object_);
}

tdbusartcacheRead *dbus_get_artcache_read_iface()
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusIfaceFn::get_artcache_read_iface);
    return static_cast<tdbusartcacheRead *>(expect.ret_dbus_object_);
}

tdbuscredentialsRead *dbus_get_credentials_read_iface()
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusIfaceFn::get_credentials_read_iface);
    return static_cast<tdbuscredentialsRead *>(expect.ret_dbus_object_);
}

tdbuscredentialsWrite *dbus_get_credentials_write_iface()
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusIfaceFn::get_credentials_write_iface);
    return static_cast<tdbuscredentialsWrite *>(expect.ret_dbus_object_);
}

tdbuslogindManager *dbus_get_logind_manager_iface()
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusIfaceFn::get_logind_manager_iface);
    return static_cast<tdbuslogindManager *>(expect.ret_dbus_object_);
}
