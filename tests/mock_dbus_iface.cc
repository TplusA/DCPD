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

#include "mock_dbus_iface.hh"

enum class DBusFn
{
    setup,
    shutdown,
    get_playback_iface,
    get_views_iface,
    get_list_navigation_iface,
    get_list_item_iface,

    first_valid_dbus_fn_id = setup,
    last_valid_dbus_fn_id = get_list_item_iface,
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
      case DBusFn::setup:
        os << "setup";
        break;

      case DBusFn::shutdown:
        os << "shutdown";
        break;

      case DBusFn::get_playback_iface:
        os << "get_playback_iface";
        break;

      case DBusFn::get_views_iface:
        os << "get_views_iface";
        break;

      case DBusFn::get_list_navigation_iface:
        os << "get_list_navigation_iface";
        break;

      case DBusFn::get_list_item_iface:
        os << "get_list_item_iface";
        break;
    }

    os << "()";

    return os;
}

class MockDBusIface::Expectation
{
  public:
    const DBusFn function_id_;

    void *const ret_dbus_object_;
    const int ret_code_;
    const bool arg_connect_to_session_bus_;
    const bool arg_with_connman_;

    Expectation(const Expectation &) = delete;
    Expectation &operator=(const Expectation &) = delete;

    explicit Expectation(DBusFn id):
        function_id_(id),
        ret_dbus_object_(nullptr),
        ret_code_(0),
        arg_connect_to_session_bus_(false),
        arg_with_connman_(false)
    {}

    explicit Expectation(DBusFn id, int ret,
                         bool connect_to_session_bus, bool with_connman):
        function_id_(id),
        ret_dbus_object_(nullptr),
        ret_code_(ret),
        arg_connect_to_session_bus_(connect_to_session_bus),
        arg_with_connman_(with_connman)
    {}

    explicit Expectation(tdbusdcpdPlayback *ret_object):
        function_id_(DBusFn::get_playback_iface),
        ret_dbus_object_(static_cast<void *>(ret_object)),
        ret_code_(0),
        arg_connect_to_session_bus_(false),
        arg_with_connman_(false)
    {}

    explicit Expectation(tdbusdcpdViews *ret_object):
        function_id_(DBusFn::get_views_iface),
        ret_dbus_object_(static_cast<void *>(ret_object)),
        ret_code_(0),
        arg_connect_to_session_bus_(false),
        arg_with_connman_(false)
    {}

    explicit Expectation(tdbusdcpdListNavigation *ret_object):
        function_id_(DBusFn::get_list_navigation_iface),
        ret_dbus_object_(static_cast<void *>(ret_object)),
        ret_code_(0),
        arg_connect_to_session_bus_(false),
        arg_with_connman_(false)
    {}

    explicit Expectation(tdbusdcpdListItem *ret_object):
        function_id_(DBusFn::get_list_item_iface),
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
    expectations_->add(Expectation(DBusFn::setup, ret, connect_to_session_bus, with_connman));
}

void MockDBusIface::expect_dbus_shutdown(void)
{
    expectations_->add(Expectation(DBusFn::shutdown));
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


MockDBusIface *mock_dbus_iface_singleton = nullptr;

int dbus_setup(bool connect_to_session_bus, bool with_connman)
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::setup);
    cppcut_assert_equal(expect.arg_connect_to_session_bus_, connect_to_session_bus);
    cppcut_assert_equal(expect.arg_with_connman_, with_connman);
    return expect.ret_code_;
}

void dbus_shutdown(void)
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::shutdown);
}

tdbusdcpdPlayback *dbus_get_playback_iface(void)
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::get_playback_iface);
    return static_cast<tdbusdcpdPlayback *>(expect.ret_dbus_object_);
}

tdbusdcpdViews *dbus_get_views_iface(void)
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::get_views_iface);
    return static_cast<tdbusdcpdViews *>(expect.ret_dbus_object_);
}

tdbusdcpdListNavigation *dbus_get_list_navigation_iface(void)
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::get_list_navigation_iface);
    return static_cast<tdbusdcpdListNavigation *>(expect.ret_dbus_object_);
}

tdbusdcpdListItem *dbus_get_list_item_iface(void)
{
    const auto &expect(mock_dbus_iface_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, DBusFn::get_list_item_iface);
    return static_cast<tdbusdcpdListItem *>(expect.ret_dbus_object_);
}
