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

#include "mock_logind_manager_dbus.hh"

enum class LogindManagerFn
{
    call_reboot_sync,

    first_valid_logind_manager_fn_id = call_reboot_sync,
    last_valid_logind_manager_fn_id = call_reboot_sync,
};

static std::ostream &operator<<(std::ostream &os, const LogindManagerFn id)
{
    if(id < LogindManagerFn::first_valid_logind_manager_fn_id ||
       id > LogindManagerFn::last_valid_logind_manager_fn_id)
    {
        os << "INVALID";
        return os;
    }

    switch(id)
    {
      case LogindManagerFn::call_reboot_sync:
        os << "call_reboot_sync";
        break;
    }

    os << "()";

    return os;
}

class MockLogindManagerDBus::Expectation
{
  public:
    const LogindManagerFn function_id_;

    gboolean ret_bool_;
    const tdbuslogindManager *dbus_object_;
    gboolean arg_interactive_;

    Expectation(const Expectation &) = delete;
    Expectation &operator=(const Expectation &) = delete;

    explicit Expectation(LogindManagerFn id, gboolean ret_bool, tdbuslogindManager *dbus_object, gboolean arg_interactive):
        function_id_(id),
        ret_bool_(ret_bool),
        dbus_object_(dbus_object),
        arg_interactive_(arg_interactive)
    {}

    Expectation(Expectation &&) = default;
};

MockLogindManagerDBus::MockLogindManagerDBus()
{
    expectations_ = new MockExpectations();
}

MockLogindManagerDBus::~MockLogindManagerDBus()
{
    delete expectations_;
}

void MockLogindManagerDBus::init()
{
    cppcut_assert_not_null(expectations_);
    expectations_->init();
}

void MockLogindManagerDBus::check() const
{
    cppcut_assert_not_null(expectations_);
    expectations_->check();
}

void MockLogindManagerDBus::expect_tdbus_logind_manager_call_reboot_sync(gboolean retval, tdbuslogindManager *object, gboolean interactive)
{
    expectations_->add(Expectation(LogindManagerFn::call_reboot_sync, retval, object, interactive));
}


MockLogindManagerDBus *mock_logind_manager_dbus_singleton = nullptr;

gboolean tdbus_logind_manager_call_reboot_sync(tdbuslogindManager *proxy, gboolean arg_interactive, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_logind_manager_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, LogindManagerFn::call_reboot_sync);
    cppcut_assert_equal(expect.dbus_object_, proxy);
    cppcut_assert_equal(expect.arg_interactive_, arg_interactive);

    if(error != nullptr)
        *error = nullptr;

    return expect.ret_bool_;
}
