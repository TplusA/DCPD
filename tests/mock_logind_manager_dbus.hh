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

#ifndef MOCK_LOGIND_MANAGER_DBUS_HH
#define MOCK_LOGIND_MANAGER_DBUS_HH

#include "logind_dbus.h"
#include "mock_expectation.hh"

class MockLogindManagerDBus
{
  public:
    MockLogindManagerDBus(const MockLogindManagerDBus &) = delete;
    MockLogindManagerDBus &operator=(const MockLogindManagerDBus &) = delete;

    class Expectation;
    typedef MockExpectationsTemplate<Expectation> MockExpectations;
    MockExpectations *expectations_;

    explicit MockLogindManagerDBus();
    ~MockLogindManagerDBus();

    void init();
    void check() const;

    void expect_tdbus_logind_manager_call_reboot_sync(gboolean retval, tdbuslogindManager *object, gboolean interactive);
    void expect_tdbus_logind_manager_call_power_off_sync(gboolean retval, tdbuslogindManager *object, gboolean interactive);
};

extern MockLogindManagerDBus *mock_logind_manager_dbus_singleton;

#endif /* !MOCK_LOGIND_MANAGER_DBUS_HH */
