/*
 * Copyright (C) 2016  T+A elektroakustik GmbH & Co. KG
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

#ifndef MOCK_AIRABLE_DBUS_HH
#define MOCK_AIRABLE_DBUS_HH

#include "airable_dbus.h"
#include "mock_expectation.hh"

class MockAirableDBus
{
  public:
    MockAirableDBus(const MockAirableDBus &) = delete;
    MockAirableDBus &operator=(const MockAirableDBus &) = delete;

    class Expectation;
    typedef MockExpectationsTemplate<Expectation> MockExpectations;
    MockExpectations *expectations_;

    explicit MockAirableDBus();
    ~MockAirableDBus();

    void init();
    void check() const;

    void expect_tdbus_airable_call_external_service_logout_sync(gboolean retval, tdbusAirable *object, const gchar *arg_service_id, const gchar *arg_url, gboolean arg_is_request, guchar arg_actor_id);
};

extern MockAirableDBus *mock_airable_dbus_singleton;


#endif /* !MOCK_AIRABLE_DBUS_HH */
