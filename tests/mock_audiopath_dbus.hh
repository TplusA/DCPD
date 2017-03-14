/*
 * Copyright (C) 2017  T+A elektroakustik GmbH & Co. KG
 *
 * This file is part of TAPSwitch.
 *
 * TAPSwitch is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 3 as
 * published by the Free Software Foundation.
 *
 * TAPSwitch is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with TAPSwitch.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef MOCK_AUDIOPATH_DBUS_CC
#define MOCK_AUDIOPATH_DBUS_CC

#include "audiopath_dbus.h"
#include "mock_expectation.hh"

class MockAudiopathDBus
{
  public:
    MockAudiopathDBus(const MockAudiopathDBus &) = delete;
    MockAudiopathDBus &operator=(const MockAudiopathDBus &) = delete;

    class Expectation;
    typedef MockExpectationsTemplate<Expectation> MockExpectations;
    MockExpectations *expectations_;

    explicit MockAudiopathDBus();
    ~MockAudiopathDBus();

    void init();
    void check() const;

    void expect_tdbus_aupath_manager_call_request_source(tdbusaupathManager *object, const gchar *arg_source_id);
    void expect_tdbus_aupath_manager_call_request_source(tdbusaupathManager *object, const gchar *arg_source_id, const gchar *out_player_id, const gboolean out_switched, bool shall_fail);

    void expect_tdbus_aupath_player_call_activate_sync(gboolean retval, tdbusaupathPlayer *object);
    void expect_tdbus_aupath_player_call_deactivate_sync(gboolean retval, tdbusaupathPlayer *object);
    void expect_tdbus_aupath_source_call_selected_sync(gboolean retval, tdbusaupathSource *object, const gchar *arg_source_id);
    void expect_tdbus_aupath_source_call_deselected_sync(gboolean retval, tdbusaupathSource *object, const gchar *arg_source_id);
};

extern MockAudiopathDBus *mock_audiopath_dbus_singleton;

#endif /* !MOCK_AUDIOPATH_DBUS_CC */
