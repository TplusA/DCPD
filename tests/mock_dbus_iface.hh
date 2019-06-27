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

#ifndef MOCK_DBUS_IFACE_HH
#define MOCK_DBUS_IFACE_HH

#include "dbus_iface_deep.h"
#include "mock_expectation.hh"

class MockDBusIface
{
  public:
    MockDBusIface(const MockDBusIface &) = delete;
    MockDBusIface &operator=(const MockDBusIface &) = delete;

    class Expectation;
    typedef MockExpectationsTemplate<Expectation> MockExpectations;
    MockExpectations *expectations_;

    bool ignore_all_;

    explicit MockDBusIface();
    ~MockDBusIface();

    void init();
    void check() const;

    void expect_dbus_setup(int ret, bool connect_to_session_bus, bool with_connman);
    void expect_dbus_shutdown();

    void expect_dbus_get_playback_iface(tdbusdcpdPlayback *);
    void expect_dbus_get_views_iface(tdbusdcpdViews *);
    void expect_dbus_get_list_navigation_iface(tdbusdcpdListNavigation *);
    void expect_dbus_get_list_item_iface(tdbusdcpdListItem *);
    void expect_dbus_get_file_transfer_iface(tdbusFileTransfer *);
    void expect_dbus_get_streamplayer_urlfifo_iface(tdbussplayURLFIFO *);
    void expect_dbus_get_streamplayer_playback_iface(tdbussplayPlayback *);
    void expect_dbus_get_airable_sec_iface(tdbusAirable *);
    void expect_dbus_get_artcache_read_iface(tdbusartcacheRead *);
    void expect_dbus_get_audiopath_manager_iface(tdbusaupathManager *);
    void expect_dbus_get_credentials_read_iface(tdbuscredentialsRead *);
    void expect_dbus_get_credentials_write_iface(tdbuscredentialsWrite *);
    void expect_dbus_get_logind_manager_iface(tdbuslogindManager *);
};

extern MockDBusIface *mock_dbus_iface_singleton;

#endif /* !MOCK_DBUS_IFACE_HH */
