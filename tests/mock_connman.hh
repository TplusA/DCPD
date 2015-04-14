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

#ifndef MOCK_CONNMAN_HH
#define MOCK_CONNMAN_HH

#include "connman.h"
#include "mock_expectation.hh"

class MockConnman
{
  public:
    MockConnman(const MockConnman &) = delete;
    MockConnman &operator=(const MockConnman &) = delete;

    class Expectation;
    typedef MockExpectationsTemplate<Expectation> MockExpectations;
    MockExpectations *expectations_;

    explicit MockConnman();
    ~MockConnman();

    void init();
    void check() const;

    void expect_connman_find_interface(struct ConnmanInterfaceData *ret, const char *mac_address);
    void expect_connman_find_active_primary_interface(struct ConnmanInterfaceData *ret, const char *default_mac_address, const char *wired_mac_address, const char *wireless_mac_address);
    void expect_connman_get_dhcp_mode(bool ret, struct ConnmanInterfaceData *iface_data);
    void expect_connman_free_interface_data(struct ConnmanInterfaceData *iface_data);
};

extern MockConnman *mock_connman_singleton;

#endif /* !MOCK_CONNMAN_HH */
