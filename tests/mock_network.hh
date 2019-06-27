/*
 * Copyright (C) 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef MOCK_NETWORK_HH
#define MOCK_NETWORK_HH

#include "network.h"
#include "mock_expectation.hh"

class MockNetwork
{
  public:
    MockNetwork(const MockNetwork &) = delete;
    MockNetwork &operator=(const MockNetwork &) = delete;

    class Expectation;
    typedef MockExpectationsTemplate<Expectation> MockExpectations;
    MockExpectations *expectations_;

    explicit MockNetwork();
    ~MockNetwork();

    void init();
    void check() const;

    void expect_create_socket(int ret, uint16_t port, int backlog);
    void expect_accept_peer_connection(int ret, int server_fd, bool non_blocking, enum MessageVerboseLevel verbose_level);
    void expect_have_data(bool ret, int peer_fd);
    void expect_close(int fd);
};

extern MockNetwork *mock_network_singleton;

#endif /* !MOCK_NETWORK_HH */
