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

#ifndef MOCK_NAMED_PIPE_HH
#define MOCK_NAMED_PIPE_HH

#include "named_pipe.h"
#include "mock_expectation.hh"

class MockNamedPipe
{
  public:
    MockNamedPipe(const MockNamedPipe &) = delete;
    MockNamedPipe &operator=(const MockNamedPipe &) = delete;

    class Expectation;
    typedef MockExpectationsTemplate<Expectation> MockExpectations;
    MockExpectations *expectations_;

    explicit MockNamedPipe();
    ~MockNamedPipe();

    void init();
    void check() const;

    void expect_fifo_create_and_open(int ret, const char *devname, bool write_not_read);
    void expect_fifo_open(int ret, const char *devname, bool write_not_read);
    void expect_fifo_close_and_delete(int *fd, const char *devname);
    void expect_fifo_close(int *fd);
    void expect_fifo_reopen(bool ret, int *fd, const char *devname, bool write_not_read);
};

extern MockNamedPipe *mock_named_pipe_singleton;

#endif /* !MOCK_NAMED_PIPE_HH */
