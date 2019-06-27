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

#ifndef MOCK_FILE_TRANSFER_DBUS_HH
#define MOCK_FILE_TRANSFER_DBUS_HH

#include "dbusdl_dbus.h"
#include "mock_expectation.hh"

class MockFileTransferDBus
{
  public:
    MockFileTransferDBus(const MockFileTransferDBus &) = delete;
    MockFileTransferDBus &operator=(const MockFileTransferDBus &) = delete;

    class Expectation;
    typedef MockExpectationsTemplate<Expectation> MockExpectations;
    MockExpectations *expectations_;

    explicit MockFileTransferDBus();
    ~MockFileTransferDBus();

    void init();
    void check() const;

    void expect_tdbus_file_transfer_call_download_sync(gboolean retval, guint ret_id, tdbusFileTransfer *object, const gchar *url, guint ticks);
    void expect_tdbus_file_transfer_call_cancel_sync(gboolean retval, tdbusFileTransfer *object, guint arg_id);
};

extern MockFileTransferDBus *mock_file_transfer_dbus_singleton;

#endif /* !MOCK_FILE_TRANSFER_DBUS_HH */
