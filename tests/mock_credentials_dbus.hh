/*
 * Copyright (C) 2016, 2017, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef MOCK_CREDENTIALS_DBUS_HH
#define MOCK_CREDENTIALS_DBUS_HH

#include "de_tahifi_credentials.h"
#include "mock_expectation.hh"

class MockCredentialsDBus
{
  public:
    MockCredentialsDBus(const MockCredentialsDBus &) = delete;
    MockCredentialsDBus &operator=(const MockCredentialsDBus &) = delete;

    class Expectation;
    typedef MockExpectationsTemplate<Expectation> MockExpectations;
    MockExpectations *expectations_;

    explicit MockCredentialsDBus();
    ~MockCredentialsDBus();

    void init();
    void check() const;

    using ReadGetKnownCategoriesData = std::vector<std::pair<const char *, const char *>>;
    void expect_tdbus_credentials_read_call_get_known_categories_sync(gboolean retval, tdbuscredentialsRead *object, const ReadGetKnownCategoriesData &categories);

    using ReadGetCredentialsData = std::vector<std::pair<const char *, const char *>>;
    void expect_tdbus_credentials_read_call_get_credentials_sync(gboolean retval, tdbuscredentialsRead *object, const ReadGetCredentialsData &credentials, const std::string &default_user);

    void expect_tdbus_credentials_read_call_get_default_credentials_sync(gboolean retval, tdbuscredentialsRead *object, const gchar *arg_category, const gchar *out_username, const gchar *out_password);

    void expect_tdbus_credentials_write_call_set_credentials_sync(gboolean retval, tdbuscredentialsWrite *proxy, const char *category, const char *username, const char *password, gboolean is_default);

    void expect_tdbus_credentials_write_call_delete_credentials_sync(gboolean retval, tdbuscredentialsWrite *proxy, const char *category, const char *username, const char *default_user);
};

extern MockCredentialsDBus *mock_credentials_dbus_singleton;

#endif /* !MOCK_CREDENTIALS_DBUS_HH */
