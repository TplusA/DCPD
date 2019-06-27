/*
 * Copyright (C) 2017, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef MOCK_ARTCACHE_DBUS_HH
#define MOCK_ARTCACHE_DBUS_HH

#include "artcache_dbus.h"
#include "de_tahifi_artcache_errors.hh"
#include "mock_expectation.hh"
#include "gvariantwrapper.hh"

class MockArtCacheDBus
{
  public:
    MockArtCacheDBus(const MockArtCacheDBus &) = delete;
    MockArtCacheDBus &operator=(const MockArtCacheDBus &) = delete;

    class Expectation;
    typedef MockExpectationsTemplate<Expectation> MockExpectations;
    MockExpectations *expectations_;

    explicit MockArtCacheDBus();
    ~MockArtCacheDBus();

    void init();
    void check() const;

    void expect_tdbus_artcache_read_call_get_scaled_image_data_sync(gboolean retval, tdbusartcacheRead *object, GVariantWrapper &&arg_stream_key, const gchar *arg_format, GVariantWrapper &&arg_hash, ArtCache::ReadError::Code out_error_code, guchar out_image_priority, GVariantWrapper &&out_image_hash, GVariantWrapper &&out_image_data);
};

extern MockArtCacheDBus *mock_artcache_dbus_singleton;

#endif /* !MOCK_ARTCACHE_DBUS_HH */
