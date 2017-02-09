/*
 * Copyright (C) 2017  T+A elektroakustik GmbH & Co. KG
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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <cppcutter.h>

#include "mock_artcache_dbus.hh"

enum class ArtCacheFn
{
    read_get_scaled_image_data,

    first_valid_artcache_fn_id = read_get_scaled_image_data,
    last_valid_artcache_fn_id = read_get_scaled_image_data,
};


static std::ostream &operator<<(std::ostream &os, const ArtCacheFn id)
{
    if(id < ArtCacheFn::first_valid_artcache_fn_id ||
       id > ArtCacheFn::last_valid_artcache_fn_id)
    {
        os << "INVALID";
        return os;
    }

    switch(id)
    {
      case ArtCacheFn::read_get_scaled_image_data:
        os << "read_get_scaled_image_data";
        break;
    }

    os << "()";

    return os;
}

class MockArtCacheDBus::Expectation
{
  public:
    struct Data
    {
        const ArtCacheFn function_id_;

        bool ret_bool_;
        void *arg_object_;
        GVariantWrapper arg_stream_key_;
        std::string arg_format_;
        GVariantWrapper arg_hash_;
        ArtCache::ReadError read_error_;
        uint8_t image_priority_;
        GVariantWrapper image_hash_;
        GVariantWrapper image_data_;

        explicit Data(ArtCacheFn fn):
            function_id_(fn),
            ret_bool_(false),
            arg_object_(nullptr),
            read_error_(ArtCache::ReadError::INTERNAL),
            image_priority_(0)
        {}
    };

    const Data d;

  private:
    /* writable reference for simple ctor code */
    Data &data_ = *const_cast<Data *>(&d);

  public:
    Expectation(const Expectation &) = delete;
    Expectation &operator=(const Expectation &) = delete;

    explicit Expectation(ArtCacheFn fn, bool retval, tdbusartcacheRead *object,
                         GVariantWrapper &&stream_key, const char *format,
                         GVariantWrapper &&known_hash,
                         ArtCache::ReadError::Code read_error, uint8_t prio,
                         GVariantWrapper &&hash, GVariantWrapper &&image_data):
        d(fn)
    {
        data_.ret_bool_ = retval;
        data_.arg_object_ = static_cast<void *>(object);
        data_.arg_stream_key_ = std::move(stream_key);
        data_.arg_format_ = format;
        data_.arg_hash_ = std::move(known_hash);
        data_.read_error_ = read_error;
        data_.image_priority_ = prio;
        data_.image_hash_ = std::move(hash);
        data_.image_data_ = std::move(image_data);
    }

    Expectation(Expectation &&) = default;
};


MockArtCacheDBus::MockArtCacheDBus()
{
    expectations_ = new MockExpectations();
}

MockArtCacheDBus::~MockArtCacheDBus()
{
    delete expectations_;
}

void MockArtCacheDBus::init()
{
    cppcut_assert_not_null(expectations_);
    expectations_->init();
}

void MockArtCacheDBus::check() const
{
    cppcut_assert_not_null(expectations_);
    expectations_->check();
}

void MockArtCacheDBus::expect_tdbus_artcache_read_call_get_scaled_image_data_sync(gboolean retval, tdbusartcacheRead *object, GVariantWrapper &&arg_stream_key, const gchar *arg_format, GVariantWrapper &&arg_hash, ArtCache::ReadError::Code out_error_code, guchar out_image_priority, GVariantWrapper &&out_image_hash, GVariantWrapper &&out_image_data)
{
    expectations_->add(Expectation(ArtCacheFn::read_get_scaled_image_data,
                                   retval, object,
                                   std::move(arg_stream_key), arg_format,
                                   std::move(arg_hash), out_error_code, out_image_priority,
                                   std::move(out_image_hash), std::move(out_image_data)));
}


MockArtCacheDBus *mock_artcache_dbus_singleton = nullptr;

static void assert_variant_arrays_equal(GVariant *expected, GVariant *value)
{
    cppcut_assert_not_null(expected);
    cppcut_assert_not_null(value);

    gsize expected_len;
    gconstpointer expected_bytes =
        g_variant_get_fixed_array(expected, &expected_len, sizeof(uint8_t));

    gsize value_len;
    gconstpointer value_bytes =
        g_variant_get_fixed_array(value, &value_len, sizeof(uint8_t));

    cut_assert_equal_memory(expected_bytes, expected_len,
                            value_bytes, value_len);
}

gboolean tdbus_artcache_read_call_get_scaled_image_data_sync(tdbusartcacheRead *proxy, GVariant *arg_stream_key, const gchar *arg_format, GVariant *arg_hash, guchar *out_error_code, guchar *out_image_priority, GVariant **out_image_hash, GVariant **out_image_data, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_artcache_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, ArtCacheFn::read_get_scaled_image_data);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));
    cppcut_assert_equal(expect.d.arg_format_.c_str(), arg_format);

    assert_variant_arrays_equal(GVariantWrapper::get(expect.d.arg_stream_key_), arg_stream_key);
    assert_variant_arrays_equal(GVariantWrapper::get(expect.d.arg_hash_), arg_hash);

    *out_error_code = expect.d.read_error_.get_raw_code();
    *out_image_priority = expect.d.image_priority_;
    *out_image_hash = GVariantWrapper::get(expect.d.image_hash_);
    *out_image_data = GVariantWrapper::get(expect.d.image_data_);

    /* we could also use GVariantWrapper::move() above and avoid the refs here,
     * but it would mean giving up constness on the expectation object; we
     * would modify the expectation, making it harder to debug problems in case
     * of failure */
    g_variant_ref(*out_image_hash);
    g_variant_ref(*out_image_data);

    if(error != NULL)
        *error = NULL;

    return expect.d.ret_bool_;
}

