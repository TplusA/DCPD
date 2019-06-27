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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "mock_credentials_dbus.hh"

enum class CredentialsFn
{
    read_get_known_categories,
    read_get_credentials,
    read_get_default_credentials,
    write_set_credentials,
    write_set_default_username,
    write_delete_credentials,

    first_valid_credentials_fn_id = read_get_known_categories,
    last_valid_credentials_fn_id = write_delete_credentials,
};

static std::ostream &operator<<(std::ostream &os, const CredentialsFn id)
{
    if(id < CredentialsFn::first_valid_credentials_fn_id ||
       id > CredentialsFn::last_valid_credentials_fn_id)
    {
        os << "INVALID";
        return os;
    }

    switch(id)
    {
      case CredentialsFn::read_get_known_categories:
        os << "read_get_known_categories";
        break;

      case CredentialsFn::read_get_credentials:
        os << "read_get_credentials";
        break;

      case CredentialsFn::read_get_default_credentials:
        os << "read_get_default_credentials";
        break;

      case CredentialsFn::write_set_credentials:
        os << "write_set_credentials";
        break;

      case CredentialsFn::write_set_default_username:
        os << "write_set_default_username";
        break;

      case CredentialsFn::write_delete_credentials:
        os << "write_delete_credentials";
        break;
    }

    os << "()";

    return os;
}

class MockCredentialsDBus::Expectation
{
  public:
    struct Data
    {
        const CredentialsFn function_id_;

        bool ret_bool_;
        std::string ret_string_;
        const ReadGetKnownCategoriesData *ret_categories_data_;
        const ReadGetCredentialsData *ret_credentials_data_;
        bool arg_bool_;
        void *arg_object_;
        std::string arg_category_;
        std::string arg_username_;
        std::string arg_password_;
        std::string out_username_;
        std::string out_password_;

        explicit Data(CredentialsFn fn):
            function_id_(fn),
            ret_bool_(false),
            ret_categories_data_(nullptr),
            ret_credentials_data_(nullptr),
            arg_bool_(false),
            arg_object_(nullptr)
        {}
    };

    const Data d;

  private:
    /* writable reference for simple ctor code */
    Data &data_ = *const_cast<Data *>(&d);

  public:
    Expectation(const Expectation &) = delete;
    Expectation &operator=(const Expectation &) = delete;

    explicit Expectation(CredentialsFn fn, bool retval, tdbuscredentialsRead *object):
        d(fn)
    {
        data_.ret_bool_ = retval;
        data_.arg_object_ = static_cast<void *>(object);
    }

    explicit Expectation(CredentialsFn fn, bool retval, tdbuscredentialsWrite *object):
        d(fn)
    {
        data_.ret_bool_ = retval;
        data_.arg_object_ = static_cast<void *>(object);
    }

    explicit Expectation(gboolean retval, tdbuscredentialsRead *object,
                         const ReadGetKnownCategoriesData &categories):
        Expectation(CredentialsFn::read_get_known_categories, retval, object)
    {
        data_.ret_categories_data_ = &categories;
    }

    explicit Expectation(gboolean retval, tdbuscredentialsRead *object,
                         const ReadGetCredentialsData &credentials,
                         const std::string &default_user):
        Expectation(CredentialsFn::read_get_credentials, retval, object)
    {
        data_.ret_credentials_data_ = &credentials;
        data_.ret_string_ = default_user;
    }

    explicit Expectation(gboolean retval, tdbuscredentialsRead *object,
                         const char *category, const char *username,
                         const char *password):
        Expectation(CredentialsFn::read_get_default_credentials, retval, object)
    {
        data_.arg_category_ = category;
        data_.out_username_ = username;
        data_.out_password_ = password;
    }

    explicit Expectation(gboolean retval, tdbuscredentialsWrite *object,
                         const char *category, const char *username,
                         const char *password, gboolean is_default):
        Expectation(CredentialsFn::write_set_credentials, retval, object)
    {
        data_.arg_category_ = category;
        data_.arg_username_ = username;
        data_.arg_password_ = password;
        data_.arg_bool_ = is_default;
    }

    explicit Expectation(gboolean retval, tdbuscredentialsWrite *object,
                         const char *category, const char *username,
                         const char *default_user):
        Expectation(CredentialsFn::write_delete_credentials, retval, object)
    {
        data_.arg_category_ = category;
        data_.arg_username_ = username;
        data_.ret_string_ = default_user;
    }

    Expectation(Expectation &&) = default;
};

MockCredentialsDBus::MockCredentialsDBus()
{
    expectations_ = new MockExpectations();
}

MockCredentialsDBus::~MockCredentialsDBus()
{
    delete expectations_;
}

void MockCredentialsDBus::init()
{
    cppcut_assert_not_null(expectations_);
    expectations_->init();
}

void MockCredentialsDBus::check() const
{
    cppcut_assert_not_null(expectations_);
    expectations_->check();
}

void MockCredentialsDBus::expect_tdbus_credentials_read_call_get_known_categories_sync(gboolean retval, tdbuscredentialsRead *object, const ReadGetKnownCategoriesData &categories)
{
    expectations_->add(Expectation(retval, object, categories));
}

void MockCredentialsDBus::expect_tdbus_credentials_read_call_get_credentials_sync(gboolean retval, tdbuscredentialsRead *object, const ReadGetCredentialsData &credentials, const std::string &default_user)
{
    expectations_->add(Expectation(retval, object, credentials, default_user));
}

void MockCredentialsDBus::expect_tdbus_credentials_read_call_get_default_credentials_sync(gboolean retval, tdbuscredentialsRead *object, const gchar *arg_category, const gchar *out_username, const gchar *out_password)
{
    expectations_->add(Expectation(retval, object, arg_category, out_username, out_password));
}

void MockCredentialsDBus::expect_tdbus_credentials_write_call_set_credentials_sync(gboolean retval, tdbuscredentialsWrite *object, const char *category, const char *username, const char *password, gboolean is_default)
{
    expectations_->add(Expectation(retval, object, category, username, password, is_default));
}

void MockCredentialsDBus::expect_tdbus_credentials_write_call_delete_credentials_sync(gboolean retval, tdbuscredentialsWrite *object, const char *category, const char *username, const char *default_user)
{
    expectations_->add(Expectation(retval, object, category, username, default_user));
}

MockCredentialsDBus *mock_credentials_dbus_singleton = nullptr;

gboolean tdbus_credentials_read_call_get_known_categories_sync(tdbuscredentialsRead *proxy, GVariant **out_categories, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_credentials_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, CredentialsFn::read_get_known_categories);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));
    cppcut_assert_not_null(out_categories);
    cppcut_assert_not_null(expect.d.ret_categories_data_);

    GVariantBuilder builder;
    g_variant_builder_init(&builder, G_VARIANT_TYPE("a(ss)"));

    for(const auto &category : *expect.d.ret_categories_data_)
    {
        cppcut_assert_not_null(category.first);
        cppcut_assert_not_null(category.second);

        g_variant_builder_add(&builder, "(ss)", category.first, category.second);
    }

    *out_categories = g_variant_builder_end(&builder);

    if(error != NULL)
        *error = NULL;

    return expect.d.ret_bool_;
}

gboolean tdbus_credentials_read_call_get_credentials_sync(tdbuscredentialsRead *proxy, const gchar *arg_category, GVariant **out_credentials, gchar **out_default_user, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_credentials_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, CredentialsFn::read_get_credentials);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));
    cppcut_assert_not_null(out_credentials);
    cppcut_assert_not_null(out_default_user);
    cppcut_assert_not_null(expect.d.ret_credentials_data_);

    GVariantBuilder builder;
    g_variant_builder_init(&builder, G_VARIANT_TYPE("a(ss)"));

    for(const auto &category : *expect.d.ret_credentials_data_)
    {
        cppcut_assert_not_null(category.first);
        cppcut_assert_not_null(category.second);

        g_variant_builder_add(&builder, "(ss)", category.first, category.second);
    }

    *out_credentials = g_variant_builder_end(&builder);
    *out_default_user = g_strdup(expect.d.ret_string_.c_str());

    if(error != NULL)
        *error = NULL;

    return expect.d.ret_bool_;
}

gboolean tdbus_credentials_read_call_get_default_credentials_sync(tdbuscredentialsRead *proxy, const gchar *arg_category, gchar **out_username, gchar **out_password, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_credentials_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, CredentialsFn::read_get_default_credentials);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));
    cppcut_assert_equal(expect.d.arg_category_.c_str(), arg_category);
    cppcut_assert_not_null(out_username);
    cppcut_assert_not_null(out_password);

    *out_username = g_strdup(expect.d.out_username_.c_str());
    *out_password = g_strdup(expect.d.out_password_.c_str());

    if(error != NULL)
        *error = NULL;

    return expect.d.ret_bool_;
}

gboolean tdbus_credentials_write_call_set_credentials_sync(tdbuscredentialsWrite *proxy, const gchar *arg_category, const gchar *arg_username, const gchar *arg_password, gboolean arg_is_default, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_credentials_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, CredentialsFn::write_set_credentials);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));
    cppcut_assert_not_null(arg_category);
    cppcut_assert_not_null(arg_username);
    cppcut_assert_not_null(arg_password);

    cppcut_assert_equal(expect.d.arg_category_.c_str(), arg_category);
    cppcut_assert_equal(expect.d.arg_username_.c_str(), arg_username);
    cppcut_assert_equal(expect.d.arg_password_.c_str(), arg_password);
    cppcut_assert_equal(gboolean(expect.d.arg_bool_), arg_is_default);

    if(error != NULL)
        *error = NULL;

    return expect.d.ret_bool_;
}

gboolean tdbus_credentials_write_call_set_default_username_sync(tdbuscredentialsWrite *proxy, const gchar *arg_category, const gchar *arg_username, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_credentials_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, CredentialsFn::write_set_default_username);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));

    cut_fail("%s(): mock not implemented", __func__);

    if(error != NULL)
        *error = NULL;

    return expect.d.ret_bool_;
}

gboolean tdbus_credentials_write_call_delete_credentials_sync(tdbuscredentialsWrite *proxy, const gchar *arg_category, const gchar *arg_username, gchar **out_default_user, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_credentials_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, CredentialsFn::write_delete_credentials);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));
    cppcut_assert_not_null(arg_category);
    cppcut_assert_not_null(arg_username);
    cppcut_assert_not_null(out_default_user);

    cppcut_assert_equal(expect.d.arg_category_.c_str(), arg_category);
    cppcut_assert_equal(expect.d.arg_username_.c_str(), arg_username);

    *out_default_user = g_strdup(expect.d.ret_string_.c_str());

    if(error != NULL)
        *error = NULL;

    return expect.d.ret_bool_;
}
