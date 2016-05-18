/*
 * Copyright (C) 2016  T+A elektroakustik GmbH & Co. KG
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

#include "mock_airable_dbus.hh"

enum class AirableFn
{
    external_service_logout_sync,

    first_valid_airable_fn_id = external_service_logout_sync,
    last_valid_airable_fn_id = external_service_logout_sync,
};


static std::ostream &operator<<(std::ostream &os, const AirableFn id)
{
    if(id < AirableFn::first_valid_airable_fn_id ||
       id > AirableFn::last_valid_airable_fn_id)
    {
        os << "INVALID";
        return os;
    }

    switch(id)
    {
      case AirableFn::external_service_logout_sync:
        os << "external_service_logout_sync";
        break;
    }

    os << "()";

    return os;
}

class MockAirableDBus::Expectation
{
  public:
    struct Data
    {
        const AirableFn function_id_;

        bool ret_bool_;
        void *arg_object_;
        std::string arg_service_id_;
        std::string arg_url_;
        bool arg_is_request_;
        uint8_t arg_actor_id_;

        explicit Data(AirableFn fn):
            function_id_(fn),
            ret_bool_(false),
            arg_object_(nullptr),
            arg_is_request_(false),
            arg_actor_id_(UINT8_MAX)
        {}
    };

    const Data d;

  private:
    /* writable reference for simple ctor code */
    Data &data_ = *const_cast<Data *>(&d);

  public:
    Expectation(const Expectation &) = delete;
    Expectation &operator=(const Expectation &) = delete;

    explicit Expectation(AirableFn fn, bool retval, tdbusAirable *object,
                         const char *service_id, const char *url,
                         bool is_request, uint8_t actor_id):
        d(fn)
    {
        data_.ret_bool_ = retval;
        data_.arg_object_ = static_cast<void *>(object);
        data_.arg_service_id_ = service_id;
        data_.arg_url_ = url;
        data_.arg_is_request_ = is_request;
        data_.arg_actor_id_ = actor_id;
    }

    Expectation(Expectation &&) = default;
};


MockAirableDBus::MockAirableDBus()
{
    expectations_ = new MockExpectations();
}

MockAirableDBus::~MockAirableDBus()
{
    delete expectations_;
}

void MockAirableDBus::init()
{
    cppcut_assert_not_null(expectations_);
    expectations_->init();
}

void MockAirableDBus::check() const
{
    cppcut_assert_not_null(expectations_);
    expectations_->check();
}

void MockAirableDBus::expect_tdbus_airable_call_external_service_logout_sync(gboolean retval, tdbusAirable *object, const gchar *arg_service_id, const gchar *arg_url, gboolean arg_is_request, guchar arg_actor_id)
{
    expectations_->add(Expectation(AirableFn::external_service_logout_sync, retval, object, arg_service_id, arg_url, arg_is_request, arg_actor_id));
}


MockAirableDBus *mock_airable_dbus_singleton = nullptr;

gboolean tdbus_airable_call_external_service_logout_sync(tdbusAirable *proxy, const gchar *arg_service_id, const gchar *arg_url, gboolean arg_is_request, guchar arg_actor_id, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_airable_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, AirableFn::external_service_logout_sync);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));
    cppcut_assert_equal(expect.d.arg_service_id_.c_str(), arg_service_id);
    cppcut_assert_equal(expect.d.arg_url_.c_str(), arg_url);
    cppcut_assert_equal(gboolean(expect.d.arg_is_request_), arg_is_request);
    cppcut_assert_equal(int(expect.d.arg_actor_id_), int(arg_actor_id));

    if(error != NULL)
        *error = NULL;

    return expect.d.ret_bool_;
}

