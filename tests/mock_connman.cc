/*
 * Copyright (C) 2015--2019, 2023  T+A elektroakustik GmbH & Co. KG
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

#include <cppcutter.h>

#include "mock_connman.hh"

enum class ConnmanFn
{
    find_interface,
    find_active_primary_interface,
    get_dhcp_mode,
    get_address_string,
    get_netmask_string,
    get_gateway_string,
    get_primary_dns_string,
    get_secondary_dns_string,
    get_wlan_security_type_string,
    get_wlan_ssid,
    free_interface_data,
    service_iterator_get,
    service_iterator_rewind,
    service_iterator_next,
    service_iterator_free,
    service_iterator_get_technology_type,
    service_iterator_get_ssid,
    service_iterator_get_strength,
    service_iterator_get_security_iterator,
    security_iterator_next,
    security_iterator_free,
    security_iterator_get_security,
    start_wlan_site_survey,

    first_valid_connman_fn_id = find_interface,
    last_valid_connman_fn_id = start_wlan_site_survey,
};

static std::ostream &operator<<(std::ostream &os, const ConnmanFn id)
{
    if(id < ConnmanFn::first_valid_connman_fn_id ||
       id > ConnmanFn::last_valid_connman_fn_id)
    {
        os << "INVALID";
        return os;
    }

    switch(id)
    {
      case ConnmanFn::find_interface:
        os << "find_interface";
        break;

      case ConnmanFn::find_active_primary_interface:
        os << "find_active_primary_interface";
        break;

      case ConnmanFn::get_dhcp_mode:
        os << "get_dhcp_mode";
        break;

      case ConnmanFn::get_address_string:
        os << "get_address_string";
        break;

      case ConnmanFn::get_netmask_string:
        os << "get_netmask_string";
        break;

      case ConnmanFn::get_gateway_string:
        os << "get_gateway_string";
        break;

      case ConnmanFn::get_primary_dns_string:
        os << "get_primary_dns_string";
        break;

      case ConnmanFn::get_secondary_dns_string:
        os << "get_secondary_dns_string";
        break;

      case ConnmanFn::get_wlan_security_type_string:
        os << "get_wlan_security_type_string";
        break;

      case ConnmanFn::get_wlan_ssid:
        os << "get_wlan_ssid";
        break;

      case ConnmanFn::free_interface_data:
        os << "free_interface_data";
        break;

      case ConnmanFn::service_iterator_get:
        os << "service_iterator_get";
        break;

      case ConnmanFn::service_iterator_rewind:
        os << "service_iterator_rewind";
        break;

      case ConnmanFn::service_iterator_next:
        os << "service_iterator_next";
        break;

      case ConnmanFn::service_iterator_free:
        os << "service_iterator_free";
        break;

      case ConnmanFn::service_iterator_get_technology_type:
        os << "service_iterator_get_technology_type";
        break;

      case ConnmanFn::service_iterator_get_ssid:
        os << "service_iterator_get_ssid";
        break;

      case ConnmanFn::service_iterator_get_strength:
        os << "service_iterator_get_strength";
        break;

      case ConnmanFn::service_iterator_get_security_iterator:
        os << "service_iterator_get_security_iterator";
        break;

      case ConnmanFn::security_iterator_next:
        os << "security_iterator_next";
        break;

      case ConnmanFn::security_iterator_free:
        os << "security_iterator_free";
        break;

      case ConnmanFn::security_iterator_get_security:
        os << "security_iterator_get_security";
        break;

      case ConnmanFn::start_wlan_site_survey:
        os << "start_wlan_site_survey";
        break;
    }

    os << "()";

    return os;
}

class MockConnman::Expectation
{
  public:
    struct Data
    {
        const ConnmanFn function_id_;

        bool ret_bool_;
        std::string ret_string_;
        const uint8_t *ret_bytes_;
        size_t ret_bytes_size_;
        struct ConnmanInterfaceData *ret_data_;
        struct ConnmanInterfaceData *ret_fallback_data_;
        struct ConnmanInterfaceData *arg_iface_data_;
        std::string arg_mac_address_;
        std::string arg_wired_mac_address_;
        std::string arg_wireless_mac_address_;
        bool arg_pointer_shall_be_null_;
        size_t arg_dest_size_;
        SurveyCallbackInvocation callback_invocation_;
        Connman::SiteSurveyResult callback_result_;
        struct ConnmanServiceIterator *service_iterator_;

        explicit Data(ConnmanFn fn):
            function_id_(fn),
            ret_bool_(false),
            ret_bytes_(nullptr),
            ret_bytes_size_(123456),
            ret_data_(nullptr),
            ret_fallback_data_(nullptr),
            arg_iface_data_(nullptr),
            arg_pointer_shall_be_null_(false),
            arg_dest_size_(9876543),
            callback_invocation_(nullptr),
            callback_result_(Connman::SiteSurveyResult(int(Connman::SiteSurveyResult::LAST_VALUE) + 1)),
            service_iterator_(nullptr)
        {}
    };

    const Data d;

  private:
    /* writable reference for simple ctor code */
    Data &data_ = *const_cast<Data *>(&d);

  public:
    Expectation(const Expectation &) = delete;
    Expectation &operator=(const Expectation &) = delete;

    explicit Expectation(struct ConnmanInterfaceData *ret, const char *mac_address):
        d(ConnmanFn::find_interface)
    {
        data_.ret_data_ = ret;
        data_.arg_mac_address_ = mac_address;
    }

    explicit Expectation(struct ConnmanInterfaceData *ret,
                         const char *default_mac_address,
                         const char *wired_mac_address,
                         const char *wireless_mac_address,
                         struct ConnmanInterfaceData *ret_fallback):
        d(ConnmanFn::find_active_primary_interface)
    {
        data_.ret_data_ = ret;
        data_.arg_mac_address_ = default_mac_address;
        data_.arg_wired_mac_address_ = wired_mac_address;
        data_.arg_wireless_mac_address_ = wireless_mac_address;
        data_.ret_fallback_data_ = ret_fallback;
    }

    explicit Expectation(bool ret, SurveyCallbackInvocation invocation,
                         Connman::SiteSurveyResult callback_result):
        d(ConnmanFn::start_wlan_site_survey)
    {
        data_.ret_bool_ = ret;
        data_.callback_invocation_ = invocation;
        data_.callback_result_ = callback_result;
    }

    explicit Expectation(struct ConnmanInterfaceData *iface_data):
        d(ConnmanFn::free_interface_data)
    {
        data_.arg_iface_data_ = iface_data;
    }

    explicit Expectation(ConnmanFn fn, struct ConnmanServiceIterator *iter):
        d(fn)
    {
        data_.service_iterator_ = iter;
    }

    explicit Expectation(ConnmanFn fn, bool ret, struct ConnmanServiceIterator *iter):
        d(fn)
    {
        data_.ret_bool_ = ret;
        data_.service_iterator_ = iter;
    }

    explicit Expectation(ConnmanFn fn, const char *ret_string,
                         struct ConnmanInterfaceData *iface_data,
                         bool expect_null_pointer, size_t dest_size,
                         bool ret):
        d(fn)
    {
        if(ret_string != NULL)
            data_.ret_string_ = ret_string;
        else
            data_.ret_string_ = "";

        data_.ret_bool_ = ret;
        data_.arg_iface_data_ = iface_data;
        data_.arg_pointer_shall_be_null_ = expect_null_pointer;
        data_.arg_dest_size_ = dest_size;
    }

    explicit Expectation(ConnmanFn fn,
                         const uint8_t *ret_bytes, size_t ret_bytes_size,
                         struct ConnmanInterfaceData *iface_data,
                         bool expect_null_pointer, size_t dest_size):
        d(fn)
    {
        data_.ret_bytes_ = ret_bytes;
        data_.ret_bytes_size_ = ret_bytes_size;
        data_.arg_iface_data_ = iface_data;
        data_.arg_pointer_shall_be_null_ = expect_null_pointer;
        data_.arg_dest_size_ = dest_size;
    }

    Expectation(Expectation &&) = default;
};


/*
 * Internal iterator implementation for mock.
 */
struct ConnmanServiceSecurityIterator
{
    MockConnman::AnyIter<MockConnman::SecurityIterData> data;

    explicit ConnmanServiceSecurityIterator(const MockConnman::SecurityIterData *const entries,
                                            size_t num_of_entries):
        data(entries, num_of_entries)
    {}

    void rewind() { data.rewind(); }
    bool next()   { return data.next(); }


    const char *get_security() { return data.get().security_; }
};

/*
 * Internal iterator implementation for mock.
 */
struct ConnmanServiceIterator
{
    MockConnman::AnyIter<MockConnman::ServiceIterData> data;

    explicit ConnmanServiceIterator(const MockConnman::ServiceIterData *const entries,
                                    size_t num_of_entries):
        data(entries, num_of_entries)
    {}

    void rewind() { data.rewind(); }
    bool next()   { return data.next(); }

    const char *get_technology_type() { return data.get().technology_type_; }
    const char *get_ssid() { return data.get().ssid_; }
    int get_strength() { return data.get().quality_; }

    struct ConnmanServiceSecurityIterator *get_security_iterator(size_t &count)
    {
        const MockConnman::ServiceIterData &d(data.get());

        count = d.security_data_count_;

        return new ConnmanServiceSecurityIterator(d.security_data_,
                                                  d.security_data_count_);
    }
};

MockConnman::MockConnman()
{
    expectations_ = new MockExpectations();

    iter_data_ = nullptr;
    iter_data_count_ = 0;
}

MockConnman::~MockConnman()
{
    delete expectations_;
}

void MockConnman::init()
{
    cppcut_assert_not_null(expectations_);
    expectations_->init();
}

void MockConnman::check() const
{
    cppcut_assert_not_null(expectations_);
    expectations_->check();
}

void MockConnman::set_connman_service_iterator_data(const MockConnman::ServiceIterData &iter_data,
                                                    size_t number_of_services)
{
    cppcut_assert_null(iter_data_);

    iter_data_ = &iter_data;
    iter_data_count_ = number_of_services;
}

struct ConnmanServiceIterator *MockConnman::do_service_iterator_get()
{
    cppcut_assert_not_null(iter_data_);
    return new ConnmanServiceIterator(iter_data_, iter_data_count_);
}

void MockConnman::expect_connman_service_iterator_get(struct ConnmanServiceIterator *ret)
{
    expectations_->add(Expectation(ConnmanFn::service_iterator_get, ret));
}

void MockConnman::expect_connman_service_iterator_rewind(struct ConnmanServiceIterator *iter)
{
    expectations_->add(Expectation(ConnmanFn::service_iterator_rewind, iter));
}

void MockConnman::expect_connman_service_iterator_next(bool ret, struct ConnmanServiceIterator *iter)
{
    expectations_->add(Expectation(ConnmanFn::service_iterator_next, ret, iter));
}

void MockConnman::expect_connman_service_iterator_free(struct ConnmanServiceIterator *iter)
{
    expectations_->add(Expectation(ConnmanFn::service_iterator_free, iter));
}

/*
void MockConnman::expect_connman_service_iterator_get_technology_type(const char *ret, struct ConnmanServiceIterator *iter);
void MockConnman::expect_connman_service_iterator_get_ssid(const char *ret, struct ConnmanServiceIterator *iter);
void MockConnman::expect_connman_service_iterator_get_strength(int ret, struct ConnmanServiceIterator *iter);
void MockConnman::expect_connman_service_iterator_get_security_iterator(struct ConnmanServiceSecurityIterator *ret, struct ConnmanServiceIterator *iter, size_t *count);
void MockConnman::expect_connman_security_iterator_next(bool ret, struct ConnmanServiceSecurityIterator *iter);
void MockConnman::expect_connman_security_iterator_free(struct ConnmanServiceSecurityIterator *iter);
void MockConnman::expect_connman_security_iterator_get_security(const char *ret, struct ConnmanServiceSecurityIterator *iter);
*/

void MockConnman::expect_connman_start_wlan_site_survey(bool ret)
{
    expectations_->add(Expectation(ret, nullptr,
                                   Connman::SiteSurveyResult(int(Connman::SiteSurveyResult::LAST_VALUE) + 1)));
}

void MockConnman::expect_connman_start_wlan_site_survey(bool ret, SurveyCallbackInvocation callback_invocation, Connman::SiteSurveyResult callback_result)
{
    expectations_->add(Expectation(ret, callback_invocation, callback_result));
}


MockConnman *mock_connman_singleton = nullptr;

const MockConnman::SecurityIterData MockConnman::sec_psk_wps[] =
{
    MockConnman::SecurityIterData("psk"),
    MockConnman::SecurityIterData("wps"),
};

const MockConnman::SecurityIterData MockConnman::sec_none("none");

const MockConnman::SecurityIterData MockConnman::sec_psk("psk");

struct ConnmanServiceIterator *connman_service_iterator_get()
{
    if(mock_connman_singleton->have_iter_data())
        return mock_connman_singleton->do_service_iterator_get();

    const auto &expect(mock_connman_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, ConnmanFn::service_iterator_get);

    return expect.d.service_iterator_;
}

void connman_service_iterator_rewind(struct ConnmanServiceIterator *iter)
{
    if(mock_connman_singleton->have_iter_data())
        return iter->rewind();

    const auto &expect(mock_connman_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, ConnmanFn::service_iterator_rewind);
    cppcut_assert_equal(expect.d.service_iterator_, iter);
}

bool connman_service_iterator_next(struct ConnmanServiceIterator *iter)
{
    if(mock_connman_singleton->have_iter_data())
        return iter->next();

    const auto &expect(mock_connman_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, ConnmanFn::service_iterator_next);
    cppcut_assert_equal(expect.d.service_iterator_, iter);

    return expect.d.ret_bool_;
}

void connman_service_iterator_free(struct ConnmanServiceIterator *iter)
{
    if(mock_connman_singleton->have_iter_data())
    {
        cppcut_assert_not_null(iter);
        delete iter;
        return;
    }

    const auto &expect(mock_connman_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, ConnmanFn::service_iterator_free);
    cppcut_assert_equal(expect.d.service_iterator_, iter);
}

const char *connman_service_iterator_get_technology_type(struct ConnmanServiceIterator *iter)
{
    if(mock_connman_singleton->have_iter_data())
        return iter->get_technology_type();

    cut_fail("not implemented");
    return NULL;
}

const char *connman_service_iterator_get_ssid(struct ConnmanServiceIterator *iter)
{
    if(mock_connman_singleton->have_iter_data())
        return iter->get_ssid();

    cut_fail("not implemented");
    return NULL;
}

int connman_service_iterator_get_strength(struct ConnmanServiceIterator *iter)
{
    if(mock_connman_singleton->have_iter_data())
        return iter->get_strength();

    cut_fail("not implemented");
    return -1;
}

struct ConnmanServiceSecurityIterator *
connman_service_iterator_get_security_iterator(struct ConnmanServiceIterator *iter,
                                               size_t *count)
{
    if(mock_connman_singleton->have_iter_data())
        return iter->get_security_iterator(*count);

    cut_fail("not implemented");
    return NULL;
}

bool connman_security_iterator_next(struct ConnmanServiceSecurityIterator *iter)
{
    if(mock_connman_singleton->have_iter_data())
        return iter->next();

    cut_fail("not implemented");
    return false;
}

void connman_security_iterator_free(struct ConnmanServiceSecurityIterator *iter)
{
    if(mock_connman_singleton->have_iter_data())
    {
        cppcut_assert_not_null(iter);
        delete iter;
        return;
    }

    cut_fail("not implemented");
}

const char *connman_security_iterator_get_security(struct ConnmanServiceSecurityIterator *iter)
{
    if(mock_connman_singleton->have_iter_data())
        return iter->get_security();

    cut_fail("not implemented");
    return NULL;
}
