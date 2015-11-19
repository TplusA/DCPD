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
    get_ipv4_address_string,
    get_ipv4_netmask_string,
    get_ipv4_gateway_string,
    get_ipv4_primary_dns_string,
    get_ipv4_secondary_dns_string,
    get_wlan_security_type_string,
    get_wlan_ssid,
    free_interface_data,
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

      case ConnmanFn::get_ipv4_address_string:
        os << "get_ipv4_address_string";
        break;

      case ConnmanFn::get_ipv4_netmask_string:
        os << "get_ipv4_netmask_string";
        break;

      case ConnmanFn::get_ipv4_gateway_string:
        os << "get_ipv4_gateway_string";
        break;

      case ConnmanFn::get_ipv4_primary_dns_string:
        os << "get_ipv4_primary_dns_string";
        break;

      case ConnmanFn::get_ipv4_secondary_dns_string:
        os << "get_ipv4_secondary_dns_string";
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
        struct ConnmanInterfaceData *arg_iface_data_;
        std::string arg_mac_address_;
        std::string arg_wired_mac_address_;
        std::string arg_wireless_mac_address_;
        bool arg_pointer_shall_be_null_;
        size_t arg_dest_size_;
        SurveyCallbackInvocation callback_invocation_;
        enum ConnmanSiteScanResult callback_result_;

        explicit Data(ConnmanFn fn):
            function_id_(fn),
            ret_bool_(false),
            ret_bytes_(nullptr),
            ret_bytes_size_(123456),
            ret_data_(nullptr),
            arg_iface_data_(nullptr),
            arg_pointer_shall_be_null_(false),
            arg_dest_size_(9876543),
            callback_invocation_(nullptr),
            callback_result_(ConnmanSiteScanResult(CONNMAN_SITE_SCAN_RESULT_LAST + 1))
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
                         const char *wireless_mac_address):
        d(ConnmanFn::find_active_primary_interface)
    {
        data_.ret_data_ = ret;
        data_.arg_mac_address_ = default_mac_address;
        data_.arg_wired_mac_address_ = wired_mac_address;
        data_.arg_wireless_mac_address_ = wireless_mac_address;
    }

    explicit Expectation(bool ret, struct ConnmanInterfaceData *iface_data):
        d(ConnmanFn::get_dhcp_mode)
    {
        data_.ret_bool_ = ret;
        data_.arg_iface_data_ = iface_data;
    }

    explicit Expectation(bool ret, SurveyCallbackInvocation invocation,
                         enum ConnmanSiteScanResult callback_result):
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

    explicit Expectation(ConnmanFn fn, const char *ret_string,
                         struct ConnmanInterfaceData *iface_data,
                         bool expect_null_pointer, size_t dest_size,
                         bool ret = false):
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


MockConnman::MockConnman()
{
    expectations_ = new MockExpectations();
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

void MockConnman::expect_find_interface(struct ConnmanInterfaceData *ret, const char *mac_address)
{
    expectations_->add(Expectation(ret, mac_address));
}

void MockConnman::expect_find_active_primary_interface(struct ConnmanInterfaceData *ret, const char *default_mac_address, const char *wired_mac_address, const char *wireless_mac_address)
{
    expectations_->add(Expectation(ret, default_mac_address, wired_mac_address, wireless_mac_address));
}

void MockConnman::expect_get_dhcp_mode(bool ret, struct ConnmanInterfaceData *iface_data)
{
    expectations_->add(Expectation(ret, iface_data));
}

void MockConnman::expect_get_ipv4_address_string(const char *ret_string, struct ConnmanInterfaceData *iface_data, bool expect_null_pointer, size_t dest_size)
{
    expectations_->add(Expectation(ConnmanFn::get_ipv4_address_string,
                                   ret_string, iface_data, expect_null_pointer, dest_size));
}

void MockConnman::expect_get_ipv4_netmask_string(const char *ret_string, struct ConnmanInterfaceData *iface_data, bool expect_null_pointer, size_t dest_size)
{
    expectations_->add(Expectation(ConnmanFn::get_ipv4_netmask_string,
                                   ret_string, iface_data, expect_null_pointer, dest_size));
}

void MockConnman::expect_get_ipv4_gateway_string(const char *ret_string, struct ConnmanInterfaceData *iface_data, bool expect_null_pointer, size_t dest_size)
{
    expectations_->add(Expectation(ConnmanFn::get_ipv4_gateway_string,
                                   ret_string, iface_data, expect_null_pointer, dest_size));
}

void MockConnman::expect_get_ipv4_primary_dns_string(const char *ret_string, struct ConnmanInterfaceData *iface_data,  bool expect_null_pointer, size_t dest_size)
{
    expectations_->add(Expectation(ConnmanFn::get_ipv4_primary_dns_string,
                                   ret_string, iface_data, expect_null_pointer, dest_size));
}

void MockConnman::expect_get_ipv4_secondary_dns_string(const char *ret_string, struct ConnmanInterfaceData *iface_data,  bool expect_null_pointer, size_t dest_size)
{
    expectations_->add(Expectation(ConnmanFn::get_ipv4_secondary_dns_string,
                                   ret_string, iface_data, expect_null_pointer, dest_size));
}

void MockConnman::expect_get_wlan_security_type_string(bool ret, const char *ret_string, struct ConnmanInterfaceData *iface_data, bool expect_null_pointer, size_t dest_size)
{
    expectations_->add(Expectation(ConnmanFn::get_wlan_security_type_string,
                                   ret_string, iface_data, expect_null_pointer, dest_size, ret));
}

void MockConnman::expect_get_wlan_ssid(const uint8_t *ret_bytes, size_t ret_bytes_size, struct ConnmanInterfaceData *iface_data, bool expect_null_pointer, size_t dest_size)
{
    expectations_->add(Expectation(ConnmanFn::get_wlan_ssid,
                                   ret_bytes, ret_bytes_size, iface_data,
                                   expect_null_pointer, dest_size));
}

void MockConnman::expect_free_interface_data(struct ConnmanInterfaceData *iface_data)
{
    expectations_->add(Expectation(iface_data));
}

void MockConnman::expect_connman_start_wlan_site_survey(bool ret)
{
    expectations_->add(Expectation(ret, nullptr,
                                   ConnmanSiteScanResult(CONNMAN_SITE_SCAN_RESULT_LAST + 1)));
}

void MockConnman::expect_connman_start_wlan_site_survey(bool ret, SurveyCallbackInvocation callback_invocation, enum ConnmanSiteScanResult callback_result)
{
    expectations_->add(Expectation(ret, callback_invocation, callback_result));
}


MockConnman *mock_connman_singleton = nullptr;

struct ConnmanInterfaceData *connman_find_interface(const char *mac_address)
{
    const auto &expect(mock_connman_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, ConnmanFn::find_interface);
    cppcut_assert_equal(expect.d.arg_mac_address_, std::string(mac_address));

    return expect.d.ret_data_;
}

struct ConnmanInterfaceData *
connman_find_active_primary_interface(const char *default_mac_address,
                                      const char *wired_mac_address,
                                      const char *wireless_mac_address)
{
    const auto &expect(mock_connman_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, ConnmanFn::find_active_primary_interface);
    cppcut_assert_equal(expect.d.arg_mac_address_, std::string(default_mac_address));
    cppcut_assert_equal(expect.d.arg_wired_mac_address_, std::string(wired_mac_address));
    cppcut_assert_equal(expect.d.arg_wireless_mac_address_, std::string(wireless_mac_address));

    return expect.d.ret_data_;
}

bool connman_get_dhcp_mode(struct ConnmanInterfaceData *iface_data)
{
    const auto &expect(mock_connman_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, ConnmanFn::get_dhcp_mode);
    cppcut_assert_equal(expect.d.arg_iface_data_, iface_data);

    return expect.d.ret_bool_;
}

static void get_ipv4_parameter_string(const MockConnman::Expectation &expect,
                                      struct ConnmanInterfaceData *iface_data,
                                      char *dest, size_t dest_size)
{
    cppcut_assert_equal(expect.d.arg_iface_data_, iface_data);
    cppcut_assert_equal(expect.d.arg_dest_size_, dest_size);

    if(expect.d.arg_pointer_shall_be_null_)
        cppcut_assert_null(dest);
    else
    {
        cppcut_assert_not_null(dest);

        if(dest_size > 0)
        {
            if(expect.d.ret_string_.size() > 0)
            {
                strncpy(dest, expect.d.ret_string_.c_str(), dest_size);
                dest[dest_size - 1] = '\0';
            }
            else
                dest[0] = '\0';
        }
    }
}

void connman_get_ipv4_address_string(struct ConnmanInterfaceData *iface_data,
                                     char *dest, size_t dest_size)
{
    const auto &expect(mock_connman_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, ConnmanFn::get_ipv4_address_string);
    get_ipv4_parameter_string(expect, iface_data, dest, dest_size);
}

void connman_get_ipv4_netmask_string(struct ConnmanInterfaceData *iface_data,
                                     char *dest, size_t dest_size)
{
    const auto &expect(mock_connman_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, ConnmanFn::get_ipv4_netmask_string);
    get_ipv4_parameter_string(expect, iface_data, dest, dest_size);
}

void connman_get_ipv4_gateway_string(struct ConnmanInterfaceData *iface_data,
                                     char *dest, size_t dest_size)
{
    const auto &expect(mock_connman_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, ConnmanFn::get_ipv4_gateway_string);
    get_ipv4_parameter_string(expect, iface_data, dest, dest_size);
}

void connman_get_ipv4_primary_dns_string(struct ConnmanInterfaceData *iface_data,
                                         char *dest, size_t dest_size)
{
    const auto &expect(mock_connman_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, ConnmanFn::get_ipv4_primary_dns_string);
    get_ipv4_parameter_string(expect, iface_data, dest, dest_size);
}

void connman_get_ipv4_secondary_dns_string(struct ConnmanInterfaceData *iface_data,
                                           char *dest, size_t dest_size)
{
    const auto &expect(mock_connman_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, ConnmanFn::get_ipv4_secondary_dns_string);
    get_ipv4_parameter_string(expect, iface_data, dest, dest_size);
}

bool connman_get_wlan_security_type_string(struct ConnmanInterfaceData *iface_data,
                                           char *dest, size_t dest_size)
{
    const auto &expect(mock_connman_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, ConnmanFn::get_wlan_security_type_string);
    get_ipv4_parameter_string(expect, iface_data, dest, dest_size);

    return expect.d.ret_bool_;
}

size_t connman_get_wlan_ssid(struct ConnmanInterfaceData *iface_data,
                             uint8_t *dest, size_t dest_size)
{
    const auto &expect(mock_connman_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, ConnmanFn::get_wlan_ssid);
    cppcut_assert_equal(expect.d.arg_iface_data_, iface_data);
    cppcut_assert_equal(expect.d.arg_dest_size_, dest_size);

    if(expect.d.arg_pointer_shall_be_null_)
    {
        cppcut_assert_null(dest);
        return 0;
    }

    cppcut_assert_not_null(dest);

    if(dest_size == 0)
        return 0;

    const size_t count = std::min(expect.d.ret_bytes_size_, dest_size);

    if(count > 0)
        memcpy(dest, expect.d.ret_bytes_, count);

    return count;
}

void connman_free_interface_data(struct ConnmanInterfaceData *iface_data)
{
    const auto &expect(mock_connman_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, ConnmanFn::free_interface_data);
    cppcut_assert_equal(expect.d.arg_iface_data_, iface_data);
}

bool connman_start_wlan_site_survey(ConnmanSurveyDoneFn callback)
{
    const auto &expect(mock_connman_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, ConnmanFn::start_wlan_site_survey);
    cppcut_assert_not_null(reinterpret_cast<void *>(callback));

    if(expect.d.callback_invocation_ != nullptr)
        expect.d.callback_invocation_(callback, expect.d.callback_result_);

    return expect.d.ret_bool_;
}
