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
    free_interface_data,

    first_valid_connman_fn_id = find_interface,
    last_valid_connman_fn_id = free_interface_data,
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

      case ConnmanFn::free_interface_data:
        os << "free_interface_data";
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
        struct ConnmanInterfaceData *ret_data_;
        struct ConnmanInterfaceData *arg_iface_data_;
        std::string arg_mac_address_;
        std::string arg_wired_mac_address_;
        std::string arg_wireless_mac_address_;

        explicit Data(ConnmanFn fn):
            function_id_(fn),
            ret_bool_(false),
            ret_data_(nullptr),
            arg_iface_data_(nullptr)
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

    explicit Expectation(struct ConnmanInterfaceData *iface_data):
        d(ConnmanFn::free_interface_data)
    {
        data_.arg_iface_data_ = iface_data;
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

void MockConnman::expect_connman_find_interface(struct ConnmanInterfaceData *ret, const char *mac_address)
{
    expectations_->add(Expectation(ret, mac_address));
}

void MockConnman::expect_connman_find_active_primary_interface(struct ConnmanInterfaceData *ret, const char *default_mac_address, const char *wired_mac_address, const char *wireless_mac_address)
{
    expectations_->add(Expectation(ret, default_mac_address, wired_mac_address, wireless_mac_address));
}

void MockConnman::expect_connman_get_dhcp_mode(bool ret, struct ConnmanInterfaceData *iface_data)
{
    expectations_->add(Expectation(ret, iface_data));
}

void MockConnman::expect_connman_free_interface_data(struct ConnmanInterfaceData *iface_data)
{
    expectations_->add(Expectation(iface_data));
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

void connman_free_interface_data(struct ConnmanInterfaceData *iface_data)
{
    const auto &expect(mock_connman_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, ConnmanFn::free_interface_data);
    cppcut_assert_equal(expect.d.arg_iface_data_, iface_data);
}