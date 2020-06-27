/*
 * Copyright (C) 2020  T+A elektroakustik GmbH & Co. KG
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
#include <algorithm>

#include "registers.hh"
#include "connman_service_list.hh"
#include "network_device_list.hh"
#include "networkprefs.h"
#include "network_status_bits.h"
#include "dcpregs_networkconfig.hh"
#include "dbus_handlers_connman_manager.hh"
#include "mainloop.hh"

#include "mock_connman.hh"
#include "mock_messages.hh"
#include "mock_backtrace.hh"
#include "mock_os.hh"

#include "test_registers_common.hh"

#if LOGGED_LOCKS_ENABLED && LOGGED_LOCKS_THREAD_CONTEXTS
thread_local LoggedLock::Context LoggedLock::context;
#endif

MainLoop::Queue MainLoop::detail::queued_work;

/*!
 * \addtogroup registers_tests Unit tests
 */
/*!@{*/

static ssize_t test_os_read(int fd, void *dest, size_t count)
{
    cut_fail("Unexpected call of os_read()");
    return -99999;
}

ssize_t (*os_read)(int fd, void *dest, size_t count) = test_os_read;

class ConnectToConnManServiceData
{
  public:
    enum class Mode
    {
        NONE,
        FROM_CONFIG,
        WPS_DIRECT_BY_SSID,
        WPS_DIRECT_BY_NAME,
        WPS_SCAN,
    };

  private:
    Mode expected_mode_;
    enum NetworkPrefsTechnology expected_tech_;
    std::string expected_service_;
    const char *expected_service_cstr_;
    std::string expected_network_name_;
    const char *expected_network_name_cstr_;
    std::vector<uint8_t> expected_network_ssid_;

    Mode called_mode_;

  public:
    ConnectToConnManServiceData(const ConnectToConnManServiceData &) = delete;
    ConnectToConnManServiceData &operator=(const ConnectToConnManServiceData &) = delete;

    explicit ConnectToConnManServiceData() { init(); }

    void init()
    {
        expected_mode_ = Mode::NONE;
        expected_tech_ = NWPREFSTECH_UNKNOWN;
        expected_service_.clear();
        expected_service_cstr_ = nullptr;
        expected_network_name_.clear();
        expected_network_name_cstr_ = nullptr;
        expected_network_ssid_.clear();
        expected_network_ssid_.shrink_to_fit();
        called_mode_ = Mode::NONE;
    }

    void expect(enum NetworkPrefsTechnology expected_tech,
                const char *expected_service_to_be_disabled)
    {
        cppcut_assert_not_equal(NWPREFSTECH_UNKNOWN, expected_tech);

        expected_mode_ = Mode::FROM_CONFIG;
        expected_tech_ = expected_tech;

        if(expected_service_to_be_disabled != nullptr)
        {
            expected_service_ = expected_service_to_be_disabled;
            expected_service_cstr_ = expected_service_.c_str();
        }

        called_mode_ = Mode::NONE;
    }

    void expect(const char *expected_service_to_be_disabled,
                const char *expected_network_name,
                const std::vector<uint8_t> *expected_network_ssid)
    {
        if(expected_service_to_be_disabled != nullptr)
        {
            expected_service_ = expected_service_to_be_disabled;
            expected_service_cstr_ = expected_service_.c_str();
        }

        if(expected_network_name != nullptr)
        {
            expected_network_name_ = expected_network_name;
            expected_network_name_cstr_ = expected_network_name_.c_str();
            expected_mode_ = Mode::WPS_DIRECT_BY_NAME;
        }
        else if(expected_network_ssid != nullptr)
        {
            expected_network_ssid_ = *expected_network_ssid;
            expected_mode_ = Mode::WPS_DIRECT_BY_SSID;
        }
        else
            expected_mode_ = Mode::WPS_SCAN;

        called_mode_ = Mode::NONE;
    }

    void called(enum NetworkPrefsTechnology tech,
                const char *service_to_be_disabled, bool immediate_activation,
                bool force_reconnect)
    {
        cppcut_assert_equal(Mode::FROM_CONFIG, expected_mode_);
        cppcut_assert_equal(Mode::NONE, called_mode_);

        called_mode_ = Mode::FROM_CONFIG;

        cppcut_assert_equal(expected_tech_, tech);
        cppcut_assert_equal(expected_service_cstr_, service_to_be_disabled);
        cut_assert_true(immediate_activation);
    }

    void called(const char *network_name, const char *network_ssid,
                const char *service_to_be_disabled)
    {
        cppcut_assert_equal(Mode::NONE, called_mode_);

        switch(expected_mode_)
        {
          case Mode::NONE:
            cut_fail("Unexpected mode NONE");
            break;

          case Mode::FROM_CONFIG:
            cut_fail("Unexpected mode FROM_CONFIG");
            break;

          case Mode::WPS_DIRECT_BY_SSID:
            called_mode_ = expected_mode_;

            {
                std::string temp;
                for(const uint8_t &byte : expected_network_ssid_)
                {
                    temp.push_back(nibble_to_char(byte >> 4));
                    temp.push_back(nibble_to_char(byte & 0x0f));
                }

                cppcut_assert_equal(temp.c_str(), network_ssid);
            }

            break;

          case Mode::WPS_DIRECT_BY_NAME:
            called_mode_ = expected_mode_;
            cppcut_assert_equal(expected_network_name_cstr_, network_name);
            cppcut_assert_null(network_ssid);
            break;

          case Mode::WPS_SCAN:
            called_mode_ = expected_mode_;
            cppcut_assert_null(network_name);
            cppcut_assert_null(network_ssid);
            break;
        }

        cppcut_assert_equal(expected_service_cstr_, service_to_be_disabled);
    }

    void check()
    {
        cppcut_assert_equal(expected_mode_, called_mode_);
        init();
    }

  private:
    static char nibble_to_char(uint8_t nibble)
    {
        return (nibble < 10) ? '0' + nibble : 'a' + nibble - 10;
    }
};

static std::ostream &operator<<(std::ostream &os, ConnectToConnManServiceData::Mode mode)
{
    switch(mode)
    {
      case ConnectToConnManServiceData::Mode::NONE:
        os << "NONE";
        break;

      case ConnectToConnManServiceData::Mode::FROM_CONFIG:
        os << "FROM_CONFIG";
        break;

      case ConnectToConnManServiceData::Mode::WPS_DIRECT_BY_SSID:
        os << "WPS_DIRECT_BY_SSID";
        break;

      case ConnectToConnManServiceData::Mode::WPS_DIRECT_BY_NAME:
        os << "WPS_DIRECT_BY_NAME";
        break;

      case ConnectToConnManServiceData::Mode::WPS_SCAN:
        os << "WPS_SCAN";
        break;
    }

    return os;
}

static ConnectToConnManServiceData connect_to_connman_service_data;

class CancelWPSData
{
  private:
    bool expected_call_;
    bool was_called_;

  public:
    CancelWPSData(const CancelWPSData &) = delete;
    CancelWPSData &operator=(const CancelWPSData &) = delete;

    explicit CancelWPSData() { init(); }

    void init()
    {
        expected_call_ = false;
        was_called_ = false;
    }

    void expect()
    {
        expected_call_ = true;
    }

    void called()
    {
        cut_assert_true(expected_call_);
        was_called_ = true;
    }

    void check()
    {
        cppcut_assert_equal(expected_call_, was_called_);
        init();
    }
};

static CancelWPSData cancel_wps_data;

/* Instead of writing a full mock for the ConnMan D-Bus API, we'll just have
 * this little function as a poor, but quick replacement */
void Connman::connect_to_service(enum NetworkPrefsTechnology tech,
                                 const char *service_to_be_disabled,
                                 bool immediate_activation, bool force_reconnect)
{
    connect_to_connman_service_data.called(tech, service_to_be_disabled,
                                           immediate_activation,
                                           force_reconnect);
}

/* Another quick replacement for the Connman D-Bus API */
void Connman::connect_to_wps_service(const char *network_name, const char *network_ssid,
                                     const char *service_to_be_disabled)
{
    connect_to_connman_service_data.called(network_name, network_ssid,
                                           service_to_be_disabled);
}

/* And another quick replacement. Should write a mock, right? */
void Connman::cancel_wps()
{
    cancel_wps_data.called();
}

/* Always tell caller that we are currently not in the progress of connecting
 * the service */
bool Connman::is_connecting(bool *is_wps)
{
    *is_wps = false;
    return false;
}

/* Of course we have networking here. */
Connman::Mode Connman::get_networking_mode()
{
    return Connman::Mode::REGULAR;
}

#if !LOGGED_LOCKS_ENABLED

namespace spi_registers_networking
{

static MockConnman *mock_connman;
static MockMessages *mock_messages;
static MockBacktrace *mock_backtrace;
static MockOs *mock_os;

static constexpr char connman_config_path[] = "/var/lib/connman";
static constexpr char network_config_path[] = "/var/local/etc";
static constexpr char network_config_file[] = "/var/local/etc/network.ini";

static constexpr char ethernet_name[]        = "/connman/service/ethernet";
static constexpr char ethernet_mac_address[] = "C4:FD:EC:AF:DE:AD";
static constexpr char wlan_name[]            = "/connman/service/wlan";
static constexpr char wlan_mac_address[]     = "B4:DD:EA:DB:EE:F1";

static constexpr char standard_ipv4_address[] = "192.168.166.177";
static constexpr char standard_ipv4_netmask[] = "255.255.255.0";
static constexpr char standard_ipv4_gateway[] = "192.168.166.15";
static constexpr char standard_dns1_address[] = "13.24.35.246";
static constexpr char standard_dns2_address[] = "4.225.136.7";

static std::vector<char> os_write_buffer;
static constexpr int expected_os_write_fd = 42;
static constexpr int expected_os_map_file_to_memory_fd = 23;

static int write_from_buffer_callback(const void *src, size_t count, int fd)
{
    cppcut_assert_equal(expected_os_write_fd, fd);
    cppcut_assert_not_null(src);
    cppcut_assert_operator(size_t(0), <, count);

    std::copy_n(static_cast<const char *>(src), count,
                std::back_inserter<std::vector<char>>(os_write_buffer));

    return 0;
}

static RegisterChangedData *register_changed_data;

static void register_changed_callback(uint8_t reg_number)
{
    register_changed_data->append(reg_number);
}

static void setup_default_connman_service_list()
{
    auto locked(Connman::ServiceList::get_singleton_for_update());
    auto &services(locked.first);

    const auto locked_devices(Connman::NetworkDeviceList::get_singleton_for_update());
    auto &devices(locked_devices.first);

    services.clear();
    devices.clear();

    Connman::ServiceData data;

    Connman::Address<Connman::AddressType::MAC> addr(ethernet_mac_address);
    devices.set_auto_select_mac_address(Connman::Technology::ETHERNET, addr);
    devices.insert(Connman::Technology::ETHERNET,
                   Connman::Address<Connman::AddressType::MAC>(addr));
    cppcut_assert_not_null(devices[addr].get());

    data.state_ = Connman::ServiceState::READY;
    data.device_ = devices[addr];
    data.is_favorite_ = true;
    data.is_auto_connect_ = true;
    data.is_immutable_ = false;
    data.active_.ipsettings_v4_.set_known();
    data.active_.ipsettings_v4_.get_rw().set_dhcp_method(Connman::DHCPV4Method::ON);
    data.active_.ipsettings_v4_.get_rw().set_address(standard_ipv4_address);
    data.active_.ipsettings_v4_.get_rw().set_netmask(standard_ipv4_netmask);
    data.active_.ipsettings_v4_.get_rw().set_gateway(standard_ipv4_gateway);
    data.active_.dns_servers_.set_known();
    data.active_.dns_servers_.get_rw().push_back(standard_dns1_address);
    data.active_.dns_servers_.get_rw().push_back(standard_dns2_address);
    data.configured_.ipsettings_v4_.set_known();
    data.configured_.ipsettings_v4_.get_rw().set_dhcp_method(Connman::DHCPV4Method::ON);

    services.insert(ethernet_name, std::move(data),
                    std::move(Connman::TechData<Connman::Technology::ETHERNET>()));

    addr.set(wlan_mac_address);
    devices.set_auto_select_mac_address(Connman::Technology::WLAN, addr);
    devices.insert(Connman::Technology::WLAN, Connman::Address<Connman::AddressType::MAC>(addr));

    data.state_ = Connman::ServiceState::IDLE;
    data.device_ = devices[addr];
    data.is_favorite_ = true;
    data.is_auto_connect_ = true;
    data.is_immutable_ = false;
    data.active_.ipsettings_v4_.set_known();
    data.active_.ipsettings_v4_.get_rw().set_dhcp_method(Connman::DHCPV4Method::ON);
    data.active_.ipsettings_v4_.get_rw().set_address(standard_ipv4_address);
    data.active_.ipsettings_v4_.get_rw().set_netmask(standard_ipv4_netmask);
    data.active_.ipsettings_v4_.get_rw().set_gateway(standard_ipv4_gateway);
    data.active_.dns_servers_.set_known();
    data.active_.dns_servers_.get_rw().push_back(standard_dns1_address);
    data.active_.dns_servers_.get_rw().push_back(standard_dns2_address);
    data.configured_.ipsettings_v4_.set_known();
    data.configured_.ipsettings_v4_.get_rw().set_dhcp_method(Connman::DHCPV4Method::ON);

    services.insert(wlan_name, std::move(data),
                    std::move(Connman::TechData<Connman::Technology::WLAN>()));
}

static bool do_inject_service_changes(Connman::ServiceList::Map::iterator::value_type &it,
                                      std::function<void(Connman::ServiceData &)> &&modify)
{
    auto &service(it.second);
    Connman::ServiceData service_data(service->get_service_data());

    modify(service_data);

    switch(service->get_technology())
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
        cut_fail("Unexpected case");
        break;

      case Connman::Technology::ETHERNET:
        {
            auto &s(static_cast<Connman::Service<Connman::Technology::ETHERNET> &>(*service));
            auto temp(s.get_tech_data());
            s.put_changes(std::move(service_data), std::move(temp));
        }

        return true;

      case Connman::Technology::WLAN:
        {
            auto &s(static_cast<Connman::Service<Connman::Technology::WLAN> &>(*service));
            auto temp(s.get_tech_data());
            s.put_changes(std::move(service_data), std::move(temp));
        }

        return true;
    }

    return false;
}

static void inject_service_changes(const char *iface_name,
                                   std::function<void(Connman::ServiceData &)> modify)
{
    auto locked(Connman::ServiceList::get_singleton_for_update());
    auto &services(locked.first);

    auto it(services.find(iface_name));
    cut_assert(it != services.end());

    do_inject_service_changes(*it, std::move(modify));
}

template <Connman::Technology TECH>
static void inject_service_changes(const char *iface_name,
                                   std::function<void(Connman::ServiceData &,
                                                      Connman::TechData<TECH> &)> modify)
{
    auto locked(Connman::ServiceList::get_singleton_for_update());
    auto &services(locked.first);

    auto it(services.find(iface_name));
    cut_assert(it != services.end());
    cppcut_assert_equal(int(TECH), int(it->second->get_technology()));

    auto &service(static_cast<Connman::Service<TECH> &>(*it->second));
    Connman::ServiceData service_data(service.get_service_data());
    Connman::TechData<TECH> tech_data(service.get_tech_data());

    modify(service_data, tech_data);

    service.put_changes(std::move(service_data), std::move(tech_data));
}

template <Connman::Technology>
struct AssumeInterfaceIsActiveTraits;

template <>
struct AssumeInterfaceIsActiveTraits<Connman::Technology::ETHERNET>
{
    static const char *get_service_name() { return ethernet_name; }
};

template <>
struct AssumeInterfaceIsActiveTraits<Connman::Technology::WLAN>
{
    static const char *get_service_name() { return wlan_name; }
};

static void activate_interface(const char *const service_name)
{
    auto locked(Connman::ServiceList::get_singleton_for_update());
    auto &services(locked.first);

    for(auto &s : services)
    {
        if(s.first == service_name)
            do_inject_service_changes(s,
                [] (Connman::ServiceData &sdata) { sdata.state_ = Connman::ServiceState::READY; });
        else
            do_inject_service_changes(s,
                [] (Connman::ServiceData &sdata) { sdata.state_ = Connman::ServiceState::IDLE; });
    }
}

template <Connman::Technology TECH, typename Traits = AssumeInterfaceIsActiveTraits<TECH>>
static void assume_interface_is_active(std::function<void(const Connman::ServiceData &,
                                                          const Connman::TechData<TECH> &)> check,
                                       std::function<void(Connman::ServiceData &,
                                                          Connman::TechData<TECH> &)> modify)
{
    activate_interface(Traits::get_service_name());

    inject_service_changes<TECH>(Traits::get_service_name(),
        [&check, &modify]
        (Connman::ServiceData &sdata, Connman::TechData<TECH> &tdata)
        {
            if(check != nullptr)
                check(sdata, tdata);

            sdata.state_ = Connman::ServiceState::ONLINE;
            tdata.security_ = "none";

            if(modify != nullptr)
                modify(sdata, tdata);
        });
}

template <Connman::Technology TECH, typename Traits = AssumeInterfaceIsActiveTraits<TECH>>
static void assume_interface_is_active(std::function<void(const Connman::ServiceData &)> check,
                                       std::function<void(Connman::ServiceData &)> modify)
{
    activate_interface(Traits::get_service_name());

    inject_service_changes(Traits::get_service_name(),
        [&check, &modify]
        (Connman::ServiceData &sdata)
        {
            if(check != nullptr)
                check(sdata);

            sdata.state_ = Connman::ServiceState::ONLINE;

            if(modify != nullptr)
                modify(sdata);
        });
}

static void assume_wlan_interface_is_active()
{
    assume_interface_is_active<Connman::Technology::WLAN>(
        std::function<void(const Connman::ServiceData &,
                           const Connman::TechData<Connman::Technology::WLAN> &)>(nullptr),
        nullptr);

}

void cut_setup()
{
    register_changed_data = new RegisterChangedData;

    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_backtrace = new MockBacktrace;
    cppcut_assert_not_null(mock_backtrace);
    mock_backtrace->init();
    mock_backtrace_singleton = mock_backtrace;

    mock_os = new MockOs;
    cppcut_assert_not_null(mock_os);
    mock_os->init();
    mock_os_singleton = mock_os;

    mock_connman = new MockConnman;
    cppcut_assert_not_null(mock_connman);
    mock_connman->init();
    mock_connman_singleton = mock_connman;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    os_write_buffer.clear();

    connect_to_connman_service_data.init();
    cancel_wps_data.init();
    register_changed_data->init();

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    network_prefs_init(network_config_path, network_config_file);
    Regs::init(register_changed_callback, nullptr);

    setup_default_connman_service_list();
}

void cut_teardown()
{
    Regs::deinit();
    network_prefs_deinit();

    Connman::ServiceList::get_singleton_for_update().first.clear();
    Connman::NetworkDeviceList::get_singleton_for_update().first.clear();

    register_changed_data->check();

    delete register_changed_data;
    register_changed_data = nullptr;

    cancel_wps_data.check();
    connect_to_connman_service_data.check();

    os_write_buffer.clear();
    os_write_buffer.shrink_to_fit();

    mock_messages->check();
    mock_backtrace->check();
    mock_os->check();
    mock_connman->check();

    mock_messages_singleton = nullptr;
    mock_backtrace_singleton = nullptr;
    mock_os_singleton = nullptr;
    mock_connman_singleton = nullptr;

    delete mock_messages;
    delete mock_backtrace;
    delete mock_os;
    delete mock_connman;

    mock_messages = nullptr;
    mock_backtrace = nullptr;
    mock_os = nullptr;
    mock_connman = nullptr;
}

/*!\test
 * Read out MAC address of built-in Ethernet interface.
 */
void test_read_mac_address()
{
    auto *reg = lookup_register_expect_handlers(51,
                                                Regs::NetworkConfig::DCP::read_51_mac_address,
                                                nullptr);
    uint8_t redzone_content[10];
    memset(redzone_content, 0xff, sizeof(redzone_content));

    uint8_t buffer[sizeof(redzone_content) + 18 + sizeof(redzone_content)];
    memset(buffer, 0xff, sizeof(buffer));

    reg->read(buffer + sizeof(redzone_content), sizeof(buffer) - 2 * sizeof(redzone_content));

    cut_assert_equal_memory(redzone_content, sizeof(redzone_content), buffer,
                            sizeof(redzone_content));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + sizeof(redzone_content) + 18, sizeof(redzone_content));
    cut_assert_equal_memory(ethernet_mac_address, sizeof(ethernet_mac_address),
                            buffer + sizeof(redzone_content), 18);
}

/*!\test
 * MAC address of built-in Ethernet interface is an invalid address if not set.
 */
void test_read_mac_address_default()
{
    Regs::deinit();
    network_prefs_deinit();

    {
        Connman::ServiceList::get_singleton_for_update().first.clear();
        Connman::NetworkDeviceList::get_singleton_for_update().first.clear();
    }

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    network_prefs_init(nullptr, nullptr);
    Regs::init(nullptr, nullptr);

    auto *reg = lookup_register_expect_handlers(51,
                                                Regs::NetworkConfig::DCP::read_51_mac_address,
                                                nullptr);
    uint8_t buffer[18];
    cppcut_assert_equal(sizeof(buffer), reg->read(buffer, sizeof(buffer)));

    const char *buffer_ptr = reinterpret_cast<const char *>(buffer);
    cppcut_assert_equal("02:00:00:00:00:00", buffer_ptr);
}

static void start_ipv4_config(Connman::Technology expected_technology)
{
    auto *reg = lookup_register_expect_handlers(54,
                                                Regs::NetworkConfig::DCP::write_54_selected_ip_profile);

    switch(expected_technology)
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
        mock_messages->expect_msg_error(0, LOG_ERR,
                                        "No active network technology, cannot modify configuration");
        break;

      case Connman::Technology::ETHERNET:
        mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "Modify Ethernet configuration");
        break;

      case Connman::Technology::WLAN:
        mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "Modify WLAN configuration");
        break;
    }

    static const uint8_t zero = 0;
    reg->write(&zero, 1);
}

static void commit_ipv4_config(enum NetworkPrefsTechnology tech,
                               int expected_return_value = 0,
                               bool is_taking_config_from_file = true,
                               const char *wps_name = nullptr,
                               const std::vector<uint8_t> *wps_ssid = nullptr,
                               bool force_expect_wps_canceled = false)
{
    auto *reg = lookup_register_expect_handlers(53,
                                                Regs::NetworkConfig::DCP::write_53_active_ip_profile);

    if(tech == NWPREFSTECH_UNKNOWN)
    {
        if(expected_return_value != 0 || force_expect_wps_canceled)
            cancel_wps_data.expect();
    }
    else
    {
        /* XXX: The empty string passed as second parameter is most certainly
         *      incorrect. Likely, there is something wrong with the test setup
         *      and/or mocks. */
        if(is_taking_config_from_file)
            connect_to_connman_service_data.expect(tech, "");
        else
            connect_to_connman_service_data.expect("", wps_name, wps_ssid);
    }

    static const uint8_t zero = 0;
    write_buffer_expect_failure(reg, &zero, 1, expected_return_value);
}

static void move_os_write_buffer_to_file(struct os_mapped_file_data &mapped_file,
                                         std::vector<char> &backing_buffer)
{
    backing_buffer.clear();
    backing_buffer.swap(os_write_buffer);

    mapped_file.fd = expected_os_map_file_to_memory_fd;
    mapped_file.ptr = backing_buffer.data();
    mapped_file.length = backing_buffer.size();
}

static const struct os_mapped_file_data *
expect_create_default_network_preferences(struct os_mapped_file_data &file_with_written_default_contents,
                                          std::vector<char> &written_default_contents,
                                          int expected_number_of_assignments)
{
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                                    "Creating default network preferences file");
    mock_os->expect_os_file_new(expected_os_write_fd, 0, network_config_file);
    for(int i = 0; i < 2 * 3 + expected_number_of_assignments * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir_callback(0, network_config_path,
                                         std::bind(move_os_write_buffer_to_file,
                                                   std::ref(file_with_written_default_contents),
                                                   std::ref(written_default_contents)));

    const struct os_mapped_file_data *mf = &file_with_written_default_contents;

    mock_os->expect_os_map_file_to_memory(0, 0, mf, network_config_file);
    mock_os->expect_os_unmap_file(0, mf);

    return mf;
}

static size_t expect_default_network_preferences_content(char *buffer_for_expected,
                                                         size_t buffer_for_expected_size,
                                                         const std::vector<char> &buffer)
{
    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "[wifi]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        ;

    snprintf(buffer_for_expected, buffer_for_expected_size,
             expected_config_file_format, ethernet_mac_address,
             wlan_mac_address);

    const size_t written_config_file_length = strlen(buffer_for_expected);

    cut_assert_equal_memory(buffer_for_expected, written_config_file_length,
                            buffer.data(), buffer.size());

    return written_config_file_length;
}

static void expect_default_network_preferences_content(const std::vector<char> &buffer)
{
    char dummy[512];
    expect_default_network_preferences_content(dummy, sizeof(dummy), buffer);
}

static size_t do_test_set_static_ipv4_config(const struct os_mapped_file_data *existing_file,
                                             char *written_config_file,
                                             size_t written_config_file_size)
{
    start_ipv4_config(Connman::Technology::ETHERNET);

    auto *reg = lookup_register_expect_handlers(56,
                                                Regs::NetworkConfig::DCP::read_56_ipv4_address,
                                                Regs::NetworkConfig::DCP::write_56_ipv4_address);

    reg->write(reinterpret_cast<const uint8_t *>(standard_ipv4_address),
               sizeof(standard_ipv4_address));

    reg = lookup_register_expect_handlers(57,
                                          Regs::NetworkConfig::DCP::read_57_ipv4_netmask,
                                          Regs::NetworkConfig::DCP::write_57_ipv4_netmask);

    reg->write(reinterpret_cast<const uint8_t *>(standard_ipv4_netmask),
               sizeof(standard_ipv4_netmask));

    reg = lookup_register_expect_handlers(58,
                                          Regs::NetworkConfig::DCP::read_58_ipv4_gateway,
                                          Regs::NetworkConfig::DCP::write_58_ipv4_gateway);

    reg->write(reinterpret_cast<const uint8_t *>(standard_ipv4_gateway),
               sizeof(standard_ipv4_gateway));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address C4:FD:EC:AF:DE:AD");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1, .ptr = nullptr, .length = 0 };
    std::vector<char> written_default_contents;

    if(existing_file == nullptr)
    {
        mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, network_config_file);

        existing_file =
            expect_create_default_network_preferences(file_with_written_default_contents,
                                                      written_default_contents, 4);
    }
    else
    {
        mock_os->expect_os_map_file_to_memory(0, 0, existing_file, network_config_file);
        mock_os->expect_os_unmap_file(0, existing_file);
    }

    mock_os->expect_os_file_new(expected_os_write_fd, 0, network_config_file);
    for(int i = 0; i < 2 * 3 + 7 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, network_config_path);

    commit_ipv4_config(NWPREFSTECH_ETHERNET);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = no\n"
        "IPv4Address = %s\n"
        "IPv4Netmask = %s\n"
        "IPv4Gateway = %s\n"
        "[wifi]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        ;

    snprintf(written_config_file, written_config_file_size,
             expected_config_file_format,
             ethernet_mac_address, standard_ipv4_address,
             standard_ipv4_netmask, standard_ipv4_gateway, wlan_mac_address);

    size_t written_config_file_length = strlen(written_config_file);

    cut_assert_equal_memory(written_config_file, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());

    return written_config_file_length;
}

static size_t do_test_set_dhcp_ipv4_config(const struct os_mapped_file_data *existing_file,
                                           char *written_config_file,
                                           size_t written_config_file_size)
{
    start_ipv4_config(Connman::Technology::ETHERNET);

    auto *reg = lookup_register_expect_handlers(55,
                                                Regs::NetworkConfig::DCP::read_55_dhcp_enabled,
                                                Regs::NetworkConfig::DCP::write_55_dhcp_enabled);

    mock_messages->expect_msg_info_formatted("Enable DHCP");
    static const uint8_t one = 1;
    reg->write(&one, 1);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address C4:FD:EC:AF:DE:AD");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1, .ptr = nullptr, .length = 0 };
    std::vector<char> written_default_contents;

    if(existing_file == nullptr)
    {
        mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, network_config_file);

        existing_file =
            expect_create_default_network_preferences(file_with_written_default_contents,
                                                      written_default_contents, 4);
    }
    else
    {
        mock_os->expect_os_map_file_to_memory(0, 0, existing_file, network_config_file);
        mock_os->expect_os_unmap_file(0, existing_file);
    }

    mock_os->expect_os_file_new(expected_os_write_fd, 0, network_config_file);
    for(int i = 0; i < 2 * 3 + 4 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, network_config_path);
    commit_ipv4_config(NWPREFSTECH_ETHERNET);

    return expect_default_network_preferences_content(written_config_file,
                                                      written_config_file_size,
                                                      os_write_buffer);
}

/*!\test
 * Initial setting of static IPv4 configuration generates a network preferences
 * file.
 */
void test_set_initial_static_ipv4_configuration()
{
    char buffer[512];
    (void)do_test_set_static_ipv4_config(nullptr, buffer, sizeof(buffer));
}

/*!\test
 * Addresses such as "192.168.060.000" are converted to "192.168.60.0".
 *
 * Connman (and most other software) doesn't like leading zeros in IP addresses
 * because they look like octal numbers. In fact, \c inet_pton(3) also chokes
 * on those.
 */
void test_leading_zeros_are_removed_from_ipv4_addresses()
{
    start_ipv4_config(Connman::Technology::ETHERNET);

    auto *reg = lookup_register_expect_handlers(56,
                                                Regs::NetworkConfig::DCP::read_56_ipv4_address,
                                                Regs::NetworkConfig::DCP::write_56_ipv4_address);

    static const std::array<std::pair<const char *, const char *>, 3> addresses_with_zeros =
    {
        std::make_pair("123.045.006.100", "123.45.6.100"),
        std::make_pair("135.07.80.010",   "135.7.80.10"),
        std::make_pair("009.000.00.0",    "9.0.0.0"),
    };

    for(const auto &p : addresses_with_zeros)
    {
        reg->write(reinterpret_cast<const uint8_t *>(p.first), strlen(p.first));

        uint8_t buffer[32];
        const size_t len = reg->read(buffer, sizeof(buffer));
        buffer[sizeof(buffer) - 1] = '\0';
        cppcut_assert_equal(p.second, reinterpret_cast<const char *>(buffer));
        cppcut_assert_equal(strlen(p.second) + 1, len);
    }
}

/*!\test
 * Initial enabling of DHCPv4 generates a network preferences file.
 */
void test_set_initial_dhcp_ipv4_configuration()
{
    char buffer[512];
    (void)do_test_set_dhcp_ipv4_config(nullptr, buffer, sizeof(buffer));
}

/*!\test
 * Setting static IPv4 configuration while a DHCPv4 configuration is active
 * rewrites the network preferences file.
 */
void test_switch_to_dhcp_ipv4_configuration()
{
    char config_file_buffer[512];
    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = do_test_set_static_ipv4_config(nullptr, config_file_buffer,
                                                 sizeof(config_file_buffer)),
    };

    os_write_buffer.clear();

    char new_config_file_buffer[512];
    (void)do_test_set_dhcp_ipv4_config(&config_file, new_config_file_buffer,
                                       sizeof(new_config_file_buffer));
}

/*!\test
 * Enabling DHCPv4 while a static IPv4 configuration is active rewrites the
 * network preferences file.
 */
void test_switch_to_static_ipv4_configuration()
{
    char config_file_buffer[512];
    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = do_test_set_dhcp_ipv4_config(nullptr, config_file_buffer,
                                               sizeof(config_file_buffer)),
    };

    os_write_buffer.clear();

    char new_config_file_buffer[512];
    (void)do_test_set_static_ipv4_config(&config_file, new_config_file_buffer,
                                         sizeof(new_config_file_buffer));
}

/*!\test
 * Only values 0 and 1 are valid parameters for register 55.
 */
void test_dhcp_parameter_boundaries()
{
    start_ipv4_config(Connman::Technology::ETHERNET);

    auto *reg = lookup_register_expect_handlers(55,
                                                Regs::NetworkConfig::DCP::read_55_dhcp_enabled,
                                                Regs::NetworkConfig::DCP::write_55_dhcp_enabled);

    uint8_t buffer = 2;

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Received invalid DHCP configuration parameter 0x02 (Invalid argument)");

    try
    {
        reg->write(&buffer, 1);
        cut_fail("Missing exception");
    }
    catch(const Regs::io_error &e)
    {
        cppcut_assert_equal(ssize_t(-1), e.result());
    }

    buffer = UINT8_MAX;

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Received invalid DHCP configuration parameter 0xff (Invalid argument)");

    try
    {
        reg->write(&buffer, 1);
        cut_fail("Missing exception");
    }
    catch(const Regs::io_error &e)
    {
        cppcut_assert_equal(ssize_t(-1), e.result());
    }
}

/*!\test
 * Switching DHCP off and setting no IPv4 configuration tells us to disable the
 * interface for IPv4.
 */
void test_explicitly_disabling_dhcp_disables_whole_interface()
{
    start_ipv4_config(Connman::Technology::ETHERNET);

    auto *reg = lookup_register_expect_handlers(55,
                                                Regs::NetworkConfig::DCP::read_55_dhcp_enabled,
                                                Regs::NetworkConfig::DCP::write_55_dhcp_enabled);

    static const uint8_t zero = 0;

    mock_messages->expect_msg_info_formatted("Disable DHCP");
    reg->write(&zero, 1);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address C4:FD:EC:AF:DE:AD");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1, .ptr = nullptr, .length = 0 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents, 4);

    mock_messages->expect_msg_error_formatted(0, LOG_WARNING,
        "Disabling IPv4 on interface C4:FD:EC:AF:DE:AD because DHCPv4 "
        "was disabled and static IPv4 configuration was not sent");

    mock_os->expect_os_file_new(expected_os_write_fd, 0, network_config_file);
    for(int i = 0; i < 2 * 3 + 3 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, network_config_path);

    commit_ipv4_config(NWPREFSTECH_ETHERNET);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "[wifi]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        ;

    char buffer[512];
    snprintf(buffer, sizeof(buffer), expected_config_file_format,
             ethernet_mac_address, wlan_mac_address);

    size_t written_config_file_length = strlen(buffer);

    cut_assert_equal_memory(buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * When being asked for DHCP mode in normal mode, Connman is consulted
 * (reporting "disabled" in this test).
 */
void test_read_dhcp_mode_in_normal_mode_with_dhcp_disabled()
{
    assume_interface_is_active<Connman::Technology::ETHERNET>(
        [] (const Connman::ServiceData &sdata)
        {
            cut_assert_true(sdata.active_.ipsettings_v4_.is_known());
            cut_assert_true(sdata.configured_.ipsettings_v4_.is_known());
        },
        [] (Connman::ServiceData &sdata)
        {
            sdata.active_.ipsettings_v4_.get_rw().set_dhcp_method(Connman::DHCPV4Method::MANUAL);
            sdata.configured_.ipsettings_v4_.get_rw().set_dhcp_method(Connman::DHCPV4Method::MANUAL);
        });

    auto *reg = lookup_register_expect_handlers(55,
                                                Regs::NetworkConfig::DCP::read_55_dhcp_enabled,
                                                Regs::NetworkConfig::DCP::write_55_dhcp_enabled);

    uint8_t buffer = UINT8_MAX;
    cppcut_assert_equal(size_t(1), reg->read(&buffer, 1));

    cppcut_assert_equal(0, int(buffer));
}

/*!\test
 * When being asked for DHCP mode in normal mode, Connman is consulted
 * (reporting "enabled" in this test).
 */
void test_read_dhcp_mode_in_normal_mode_with_dhcp_enabled()
{
    assume_interface_is_active<Connman::Technology::ETHERNET>(
        [] (const Connman::ServiceData &sdata)
        {
            cut_assert_true(sdata.active_.ipsettings_v4_.is_known());
            cut_assert_true(sdata.active_.ipsettings_v4_.get().get_dhcp_method() == Connman::DHCPV4Method::ON);
            cut_assert_true(sdata.configured_.ipsettings_v4_.is_known());
            cut_assert_true(sdata.configured_.ipsettings_v4_.get().get_dhcp_method() == Connman::DHCPV4Method::ON);
        },
        nullptr);

    auto *reg = lookup_register_expect_handlers(55,
                                                Regs::NetworkConfig::DCP::read_55_dhcp_enabled,
                                                Regs::NetworkConfig::DCP::write_55_dhcp_enabled);

    uint8_t buffer = UINT8_MAX;
    cppcut_assert_equal(size_t(1), reg->read(&buffer, 1));

    cppcut_assert_equal(1, int(buffer));
}

/*!\test
 * When being asked for DHCP mode in edit mode, Connman is consulted if the
 * mode has not been set during this edit session.
 */
void test_read_dhcp_mode_in_edit_mode_before_any_changes()
{
    start_ipv4_config(Connman::Technology::ETHERNET);

    auto *reg = lookup_register_expect_handlers(55,
                                                Regs::NetworkConfig::DCP::read_55_dhcp_enabled,
                                                Regs::NetworkConfig::DCP::write_55_dhcp_enabled);

    uint8_t buffer = UINT8_MAX;
    cppcut_assert_equal(size_t(1), reg->read(&buffer, 1));

    cppcut_assert_equal(1, int(buffer));
}

/*!\test
 * When being asked for DHCP mode in edit mode, the mode written during this
 * edit session is returned.
 */
void test_read_dhcp_mode_in_edit_mode_after_change()
{
    start_ipv4_config(Connman::Technology::ETHERNET);

    auto *reg = lookup_register_expect_handlers(55,
                                                Regs::NetworkConfig::DCP::read_55_dhcp_enabled,
                                                Regs::NetworkConfig::DCP::write_55_dhcp_enabled);

    mock_messages->expect_msg_info_formatted("Enable DHCP");
    static const uint8_t one = 1;
    reg->write(&one, 1);

    uint8_t buffer = UINT8_MAX;
    cppcut_assert_equal(size_t(1), reg->read(&buffer, 1));

    cppcut_assert_equal(1, int(buffer));
}

template <uint8_t Register>
struct RegisterTraits;

template <>
struct RegisterTraits<56U>
{
    static constexpr auto expected_read_handler = &Regs::NetworkConfig::DCP::read_56_ipv4_address;
    static constexpr auto expected_write_handler = &Regs::NetworkConfig::DCP::write_56_ipv4_address;
    static constexpr auto &expected_address = standard_ipv4_address;
};

template <>
struct RegisterTraits<57U>
{
    static constexpr auto expected_read_handler = &Regs::NetworkConfig::DCP::read_57_ipv4_netmask;
    static constexpr auto expected_write_handler = &Regs::NetworkConfig::DCP::write_57_ipv4_netmask;
    static constexpr auto &expected_address = standard_ipv4_netmask;
};

template <>
struct RegisterTraits<58U>
{
    static constexpr auto expected_read_handler = &Regs::NetworkConfig::DCP::read_58_ipv4_gateway;
    static constexpr auto expected_write_handler = &Regs::NetworkConfig::DCP::write_58_ipv4_gateway;
    static constexpr auto &expected_address = standard_ipv4_gateway;
};

template <>
struct RegisterTraits<62U>
{
    static constexpr auto expected_read_handler = &Regs::NetworkConfig::DCP::read_62_primary_dns;
    static constexpr auto expected_write_handler = &Regs::NetworkConfig::DCP::write_62_primary_dns;
    static constexpr auto &expected_address = standard_dns1_address;
};

template <>
struct RegisterTraits<63U>
{
    static constexpr auto expected_read_handler = &Regs::NetworkConfig::DCP::read_63_secondary_dns;
    static constexpr auto expected_write_handler = &Regs::NetworkConfig::DCP::write_63_secondary_dns;
    static constexpr auto &expected_address = standard_dns2_address;
};

template <uint8_t Register, typename RegTraits = RegisterTraits<Register>>
static void read_ipv4_parameter_in_normal_mode()
{
    auto *reg = lookup_register_expect_handlers(Register,
                                                RegTraits::expected_read_handler,
                                                RegTraits::expected_write_handler);
    uint8_t buffer[50];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    cppcut_assert_equal(sizeof(RegTraits::expected_address),
                        reg->read(buffer, sizeof(buffer)));

    cut_assert_equal_memory(RegTraits::expected_address, sizeof(RegTraits::expected_address),
                            buffer, sizeof(RegTraits::expected_address));
}

template <uint8_t Register, typename RegTraits = RegisterTraits<Register>>
static void read_ipv4_parameter_in_edit_mode_before_any_changes()
{
    start_ipv4_config(Connman::Technology::ETHERNET);

    auto *reg = lookup_register_expect_handlers(Register,
                                                RegTraits::expected_read_handler,
                                                RegTraits::expected_write_handler);
    uint8_t buffer[50];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    cppcut_assert_equal(sizeof(RegTraits::expected_address),
                        reg->read(buffer, sizeof(buffer)));

    cut_assert_equal_memory(RegTraits::expected_address, sizeof(RegTraits::expected_address),
                            buffer, sizeof(RegTraits::expected_address));
}

template <uint8_t Register, typename RegTraits = RegisterTraits<Register>>
static void read_ipv4_parameter_in_edit_mode_after_change()
{
    start_ipv4_config(Connman::Technology::ETHERNET);

    auto *reg = lookup_register_expect_handlers(Register,
                                                RegTraits::expected_read_handler,
                                                RegTraits::expected_write_handler);
    reg->write((uint8_t *)standard_ipv4_address, sizeof(standard_ipv4_address));

    uint8_t buffer[4 + 16 + 4];
    memset(buffer, UINT8_MAX, sizeof(buffer));
    cppcut_assert_operator(sizeof(standard_ipv4_address), <=, sizeof(buffer));

    cppcut_assert_equal(sizeof(standard_ipv4_address),
                        reg->read(buffer + 4, sizeof(standard_ipv4_address)));

    cut_assert_equal_memory(standard_ipv4_address, sizeof(standard_ipv4_address), buffer + 4, sizeof(standard_ipv4_address));

    static const uint8_t red_zone_bytes[] =
    {
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX
    };

    cut_assert_equal_memory(red_zone_bytes, sizeof(red_zone_bytes),
                            buffer, sizeof(red_zone_bytes));
    cut_assert_equal_memory(red_zone_bytes, sizeof(red_zone_bytes),
                            buffer + sizeof(standard_ipv4_address) + sizeof(red_zone_bytes),
                            sizeof(red_zone_bytes));
}

/*!\test
 * When being asked for the IPv4 address in normal mode, Connman is consulted.
 */
void test_read_ipv4_address_in_normal_mode()
{
    read_ipv4_parameter_in_normal_mode<56>();
}

/*!\test
 * When being asked for the IPv4 address in edit mode, Connman is consulted if
 * the address has not been set during this edit session.
 */
void test_read_ipv4_address_in_edit_mode_before_any_changes()
{
    read_ipv4_parameter_in_edit_mode_before_any_changes<56>();
}

/*!\test
 * When being asked for the IPv4 address in edit mode, the address written
 * during this edit session is returned.
 */
void test_read_ipv4_address_in_edit_mode_after_change()
{
    read_ipv4_parameter_in_edit_mode_after_change<56>();
}

/*!\test
 * When being asked for the IPv4 netmask in normal mode, Connman is consulted.
 */
void test_read_ipv4_netmask_in_normal_mode()
{
    read_ipv4_parameter_in_normal_mode<57>();
}

/*!\test
 * When being asked for the IPv4 netmask in edit mode, Connman is consulted if
 * the mask has not been set during this edit session.
 */
void test_read_ipv4_netmask_in_edit_mode_before_any_changes()
{
    read_ipv4_parameter_in_edit_mode_before_any_changes<57>();
}

/*!\test
 * When being asked for the IPv4 netmask in edit mode, the address written
 * during this edit session is returned.
 */
void test_read_ipv4_netmask_in_edit_mode_after_change()
{
    read_ipv4_parameter_in_edit_mode_after_change<57>();
}

/*!\test
 * When being asked for the IPv4 gateway in normal mode, Connman is consulted.
 */
void test_read_ipv4_gateway_in_normal_mode()
{
    read_ipv4_parameter_in_normal_mode<58>();
}

/*!\test
 * When being asked for the IPv4 gateway in edit mode, Connman is consulted if
 * the gateway has not been set during this edit session.
 */
void test_read_ipv4_gateway_in_edit_mode_before_any_changes()
{
    read_ipv4_parameter_in_edit_mode_before_any_changes<58>();
}

/*!\test
 * When being asked for the IPv4 gateway in edit mode, the gateway written
 * during this edit session is returned.
 */
void test_read_ipv4_gateway_in_edit_mode_after_change()
{
    read_ipv4_parameter_in_edit_mode_after_change<58>();
}

template <uint8_t Register, typename RegTraits = RegisterTraits<Register>>
static void set_one_dns_server()
{
    char config_file_buffer[512];
    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = do_test_set_static_ipv4_config(nullptr, config_file_buffer,
                                                 sizeof(config_file_buffer)),
    };

    os_write_buffer.clear();

    assume_interface_is_active<Connman::Technology::ETHERNET>(
        nullptr,
        [] (Connman::ServiceData &sdata)
        {
            sdata.active_.dns_servers_.set_unknown();
        });

    start_ipv4_config(Connman::Technology::ETHERNET);

    auto *reg = lookup_register_expect_handlers(Register,
                                                RegTraits::expected_read_handler,
                                                RegTraits::expected_write_handler);
    reg->write(reinterpret_cast<const uint8_t *>(RegTraits::expected_address),
               sizeof(RegTraits::expected_address));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address C4:FD:EC:AF:DE:AD");
    mock_os->expect_os_map_file_to_memory(0, 0, &config_file, network_config_file);
    mock_os->expect_os_unmap_file(0, &config_file);
    mock_os->expect_os_file_new(expected_os_write_fd, 0, network_config_file);
    for(int i = 0; i < 2 * 3 + 8 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, network_config_path);

    commit_ipv4_config(NWPREFSTECH_ETHERNET);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = no\n"
        "IPv4Address = %s\n"
        "IPv4Netmask = %s\n"
        "IPv4Gateway = %s\n"
        "PrimaryDNS = %s\n"
        "[wifi]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        ;

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format,
             ethernet_mac_address, standard_ipv4_address,
             standard_ipv4_netmask, standard_ipv4_gateway,
             RegTraits::expected_address, wlan_mac_address);

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Add primary DNS server address to static IPv4 configuration without
 * previously defined DNS servers.
 */
void test_set_only_first_dns_server()
{
    set_one_dns_server<62>();
}

/*!\test
 * Add secondary DNS server address to static IPv4 configuration without
 * previously defined DNS servers.
 *
 * Since this is the only address sent to the device, it becomes the primary
 * DNS server.
 */
void test_set_only_second_dns_server()
{
    set_one_dns_server<63>();
}

/*!\test
 * Add two DNS servers to static IPv4 configuration without previously defined
 * DNS servers.
 */
void test_set_both_dns_servers()
{
    char config_file_buffer[512];
    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = do_test_set_static_ipv4_config(nullptr, config_file_buffer,
                                                 sizeof(config_file_buffer)),
    };

    os_write_buffer.clear();

    start_ipv4_config(Connman::Technology::ETHERNET);

    auto *reg = lookup_register_expect_handlers(62,
                                                Regs::NetworkConfig::DCP::read_62_primary_dns,
                                                Regs::NetworkConfig::DCP::write_62_primary_dns);
    reg->write(reinterpret_cast<const uint8_t *>(standard_dns1_address),
               sizeof(standard_dns1_address));

    reg = lookup_register_expect_handlers(63,
                                          Regs::NetworkConfig::DCP::read_63_secondary_dns,
                                          Regs::NetworkConfig::DCP::write_63_secondary_dns);
    reg->write(reinterpret_cast<const uint8_t *>(standard_dns2_address),
               sizeof(standard_dns2_address));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address C4:FD:EC:AF:DE:AD");
    mock_os->expect_os_map_file_to_memory(0, 0, &config_file, network_config_file);
    mock_os->expect_os_unmap_file(0, &config_file);
    mock_os->expect_os_file_new(expected_os_write_fd, 0, network_config_file);
    for(int i = 0; i < 2 * 3 + 9 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, network_config_path);

    commit_ipv4_config(NWPREFSTECH_ETHERNET);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = no\n"
        "IPv4Address = %s\n"
        "IPv4Netmask = %s\n"
        "IPv4Gateway = %s\n"
        "PrimaryDNS = %s\n"
        "SecondaryDNS = %s\n"
        "[wifi]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        ;

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format,
             ethernet_mac_address, standard_ipv4_address,
             standard_ipv4_netmask, standard_ipv4_gateway,
             standard_dns1_address, standard_dns2_address, wlan_mac_address);

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Read out the primary DNS in edit mode, Connman is consulted if the primary
 * DNS server has not been set during this edit session.
 */
void test_read_primary_dns_in_edit_mode_before_any_changes()
{
    start_ipv4_config(Connman::Technology::ETHERNET);

    auto *reg = lookup_register_expect_handlers(62,
                                                Regs::NetworkConfig::DCP::read_62_primary_dns,
                                                Regs::NetworkConfig::DCP::write_62_primary_dns);

    char buffer[128];

    size_t dns_server_size = reg->read(reinterpret_cast<uint8_t *>(buffer), sizeof(buffer));

    cppcut_assert_equal(sizeof(standard_dns1_address), dns_server_size);
    cppcut_assert_equal(standard_dns1_address, static_cast<const char *>(buffer));

    commit_ipv4_config(NWPREFSTECH_UNKNOWN);
}

/*!\test
 * Read out the secondary DNS in edit mode, Connman is consulted if the
 * secondary DNS server has not been set during this edit session.
 */
void test_read_secondary_dns_in_edit_mode_before_any_changes()
{
    start_ipv4_config(Connman::Technology::ETHERNET);

    auto *reg = lookup_register_expect_handlers(63,
                                                Regs::NetworkConfig::DCP::read_63_secondary_dns,
                                                Regs::NetworkConfig::DCP::write_63_secondary_dns);

    char buffer[128];

    size_t dns_server_size = reg->read(reinterpret_cast<uint8_t *>(buffer), sizeof(buffer));

    cppcut_assert_equal(sizeof(standard_dns2_address), dns_server_size);
    cppcut_assert_equal(standard_dns2_address, static_cast<const char *>(buffer));

    commit_ipv4_config(NWPREFSTECH_UNKNOWN);
}

/*!\test
 * Given two previously defined DNS servers, replace the primary one.
 */
void test_replace_primary_dns_server_of_two_servers()
{
    start_ipv4_config(Connman::Technology::ETHERNET);

    static constexpr char new_primary_dns[] = "50.60.117.208";

    auto *reg = lookup_register_expect_handlers(62,
                                                Regs::NetworkConfig::DCP::read_62_primary_dns,
                                                Regs::NetworkConfig::DCP::write_62_primary_dns);

    reg->write(reinterpret_cast<const uint8_t *>(new_primary_dns),
               sizeof(new_primary_dns));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address C4:FD:EC:AF:DE:AD");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1, .ptr = nullptr, .length = 0 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents, 4);

    mock_os->expect_os_file_new(expected_os_write_fd, 0, network_config_file);
    for(int i = 0; i < 2 * 3 + 6 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, network_config_path);

    commit_ipv4_config(NWPREFSTECH_ETHERNET);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "PrimaryDNS = %s\n"
        "SecondaryDNS = %s\n"
        "[wifi]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        ;

    char output_config_file[512];

    snprintf(output_config_file, sizeof(output_config_file),
             expected_config_file_format,
             ethernet_mac_address, new_primary_dns, standard_dns2_address,
             wlan_mac_address);

    size_t output_config_file_length = strlen(output_config_file);

    cut_assert_equal_memory(output_config_file, output_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Given two previously defined DNS servers, replace the secondary one.
 */
void test_replace_secondary_dns_server_of_two_servers()
{
    start_ipv4_config(Connman::Technology::ETHERNET);

    static constexpr char new_secondary_dns[] = "50.60.117.209";

    auto *reg = lookup_register_expect_handlers(63,
                                                Regs::NetworkConfig::DCP::read_63_secondary_dns,
                                                Regs::NetworkConfig::DCP::write_63_secondary_dns);

    reg->write(reinterpret_cast<const uint8_t *>(new_secondary_dns),
               sizeof(new_secondary_dns));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address C4:FD:EC:AF:DE:AD");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1, .ptr = nullptr, .length = 0 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents, 4);

    mock_os->expect_os_file_new(expected_os_write_fd, 0, network_config_file);
    for(int i = 0; i < 2 * 3 + 6 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, network_config_path);

    commit_ipv4_config(NWPREFSTECH_ETHERNET);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "PrimaryDNS = %s\n"
        "SecondaryDNS = %s\n"
        "[wifi]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        ;

    char output_config_file[512];

    snprintf(output_config_file, sizeof(output_config_file),
             expected_config_file_format,
             ethernet_mac_address, standard_dns1_address, new_secondary_dns,
             wlan_mac_address);

    size_t output_config_file_length = strlen(output_config_file);

    cut_assert_equal_memory(output_config_file, output_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Given one previously defined DNS server, add a secondary one.
 */
void test_add_secondary_dns_server_to_primary_server()
{
    static constexpr char assumed_primary_dns[] = "213.1.92.9";

    inject_service_changes(ethernet_name,
                           [] (Connman::ServiceData &sdata)
                           {
                               sdata.active_.dns_servers_.get_rw().clear();
                               sdata.active_.dns_servers_.get_rw().push_back(assumed_primary_dns);
                           });

    start_ipv4_config(Connman::Technology::ETHERNET);

    auto *reg = lookup_register_expect_handlers(63,
                                                Regs::NetworkConfig::DCP::read_63_secondary_dns,
                                                Regs::NetworkConfig::DCP::write_63_secondary_dns);

    reg->write(reinterpret_cast<const uint8_t *>(standard_dns2_address),
               sizeof(standard_dns2_address));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address C4:FD:EC:AF:DE:AD");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1, .ptr = nullptr, .length = 0 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents, 4);

    mock_os->expect_os_file_new(expected_os_write_fd, 0, network_config_file);
    for(int i = 0; i < 2 * 3 + 6 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, network_config_path);

    commit_ipv4_config(NWPREFSTECH_ETHERNET);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "PrimaryDNS = %s\n"
        "SecondaryDNS = %s\n"
        "[wifi]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        ;

    char output_config_file[512];

    snprintf(output_config_file, sizeof(output_config_file),
             expected_config_file_format,
             ethernet_mac_address, assumed_primary_dns, standard_dns2_address,
             wlan_mac_address);

    size_t output_config_file_length = strlen(output_config_file);

    cut_assert_equal_memory(output_config_file, output_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * WPA passphrase for Ethernet connections is ignored and not written to file.
 */
void test_set_wlan_security_mode_on_ethernet_service_is_ignored()
{
    start_ipv4_config(Connman::Technology::ETHERNET);

    auto *reg = lookup_register_expect_handlers(92,
                                                Regs::NetworkConfig::DCP::read_92_wlan_security,
                                                Regs::NetworkConfig::DCP::write_92_wlan_security);
    reg->write(reinterpret_cast<const uint8_t *>("none"), 4);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address C4:FD:EC:AF:DE:AD");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1, .ptr = nullptr, .length = 0 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents, 4);

    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                                    "Ignoring wireless parameters for active wired interface");

    mock_os->expect_os_file_new(expected_os_write_fd, 0, network_config_file);
    for(int i = 0; i < 2 * 3 + 4 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, network_config_path);

    commit_ipv4_config(NWPREFSTECH_ETHERNET);

    expect_default_network_preferences_content(os_write_buffer);
}

/*!\test
 * There is no wireless security mode for Ethernet connections.
 */
void test_get_wlan_security_mode_for_ethernet_returns_error()
{
    uint8_t buffer[64];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    auto *reg = lookup_register_expect_handlers(92,
                                                Regs::NetworkConfig::DCP::read_92_wlan_security,
                                                Regs::NetworkConfig::DCP::write_92_wlan_security);

    read_buffer_expect_failure(reg, buffer, sizeof(buffer), -1);
    cppcut_assert_equal(uint8_t(0), buffer[0]);
    cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[1]);
}

static void set_wlan_name(const char *wps_name)
{
    cppcut_assert_not_null(wps_name);

    auto *reg = lookup_register_expect_handlers(94,
                                                Regs::NetworkConfig::DCP::read_94_ssid,
                                                Regs::NetworkConfig::DCP::write_94_ssid);

    reg->write(reinterpret_cast<const uint8_t *>(wps_name), strlen(wps_name));
}

static void set_wlan_name(const std::vector<uint8_t> &wps_ssid)
{
    cut_assert_false(wps_ssid.empty());

    auto *reg = lookup_register_expect_handlers(94,
                                                Regs::NetworkConfig::DCP::read_94_ssid,
                                                Regs::NetworkConfig::DCP::write_94_ssid);

    reg->write(wps_ssid.data(), wps_ssid.size());
}

static void set_wlan_security_mode(const char *requested_security_mode,
                                   bool expecting_configuration_file_be_written = true,
                                   const char *wps_name = nullptr,
                                   const std::vector<uint8_t> *wps_ssid = nullptr)
{
    cppcut_assert_not_null(requested_security_mode);

    assume_wlan_interface_is_active();

    start_ipv4_config(Connman::Technology::WLAN);

    auto *reg = lookup_register_expect_handlers(92,
                                                Regs::NetworkConfig::DCP::read_92_wlan_security,
                                                Regs::NetworkConfig::DCP::write_92_wlan_security);
    reg->write(reinterpret_cast<const uint8_t *>(requested_security_mode),
               strlen(requested_security_mode));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address B4:DD:EA:DB:EE:F1");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1, .ptr = nullptr, .length = 0 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents, 4);

    if(expecting_configuration_file_be_written)
    {
        mock_os->expect_os_file_new(expected_os_write_fd, 0, network_config_file);
        for(int i = 0; i < 2 * 3 + (2 + 3) * 4; ++i)
            mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
        mock_os->expect_os_file_close(0, expected_os_write_fd);
        mock_os->expect_os_sync_dir(0, network_config_path);
    }

    if(wps_ssid != nullptr)
        set_wlan_name(*wps_ssid);
    else if(wps_name != nullptr)
        set_wlan_name(wps_name);

    const bool is_wps_abort(strcmp(requested_security_mode, "wps-abort") == 0);

    commit_ipv4_config(is_wps_abort ? NWPREFSTECH_UNKNOWN : NWPREFSTECH_WLAN,
                       0, expecting_configuration_file_be_written,
                       wps_name, wps_ssid, is_wps_abort);

    if(expecting_configuration_file_be_written)
    {
        static const char expected_config_file_format[] =
            "[ethernet]\n"
            "MAC = %s\n"
            "DHCP = yes\n"
            "[wifi]\n"
            "MAC = %s\n"
            "DHCP = yes\n"
            "Security = %s\n";

        char new_config_file_buffer[512];
        snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
                 expected_config_file_format, ethernet_mac_address,
                 wlan_mac_address, requested_security_mode);

        size_t written_config_file_length = strlen(new_config_file_buffer);

        cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                                os_write_buffer.data(), os_write_buffer.size());
    }
}

/*!\test
 * Disable WLAN security.
 */
void test_set_wlan_security_mode_none()
{
    set_wlan_security_mode("none");
}

/*!\test
 * Set WLAN security mode to WPA/PSK.
 */
void test_set_wlan_security_mode_wpa_psk()
{
    set_wlan_security_mode("psk");
}

/*!\test
 * Set WLAN security mode to WPA EAP mode ("WPA Enterprise").
 */
void test_set_wlan_security_mode_wpa_eap()
{
    set_wlan_security_mode("ieee8021x");
}

/*!\test
 * Set WLAN security mode to WPS, name is given.
 */
void test_set_wlan_security_mode_wps_with_name()
{
    set_wlan_security_mode("wps", false, "MyNetwork", nullptr);
}

/*!\test
 * Set WLAN security mode to WPS, SSID is given.
 */
void test_set_wlan_security_mode_wps_with_ssid()
{
    const std::vector<uint8_t> ssid { 0x05, 0xfb, 0x81, 0xc2, 0x7a, };
    set_wlan_security_mode("wps", false, nullptr, &ssid);
}

/*!\test
 * Set WLAN security mode to WPS, scan mode.
 */
void test_set_wlan_security_mode_wps()
{
    set_wlan_security_mode("wps", false, nullptr, nullptr);
}

/*!\test
 * Set WLAN security mode to pseudo mode "wps-abort" to abort WPS.
 */
void test_set_wlan_security_mode_to_abort_wps()
{
    set_wlan_security_mode("wps-abort", false, nullptr, nullptr);
}

/*!\test
 * Setting WLAN security mode to WEP is not implemented.
 */
void test_set_wlan_security_mode_wep()
{
    assume_wlan_interface_is_active();

    start_ipv4_config(Connman::Technology::WLAN);

    auto *reg = lookup_register_expect_handlers(92,
                                                Regs::NetworkConfig::DCP::read_92_wlan_security,
                                                Regs::NetworkConfig::DCP::write_92_wlan_security);
    reg->write(reinterpret_cast<const uint8_t *>("wep"), 3);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address B4:DD:EA:DB:EE:F1");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1, .ptr = nullptr, .length = 0 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents, 4);

    mock_messages->expect_msg_error(0, LOG_CRIT,
                                    "BUG: Support for insecure WLAN mode "
                                    "\"WEP\" not implemented");
    mock_backtrace->expect_backtrace_log();
    mock_messages->expect_msg_error(EINVAL, LOG_ERR,
                                    "Cannot set WLAN parameters, security mode missing");

    commit_ipv4_config(NWPREFSTECH_UNKNOWN, -1);

    expect_default_network_preferences_content(written_default_contents);
}

/*!\test
 * Setting invalid WLAN security mode is detected when attempting to write
 * configuration.
 */
void test_set_invalid_wlan_security_mode()
{
    assume_wlan_interface_is_active();

    start_ipv4_config(Connman::Technology::WLAN);

    auto *reg = lookup_register_expect_handlers(92,
                                                Regs::NetworkConfig::DCP::read_92_wlan_security,
                                                Regs::NetworkConfig::DCP::write_92_wlan_security);
    reg->write(reinterpret_cast<const uint8_t *>("foo"), 3);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address B4:DD:EA:DB:EE:F1");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1, .ptr = nullptr, .length = 0 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents, 4);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
                                              "Invalid WLAN security mode \"foo\" (Invalid argument)");
    mock_messages->expect_msg_error(EINVAL, LOG_ERR,
                                    "Cannot set WLAN parameters, security mode missing");

    commit_ipv4_config(NWPREFSTECH_UNKNOWN, -1);

    expect_default_network_preferences_content(written_default_contents);
}

static void get_wlan_security_mode(const char *assumed_connman_security_mode,
                                   const char *expected_error_message = nullptr)
{
    assume_interface_is_active<Connman::Technology::WLAN>(
        nullptr,
        [assumed_connman_security_mode]
        (Connman::ServiceData &sdata, Connman::TechData<Connman::Technology::WLAN> &tdata)
        {
            tdata.security_ = assumed_connman_security_mode;
        });

    static const uint8_t redzone_content[] =
    {
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
    };

    uint8_t buffer[32];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    static constexpr const size_t read_size = sizeof(buffer) - 2 * sizeof(redzone_content);

    auto *reg = lookup_register_expect_handlers(92,
                                                Regs::NetworkConfig::DCP::read_92_wlan_security,
                                                Regs::NetworkConfig::DCP::write_92_wlan_security);
    uint8_t *const dest = &buffer[sizeof(redzone_content)];

    if(expected_error_message != nullptr)
        mock_messages->expect_msg_error_formatted(0, LOG_ERR,
                                                  expected_error_message);

    const size_t mode_length = reg->read(dest, read_size);

    cppcut_assert_operator(size_t(0), <, mode_length);
    cppcut_assert_equal('\0', static_cast<char>(dest[mode_length - 1]));
    cppcut_assert_equal(assumed_connman_security_mode,
                        reinterpret_cast<char *>(dest));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer, sizeof(redzone_content));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + sizeof(buffer) - sizeof(redzone_content),
                            sizeof(redzone_content));
}

/*!\test
 * Read out WLAN security mode when no security mode is enabled.
 */
void test_get_wlan_security_mode_assume_none()
{
    get_wlan_security_mode("none");
}

/*!\test
 * Read out WLAN security mode in WEP mode.
 */
void test_get_wlan_security_mode_assume_wep()
{
    get_wlan_security_mode("wep");
}

/*!\test
 * Read out WLAN security mode in WPA/WPA2 PSK mode.
 */
void test_get_wlan_security_mode_assume_psk()
{
    get_wlan_security_mode("psk");
}

/*!\test
 * Read out WLAN security mode in WPA EAP mode ("WPA Enterprise").
 */
void test_get_wlan_security_mode_assume_wpa_eap()
{
    get_wlan_security_mode("ieee8021x");
}

/*!\test
 * Read out WLAN security mode in some unknown future mode.
 *
 * This test shows that we are simply passing through any mode name that is
 * currently configured into Connman configuration.
 */
void test_get_wlan_security_mode_assume_unknown_mode()
{
    get_wlan_security_mode("fortknox");
}

static void set_passphrase_with_security_mode(const char *passphrase,
                                              size_t passphrase_size,
                                              const char *connman_security_mode)
{
    assume_wlan_interface_is_active();

    start_ipv4_config(Connman::Technology::WLAN);

    auto *reg = lookup_register_expect_handlers(102,
                                                Regs::NetworkConfig::DCP::read_102_passphrase,
                                                Regs::NetworkConfig::DCP::write_102_passphrase);
    reg->write(reinterpret_cast<const uint8_t *>(passphrase), passphrase_size);

    reg = lookup_register_expect_handlers(92,
                                          Regs::NetworkConfig::DCP::read_92_wlan_security,
                                          Regs::NetworkConfig::DCP::write_92_wlan_security);
    reg->write(reinterpret_cast<const uint8_t *>(connman_security_mode), strlen(connman_security_mode));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address B4:DD:EA:DB:EE:F1");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1, .ptr = nullptr, .length = 0 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents, 4);

    mock_os->expect_os_file_new(expected_os_write_fd, 0, network_config_file);

    if(strcmp(connman_security_mode, "none") == 0)
    {
        passphrase = "";
        passphrase_size = 0;
    }

    const int expected_number_of_writes =
        2 * 3 + (2 + 3 + ((passphrase_size == 0) ? 0 : 1)) * 4;

    for(int i = 0; i < expected_number_of_writes; ++i)
        mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);

    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, network_config_path);

    commit_ipv4_config(NWPREFSTECH_WLAN);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "[wifi]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "Security = %s\n"
        "Passphrase = %s\n";

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format, ethernet_mac_address,
             wlan_mac_address,
             connman_security_mode, passphrase);

    const size_t written_config_file_length =
        strlen(new_config_file_buffer) -
        ((passphrase_size == 0) ? 14 : 0);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Passphrase may be sent as ASCII string.
 */
void test_set_ascii_passphrase_with_psk_security_mode()
{
    static constexpr char ascii_passphrase[] = "My Secret 123&Foo~Bar";

    cppcut_assert_operator(size_t(64), >, sizeof(ascii_passphrase) - 1);
    set_passphrase_with_security_mode(ascii_passphrase, sizeof(ascii_passphrase) - 1,
                                      "psk");
}

/*!\test
 * Passphrase may be sent as string containing only hex characters.
 */
void test_set_hex_passphrase_with_psk_security_mode()
{
    static constexpr char hex_passphrase[] =
        "1234567890abcdef"
        "1234567890abcdef"
        "1234567890abcdef"
        "1234567890abcdef";

    cppcut_assert_equal(size_t(64), sizeof(hex_passphrase) - 1);
    set_passphrase_with_security_mode(hex_passphrase, sizeof(hex_passphrase) - 1,
                                      "psk");
}

/*!\test
 * ASCII passphrase lengths are more or less with out any limits.
 */
void test_ascii_passphrase_has_no_practical_length_boundaries()
{
    assume_wlan_interface_is_active();

    start_ipv4_config(Connman::Technology::WLAN);

    static constexpr char passphrase[] =
        "12345678901234567890"
        "abcdefghijklmnopqrst"
        " ~123456789012345678"
        "abcdefghijklmnopqrst";
    static auto *passphrase_arg = reinterpret_cast<const uint8_t *>(passphrase);

    auto *reg = lookup_register_expect_handlers(102,
                                                Regs::NetworkConfig::DCP::read_102_passphrase,
                                                Regs::NetworkConfig::DCP::write_102_passphrase);

    reg->write(passphrase_arg, 0);
    reg->write(passphrase_arg, 1);
    reg->write(passphrase_arg, 63);
    reg->write(passphrase_arg, 64);  /* length of a hex password */
    reg->write(passphrase_arg, 65);
    reg->write(passphrase_arg, sizeof(passphrase) - 1);
}

/*!\test
 * Passphrase shall not contain special characters.
 */
void test_passphrase_must_be_within_sane_ascii_character_subset()
{
    assume_wlan_interface_is_active();

    start_ipv4_config(Connman::Technology::WLAN);

    auto *reg = lookup_register_expect_handlers(102,
                                                Regs::NetworkConfig::DCP::read_102_passphrase,
                                                Regs::NetworkConfig::DCP::write_102_passphrase);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Invalid passphrase: expected ASCII passphrase (Invalid argument)");
    write_buffer_expect_failure(reg, "\x80", 1, -1);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Invalid passphrase: expected ASCII passphrase (Invalid argument)");
    write_buffer_expect_failure(reg, "\x1f", 1, -1);
}

struct StringWithLength
{
    const size_t length_;
    const uint8_t *string_;

    StringWithLength(const StringWithLength &) = delete;
    StringWithLength &operator=(const StringWithLength &) = delete;
    StringWithLength(StringWithLength &&) = default;
    StringWithLength &operator=(StringWithLength &&) = delete;

    template <size_t Length>
    explicit StringWithLength(const char (&str)[Length]):
        length_(Length - 1),
        string_(reinterpret_cast<const uint8_t *>(str))
    {}
};

/*!\test
 * ASCII passphrase must contain characters in certain range
 */
void test_ascii_passphrase_character_set()
{
    assume_wlan_interface_is_active();

    start_ipv4_config(Connman::Technology::WLAN);

    auto *reg = lookup_register_expect_handlers(102,
                                                Regs::NetworkConfig::DCP::read_102_passphrase,
                                                Regs::NetworkConfig::DCP::write_102_passphrase);

    static const std::array<StringWithLength, 7> non_ascii_passphrases =
    {
        StringWithLength("\0""012345678ghij"),
        StringWithLength("01\0""2345678ghij"),
        StringWithLength("abcde\x01ghij"),
        StringWithLength("abcde\tfghij"),
        StringWithLength("\nabcdefghijklmno"),
        StringWithLength("abcdefghijklmno\x7f"),
        StringWithLength("abcdefghi\x1fklmno"),
    };

    for(const auto &str : non_ascii_passphrases)
    {
        mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
            "Invalid passphrase: expected ASCII passphrase (Invalid argument)");
        write_buffer_expect_failure(reg, str.string_, str.length_, -1);
    }
}

/*!\test
 * Passphrase with security mode "none" makes no sense and is ignored.
 */
void test_set_passphrase_with_security_mode_none_works()
{
    static constexpr char ascii_passphrase[] = "SuperSecret";

    cppcut_assert_operator(size_t(64), >, sizeof(ascii_passphrase) - 1);
    set_passphrase_with_security_mode(ascii_passphrase, sizeof(ascii_passphrase) - 1,
                                      "none");
}

/*!\test
 * Explicitly empty passphrase with security mode "none" is accepted.
 */
void test_set_empty_passphrase_with_security_mode_none_works()
{
    set_passphrase_with_security_mode("", 0, "none");
}

/*!\test
 * Passphrase without any security mode makes no sense and is rejected.
 */
void test_set_passphrase_without_security_mode_does_not_work()
{
    assume_interface_is_active<Connman::Technology::WLAN>(
        nullptr,
        [] (Connman::ServiceData &sdata, Connman::TechData<Connman::Technology::WLAN> &tdata)
        {
            tdata.security_.set_unknown();
        });

    start_ipv4_config(Connman::Technology::WLAN);

    static constexpr char passphrase[] = "SuperSecret";
    auto *reg = lookup_register_expect_handlers(102,
                                                Regs::NetworkConfig::DCP::read_102_passphrase,
                                                Regs::NetworkConfig::DCP::write_102_passphrase);
    reg->write(reinterpret_cast<const uint8_t *>(passphrase), sizeof(passphrase) - 1);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address B4:DD:EA:DB:EE:F1");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1, .ptr = nullptr, .length = 0 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents, 4);

    mock_messages->expect_msg_error(EINVAL, LOG_ERR,
                                    "Cannot set WLAN parameters, security mode missing");

    commit_ipv4_config(NWPREFSTECH_UNKNOWN, -1);

    expect_default_network_preferences_content(written_default_contents);
}

/*!\test
 * Passphrase can be read out while the configuration is in edit mode.
 */
void test_get_wlan_passphrase_in_edit_mode()
{
    assume_wlan_interface_is_active();

    start_ipv4_config(Connman::Technology::WLAN);

    static const uint8_t redzone_content[] =
    {
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
    };

    uint8_t buffer[64 + 2 * sizeof(redzone_content)];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    auto *reg = lookup_register_expect_handlers(102,
                                                Regs::NetworkConfig::DCP::read_102_passphrase,
                                                Regs::NetworkConfig::DCP::write_102_passphrase);

    mock_messages->expect_msg_info("No passphrase set yet");

    cppcut_assert_equal(size_t(0), reg->read(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[0]);
    cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[sizeof(buffer) - 1]);

    /* set hex passphrase and read back */
    static const uint8_t passphrase[] =
        "12345678901234567890"
        "abcdefabcdefabcdefab"
        "12345678901234567890"
        "abcd";

    reg->write(reinterpret_cast<const uint8_t *>(passphrase), sizeof(passphrase) - 1);

    uint8_t *const dest = &buffer[sizeof(redzone_content)];
    const size_t passphrase_length = reg->read(dest, 64);

    cppcut_assert_equal(size_t(64), passphrase_length);
    cut_assert_equal_memory(passphrase, sizeof(passphrase) - 1,
                            dest, 64);
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer, sizeof(redzone_content));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + sizeof(buffer) - sizeof(redzone_content),
                            sizeof(redzone_content));

    /* wipe out passphrase and read back */
    reg->write(reinterpret_cast<const uint8_t *>(passphrase), 0);

    mock_messages->expect_msg_info("Passphrase set, but empty");

    memset(buffer, UINT8_MAX, sizeof(buffer));
    cppcut_assert_equal(size_t(0), reg->read(dest, 64));
    cppcut_assert_equal(uint8_t(UINT8_MAX), dest[0]);
    cppcut_assert_equal(uint8_t(UINT8_MAX), dest[63]);
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer, sizeof(redzone_content));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + sizeof(buffer) - sizeof(redzone_content),
                            sizeof(redzone_content));
}

/*!\test
 * Passphrase cannot be read out while the configuration is in read-only mode.
 */
void test_get_wlan_passphrase_in_regular_mode()
{
    assume_wlan_interface_is_active();

    uint8_t buffer[64];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    auto *reg = lookup_register_expect_handlers(102,
                                                Regs::NetworkConfig::DCP::read_102_passphrase,
                                                Regs::NetworkConfig::DCP::write_102_passphrase);

    mock_messages->expect_msg_error(0, LOG_NOTICE,
                                    "Passphrase cannot be read out while in non-edit mode");

    read_buffer_expect_failure(reg, buffer, sizeof(buffer), -1);
    cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[0]);
    cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[sizeof(buffer) - 1]);
}

/*!\test
 * In most cases, the SSID will be a rather simple ASCII string.
 *
 * Here, "simple" means regular ASCII characters and no spaces. If the SSID is
 * simple enough, it will be written to the "NetworkName" field of the
 * configuration file.
 *
 * The zero-terminator is usually not part of the SSID and must not be sent
 * over DCP (otherwise the SSID will be considered binary because it ends with
 * a 0 byte).
 */
void test_set_simple_ascii_wlan_ssid()
{
    assume_wlan_interface_is_active();

    start_ipv4_config(Connman::Technology::WLAN);

    auto *reg = lookup_register_expect_handlers(94,
                                                Regs::NetworkConfig::DCP::read_94_ssid,
                                                Regs::NetworkConfig::DCP::write_94_ssid);

    static constexpr char ssid[] = "MyNiceWLAN";

    reg->write(reinterpret_cast<const uint8_t *>(ssid), sizeof(ssid) - 1);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address B4:DD:EA:DB:EE:F1");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1, .ptr = nullptr, .length = 0 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents, 4);

    mock_os->expect_os_file_new(expected_os_write_fd, 0, network_config_file);
    for(int i = 0; i < 2 * 3 + (2 + 4) * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, network_config_path);

    commit_ipv4_config(NWPREFSTECH_WLAN);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "[wifi]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "NetworkName = %s\n"
        "Security = none\n";

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format, ethernet_mac_address,
             wlan_mac_address, ssid);

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * An SSID may be any binary string with a length of up to 32 bytes.
 */
void test_set_binary_wlan_ssid()
{
    assume_wlan_interface_is_active();

    start_ipv4_config(Connman::Technology::WLAN);

    auto *reg = lookup_register_expect_handlers(94,
                                                Regs::NetworkConfig::DCP::read_94_ssid,
                                                Regs::NetworkConfig::DCP::write_94_ssid);

    static constexpr uint8_t ssid[] =
    {
        0x00, 0x08, 0xfe, 0xff, 0x41, 0x42, 0x43, 0x7f,
    };

    static constexpr char ssid_as_hex_string[] = "0008feff4142437f";

    reg->write(ssid, sizeof(ssid));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address B4:DD:EA:DB:EE:F1");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1, .ptr = nullptr, .length = 0 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents, 4);

    mock_os->expect_os_file_new(expected_os_write_fd, 0, network_config_file);
    for(int i = 0; i < 2 * 3 + (2 + 4) * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, network_config_path);

    commit_ipv4_config(NWPREFSTECH_WLAN);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "[wifi]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "SSID = %s\n"
        "Security = none\n";

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format, ethernet_mac_address,
             wlan_mac_address, ssid_as_hex_string);

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * The empty SSID is a special wildcard SSID and cannot be used here.
 */
void test_set_empty_wlan_ssid_is_an_error()
{
    assume_wlan_interface_is_active();

    start_ipv4_config(Connman::Technology::WLAN);

    auto *reg = lookup_register_expect_handlers(94,
                                                Regs::NetworkConfig::DCP::read_94_ssid,
                                                Regs::NetworkConfig::DCP::write_94_ssid);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
                                              "Empty SSID rejected (Invalid argument)");

    uint8_t dummy = UINT8_MAX;
    write_buffer_expect_failure(reg, &dummy, 0, -1);

    commit_ipv4_config(NWPREFSTECH_UNKNOWN);
}

static char nibble_to_char(uint8_t nibble)
{
    static const std::array<const char, 16> tab
    {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    };

    return nibble < sizeof(tab) ? tab[nibble] : '?';
}

/*!\test
 * Read out the SSID for displaying purposes.
 */
void test_get_wlan_ssid_in_normal_mode()
{
    assume_wlan_interface_is_active();

    static constexpr uint8_t redzone_content[] =
    {
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
    };

    static constexpr uint8_t assumed_ssid[] =
    {
        0x09, 0x20, 0x60, 0xfe, 0x00, 0x01, 0xff, 0x80,
        0x7e, 0x7f, 0x00, 0x08, 0x61, 0xcb, 0xa7, 0xd0,
        0x0a, 0x21, 0x61, 0xff, 0x01, 0x02, 0x00, 0x81,
        0x7f, 0x80, 0x01, 0x09, 0x62, 0xcc, 0xa8, 0xd1,
    };

    assume_interface_is_active<Connman::Technology::WLAN>(
        nullptr,
        [] (Connman::ServiceData &sdata, Connman::TechData<Connman::Technology::WLAN> &tdata)
        {
            tdata.network_name_.set_unknown();
            tdata.network_ssid_ = "";

            for(const uint8_t &byte : assumed_ssid)
            {
                tdata.network_ssid_.get_rw().push_back(nibble_to_char(byte >> 4));
                tdata.network_ssid_.get_rw().push_back(nibble_to_char(byte & 0x0f));
            }
        });

    uint8_t buffer[32 + 2 * sizeof(redzone_content)];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    auto *reg = lookup_register_expect_handlers(94,
                                                Regs::NetworkConfig::DCP::read_94_ssid,
                                                Regs::NetworkConfig::DCP::write_94_ssid);
    uint8_t *const dest = &buffer[sizeof(redzone_content)];

    const size_t ssid_length = reg->read(dest, 32);

    cut_assert_equal_memory(assumed_ssid, ssize_t(sizeof(assumed_ssid)),
                            dest, ssid_length);
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer, sizeof(redzone_content));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + sizeof(buffer) - sizeof(redzone_content),
                            sizeof(redzone_content));
}

/*!\test
 * Read out the SSID in edit mode, Connman is consulted if the SSID has not
 * been set during this edit session.
 */
void test_get_wlan_ssid_in_edit_mode_before_any_changes()
{
    assume_wlan_interface_is_active();

    start_ipv4_config(Connman::Technology::WLAN);

    static constexpr uint8_t redzone_content[] =
    {
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
    };

    static constexpr uint8_t assumed_ssid[] =
    {
        0x7e, 0x7f, 0x00, 0x08, 0x61, 0xcb, 0xa7, 0xd0,
        0x09, 0x20, 0x60, 0xfe, 0x00, 0x01, 0xff, 0x80,
        0x0a, 0x21, 0x61, 0xff, 0x01, 0x02, 0x00, 0x81,
    };

    assume_interface_is_active<Connman::Technology::WLAN>(
        nullptr,
        [] (Connman::ServiceData &sdata, Connman::TechData<Connman::Technology::WLAN> &tdata)
        {
            tdata.network_name_.set_unknown();
            tdata.network_ssid_ = "";

            for(const uint8_t &byte : assumed_ssid)
            {
                tdata.network_ssid_.get_rw().push_back(nibble_to_char(byte >> 4));
                tdata.network_ssid_.get_rw().push_back(nibble_to_char(byte & 0x0f));
            }
        });

    cppcut_assert_operator(size_t(32), <=, sizeof(assumed_ssid) + sizeof(redzone_content));

    uint8_t buffer[sizeof(assumed_ssid) + 2 * sizeof(redzone_content)];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    auto *reg = lookup_register_expect_handlers(94,
                                                Regs::NetworkConfig::DCP::read_94_ssid,
                                                Regs::NetworkConfig::DCP::write_94_ssid);
    uint8_t *const dest = &buffer[sizeof(redzone_content)];

    const size_t ssid_length = reg->read(dest, 32);

    cut_assert_equal_memory(dest, sizeof(assumed_ssid),
                            buffer + sizeof(redzone_content), ssid_length);
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer, sizeof(redzone_content));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + sizeof(buffer) - sizeof(redzone_content),
                            sizeof(redzone_content));
}

/*!\test
 * Read out the SSID in edit mode, return SSID currently being edited.
 */
void test_get_wlan_ssid_in_edit_mode_after_change()
{
    assume_wlan_interface_is_active();

    start_ipv4_config(Connman::Technology::WLAN);

    auto *reg = lookup_register_expect_handlers(94,
                                                Regs::NetworkConfig::DCP::read_94_ssid,
                                                Regs::NetworkConfig::DCP::write_94_ssid);

    static constexpr uint8_t ssid[] =
    {
        0x0a, 0x21, 0x61, 0xff, 0x01, 0x02, 0x00, 0x81,
        0x09, 0x20, 0x60, 0xfe, 0x00, 0x01, 0xff, 0x80,
        0x7f, 0x80, 0x01, 0x09, 0x62, 0xcc, 0xa8, 0xd1,
    };

    static constexpr uint8_t redzone_content[] =
    {
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
    };

    cppcut_assert_equal(size_t(32), sizeof(ssid) + sizeof(redzone_content));

    reg->write(ssid, sizeof(ssid));

    uint8_t buffer[32];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    const size_t ssid_length = reg->read(buffer, sizeof(buffer));

    cut_assert_equal_memory(ssid, sizeof(ssid),
                            buffer, ssid_length);
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + ssid_length, sizeof(redzone_content));
}

/*!\test
 * Attempting to set ad-hoc mode results in an error.
 *
 * Connman does not support ad-hoc mode, so we do not either.
 */
void test_set_ibss_mode_adhoc_is_not_supported()
{
    assume_wlan_interface_is_active();

    start_ipv4_config(Connman::Technology::WLAN);

    auto *reg = lookup_register_expect_handlers(93,
                                                Regs::NetworkConfig::DCP::read_93_ibss,
                                                Regs::NetworkConfig::DCP::write_93_ibss);

    mock_messages->expect_msg_error(EINVAL, LOG_NOTICE,
                                    "Cannot change IBSS mode to ad-hoc, "
                                    "always using infrastructure mode");
    write_buffer_expect_failure(reg, "true", 4, -1);
}

/*!\test
 * Attempting to set infrastructure mode succeeds, but the attempt is logged
 * and gets ignored.
 */
void test_set_ibss_mode_infrastructure_is_ignored()
{
    assume_wlan_interface_is_active();

    start_ipv4_config(Connman::Technology::WLAN);

    auto *reg = lookup_register_expect_handlers(93,
                                                Regs::NetworkConfig::DCP::read_93_ibss,
                                                Regs::NetworkConfig::DCP::write_93_ibss);

    mock_messages->expect_msg_info("Ignoring IBSS infrastructure mode request "
                                   "(always using that mode)");
    reg->write(reinterpret_cast<const uint8_t *>("false"), 5);
}

/*!\test
 * Even though we do not support setting IBSS mode, it is still not allowed to
 * send junk.
 */
void test_set_junk_ibss_mode_is_an_error()
{
    assume_wlan_interface_is_active();

    start_ipv4_config(Connman::Technology::WLAN);

    static const std::array<StringWithLength, 13> junk_requests =
    {
        StringWithLength("\0\0\0\0"),
        StringWithLength("\0\0\0\0\0\0\0\0"),
        StringWithLength("t\0\0\0"),
        StringWithLength("tru\0"),
        StringWithLength("rue\0"),
        StringWithLength("f\0\0\0"),
        StringWithLength("fals"),
        StringWithLength("alse"),
        StringWithLength("abcdefg"),
        StringWithLength("\ntrue"),
        StringWithLength("\nfalse"),
        StringWithLength("\0true"),
        StringWithLength("\0false"),
    };

    auto *reg = lookup_register_expect_handlers(93,
                                                Regs::NetworkConfig::DCP::read_93_ibss,
                                                Regs::NetworkConfig::DCP::write_93_ibss);

    for(const auto &str : junk_requests)
    {
        mock_messages->expect_msg_error(EINVAL, LOG_ERR,
                                        "Got invalid IBSS mode request");
        write_buffer_expect_failure(reg, str.string_, str.length_, -1);
    }
}

/*!\test
 * We always tell we are operating in infrastructure mode.
 */
void test_get_ibss_mode_returns_infrastructure_mode()
{
    assume_wlan_interface_is_active();

    auto *reg = lookup_register_expect_handlers(93,
                                                Regs::NetworkConfig::DCP::read_93_ibss,
                                                Regs::NetworkConfig::DCP::write_93_ibss);

    uint8_t response[8];
    cppcut_assert_equal(size_t(6), reg->read(response, sizeof(response)));
    cppcut_assert_equal("false", reinterpret_cast<const char *>(response));
}

/*!\test
 * Attempting to set WPA cipher mode succeeds, but the attempt is logged and
 * gets ignored.
 */
void test_set_wpa_cipher_is_ignored()
{
    assume_wlan_interface_is_active();

    start_ipv4_config(Connman::Technology::WLAN);

    auto *reg = lookup_register_expect_handlers(101,
                                                Regs::NetworkConfig::DCP::read_101_wpa_cipher,
                                                Regs::NetworkConfig::DCP::write_101_wpa_cipher);

    mock_messages->expect_msg_info("Ignoring setting WPA cipher (automatic, AES preferred)");
    reg->write(reinterpret_cast<const uint8_t *>("TKIP"), 4);

    mock_messages->expect_msg_info("Ignoring setting WPA cipher (automatic, AES preferred)");
    reg->write(reinterpret_cast<const uint8_t *>("TKIP"), 5);

    mock_messages->expect_msg_info("Ignoring setting WPA cipher (automatic, AES preferred)");
    reg->write(reinterpret_cast<const uint8_t *>("AES"), 3);

    mock_messages->expect_msg_info("Ignoring setting WPA cipher (automatic, AES preferred)");
    reg->write(reinterpret_cast<const uint8_t *>("AES"), 4);
}

/*!\test
 * Even though we do not support setting WPA cipher, it is still not allowed to
 * send junk.
 */
void test_set_junk_wpa_cipher_is_an_error()
{
    assume_wlan_interface_is_active();

    start_ipv4_config(Connman::Technology::WLAN);

    static const std::array<StringWithLength, 16> junk_requests =
    {
        StringWithLength("\0\0\0\0"),
        StringWithLength("\0\0\0\0\0\0\0\0"),
        StringWithLength("aes"),
        StringWithLength("A\0\0"),
        StringWithLength("ES\0"),
        StringWithLength("tkip"),
        StringWithLength("T\0\0"),
        StringWithLength("KIP"),
        StringWithLength("abcdefg"),
        StringWithLength("DES"),
        StringWithLength("RSA"),
        StringWithLength("RIJNDAEL"),
        StringWithLength("\nAES"),
        StringWithLength("\nTKIP"),
        StringWithLength("\0AES"),
        StringWithLength("\0TKIP"),
    };

    auto *reg = lookup_register_expect_handlers(101,
                                                Regs::NetworkConfig::DCP::read_101_wpa_cipher,
                                                Regs::NetworkConfig::DCP::write_101_wpa_cipher);

    for(const auto &str : junk_requests)
    {
        mock_messages->expect_msg_error(EINVAL, LOG_ERR,
                                        "Got invalid WPA cipher");
        write_buffer_expect_failure(reg, str.string_, str.length_, -1);
    }
}

/*!\test
 * We always tell we are using AES.
 */
void test_get_wpa_cipher_returns_aes()
{
    assume_wlan_interface_is_active();

    auto *reg = lookup_register_expect_handlers(101,
                                                Regs::NetworkConfig::DCP::read_101_wpa_cipher,
                                                Regs::NetworkConfig::DCP::write_101_wpa_cipher);

    uint8_t response[8];
    cppcut_assert_equal(size_t(4), reg->read(response, sizeof(response)));
    cppcut_assert_equal("AES", reinterpret_cast<const char *>(response));
}

/*!\test
 * Network configuration cannot be saved after shutdown.
 */
void test_configuration_update_is_blocked_after_shutdown()
{
    start_ipv4_config(Connman::Technology::ETHERNET);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Shutdown guard \"networkconfig\" down");
    Regs::NetworkConfig::prepare_for_shutdown();

    /* in-memory edits are still working... */
    auto *reg = lookup_register_expect_handlers(55,
                                                Regs::NetworkConfig::DCP::read_55_dhcp_enabled,
                                                Regs::NetworkConfig::DCP::write_55_dhcp_enabled);
    static const uint8_t zero = 0;

    mock_messages->expect_msg_info_formatted("Disable DHCP");
    reg->write(&zero, 1);

    /* ...but writing to file is blocked */
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address C4:FD:EC:AF:DE:AD");
    mock_messages->expect_msg_info("Not writing network configuration during shutdown.");
    commit_ipv4_config(NWPREFSTECH_UNKNOWN, -1);
}

/*!\test
 * Attempting to shut down twice has no effect.
 */
void test_shutdown_can_be_called_only_once()
{
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Shutdown guard \"networkconfig\" down");
    Regs::NetworkConfig::prepare_for_shutdown();

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Shutdown guard \"networkconfig\" down");
    Regs::NetworkConfig::prepare_for_shutdown();
}

static void expect_network_status(const std::array<uint8_t, 3> &expected_status)
{
    auto *reg = lookup_register_expect_handlers(50,
                                                Regs::NetworkConfig::DCP::read_50_network_status,
                                                nullptr);
    uint8_t status[expected_status.size()];
    cppcut_assert_equal(sizeof(status), reg->read(status, sizeof(status)));

    cut_assert_equal_memory(expected_status.data(), expected_status.size(),
                            status, sizeof(status));
}

/*!\test
 * In case there is a ready Ethernet and an idle WLAN service, the network
 * status register indicates connected in Ethernet mode.
 */
void test_network_status__ethernet_ready__wlan_idle()
{
    static const std::array<const char *const, 17> network_status_logs
    {
        "Network device: Ethernet C4:FD:EC:AF:DE:AD, auto, physical",
        "Network (requested): IPv4 settings invalid",
        "Network (requested): No IPv6 configuration",
        "Network (requested): No proxy configuration",
        "Network (requested): DNS server list *unknown*",
        "Network (requested): NTP server list *unknown*",
        "Network (requested): Domain list *unknown*",
        "Network (active): IPv4 configuration method DHCP",
        "Network (active): IPv4 address 192.168.166.177",
        "Network (active): IPv4 netmask 255.255.255.0",
        "Network (active): IPv4 gateway 192.168.166.15",
        "Network (active): No IPv6 configuration",
        "Network (active): No proxy configuration",
        "Network (active): DNS server 13.24.35.246",
        "Network (active): DNS server 4.225.136.7",
        "Network (active): NTP server list *unknown*",
        "Network (active): Domain list *unknown*",
    };

    for(const auto *log : network_status_logs)
        mock_messages->expect_msg_info_formatted(log);

    expect_network_status({NETWORK_STATUS_IPV4_DHCP,
                           NETWORK_STATUS_DEVICE_ETHERNET,
                           NETWORK_STATUS_CONNECTION_CONNECTED});
}

/*!\test
 * In case there is an idle Ethernet and a ready WLAN service, the network
 * status register indicates connected in WLAN mode.
 */
void test_network_status__ethernet_idle__wlan_ready()
{
    inject_service_changes(ethernet_name,
        [] (Connman::ServiceData &sdata) { sdata.state_ = Connman::ServiceState::IDLE; });

    inject_service_changes(wlan_name,
        [] (Connman::ServiceData &sdata) { sdata.state_ = Connman::ServiceState::READY; });

    static const std::array<const char *const, 17> network_status_logs
    {
        "Network device: WLAN B4:DD:EA:DB:EE:F1, auto, physical",
        "Network (requested): IPv4 settings invalid",
        "Network (requested): No IPv6 configuration",
        "Network (requested): No proxy configuration",
        "Network (requested): DNS server list *unknown*",
        "Network (requested): NTP server list *unknown*",
        "Network (requested): Domain list *unknown*",
        "Network (active): IPv4 configuration method DHCP",
        "Network (active): IPv4 address 192.168.166.177",
        "Network (active): IPv4 netmask 255.255.255.0",
        "Network (active): IPv4 gateway 192.168.166.15",
        "Network (active): No IPv6 configuration",
        "Network (active): No proxy configuration",
        "Network (active): DNS server 13.24.35.246",
        "Network (active): DNS server 4.225.136.7",
        "Network (active): NTP server list *unknown*",
        "Network (active): Domain list *unknown*",
    };

    for(const auto *log : network_status_logs)
        mock_messages->expect_msg_info_formatted(log);

    expect_network_status({NETWORK_STATUS_IPV4_DHCP,
                           NETWORK_STATUS_DEVICE_WLAN,
                           NETWORK_STATUS_CONNECTION_CONNECTED});
}

/*!\test
 * In case of idle Ethernet and WLAN services, the network status register
 * indicates disconnected in Ethernet mode.
 */
void test_network_status__ethernet_idle__wlan_idle()
{
    inject_service_changes(ethernet_name,
        [] (Connman::ServiceData &sdata)
        {
            sdata.state_ = Connman::ServiceState::IDLE;
            sdata.active_.ipsettings_v4_.set_unknown();
            sdata.active_.ipsettings_v6_.set_unknown();
        });

    inject_service_changes(wlan_name,
        [] (Connman::ServiceData &sdata)
        {
            sdata.state_ = Connman::ServiceState::IDLE;
            sdata.active_.ipsettings_v4_.set_unknown();
            sdata.active_.ipsettings_v6_.set_unknown();
        });

    static const std::array<const char *const, 9> network_status_logs
    {
        "Network device: Ethernet C4:FD:EC:AF:DE:AD, auto, physical",
        "Network (requested): IPv4 settings invalid",
        "Network (requested): No IPv6 configuration",
        "Network (requested): No proxy configuration",
        "Network (requested): DNS server list *unknown*",
        "Network (requested): NTP server list *unknown*",
        "Network (requested): Domain list *unknown*",
        "Network (active): No IPv4 configuration",
        "Network (active): No IPv6 configuration",
    };

    for(const auto *log : network_status_logs)
        mock_messages->expect_msg_info_formatted(log);

    expect_network_status({NETWORK_STATUS_IPV4_NOT_CONFIGURED,
                           NETWORK_STATUS_DEVICE_ETHERNET,
                           NETWORK_STATUS_CONNECTION_NONE});
}

/*!\test
 * In case there is no WLAN, but an idle Ethernet service available, the status
 * register indicates disconnected in Ethernet mode.
 */
void test_network_status__ethernet_idle___wlan_unavailable()
{
    {
        auto locked(Connman::ServiceList::get_singleton_for_update());
        auto &services(locked.first);
        services.erase(wlan_name);
    }

    inject_service_changes(ethernet_name,
        [] (Connman::ServiceData &sdata)
        {
            sdata.state_ = Connman::ServiceState::IDLE;
            sdata.active_.ipsettings_v4_.set_unknown();
            sdata.active_.ipsettings_v6_.set_unknown();
        });

    static const std::array<const char *const, 9> network_status_logs
    {
        "Network device: Ethernet C4:FD:EC:AF:DE:AD, auto, physical",
        "Network (requested): IPv4 settings invalid",
        "Network (requested): No IPv6 configuration",
        "Network (requested): No proxy configuration",
        "Network (requested): DNS server list *unknown*",
        "Network (requested): NTP server list *unknown*",
        "Network (requested): Domain list *unknown*",
        "Network (active): No IPv4 configuration",
        "Network (active): No IPv6 configuration",
    };

    for(const auto *log : network_status_logs)
        mock_messages->expect_msg_info_formatted(log);

    expect_network_status({NETWORK_STATUS_IPV4_NOT_CONFIGURED,
                           NETWORK_STATUS_DEVICE_ETHERNET,
                           NETWORK_STATUS_CONNECTION_NONE});
}

/*!\test
 * In case there is no Ethernet, but an idle WLAN service available, the status
 * register indicates disconnected in WLAN mode.
 */
void test_network_status__ethernet_unavailable___wlan_idle()
{
    {
        auto locked(Connman::ServiceList::get_singleton_for_update());
        auto &services(locked.first);
        services.erase(ethernet_name);
    }

    inject_service_changes(wlan_name,
        [] (Connman::ServiceData &sdata)
        {
            sdata.state_ = Connman::ServiceState::IDLE;
            sdata.active_.ipsettings_v4_.set_unknown();
            sdata.active_.ipsettings_v6_.set_unknown();
        });

    static const std::array<const char *const, 9> network_status_logs
    {
        "Network device: WLAN B4:DD:EA:DB:EE:F1, auto, physical",
        "Network (requested): IPv4 settings invalid",
        "Network (requested): No IPv6 configuration",
        "Network (requested): No proxy configuration",
        "Network (requested): DNS server list *unknown*",
        "Network (requested): NTP server list *unknown*",
        "Network (requested): Domain list *unknown*",
        "Network (active): No IPv4 configuration",
        "Network (active): No IPv6 configuration",
    };

    for(const auto *log : network_status_logs)
        mock_messages->expect_msg_info_formatted(log);

    expect_network_status({NETWORK_STATUS_IPV4_NOT_CONFIGURED,
                           NETWORK_STATUS_DEVICE_WLAN,
                           NETWORK_STATUS_CONNECTION_NONE});
}

/*!\test
 * In case there no service at all, the status register indicates disconnected
 * in no specific mode.
 */
void test_network_status__ethernet_unavailable___wlan_unavailable()
{
    {
        auto locked(Connman::ServiceList::get_singleton_for_update());
        auto &services(locked.first);
        services.clear();
    }

    static const std::array<const char *const, 1> network_status_logs
    {
        "Network: no service configured",
    };

    for(const auto *log : network_status_logs)
        mock_messages->expect_msg_info_formatted(log);

    expect_network_status({NETWORK_STATUS_IPV4_NOT_CONFIGURED,
                           NETWORK_STATUS_DEVICE_NONE,
                           NETWORK_STATUS_CONNECTION_NONE});
}

}

#endif /* !LOGGED_LOCKS_ENABLED  */

/*!@}*/
