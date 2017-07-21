/*
 * Copyright (C) 2016, 2017  T+A elektroakustik GmbH & Co. KG
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

#include <algorithm>

#include "networkprefs.h"
#include "connman_service_list.hh"
#include "network_device_list.hh"

#include "mock_messages.hh"
#include "mock_os.hh"

namespace networkprefs_tests
{

static MockMessages *mock_messages;
static MockOs *mock_os;

static constexpr char default_ethernet_mac[] = "09:fa:01:d4:67:e2";
static constexpr char default_wlan_mac[] = "19:af:10:4d:76:e3";
static constexpr char default_path_to_config[] = "/cfg";
static constexpr char default_path_to_connman[] = "/connman";
static constexpr char default_config_file[] = "/cfg/network.ini";

static constexpr char ethernet_name[]         = "/connman/service/ethernet";
static constexpr char wlan_name[]             = "/connman/service/wlan";

static constexpr char standard_ipv4_address[] = "210.132.108.248";
static constexpr char standard_ipv4_netmask[] = "255.255.63.0";
static constexpr char standard_ipv4_gateway[] = "210.132.116.67";
static constexpr char standard_dns1_address[] = "13.24.35.246";
static constexpr char standard_dns2_address[] = "4.225.136.7";

static std::vector<char> os_write_buffer;
static constexpr int expected_os_write_fd = 17;
static constexpr int expected_os_map_file_to_memory_fd = 24;

static int write_from_buffer_callback(const void *src, size_t count, int fd)
{
    cppcut_assert_equal(expected_os_write_fd, fd);
    cppcut_assert_not_null(src);
    cppcut_assert_operator(size_t(0), <, count);

    std::copy_n(static_cast<const char *>(src), count,
                std::back_inserter<std::vector<char>>(os_write_buffer));

    return 0;
}

static void setup_default_connman_service_list()
{
    auto locked(Connman::ServiceList::get_singleton_for_update());
    auto &services(locked.first);

    const auto locked_devices(Connman::NetworkDeviceList::get_singleton_for_update());
    auto &devices(locked_devices.first);

    Connman::ServiceData data;

    Connman::Address<Connman::AddressType::MAC> addr(default_ethernet_mac);
    devices.set_auto_select_mac_address(Connman::Technology::ETHERNET, addr);
    devices.insert(Connman::Technology::ETHERNET, Connman::Address<Connman::AddressType::MAC>(addr));

    data.state_ = Connman::ServiceState::READY;
    data.device_ = devices[addr];
    data.is_favorite_ = true;
    data.is_auto_connect_ = true;
    data.is_immutable_ = false;
    data.ip_settings_v4_.set_known();
    data.ip_settings_v4_.get_rw().set_dhcp_method(Connman::DHCPV4Method::ON);
    data.ip_settings_v4_.get_rw().set_address(standard_ipv4_address);
    data.ip_settings_v4_.get_rw().set_netmask(standard_ipv4_netmask);
    data.ip_settings_v4_.get_rw().set_gateway(standard_ipv4_gateway);
    data.ip_configuration_v4_.set_known();
    data.ip_configuration_v4_.get_rw().set_dhcp_method(Connman::DHCPV4Method::ON);
    data.dns_servers_.set_known();
    data.dns_servers_.get_rw().push_back(standard_dns1_address);
    data.dns_servers_.get_rw().push_back(standard_dns2_address);

    services.insert(ethernet_name, std::move(data),
                    std::move(Connman::TechData<Connman::Technology::ETHERNET>()));

    addr.set(default_wlan_mac);
    devices.set_auto_select_mac_address(Connman::Technology::WLAN, addr);
    devices.insert(Connman::Technology::WLAN, Connman::Address<Connman::AddressType::MAC>(addr));

    data.state_ = Connman::ServiceState::IDLE;
    data.device_ = devices[addr];
    data.is_favorite_ = true;
    data.is_auto_connect_ = true;
    data.is_immutable_ = false;
    data.ip_settings_v4_.set_known();
    data.ip_settings_v4_.get_rw().set_dhcp_method(Connman::DHCPV4Method::ON);
    data.ip_settings_v4_.get_rw().set_address(standard_ipv4_address);
    data.ip_settings_v4_.get_rw().set_netmask(standard_ipv4_netmask);
    data.ip_settings_v4_.get_rw().set_gateway(standard_ipv4_gateway);
    data.ip_configuration_v4_.set_known();
    data.ip_configuration_v4_.get_rw().set_dhcp_method(Connman::DHCPV4Method::ON);
    data.dns_servers_.set_known();
    data.dns_servers_.get_rw().push_back(standard_dns1_address);
    data.dns_servers_.get_rw().push_back(standard_dns2_address);

    services.insert(wlan_name, std::move(data),
                    std::move(Connman::TechData<Connman::Technology::WLAN>()));
}

void cut_setup()
{
    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_os = new MockOs;
    cppcut_assert_not_null(mock_os);
    mock_os->init();
    mock_os_singleton = mock_os;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    os_write_buffer.clear();

    network_prefs_init(default_path_to_config, default_config_file);

    setup_default_connman_service_list();
}

void cut_teardown()
{
    network_prefs_deinit();

    Connman::ServiceList::get_singleton_for_update().first.clear();
    Connman::NetworkDeviceList::get_singleton_for_update().first.clear();

    os_write_buffer.clear();
    os_write_buffer.shrink_to_fit();

    mock_messages->check();
    mock_os->check();

    mock_messages_singleton = nullptr;
    mock_os_singleton = nullptr;

    delete mock_messages;
    delete mock_os;

    mock_messages = nullptr;
    mock_os = nullptr;
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
    mock_os->expect_os_file_new(expected_os_write_fd, default_config_file);
    for(int i = 0; i < 2 * 3 + expected_number_of_assignments * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);
    mock_os->expect_os_sync_dir_callback(default_path_to_config,
                                         std::bind(move_os_write_buffer_to_file,
                                                   std::ref(file_with_written_default_contents),
                                                   std::ref(written_default_contents)));

    const struct os_mapped_file_data *mf = &file_with_written_default_contents;

    mock_os->expect_os_map_file_to_memory(0, mf, default_config_file);
    mock_os->expect_os_unmap_file(mf);

    return mf;
}

static void do_migration(const char *const old_ethernet_config_name,
                         const struct os_mapped_file_data *const old_ethernet_config,
                         const char *const old_wlan_config_name,
                         const struct os_mapped_file_data *const old_wlan_config,
                         size_t expected_number_of_sections,
                         size_t expected_number_of_assignments,
                         const struct os_mapped_file_data *const existing_new_config = nullptr)
{
    mock_os->expect_os_map_file_to_memory(old_ethernet_config,
                                          old_ethernet_config_name);
    if(old_ethernet_config != nullptr)
        mock_os->expect_os_unmap_file(old_ethernet_config);

    mock_os->expect_os_map_file_to_memory(old_wlan_config,
                                          old_wlan_config_name);
    if(old_wlan_config != nullptr)
        mock_os->expect_os_unmap_file(old_wlan_config);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "MIGRATING OLD NETWORK CONFIGURATION");

    struct os_mapped_file_data network_ini = { .fd = -1 };
    std::vector<char> written_default_contents;

    if(existing_new_config == nullptr)
    {
        mock_os->expect_os_map_file_to_memory(-1, false, default_config_file);
        expect_create_default_network_preferences(network_ini, written_default_contents, 4);
    }
    else
    {
        mock_os->expect_os_map_file_to_memory(existing_new_config, default_config_file);
        mock_os->expect_os_unmap_file(existing_new_config);
    }

    if(old_ethernet_config != nullptr)
    {
        mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
            "Migrating network configuration file: \"/connman/builtin_09fa01d467e2.config\"");
        mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
            "Converted \"/connman/builtin_09fa01d467e2.config\"");
    }

    if(old_wlan_config != nullptr)
    {
        mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
            "Migrating network configuration file: \"/connman/wlan_device.config\"");
        mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
            "Converted \"/connman/wlan_device.config\"");
    }

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration file");

    mock_os->expect_os_file_new(expected_os_write_fd, default_config_file);
    const int expected_number_of_writes =
        expected_number_of_sections * 3 + expected_number_of_assignments * 4;
    for(int i = 0; i < expected_number_of_writes; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);
    mock_os->expect_os_sync_dir(default_path_to_config);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Deleting old network configuration files");

    /* both deletes are always done */
    mock_os->expect_os_file_delete(old_ethernet_config_name);
    mock_os->expect_os_file_delete(old_wlan_config_name);

    /* only one of the following items are supposed to be deleted */
    std::vector<MockOs::ForeachItemData> items;
    items.emplace_back(MockOs::ForeachItemData("/connman/builtin.00f00d1f00d1.config", false));
    items.emplace_back(MockOs::ForeachItemData("/connman/builtin_00f00d1f00d1_config", false));
    items.emplace_back(MockOs::ForeachItemData("/connman/builtin_00f00d1f00d1.config", false));
    items.emplace_back(MockOs::ForeachItemData("/connman/builtin_00f00d1f00d12.config", false));
    items.emplace_back(MockOs::ForeachItemData("/connman/ethernet_0050c2d884e7_cable", true));
    items.emplace_back(MockOs::ForeachItemData("/connman/settings", false));
    items.emplace_back(MockOs::ForeachItemData("/connman/wifi_00e1b0534115_5441557064617465536572766572_managed_psk", true));

    mock_os->expect_os_foreach_in_path(0, default_path_to_connman, items);
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Deleting residual configuration file: \"builtin_00f00d1f00d1.config\"");
    mock_os->expect_os_file_delete("/connman/builtin_00f00d1f00d1.config");

    mock_os->expect_os_sync_dir(default_path_to_connman);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
                                              "Migrated old network configuration");

    cut_assert_true(os_write_buffer.empty());

    network_prefs_migrate_old_network_configuration_files(default_path_to_connman);
}

/*!\test
 * Migration of old Ethernet and WLAN configuration.
 */
void test_migrate_old_configuration_files_with_manual_configs()
{
    /* file: builtin_09fa01d467e2.config */
    static const char old_ethernet_config_data[] =
        "[global]\n"
        "Name = StrBo\n"
        "Description = StrBo-managed built-in wired interface\n"
        "[service_config]\n"
        "MAC = 09:fa:01:d4:67:e2\n"
        "Type = ethernet\n"
        "IPv4 = 192.168.22.50/255.255.255.0/192.168.22.10\n"
        "Nameservers = 192.168.22.200\n"
        ;

    /* file: wlan_device.config */
    static const char old_wlan_config_data[] =
        "[global]\n"
        "Name = StrBo\n"
        "Description = StrBo-managed built-in wireless interface\n"
        "[service_config]\n"
        "Type = wifi\n"
        "IPv4 = 10.0.11.13/255.0.0.0/10.1.0.1\n"
        "Nameservers = 10.1.0.2\n"
        "Security = psk\n"
        "Name = TAUpdateServer\n"
        "SSID = 5441557064617465536572766572\n"
        "Passphrase = whatever\n"
        ;

    static const struct os_mapped_file_data old_ethernet_config =
    {
        .fd = 82,
        .ptr = const_cast<char *>(old_ethernet_config_data),
        .length = sizeof(old_ethernet_config_data) - 1,
    };

    static const struct os_mapped_file_data old_wlan_config =
    {
        .fd = 59,
        .ptr = const_cast<char *>(old_wlan_config_data),
        .length = sizeof(old_wlan_config_data) - 1,
    };

    do_migration("/connman/builtin_09fa01d467e2.config", &old_ethernet_config,
                 "/connman/wlan_device.config",          &old_wlan_config,
                 2, 16);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = no\n"
        "IPv4Address = 192.168.22.50\n"
        "IPv4Netmask = 255.255.255.0\n"
        "IPv4Gateway = 192.168.22.10\n"
        "PrimaryDNS = 192.168.22.200\n"
        "[wifi]\n"
        "MAC = %s\n"
        "DHCP = no\n"
        "IPv4Address = 10.0.11.13\n"
        "IPv4Netmask = 255.0.0.0\n"
        "IPv4Gateway = 10.1.0.1\n"
        "PrimaryDNS = 10.1.0.2\n"
        "NetworkName = TAUpdateServer\n"
        "SSID = 5441557064617465536572766572\n"
        "Security = psk\n"
        "Passphrase = whatever\n"
        ;

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format, default_ethernet_mac,
             default_wlan_mac);

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Migration of old Ethernet and WLAN configuration, both DHCP.
 */
void test_migrate_old_configuration_files_with_dhcp_configs()
{
    /* file: builtin_09fa01d467e2.config */
    static const char old_ethernet_config_data[] =
        "[global]\n"
        "Name = StrBo\n"
        "Description = StrBo-managed built-in wired interface\n"
        "[service_config]\n"
        "MAC = 09:fa:01:d4:67:e2\n"
        "Type = ethernet\n"
        "IPv4 = dhcp\n"
        ;

    /* file: wlan_device.config */
    static const char old_wlan_config_data[] =
        "[global]\n"
        "Name = StrBo\n"
        "Description = StrBo-managed built-in wireless interface\n"
        "[service_config]\n"
        "Type = wifi\n"
        "IPv4 = dhcp\n"
        "Security = psk\n"
        "Name = TAUpdateServer\n"
        "SSID = 5441557064617465536572766572\n"
        "Passphrase = whatever\n"
        ;

    static const struct os_mapped_file_data old_ethernet_config =
    {
        .fd = 84,
        .ptr = const_cast<char *>(old_ethernet_config_data),
        .length = sizeof(old_ethernet_config_data) - 1,
    };

    static const struct os_mapped_file_data old_wlan_config =
    {
        .fd = 61,
        .ptr = const_cast<char *>(old_wlan_config_data),
        .length = sizeof(old_wlan_config_data) - 1,
    };

    do_migration("/connman/builtin_09fa01d467e2.config", &old_ethernet_config,
                 "/connman/wlan_device.config",          &old_wlan_config,
                 2, 8);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "[wifi]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "NetworkName = TAUpdateServer\n"
        "SSID = 5441557064617465536572766572\n"
        "Security = psk\n"
        "Passphrase = whatever\n"
        ;

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format, default_ethernet_mac,
             default_wlan_mac);

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Migration of old Ethernet-only configuration.
 */
void test_migrate_old_ethernet_configuration_file_with_manual_config()
{
    /* file: builtin_09fa01d467e2.config */
    static const char old_ethernet_config_data[] =
        "[global]\n"
        "Name = StrBo\n"
        "Description = StrBo-managed built-in wired interface\n"
        "[service_config]\n"
        "MAC = 09:fa:01:d4:67:e2\n"
        "Type = ethernet\n"
        "IPv4 = 192.168.22.50/255.255.255.0/192.168.22.10\n"
        "Nameservers = 192.168.22.200\n"
        ;

    static const struct os_mapped_file_data old_ethernet_config =
    {
        .fd = 84,
        .ptr = const_cast<char *>(old_ethernet_config_data),
        .length = sizeof(old_ethernet_config_data) - 1,
    };

    do_migration("/connman/builtin_09fa01d467e2.config", &old_ethernet_config,
                 "/connman/wlan_device.config",          nullptr,
                 2, 8);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = no\n"
        "IPv4Address = 192.168.22.50\n"
        "IPv4Netmask = 255.255.255.0\n"
        "IPv4Gateway = 192.168.22.10\n"
        "PrimaryDNS = 192.168.22.200\n"
        "[wifi]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        ;

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format, default_ethernet_mac,
             default_wlan_mac);

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Migration of old WLAN-only configuration.
 */
void test_migrate_old_wlan_configuration_file_with_manual_config()
{
    /* file: wlan_device.config */
    static const char old_wlan_config_data[] =
        "[global]\n"
        "Name = StrBo\n"
        "Description = StrBo-managed built-in wireless interface\n"
        "[service_config]\n"
        "Type = wifi\n"
        "IPv4 = 10.0.11.13/255.0.0.0/10.1.0.1\n"
        "Nameservers = 10.1.0.2\n"
        "Security = psk\n"
        "Name = TAUpdateServer\n"
        "SSID = 5441557064617465536572766572\n"
        "Passphrase = whatever\n"
        ;

    static const struct os_mapped_file_data old_wlan_config =
    {
        .fd = 61,
        .ptr = const_cast<char *>(old_wlan_config_data),
        .length = sizeof(old_wlan_config_data) - 1,
    };

    do_migration("/connman/builtin_09fa01d467e2.config", nullptr,
                 "/connman/wlan_device.config",          &old_wlan_config,
                 2, 12);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "[wifi]\n"
        "MAC = %s\n"
        "DHCP = no\n"
        "IPv4Address = 10.0.11.13\n"
        "IPv4Netmask = 255.0.0.0\n"
        "IPv4Gateway = 10.1.0.1\n"
        "PrimaryDNS = 10.1.0.2\n"
        "NetworkName = TAUpdateServer\n"
        "SSID = 5441557064617465536572766572\n"
        "Security = psk\n"
        "Passphrase = whatever\n"
        ;

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format, default_ethernet_mac,
             default_wlan_mac);

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * In case there are no old configuration files, nothing should happen.
 *
 * This is the regular case on a fresh, recent system as well as on updated
 * systems after successful migration.
 */
void test_migrate_with_no_configuration_files()
{
    mock_os->expect_os_map_file_to_memory(nullptr, "/connman/builtin_09fa01d467e2.config");
    mock_os->expect_os_map_file_to_memory(nullptr, "/connman/wlan_device.config");

    network_prefs_migrate_old_network_configuration_files(default_path_to_connman);

    cut_assert_true(os_write_buffer.empty());
}

/*!\test
 * In case a new configuration file is in place, it gets replaced during
 * migration.
 *
 * This case may occur on systems that got downgraded from a more recent
 * version, and then are upgraded again. The more recent system may have
 * written new configuration data before the downgrade took place. The
 * downgraded system writes old-style configuration files (possibly containing
 * completely different data) and ignores the new file. When upgrading, we are
 * running into the case tested by this unit test.
 */
void test_migration_replaces_existing_dhcp_configuration_data()
{
    /* file: builtin_09fa01d467e2.config */
    static const char old_ethernet_config_data[] =
        "[global]\n"
        "Name = StrBo\n"
        "Description = StrBo-managed built-in wired interface\n"
        "[service_config]\n"
        "MAC = 09:fa:01:d4:67:e2\n"
        "Type = ethernet\n"
        "IPv4 = 172.19.4.30/255.240.0.0/172.19.3.254\n"
        "Nameservers = 172.19.3.253\n"
        ;

    /* file: wlan_device.config */
    static const char old_wlan_config_data[] =
        "[global]\n"
        "Name = StrBo\n"
        "Description = StrBo-managed built-in wireless interface\n"
        "[service_config]\n"
        "Type = wifi\n"
        "IPv4 = 172.29.7.20/255.240.0.0/172.29.7.254\n"
        "Nameservers = 172.30.0.1\n"
        "Security = psk\n"
        "Name = TAUpdateServer\n"
        "SSID = 5441557064617465536572766572\n"
        "Passphrase = whatever\n"
        ;

    /* file: network.ini */
    static const char existing_new_config_data[] =
        "[ethernet]\n"
        "MAC = 01:aa:bf:d4:67:00\n"
        "DHCP = yes\n"
        "[wifi]\n"
        "MAC = 01:bb:cc:d4:67:ff\n"
        "DHCP = yes\n"
        "NetworkName = MyLittleInsecureNetwork\n"
        "Security = wep\n"
        "Passphrase = 1234\n"
        ;

    static const struct os_mapped_file_data old_ethernet_config =
    {
        .fd = 82,
        .ptr = const_cast<char *>(old_ethernet_config_data),
        .length = sizeof(old_ethernet_config_data) - 1,
    };

    static const struct os_mapped_file_data old_wlan_config =
    {
        .fd = 59,
        .ptr = const_cast<char *>(old_wlan_config_data),
        .length = sizeof(old_wlan_config_data) - 1,
    };

    static const struct os_mapped_file_data existing_new_config =
    {
        .fd = 123,
        .ptr = const_cast<char *>(existing_new_config_data),
        .length = sizeof(existing_new_config_data) - 1,
    };

    do_migration("/connman/builtin_09fa01d467e2.config", &old_ethernet_config,
                 "/connman/wlan_device.config",          &old_wlan_config,
                 2, 16,
                 &existing_new_config);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = no\n"
        "IPv4Address = 172.19.4.30\n"
        "IPv4Netmask = 255.240.0.0\n"
        "IPv4Gateway = 172.19.3.254\n"
        "PrimaryDNS = 172.19.3.253\n"
        "[wifi]\n"
        "MAC = %s\n"
        "DHCP = no\n"
        "NetworkName = TAUpdateServer\n"
        "Security = psk\n"
        "Passphrase = whatever\n"
        "IPv4Address = 172.29.7.20\n"
        "IPv4Netmask = 255.240.0.0\n"
        "IPv4Gateway = 172.29.7.254\n"
        "PrimaryDNS = 172.30.0.1\n"
        "SSID = 5441557064617465536572766572\n"
        ;

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format, default_ethernet_mac,
             default_wlan_mac);

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * In case a new configuration file is in place, it gets replaced during
 * migration.
 *
 * Like #test_migration_replaces_existing_dhcp_configuration_data(), but manual
 * configuration gets replaced by a pure DHCP configuration.
 */
void test_migration_replaces_existing_manual_configuration_data()
{
    /* file: builtin_09fa01d467e2.config */
    static const char old_ethernet_config_data[] =
        "[global]\n"
        "Name = StrBo\n"
        "Description = StrBo-managed built-in wired interface\n"
        "[service_config]\n"
        "MAC = 09:fa:01:d4:67:e2\n"
        "Type = ethernet\n"
        "IPv4 = dhcp\n"
        ;

    /* file: wlan_device.config */
    static const char old_wlan_config_data[] =
        "[global]\n"
        "Name = StrBo\n"
        "Description = StrBo-managed built-in wireless interface\n"
        "[service_config]\n"
        "Type = wifi\n"
        "IPv4 = dhcp\n"
        "Security = wep\n"
        "Name = InsecureNet\n"
        "Passphrase = 1234\n"
        ;

    /* file: network.ini */
    static const char existing_new_config_data[] =
        "[ethernet]\n"
        "MAC = 01:aa:bf:d4:67:00\n"
        "DHCP = no\n"
        "IPv4Address = 172.19.4.30\n"
        "IPv4Netmask = 255.240.0.0\n"
        "IPv4Gateway = 172.19.3.254\n"
        "PrimaryDNS = 172.19.3.253\n"
        "[wifi]\n"
        "MAC = 01:bb:cc:d4:67:ff\n"
        "DHCP = no\n"
        "NetworkName = TAUpdateServer\n"
        "Security = psk\n"
        "Passphrase = whatever\n"
        "IPv4Address = 172.29.7.20\n"
        "IPv4Netmask = 255.240.0.0\n"
        "IPv4Gateway = 172.29.7.254\n"
        "PrimaryDNS = 172.30.0.1\n"
        "SSID = 5441557064617465536572766572\n"
        ;

    static const struct os_mapped_file_data old_ethernet_config =
    {
        .fd = 82,
        .ptr = const_cast<char *>(old_ethernet_config_data),
        .length = sizeof(old_ethernet_config_data) - 1,
    };

    static const struct os_mapped_file_data old_wlan_config =
    {
        .fd = 59,
        .ptr = const_cast<char *>(old_wlan_config_data),
        .length = sizeof(old_wlan_config_data) - 1,
    };

    static const struct os_mapped_file_data existing_new_config =
    {
        .fd = 123,
        .ptr = const_cast<char *>(existing_new_config_data),
        .length = sizeof(existing_new_config_data) - 1,
    };

    do_migration("/connman/builtin_09fa01d467e2.config", &old_ethernet_config,
                 "/connman/wlan_device.config",          &old_wlan_config,
                 2, 7,
                 &existing_new_config);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "[wifi]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "NetworkName = InsecureNet\n"
        "Security = wep\n"
        "Passphrase = 1234\n"
        ;

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format, default_ethernet_mac,
             default_wlan_mac);

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

}
