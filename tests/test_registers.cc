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

#include <cppcutter.h>
#include <array>
#include <algorithm>

#include "registers.h"
#include "dcpregs_drcp.h"
#include "dcpregs_networking.h"
#include "drcp_command_codes.h"

#include "mock_dcpd_dbus.hh"
#include "mock_dbus_iface.hh"
#include "mock_connman.hh"
#include "mock_messages.hh"
#include "mock_os.hh"

/*!
 * \addtogroup registers_tests Unit tests
 * \ingroup registers
 *
 * SPI registers unit tests.
 */
/*!@{*/

namespace spi_registers_tests
{

static MockMessages *mock_messages;
static MockDcpdDBus *mock_dcpd_dbus;
static const std::array<uint8_t, 11> existing_registers =
{
    17, 37, 51, 53, 54, 55, 56, 57, 58, 71, 72,
};

void cut_setup(void)
{
    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_dcpd_dbus = new MockDcpdDBus();
    cppcut_assert_not_null(mock_dcpd_dbus);
    mock_dcpd_dbus->init();
    mock_dcpd_dbus_singleton = mock_dcpd_dbus;
}

void cut_teardown(void)
{
    mock_messages->check();
    mock_dcpd_dbus->check();

    mock_messages_singleton = nullptr;
    mock_dcpd_dbus_singleton = nullptr;

    delete mock_messages;
    delete mock_dcpd_dbus;

    mock_messages = nullptr;
    mock_dcpd_dbus = nullptr;
}

/*!\test
 * Look up some register known to be implemented.
 */
void test_lookup_existing_register(void)
{
    const struct dcp_register_t *reg = register_lookup(51);

    cppcut_assert_not_null(reg);
    cppcut_assert_equal(51U, unsigned(reg->address));
}

/*!\test
 * Look up some register known not to be implemented.
 */
void test_lookup_nonexistent_register_fails_gracefully(void)
{
    cppcut_assert_null(register_lookup(10));
}

/*!\test
 * Look up all registers that should be implemented.
 *
 * Also check if the register structures are consistently defined.
 */
void test_lookup_all_existing_registers(void)
{
    for(auto r : existing_registers)
    {
        const struct dcp_register_t *reg = register_lookup(r);

        cppcut_assert_not_null(reg);
        cppcut_assert_equal(unsigned(r), unsigned(reg->address));
        cppcut_assert_operator(0, <, reg->max_data_size);
    }
}

/*!\test
 * Look up all registers that should not be implemented.
 */
void test_lookup_all_nonexistent_registers(void)
{
    for(unsigned int r = 0; r <= UINT8_MAX; ++r)
    {
        auto found =
            std::find(existing_registers.begin(), existing_registers.end(), r);

        if(found == existing_registers.end())
            cppcut_assert_null(register_lookup(r));
        else
            cppcut_assert_not_null(register_lookup(r));
    }
}

};

namespace spi_registers_tests_drc
{

static MockMessages *mock_messages;
static MockOs *mock_os;
static MockDcpdDBus *mock_dcpd_dbus;
static MockDBusIface *mock_dbus_iface;

static tdbusdcpdPlayback *const dbus_dcpd_playback_iface_dummy =
    reinterpret_cast<tdbusdcpdPlayback *>(0x12345678);

static tdbusdcpdViews *const dbus_dcpd_views_iface_dummy =
    reinterpret_cast<tdbusdcpdViews *>(0x87654321);

static tdbusdcpdListNavigation *const dbus_dcpd_list_navigation_iface_dummy =
    reinterpret_cast<tdbusdcpdListNavigation *>(0x24681357);

static tdbusdcpdListItem *const dbus_dcpd_list_item_iface_dummy =
    reinterpret_cast<tdbusdcpdListItem *>(0x75318642);

void cut_setup(void)
{
    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_os = new MockOs;
    cppcut_assert_not_null(mock_os);
    mock_os->init();
    mock_os_singleton = mock_os;

    mock_dcpd_dbus = new MockDcpdDBus();
    cppcut_assert_not_null(mock_dcpd_dbus);
    mock_dcpd_dbus->init();
    mock_dcpd_dbus_singleton = mock_dcpd_dbus;

    mock_dbus_iface = new MockDBusIface;
    cppcut_assert_not_null(mock_dbus_iface);
    mock_dbus_iface->init();
    mock_dbus_iface_singleton = mock_dbus_iface;
}

void cut_teardown(void)
{
    mock_messages->check();
    mock_os->check();
    mock_dcpd_dbus->check();
    mock_dbus_iface->check();

    mock_messages_singleton = nullptr;
    mock_os_singleton = nullptr;
    mock_dcpd_dbus_singleton = nullptr;
    mock_dbus_iface_singleton = nullptr;

    delete mock_messages;
    delete mock_os;
    delete mock_dcpd_dbus;
    delete mock_dbus_iface;

    mock_messages = nullptr;
    mock_os = nullptr;
    mock_dcpd_dbus = nullptr;
    mock_dbus_iface = nullptr;
}

/*!\test
 * Check that writes to register 72 (DRC command) are indeed wired to calls of
 * dcpregs_write_drcp_command(), and that reading from register 72 is not
 * possible.
 */
void test_dcp_register_72_calls_correct_write_handler(void)
{
    const struct dcp_register_t *reg = register_lookup(72);

    cppcut_assert_not_null(reg);
    cppcut_assert_equal(72U, unsigned(reg->address));
    cut_assert(reg->write_handler == dcpregs_write_drcp_command);
    cut_assert(reg->read_handler == NULL);
}

/*!\test
 * Slave sends some unsupported DRC command over DCP.
 */
void test_slave_drc_invalid_command(void)
{
    static const uint8_t buffer[] = { 0xbe };

    mock_messages->expect_msg_info_formatted("DRC: command code 0xbe");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Received unsupported DRC command 0xbe (Invalid argument)");
    cppcut_assert_equal(-1, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for starting playback.
 */
void test_slave_drc_playback_start(void)
{
    static const uint8_t buffer[] = { DRCP_PLAYBACK_START };

    mock_messages->expect_msg_info_formatted("DRC: command code 0xb3");
    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_start(dbus_dcpd_playback_iface_dummy);
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends complex DRC command for setting the fast wind speed factor.
 */
void test_slave_drc_playback_fast_find_set_speed(void)
{
    static const uint8_t buffer[] = { DRCP_FAST_WIND_SET_SPEED, DRCP_KEY_DIGIT_4 };

    mock_messages->expect_msg_info_formatted("DRC: command code 0xc4");
    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_fast_wind_set_factor(dbus_dcpd_playback_iface_dummy, 15.0);
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends complex DRC command for setting the fast wind speed factor, but
 * with an invalid out-of-range parameter.
 */
void test_slave_drc_playback_fast_find_set_speed_invalid_parameter(void)
{
    static const uint8_t buffer[] = { DRCP_FAST_WIND_SET_SPEED, DRCP_BROWSE_PLAY_VIEW_SET };

    mock_messages->expect_msg_info_formatted("DRC: command code 0xc4");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0xc4 failed: -1");
    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    cppcut_assert_equal(-1, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends complex DRC command for setting the fast wind speed factor, but
 * without any parameter.
 */
void test_slave_drc_playback_fast_find_set_speed_without_parameter(void)
{
    static const uint8_t buffer[] = { DRCP_FAST_WIND_SET_SPEED };

    mock_messages->expect_msg_info_formatted("DRC: command code 0xc4");
    mock_messages->expect_msg_error_formatted(0, LOG_EMERG, "Assertion failed at ", "length == 1");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0xc4 failed: -1");
    mock_os->expect_os_abort();
    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    cppcut_assert_equal(-1, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends complex DRC command for setting the fast wind speed factor, but
 * with two parameters instead of one.
 */
void test_slave_drc_playback_fast_find_set_speed_with_two_parameters(void)
{
    static const uint8_t buffer[] = { DRCP_FAST_WIND_SET_SPEED, DRCP_KEY_DIGIT_4, DRCP_KEY_DIGIT_4 };

    mock_messages->expect_msg_info_formatted("DRC: command code 0xc4");
    mock_messages->expect_msg_error_formatted(0, LOG_EMERG, "Assertion failed at ", "length == 1");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0xc4 failed: -1");
    mock_os->expect_os_abort();
    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    cppcut_assert_equal(-1, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for opening the internet radio view.
 */
void test_slave_drc_views_goto_internet_radio(void)
{
    static const uint8_t buffer[] = { DRCP_GOTO_INTERNET_RADIO, 0x00 };

    mock_messages->expect_msg_info_formatted("DRC: command code 0xaa");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_open(dbus_dcpd_views_iface_dummy, "Internet Radio");
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for toggling between browsing and playing views.
 */
void test_slave_drc_views_toggle_browse_and_play(void)
{
    static const uint8_t buffer[] = { DRCP_BROWSE_PLAY_VIEW_TOGGLE, 0x00 };

    mock_messages->expect_msg_info_formatted("DRC: command code 0xba");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_toggle(dbus_dcpd_views_iface_dummy, "Browse", "Play");
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for moving the cursor one line up.
 */
void test_slave_drc_list_navigation_scroll_one_line_up(void)
{
    static const uint8_t buffer[] = { DRCP_SCROLL_UP_ONE, 0x00 };

    mock_messages->expect_msg_info_formatted("DRC: command code 0x26");
    mock_dbus_iface->expect_dbus_get_list_navigation_iface(dbus_dcpd_list_navigation_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_list_navigation_emit_move_lines(dbus_dcpd_list_navigation_iface_dummy, -1);
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for moving the cursor one page down.
 */
void test_slave_drc_list_navigation_scroll_one_page_down(void)
{
    static const uint8_t buffer[] = { DRCP_SCROLL_PAGE_DOWN, 0x00 };

    mock_messages->expect_msg_info_formatted("DRC: command code 0x98");
    mock_dbus_iface->expect_dbus_get_list_navigation_iface(dbus_dcpd_list_navigation_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_list_navigation_emit_move_pages(dbus_dcpd_list_navigation_iface_dummy, 1);
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for adding the currently selected item to the
 * favorites list.
 */
void test_slave_drc_list_item_add_to_favorites(void)
{
    static const uint8_t buffer[] = { DRCP_FAVORITES_ADD_ITEM, 0x00 };

    mock_messages->expect_msg_info_formatted("DRC: command code 0x2d");
    mock_dbus_iface->expect_dbus_get_list_item_iface(dbus_dcpd_list_item_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_list_item_emit_add_to_list(dbus_dcpd_list_item_iface_dummy, "Favorites", 0);
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

};

namespace spi_registers_networking
{

static MockConnman *mock_connman;
static MockMessages *mock_messages;
static MockOs *mock_os;

static const char ethernet_mac_address[] = "DE:CA:FD:EA:DB:AD";
static const char wlan_mac_address[]     = "BA:DD:EA:DB:EE:F1";
static const char expected_config_filename[] = "/var/lib/connman/builtin_decafdeadbad.config";
static struct ConnmanInterfaceData *const dummy_connman_iface =
    reinterpret_cast<struct ConnmanInterfaceData *>(0xbeefbeef);


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

void cut_setup(void)
{
    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_os = new MockOs;
    cppcut_assert_not_null(mock_os);
    mock_os->init();
    mock_os_singleton = mock_os;

    mock_connman = new MockConnman;
    cppcut_assert_not_null(mock_connman);
    mock_connman->init();
    mock_connman_singleton = mock_connman;

    os_write_buffer.clear();

    dcpregs_networking_init();
    register_init(ethernet_mac_address, wlan_mac_address, "/var/lib/connman");
}

void cut_teardown(void)
{
    os_write_buffer.clear();

    mock_messages->check();
    mock_os->check();
    mock_connman->check();

    mock_messages_singleton = nullptr;
    mock_os_singleton = nullptr;
    mock_connman_singleton = nullptr;

    delete mock_messages;
    delete mock_os;
    delete mock_connman;

    mock_messages = nullptr;
    mock_os = nullptr;
    mock_connman = nullptr;
}

/*!\test
 * Read out MAC address of built-in Ethernet interface.
 */
void test_read_mac_address(void)
{
    const struct dcp_register_t *reg = register_lookup(51);
    cppcut_assert_not_null(reg);

    uint8_t redzone_content[10];
    memset(redzone_content, 0xff, sizeof(redzone_content));

    uint8_t buffer[sizeof(redzone_content) + 18 + sizeof(redzone_content)];
    memset(buffer, 0xff, sizeof(buffer));

    mock_messages->expect_msg_info("read 51 handler %p %zu");

    reg->read_handler(buffer + sizeof(redzone_content), sizeof(buffer) - 2 * sizeof(redzone_content));

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
void test_read_mac_address_default(void)
{
    register_init(NULL, NULL, NULL);

    const struct dcp_register_t *reg = register_lookup(51);
    cppcut_assert_not_null(reg);

    uint8_t buffer[18];

    mock_messages->expect_msg_info("read 51 handler %p %zu");
    reg->read_handler(buffer, sizeof(buffer));

    const char *buffer_ptr = static_cast<const char *>(static_cast<void *>(buffer));
    cppcut_assert_equal("02:00:00:00:00:00", buffer_ptr);
}

static void start_ipv4_config()
{
    const struct dcp_register_t *reg = register_lookup(54);
    cppcut_assert_not_null(reg);
    cut_assert(reg->write_handler == dcpregs_write_54_selected_ip_profile);

    mock_messages->expect_msg_info("write 54 handler %p %zu");

    static const uint8_t zero = 0;
    cppcut_assert_equal(0, reg->write_handler(&zero, 1));
}

static void commit_ipv4_config(bool add_message_expectation)
{
    const struct dcp_register_t *reg = register_lookup(53);
    cppcut_assert_not_null(reg);
    cut_assert(reg->write_handler == dcpregs_write_53_active_ip_profile);

    if(add_message_expectation)
        mock_messages->expect_msg_info("write 53 handler %p %zu");

    static const uint8_t zero = 0;
    cppcut_assert_equal(0, reg->write_handler(&zero, 1));
}

static size_t do_test_set_static_ipv4_config(const struct os_mapped_file_data *existing_file,
                                             char *written_config_file,
                                             size_t written_config_file_size)
{
    start_ipv4_config();

    static const char ipv4_address[] = "192.168.166.177";
    static const char ipv4_netmask[] = "255.255.255.0";
    static const char ipv4_gateway[] = "192.168.166.15";

    const struct dcp_register_t *reg = register_lookup(56);
    cppcut_assert_not_null(reg);
    cut_assert(reg->write_handler == dcpregs_write_56_ipv4_address);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(ipv4_address)), sizeof(ipv4_address)));

    reg = register_lookup(57);
    cppcut_assert_not_null(reg);
    cut_assert(reg->write_handler == dcpregs_write_57_ipv4_netmask);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(ipv4_netmask)), sizeof(ipv4_netmask)));

    reg = register_lookup(58);
    cppcut_assert_not_null(reg);
    cut_assert(reg->write_handler == dcpregs_write_58_ipv4_gateway);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(ipv4_gateway)), sizeof(ipv4_gateway)));

    mock_messages->expect_msg_info("write 53 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");

    if(existing_file == nullptr)
        mock_os->expect_os_map_file_to_memory(-1, false, expected_config_filename);
    else
    {
        mock_os->expect_os_map_file_to_memory(existing_file, expected_config_filename);
        mock_os->expect_os_unmap_file(existing_file);
    }

    mock_os->expect_os_file_new(expected_os_write_fd, expected_config_filename);
    for(int i = 0; i < 2 * 3 + (2 + 3) * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);

    commit_ipv4_config(false);

    static const char expected_config_file_format[] =
        "[global]\n"
        "Name = StrBo\n"
        "Description = StrBo-managed built-in wired interface\n"
        "[service_config]\n"
        "MAC = %s\n"
        "Type = ethernet\n"
        "IPv4 = %s/%s/%s\n";

    snprintf(written_config_file, written_config_file_size,
             expected_config_file_format,
             ethernet_mac_address, ipv4_address, ipv4_netmask, ipv4_gateway);

    size_t written_config_file_length = strlen(written_config_file);

    cut_assert_equal_memory(written_config_file, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());

    return written_config_file_length;
}

static size_t do_test_set_dhcp_ipv4_config(const struct os_mapped_file_data *existing_file,
                                           char *written_config_file,
                                           size_t written_config_file_size)
{
    start_ipv4_config();

    const struct dcp_register_t *reg = register_lookup(55);
    cppcut_assert_not_null(reg);
    mock_messages->expect_msg_info("write 55 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Enable DHCP");
    cut_assert(reg->write_handler == dcpregs_write_55_dhcp_enabled);
    static const uint8_t one = 1;
    cppcut_assert_equal(0, reg->write_handler(&one, 1));

    mock_messages->expect_msg_info("write 53 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");

    if(existing_file == nullptr)
        mock_os->expect_os_map_file_to_memory(-1, false, expected_config_filename);
    else
    {
        mock_os->expect_os_map_file_to_memory(existing_file, expected_config_filename);
        mock_os->expect_os_unmap_file(existing_file);
    }

    mock_os->expect_os_file_new(expected_os_write_fd, expected_config_filename);
    for(int i = 0; i < 2 * 3 + (2 + 3) * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);

    commit_ipv4_config(false);

    static const char expected_config_file_format[] =
        "[global]\n"
        "Name = StrBo\n"
        "Description = StrBo-managed built-in wired interface\n"
        "[service_config]\n"
        "MAC = %s\n"
        "Type = ethernet\n"
        "IPv4 = dhcp\n";

    snprintf(written_config_file, written_config_file_size,
             expected_config_file_format, ethernet_mac_address);

    size_t written_config_file_length = strlen(written_config_file);

    cut_assert_equal_memory(written_config_file, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());

    return written_config_file_length;
}

/*!\test
 * Initial setting of static IPv4 configuration generates a Connman
 * configuration file.
 */
void test_set_initial_static_ipv4_configuration(void)
{
    char buffer[512];
    (void)do_test_set_static_ipv4_config(NULL, buffer, sizeof(buffer));
}

/*!\test
 * Initial enabling of DHCPv4 generates a Connman configuration file.
 */
void test_set_initial_dhcp_ipv4_configuration(void)
{
    char buffer[512];
    (void)do_test_set_dhcp_ipv4_config(NULL, buffer, sizeof(buffer));
}

/*!\test
 * Setting static IPv4 configuration while a DHCPv4 configuration is active
 * rewrites the corresponding Connman configuration file.
 */
void test_switch_to_dhcp_ipv4_configuration(void)
{
    char config_file_buffer[512];
    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = do_test_set_static_ipv4_config(NULL, config_file_buffer,
                                                 sizeof(config_file_buffer)),
    };

    os_write_buffer.clear();

    char new_config_file_buffer[512];
    (void)do_test_set_dhcp_ipv4_config(&config_file, new_config_file_buffer,
                                       sizeof(new_config_file_buffer));
}

/*!\test
 * Enabling DHCPv4 while a static IPv4 configuration is active rewrites the
 * corresponding Connman configuration file.
 */
void test_switch_to_static_ipv4_configuration(void)
{
    char config_file_buffer[512];
    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = do_test_set_dhcp_ipv4_config(NULL, config_file_buffer,
                                               sizeof(config_file_buffer)),
    };

    os_write_buffer.clear();

    char new_config_file_buffer[512];
    (void)do_test_set_static_ipv4_config(&config_file, new_config_file_buffer,
                                         sizeof(new_config_file_buffer));
}

/*!\test
 * When being asked for DHCP mode in normal mode, Connman is consulted
 * (reporting "disabled" in this test).
 */
void test_read_dhcp_mode_in_normal_mode_with_dhcp_disabled(void)
{
    const struct dcp_register_t *reg = register_lookup(55);
    cppcut_assert_not_null(reg);
    cut_assert(reg->read_handler == dcpregs_read_55_dhcp_enabled);

    mock_messages->expect_msg_info("read 55 handler %p %zu");
    mock_connman->expect_connman_find_active_primary_interface(dummy_connman_iface,
                                                               ethernet_mac_address,
                                                               ethernet_mac_address,
                                                               wlan_mac_address);
    mock_connman->expect_connman_get_dhcp_mode(false, dummy_connman_iface);
    mock_connman->expect_connman_free_interface_data(dummy_connman_iface);

    uint8_t buffer = UINT8_MAX;
    cppcut_assert_equal(ssize_t(1), reg->read_handler(&buffer, 1));

    cppcut_assert_equal(0, int(buffer));
}

/*!\test
 * When being asked for DHCP mode in normal mode, Connman is consulted
 * (reporting "enabled" in this test).
 */
void test_read_dhcp_mode_in_normal_mode_with_dhcp_enabled(void)
{
    const struct dcp_register_t *reg = register_lookup(55);
    cppcut_assert_not_null(reg);
    cut_assert(reg->read_handler == dcpregs_read_55_dhcp_enabled);

    mock_messages->expect_msg_info("read 55 handler %p %zu");
    mock_connman->expect_connman_find_active_primary_interface(dummy_connman_iface,
                                                               ethernet_mac_address,
                                                               ethernet_mac_address,
                                                               wlan_mac_address);
    mock_connman->expect_connman_get_dhcp_mode(true, dummy_connman_iface);
    mock_connman->expect_connman_free_interface_data(dummy_connman_iface);

    uint8_t buffer = UINT8_MAX;
    cppcut_assert_equal(ssize_t(1), reg->read_handler(&buffer, 1));

    cppcut_assert_equal(1, int(buffer));
}

/*!\test
 * When being asked for DHCP mode in edit mode, Connman is consulted if the
 * mode has not been set during this edit session.
 */
void test_read_dhcp_mode_in_edit_mode_before_any_changes(void)
{
    start_ipv4_config();

    const struct dcp_register_t *reg = register_lookup(55);
    cppcut_assert_not_null(reg);
    cut_assert(reg->read_handler == dcpregs_read_55_dhcp_enabled);

    mock_messages->expect_msg_info("read 55 handler %p %zu");
    mock_connman->expect_connman_find_interface(dummy_connman_iface, ethernet_mac_address);
    mock_connman->expect_connman_get_dhcp_mode(true, dummy_connman_iface);
    mock_connman->expect_connman_free_interface_data(dummy_connman_iface);

    uint8_t buffer = UINT8_MAX;
    cppcut_assert_equal(ssize_t(1), reg->read_handler(&buffer, 1));

    cppcut_assert_equal(1, int(buffer));
}

/*!\test
 * When being asked for DHCP mode in edit mode, the mode written during this
 * edit session is returned.
 */
void test_read_dhcp_mode_in_edit_mode_after_change(void)
{
    start_ipv4_config();

    const struct dcp_register_t *reg = register_lookup(55);
    cppcut_assert_not_null(reg);
    cut_assert(reg->read_handler == dcpregs_read_55_dhcp_enabled);
    cut_assert(reg->write_handler == dcpregs_write_55_dhcp_enabled);

    mock_messages->expect_msg_info("write 55 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Enable DHCP");
    static const uint8_t one = 1;
    cppcut_assert_equal(0, reg->write_handler(&one, 1));

    mock_messages->expect_msg_info("read 55 handler %p %zu");

    uint8_t buffer = UINT8_MAX;
    cppcut_assert_equal(ssize_t(1), reg->read_handler(&buffer, 1));

    cppcut_assert_equal(1, int(buffer));
}

};

/*!@}*/
