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
#include <array>
#include <algorithm>

#include "registers.h"
#include "registers_priv.h"
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
static const std::array<uint8_t, 19> existing_registers =
{
    17, 37, 50, 51, 53, 54, 55, 56, 57, 58, 62, 63, 71, 72,
    92, 93, 94, 101, 102,
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
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_NOTICE, "Unexpected data length 0, expected 1 (Invalid argument)");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0xc4 failed: -1");
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
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_NOTICE, "Unexpected data length 2, expected 1 (Invalid argument)");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0xc4 failed: -1");
    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    cppcut_assert_equal(-1, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for opening the view with binary ID 0.
 */
void test_slave_drc_views_goto_view_by_id_0(void)
{
    static const uint8_t buffer[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x00, DRCP_ACCEPT };

    mock_messages->expect_msg_info_formatted("DRC: command code 0x9a");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_open(dbus_dcpd_views_iface_dummy, "UPnP");
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for opening the view with binary ID 1.
 */
void test_slave_drc_views_goto_view_by_id_1(void)
{
    static const uint8_t buffer[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x01, DRCP_ACCEPT };

    mock_messages->expect_msg_info_formatted("DRC: command code 0x9a");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_open(dbus_dcpd_views_iface_dummy, "TuneIn");
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for opening the view with binary ID 2.
 */
void test_slave_drc_views_goto_view_by_id_2(void)
{
    static const uint8_t buffer[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x02, DRCP_ACCEPT };

    mock_messages->expect_msg_info_formatted("DRC: command code 0x9a");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_open(dbus_dcpd_views_iface_dummy, "Filesystem");
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for opening a view with unknown binary ID.
 */
void test_slave_drc_views_goto_view_by_id_unknown_id(void)
{
    static const uint8_t buffer_lowest_unknown[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x03, DRCP_ACCEPT };
    static const uint8_t buffer_highest_unknown[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, UINT8_MAX, DRCP_ACCEPT };

    mock_messages->expect_msg_info_formatted("DRC: command code 0x9a");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_NOTICE, "Unknown view ID 0x03 (Invalid argument)");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0x9a failed: -1");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    cppcut_assert_equal(-1, dcpregs_write_drcp_command(buffer_lowest_unknown, sizeof(buffer_lowest_unknown)));

    mock_messages->expect_msg_info_formatted("DRC: command code 0x9a");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_NOTICE, "Unknown view ID 0xff (Invalid argument)");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0x9a failed: -1");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    cppcut_assert_equal(-1, dcpregs_write_drcp_command(buffer_highest_unknown, sizeof(buffer_highest_unknown)));
}

/*!\test
 * Slave sends malformed DRC command for opening a view by ID.
 */
void test_slave_drc_views_goto_view_by_id_must_be_terminated_with_accept_code(void)
{
    static const uint8_t buffer[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x00, DRCP_ACCEPT - 1U };

    mock_messages->expect_msg_info_formatted("DRC: command code 0x9a");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0x9a failed: -1");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    cppcut_assert_equal(-1, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends too short DRC command for opening view by ID.
 */
void test_slave_drc_views_goto_view_by_id_with_too_few_data_bytes(void)
{
    static const uint8_t buffer[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x00 };

    mock_messages->expect_msg_info_formatted("DRC: command code 0x9a");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_NOTICE, "Unexpected data length 1, expected 2 (Invalid argument)");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0x9a failed: -1");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    cppcut_assert_equal(-1, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends too long DRC command for opening view by ID.
 */
void test_slave_drc_views_goto_view_by_id_with_too_many_data_bytes(void)
{
    static const uint8_t buffer[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x00, DRCP_ACCEPT, 0x00 };

    mock_messages->expect_msg_info_formatted("DRC: command code 0x9a");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_NOTICE, "Unexpected data length 3, expected 2 (Invalid argument)");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0x9a failed: -1");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
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

static constexpr char ethernet_mac_address[] = "DE:CA:FD:EA:DB:AD";
static constexpr char wlan_mac_address[]     = "BA:DD:EA:DB:EE:F1";
static constexpr char expected_ethernet_config_filename[] =
    "/var/lib/connman/builtin_decafdeadbad.config";
static constexpr char expected_wlan_config_filename[] =
    "/var/lib/connman/builtin_baddeadbeef1.config";
static struct ConnmanInterfaceData *const dummy_connman_iface =
    reinterpret_cast<struct ConnmanInterfaceData *>(0xbeefbeef);

static constexpr char standard_ipv4_address[] = "192.168.166.177";
static constexpr char standard_ipv4_netmask[] = "255.255.255.0";
static constexpr char standard_ipv4_gateway[] = "192.168.166.15";
static constexpr char standard_dns1_address[] = "113.224.135.246";
static constexpr char standard_dns2_address[] = "114.225.136.247";

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
    register_init(ethernet_mac_address, wlan_mac_address, "/var/lib/connman", NULL);
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

static const struct dcp_register_t *
lookup_register_expect_handlers(uint8_t register_number,
                                ssize_t (*const expected_read_handler)(uint8_t *, size_t),
                                int (*const expected_write_handler)(const uint8_t *, size_t))
{
    const struct dcp_register_t *reg = register_lookup(register_number);
    cppcut_assert_not_null(reg);

    cut_assert(reg->read_handler == expected_read_handler);
    cut_assert(reg->write_handler == expected_write_handler);

    return reg;
}

/*!\test
 * Read out MAC address of built-in Ethernet interface.
 */
void test_read_mac_address(void)
{
    auto *reg = lookup_register_expect_handlers(51,
                                                dcpregs_read_51_mac_address,
                                                NULL);
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
    register_init(NULL, NULL, NULL, NULL);

    auto *reg = lookup_register_expect_handlers(51,
                                                dcpregs_read_51_mac_address,
                                                NULL);
    uint8_t buffer[18];

    mock_messages->expect_msg_info("read 51 handler %p %zu");
    reg->read_handler(buffer, sizeof(buffer));

    const char *buffer_ptr = static_cast<const char *>(static_cast<void *>(buffer));
    cppcut_assert_equal("02:00:00:00:00:00", buffer_ptr);
}

static void start_ipv4_config()
{
    auto *reg = lookup_register_expect_handlers(54,
                                                NULL,
                                                dcpregs_write_54_selected_ip_profile);

    mock_messages->expect_msg_info("write 54 handler %p %zu");

    static const uint8_t zero = 0;
    cppcut_assert_equal(0, reg->write_handler(&zero, 1));
}

static void commit_ipv4_config(bool add_message_expectation,
                               int expected_return_value = 0)
{
    auto *reg = lookup_register_expect_handlers(53,
                                                NULL,
                                                dcpregs_write_53_active_ip_profile);

    if(add_message_expectation)
        mock_messages->expect_msg_info("write 53 handler %p %zu");

    static const uint8_t zero = 0;
    cppcut_assert_equal(expected_return_value, reg->write_handler(&zero, 1));
}

static size_t do_test_set_static_ipv4_config(const struct os_mapped_file_data *existing_file,
                                             char *written_config_file,
                                             size_t written_config_file_size)
{
    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(56,
                                                dcpregs_read_56_ipv4_address,
                                                dcpregs_write_56_ipv4_address);

    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(standard_ipv4_address)), sizeof(standard_ipv4_address)));

    reg = lookup_register_expect_handlers(57,
                                          dcpregs_read_57_ipv4_netmask,
                                          dcpregs_write_57_ipv4_netmask);

    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(standard_ipv4_netmask)), sizeof(standard_ipv4_netmask)));

    reg = lookup_register_expect_handlers(58,
                                          dcpregs_read_58_ipv4_gateway,
                                          dcpregs_write_58_ipv4_gateway);

    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(standard_ipv4_gateway)), sizeof(standard_ipv4_gateway)));

    mock_messages->expect_msg_info("write 53 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");

    if(existing_file == nullptr)
        mock_os->expect_os_map_file_to_memory(-1, false, expected_ethernet_config_filename);
    else
    {
        mock_os->expect_os_map_file_to_memory(existing_file, expected_ethernet_config_filename);
        mock_os->expect_os_unmap_file(existing_file);
    }

    mock_os->expect_os_file_new(expected_os_write_fd, expected_ethernet_config_filename);
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
             ethernet_mac_address, standard_ipv4_address,
             standard_ipv4_netmask, standard_ipv4_gateway);

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

    auto *reg = lookup_register_expect_handlers(55,
                                                dcpregs_read_55_dhcp_enabled,
                                                dcpregs_write_55_dhcp_enabled);

    mock_messages->expect_msg_info("write 55 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Enable DHCP");
    static const uint8_t one = 1;
    cppcut_assert_equal(0, reg->write_handler(&one, 1));

    mock_messages->expect_msg_info("write 53 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");

    if(existing_file == nullptr)
        mock_os->expect_os_map_file_to_memory(-1, false, expected_ethernet_config_filename);
    else
    {
        mock_os->expect_os_map_file_to_memory(existing_file, expected_ethernet_config_filename);
        mock_os->expect_os_unmap_file(existing_file);
    }

    mock_os->expect_os_file_new(expected_os_write_fd, expected_ethernet_config_filename);
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
 * Only values 0 and 1 are valid parameters for register 55.
 */
void test_dhcp_parameter_boundaries(void)
{
    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(55,
                                                dcpregs_read_55_dhcp_enabled,
                                                dcpregs_write_55_dhcp_enabled);

    uint8_t buffer = 2;

    mock_messages->expect_msg_info("write 55 handler %p %zu");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Received invalid DHCP configuration parameter 0x02 (Invalid argument)");
    cppcut_assert_equal(-1, reg->write_handler(&buffer, 1));

    buffer = UINT8_MAX;

    mock_messages->expect_msg_info("write 55 handler %p %zu");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Received invalid DHCP configuration parameter 0xff (Invalid argument)");
    cppcut_assert_equal(-1, reg->write_handler(&buffer, 1));
}

/*!\test
 * Switching DHCP off and setting no IPv4 configuration tells us to disable the
 * interface for IPv4.
 */
void test_explicitly_disabling_dhcp_disables_whole_interface(void)
{
    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(55,
                                                dcpregs_read_55_dhcp_enabled,
                                                dcpregs_write_55_dhcp_enabled);

    static const uint8_t zero = 0;

    mock_messages->expect_msg_info("write 55 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Disable DHCP");
    cppcut_assert_equal(0, reg->write_handler(&zero, 1));

    mock_messages->expect_msg_info("write 53 handler %p %zu");
    mock_messages->expect_msg_info_formatted(
        "Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");
    mock_messages->expect_msg_error_formatted(0, LOG_WARNING,
        "Disabling IPv4 on interface DE:CA:FD:EA:DB:AD because DHCPv4 "
        "was disabled and static IPv4 configuration was not sent");
    mock_os->expect_os_map_file_to_memory(-1, false, expected_ethernet_config_filename);
    mock_os->expect_os_file_new(expected_os_write_fd, expected_ethernet_config_filename);
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
        "IPv4 = off\n";

    char buffer[512];
    snprintf(buffer, sizeof(buffer),
             expected_config_file_format, ethernet_mac_address);

    size_t written_config_file_length = strlen(buffer);

    cut_assert_equal_memory(buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * When being asked for DHCP mode in normal mode, Connman is consulted
 * (reporting "disabled" in this test).
 */
void test_read_dhcp_mode_in_normal_mode_with_dhcp_disabled(void)
{
    auto *reg = lookup_register_expect_handlers(55,
                                                dcpregs_read_55_dhcp_enabled,
                                                dcpregs_write_55_dhcp_enabled);

    mock_messages->expect_msg_info("read 55 handler %p %zu");
    mock_connman->expect_find_active_primary_interface(dummy_connman_iface,
                                                       ethernet_mac_address,
                                                       ethernet_mac_address,
                                                       wlan_mac_address);
    mock_connman->expect_get_dhcp_mode(false, dummy_connman_iface);
    mock_connman->expect_free_interface_data(dummy_connman_iface);

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
    auto *reg = lookup_register_expect_handlers(55,
                                                dcpregs_read_55_dhcp_enabled,
                                                dcpregs_write_55_dhcp_enabled);

    mock_messages->expect_msg_info("read 55 handler %p %zu");
    mock_connman->expect_find_active_primary_interface(dummy_connman_iface,
                                                       ethernet_mac_address,
                                                       ethernet_mac_address,
                                                       wlan_mac_address);
    mock_connman->expect_get_dhcp_mode(true, dummy_connman_iface);
    mock_connman->expect_free_interface_data(dummy_connman_iface);

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

    auto *reg = lookup_register_expect_handlers(55,
                                                dcpregs_read_55_dhcp_enabled,
                                                dcpregs_write_55_dhcp_enabled);

    mock_messages->expect_msg_info("read 55 handler %p %zu");
    mock_connman->expect_find_interface(dummy_connman_iface, ethernet_mac_address);
    mock_connman->expect_get_dhcp_mode(true, dummy_connman_iface);
    mock_connman->expect_free_interface_data(dummy_connman_iface);

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

    auto *reg = lookup_register_expect_handlers(55,
                                                dcpregs_read_55_dhcp_enabled,
                                                dcpregs_write_55_dhcp_enabled);

    mock_messages->expect_msg_info("write 55 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Enable DHCP");
    static const uint8_t one = 1;
    cppcut_assert_equal(0, reg->write_handler(&one, 1));

    mock_messages->expect_msg_info("read 55 handler %p %zu");

    uint8_t buffer = UINT8_MAX;
    cppcut_assert_equal(ssize_t(1), reg->read_handler(&buffer, 1));

    cppcut_assert_equal(1, int(buffer));
}

template <uint8_t Register>
struct RegisterTraits;

template <>
struct RegisterTraits<56U>
{
    static constexpr auto expected_read_handler_log_message = "read 56 handler %p %zu";
    static constexpr auto expected_read_handler = &dcpregs_read_56_ipv4_address;
    static constexpr auto expected_write_handler = &dcpregs_write_56_ipv4_address;
    static constexpr auto expect_get_string_memberfn = &MockConnman::expect_get_ipv4_address_string;
};

template <>
struct RegisterTraits<57U>
{
    static constexpr auto expected_read_handler_log_message = "read 57 handler %p %zu";
    static constexpr auto expected_read_handler = &dcpregs_read_57_ipv4_netmask;
    static constexpr auto expected_write_handler = &dcpregs_write_57_ipv4_netmask;
    static constexpr auto expect_get_string_memberfn = &MockConnman::expect_get_ipv4_netmask_string;
};

template <>
struct RegisterTraits<58U>
{
    static constexpr auto expected_read_handler_log_message = "read 58 handler %p %zu";
    static constexpr auto expected_read_handler = &dcpregs_read_58_ipv4_gateway;
    static constexpr auto expected_write_handler = &dcpregs_write_58_ipv4_gateway;
    static constexpr auto expect_get_string_memberfn = &MockConnman::expect_get_ipv4_gateway_string;
};

template <>
struct RegisterTraits<62U>
{
    static constexpr auto expected_read_handler = &dcpregs_read_62_primary_dns;
    static constexpr auto expected_write_handler = &dcpregs_write_62_primary_dns;
    static constexpr auto expect_get_string_memberfn = &MockConnman::expect_get_ipv4_gateway_string;
};

template <>
struct RegisterTraits<63U>
{
    static constexpr auto expected_read_handler = &dcpregs_read_63_secondary_dns;
    static constexpr auto expected_write_handler = &dcpregs_write_63_secondary_dns;
    static constexpr auto expect_get_string_memberfn = &MockConnman::expect_get_ipv4_gateway_string;
};

template <uint8_t Register, typename RegTraits = RegisterTraits<Register>>
static void read_ipv4_parameter_in_normal_mode(void)
{
    auto *reg = lookup_register_expect_handlers(Register,
                                                RegTraits::expected_read_handler,
                                                RegTraits::expected_write_handler);
    uint8_t buffer[50];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    mock_messages->expect_msg_info(RegTraits::expected_read_handler_log_message);
    mock_connman->expect_find_active_primary_interface(dummy_connman_iface,
                                                       ethernet_mac_address,
                                                       ethernet_mac_address,
                                                       wlan_mac_address);
    (mock_connman->*RegTraits::expect_get_string_memberfn)(standard_ipv4_address,
                                                           dummy_connman_iface, false,
                                                           sizeof(buffer));
    mock_connman->expect_free_interface_data(dummy_connman_iface);

    cppcut_assert_equal(ssize_t(sizeof(standard_ipv4_address)),
                        reg->read_handler(buffer, sizeof(buffer)));

    cut_assert_equal_memory(standard_ipv4_address, sizeof(standard_ipv4_address),
                            buffer, sizeof(standard_ipv4_address));
}

template <uint8_t Register, typename RegTraits = RegisterTraits<Register>>
static void read_ipv4_parameter_in_edit_mode_before_any_changes(void)
{
    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(Register,
                                                RegTraits::expected_read_handler,
                                                RegTraits::expected_write_handler);
    uint8_t buffer[50];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    mock_messages->expect_msg_info(RegTraits::expected_read_handler_log_message);
    mock_connman->expect_find_interface(dummy_connman_iface, ethernet_mac_address);
    (mock_connman->*RegTraits::expect_get_string_memberfn)(standard_ipv4_address,
                                                           dummy_connman_iface, false,
                                                           sizeof(buffer));
    mock_connman->expect_free_interface_data(dummy_connman_iface);

    cppcut_assert_equal(ssize_t(sizeof(standard_ipv4_address)),
                        reg->read_handler(buffer, sizeof(buffer)));

    cut_assert_equal_memory(standard_ipv4_address, sizeof(standard_ipv4_address),
                            buffer, sizeof(standard_ipv4_address));
}

template <uint8_t Register, typename RegTraits = RegisterTraits<Register>>
static void read_ipv4_parameter_in_edit_mode_after_change(void)
{
    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(Register,
                                                RegTraits::expected_read_handler,
                                                RegTraits::expected_write_handler);
    cppcut_assert_equal(0, reg->write_handler((uint8_t *)standard_ipv4_address,
                                              sizeof(standard_ipv4_address)));

    uint8_t buffer[4 + 16 + 4];
    memset(buffer, UINT8_MAX, sizeof(buffer));
    cppcut_assert_operator(sizeof(standard_ipv4_address), <=, sizeof(buffer));

    mock_messages->expect_msg_info(RegTraits::expected_read_handler_log_message);

    cppcut_assert_equal(ssize_t(sizeof(standard_ipv4_address)),
                        reg->read_handler(buffer + 4, sizeof(standard_ipv4_address)));

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
void test_read_ipv4_address_in_normal_mode(void)
{
    read_ipv4_parameter_in_normal_mode<56>();
}

/*!\test
 * When being asked for the IPv4 address in edit mode, Connman is consulted if
 * the address has not been set during this edit session.
 */
void test_read_ipv4_address_in_edit_mode_before_any_changes(void)
{
    read_ipv4_parameter_in_edit_mode_before_any_changes<56>();
}

/*!\test
 * When being asked for the IPv4 address in edit mode, the address written
 * during this edit session is returned.
 */
void test_read_ipv4_address_in_edit_mode_after_change(void)
{
    read_ipv4_parameter_in_edit_mode_after_change<56>();
}

/*!\test
 * When being asked for the IPv4 netmask in normal mode, Connman is consulted.
 */
void test_read_ipv4_netmask_in_normal_mode(void)
{
    read_ipv4_parameter_in_normal_mode<57>();
}

/*!\test
 * When being asked for the IPv4 netmask in edit mode, Connman is consulted if
 * the mask has not been set during this edit session.
 */
void test_read_ipv4_netmask_in_edit_mode_before_any_changes(void)
{
    read_ipv4_parameter_in_edit_mode_before_any_changes<57>();
}

/*!\test
 * When being asked for the IPv4 netmask in edit mode, the address written
 * during this edit session is returned.
 */
void test_read_ipv4_netmask_in_edit_mode_after_change(void)
{
    read_ipv4_parameter_in_edit_mode_after_change<57>();
}

/*!\test
 * When being asked for the IPv4 gateway in normal mode, Connman is consulted.
 */
void test_read_ipv4_gateway_in_normal_mode(void)
{
    read_ipv4_parameter_in_normal_mode<58>();
}

/*!\test
 * When being asked for the IPv4 gateway in edit mode, Connman is consulted if
 * the gateway has not been set during this edit session.
 */
void test_read_ipv4_gateway_in_edit_mode_before_any_changes(void)
{
    read_ipv4_parameter_in_edit_mode_before_any_changes<58>();
}

/*!\test
 * When being asked for the IPv4 gateway in edit mode, the gateway written
 * during this edit session is returned.
 */
void test_read_ipv4_gateway_in_edit_mode_after_change(void)
{
    read_ipv4_parameter_in_edit_mode_after_change<58>();
}

template <uint8_t Register, typename RegTraits = RegisterTraits<Register>>
static void set_one_dns_server(const char *dns_server_address, size_t dns_server_size,
                               const char *old_primary_dns,
                               const char *old_secondary_dns)
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

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(Register,
                                                RegTraits::expected_read_handler,
                                                RegTraits::expected_write_handler);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(dns_server_address)), dns_server_size));

    mock_messages->expect_msg_info("write 53 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");
    mock_connman->expect_find_active_primary_interface(
        dummy_connman_iface,
        ethernet_mac_address, ethernet_mac_address, wlan_mac_address);
    mock_connman->expect_get_ipv4_primary_dns_string(old_primary_dns, dummy_connman_iface, false, 16);
    mock_connman->expect_get_ipv4_secondary_dns_string(old_secondary_dns, dummy_connman_iface, false, 16);
    mock_connman->expect_free_interface_data(dummy_connman_iface);
    mock_os->expect_os_map_file_to_memory(&config_file, expected_ethernet_config_filename);
    mock_os->expect_os_unmap_file(&config_file);
    mock_os->expect_os_file_new(expected_os_write_fd, expected_ethernet_config_filename);
    for(int i = 0; i < 2 * 3 + (2 + 4) * 4; ++i)
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
        "IPv4 = %s/%s/%s\n"
        "Nameservers = %s%s%s\n";

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format,
             ethernet_mac_address, standard_ipv4_address,
             standard_ipv4_netmask, standard_ipv4_gateway,
             dns_server_address, "", "");

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Add primary DNS server address to static IPv4 configuration without
 * previously defined DNS servers.
 */
void test_set_only_first_dns_server(void)
{
    set_one_dns_server<62>(standard_dns1_address, sizeof(standard_dns1_address),
                           NULL, NULL);
}

/*!\test
 * Add secondary DNS server address to static IPv4 configuration without
 * previously defined DNS servers.
 *
 * Since this is the only address sent to the device, it becomes the primary
 * DNS server.
 */
void test_set_only_second_dns_server(void)
{
    set_one_dns_server<63>(standard_dns2_address, sizeof(standard_dns2_address),
                           NULL, NULL);
}

/*!\test
 * Add two DNS servers to static IPv4 configuration without previously defined
 * DNS servers.
 */
void test_set_both_dns_servers(void)
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

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(62,
                                                dcpregs_read_62_primary_dns,
                                                dcpregs_write_62_primary_dns);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(standard_dns1_address)), sizeof(standard_dns1_address)));

    reg = lookup_register_expect_handlers(63,
                                          dcpregs_read_63_secondary_dns,
                                          dcpregs_write_63_secondary_dns);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(standard_dns2_address)), sizeof(standard_dns2_address)));

    mock_messages->expect_msg_info("write 53 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");
    mock_os->expect_os_map_file_to_memory(&config_file, expected_ethernet_config_filename);
    mock_os->expect_os_unmap_file(&config_file);
    mock_os->expect_os_file_new(expected_os_write_fd, expected_ethernet_config_filename);
    for(int i = 0; i < 2 * 3 + (2 + 4) * 4; ++i)
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
        "IPv4 = %s/%s/%s\n"
        "Nameservers = %s,%s\n";

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format,
             ethernet_mac_address, standard_ipv4_address,
             standard_ipv4_netmask, standard_ipv4_gateway,
             standard_dns1_address, standard_dns2_address);

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Read out the primary DNS in edit mode, Connman is consulted if the primary
 * DNS server has not been set during this edit session.
 */
void test_read_primary_dns_in_edit_mode_before_any_changes(void)
{
    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(62,
                                                dcpregs_read_62_primary_dns,
                                                dcpregs_write_62_primary_dns);

    static constexpr char assumed_primary_dns[] = "50.60.117.208";

    char buffer[128];

    mock_messages->expect_msg_info("read 62 handler %p %zu");
    mock_connman->expect_find_interface(dummy_connman_iface, ethernet_mac_address);
    mock_connman->expect_get_ipv4_primary_dns_string(assumed_primary_dns,
                                                     dummy_connman_iface,
                                                     false, sizeof(buffer));
    mock_connman->expect_free_interface_data(dummy_connman_iface);

    ssize_t dns_server_size = reg->read_handler(static_cast<uint8_t *>(static_cast<void *>(buffer)), sizeof(buffer));

    cppcut_assert_equal(ssize_t(sizeof(assumed_primary_dns)), dns_server_size);
    cppcut_assert_equal(assumed_primary_dns, static_cast<const char *>(buffer));

    commit_ipv4_config(true);
}

/*!\test
 * Read out the secondary DNS in edit mode, Connman is consulted if the
 * secondary DNS server has not been set during this edit session.
 */
void test_read_secondary_dns_in_edit_mode_before_any_changes(void)
{
    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(63,
                                                dcpregs_read_63_secondary_dns,
                                                dcpregs_write_63_secondary_dns);

    static constexpr char assumed_secondary_dns[] = "1.2.3.4";

    char buffer[128];

    mock_messages->expect_msg_info("read 63 handler %p %zu");
    mock_connman->expect_find_interface(dummy_connman_iface, ethernet_mac_address);
    mock_connman->expect_get_ipv4_secondary_dns_string(assumed_secondary_dns,
                                                       dummy_connman_iface,
                                                       false, sizeof(buffer));
    mock_connman->expect_free_interface_data(dummy_connman_iface);

    ssize_t dns_server_size = reg->read_handler(static_cast<uint8_t *>(static_cast<void *>(buffer)), sizeof(buffer));

    cppcut_assert_equal(ssize_t(sizeof(assumed_secondary_dns)), dns_server_size);
    cppcut_assert_equal("1.2.3.4", static_cast<const char *>(buffer));

    commit_ipv4_config(true);
}

/*!\test
 * Given two previously defined DNS servers, replace the primary one.
 */
void test_replace_primary_dns_server_of_two_servers(void)
{
    start_ipv4_config();

    static constexpr char assumed_primary_dns[] = "50.60.117.208";
    static constexpr char assumed_secondary_dns[] = "1.2.3.4";

    auto *reg = lookup_register_expect_handlers(62,
                                                dcpregs_read_62_primary_dns,
                                                dcpregs_write_62_primary_dns);

    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(standard_dns1_address)), sizeof(standard_dns1_address)));

    mock_messages->expect_msg_info("write 53 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");
    mock_os->expect_os_map_file_to_memory(-1, false, expected_ethernet_config_filename);
    mock_connman->expect_find_active_primary_interface(dummy_connman_iface,
                                                       ethernet_mac_address,
                                                       ethernet_mac_address,
                                                       wlan_mac_address);
    mock_connman->expect_get_ipv4_primary_dns_string(assumed_primary_dns,
                                                     dummy_connman_iface,
                                                     false, 16);
    mock_connman->expect_get_ipv4_secondary_dns_string(assumed_secondary_dns,
                                                       dummy_connman_iface,
                                                       false, 16);
    mock_connman->expect_free_interface_data(dummy_connman_iface);
    mock_os->expect_os_file_new(expected_os_write_fd, expected_ethernet_config_filename);
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
        "Nameservers = %s,%s\n";

    char output_config_file[512];

    snprintf(output_config_file, sizeof(output_config_file),
             expected_config_file_format,
             ethernet_mac_address, standard_dns1_address, assumed_secondary_dns);

    size_t output_config_file_length = strlen(output_config_file);

    cut_assert_equal_memory(output_config_file, output_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Given two previously defined DNS servers, replace the secondary one.
 */
void test_replace_secondary_dns_server_of_two_servers(void)
{
    start_ipv4_config();

    static constexpr char assumed_primary_dns[] = "50.60.117.208";
    static constexpr char assumed_secondary_dns[] = "1.2.3.4";

    auto *reg = lookup_register_expect_handlers(63,
                                                dcpregs_read_63_secondary_dns,
                                                dcpregs_write_63_secondary_dns);

    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(standard_dns2_address)), sizeof(standard_dns2_address)));

    mock_messages->expect_msg_info("write 53 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");
    mock_os->expect_os_map_file_to_memory(-1, false, expected_ethernet_config_filename);
    mock_connman->expect_find_active_primary_interface(dummy_connman_iface,
                                                       ethernet_mac_address,
                                                       ethernet_mac_address,
                                                       wlan_mac_address);
    mock_connman->expect_get_ipv4_primary_dns_string(assumed_primary_dns,
                                                     dummy_connman_iface,
                                                     false, 16);
    mock_connman->expect_get_ipv4_secondary_dns_string(assumed_secondary_dns,
                                                       dummy_connman_iface,
                                                       false, 16);
    mock_connman->expect_free_interface_data(dummy_connman_iface);
    mock_os->expect_os_file_new(expected_os_write_fd, expected_ethernet_config_filename);
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
        "Nameservers = %s,%s\n";

    char output_config_file[512];

    snprintf(output_config_file, sizeof(output_config_file),
             expected_config_file_format,
             ethernet_mac_address, assumed_primary_dns, standard_dns2_address);

    size_t output_config_file_length = strlen(output_config_file);

    cut_assert_equal_memory(output_config_file, output_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Given one previously defined DNS server, add a secondary one.
 */
void test_add_secondary_dns_server_to_primary_server(void)
{
    start_ipv4_config();

    static constexpr char assumed_primary_dns[] = "213.1.92.9";

    auto *reg = lookup_register_expect_handlers(63,
                                                dcpregs_read_63_secondary_dns,
                                                dcpregs_write_63_secondary_dns);

    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(standard_dns2_address)), sizeof(standard_dns2_address)));

    mock_messages->expect_msg_info("write 53 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");
    mock_os->expect_os_map_file_to_memory(-1, false, expected_ethernet_config_filename);
    mock_connman->expect_find_active_primary_interface(dummy_connman_iface,
                                                       ethernet_mac_address,
                                                       ethernet_mac_address,
                                                       wlan_mac_address);
    mock_connman->expect_get_ipv4_primary_dns_string(assumed_primary_dns,
                                                     dummy_connman_iface,
                                                     false, 16);
    mock_connman->expect_get_ipv4_secondary_dns_string("",
                                                       dummy_connman_iface,
                                                       false, 16);
    mock_connman->expect_free_interface_data(dummy_connman_iface);
    mock_os->expect_os_file_new(expected_os_write_fd, expected_ethernet_config_filename);
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
        "Nameservers = %s,%s\n";

    char output_config_file[512];

    snprintf(output_config_file, sizeof(output_config_file),
             expected_config_file_format,
             ethernet_mac_address, assumed_primary_dns, standard_dns2_address);

    size_t output_config_file_length = strlen(output_config_file);

    cut_assert_equal_memory(output_config_file, output_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * WPA passphrase for Ethernet connections is ignored and not written to file.
 */
void test_set_wlan_security_mode_on_ethernet_service_is_ignored(void)
{
    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(92,
                                                dcpregs_read_92_wlan_security,
                                                dcpregs_write_92_wlan_security);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>("NONE")), 4));

    mock_messages->expect_msg_info("write 53 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");
    mock_messages->expect_msg_info("Ignoring wireless parameters for active wired interface");
    mock_os->expect_os_map_file_to_memory(-1, false, expected_ethernet_config_filename);
    mock_os->expect_os_file_new(expected_os_write_fd, expected_ethernet_config_filename);
    for(int i = 0; i < 2 * 3 + (2 + 2) * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);

    commit_ipv4_config(false);

    static const char expected_config_file_format[] =
        "[global]\n"
        "Name = StrBo\n"
        "Description = StrBo-managed built-in wired interface\n"
        "[service_config]\n"
        "MAC = %s\n"
        "Type = ethernet\n";

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format, ethernet_mac_address);

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * There is no wireless security mode for Ethernet connections.
 */
void test_get_wlan_security_mode_for_ethernet_returns_error(void)
{
    uint8_t buffer[64];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    auto *reg = lookup_register_expect_handlers(92,
                                                dcpregs_read_92_wlan_security,
                                                dcpregs_write_92_wlan_security);

    mock_connman->expect_find_active_primary_interface(dummy_connman_iface,
                                                       ethernet_mac_address,
                                                       ethernet_mac_address,
                                                       wlan_mac_address);
    mock_connman->expect_get_wlan_security_type_string(false, "", dummy_connman_iface, false, 12);
    mock_messages->expect_msg_error(EINVAL, LOG_ERR,
                                    "No Connman security type set for active interface");
    mock_connman->expect_free_interface_data(dummy_connman_iface);

    cppcut_assert_equal(ssize_t(-1), reg->read_handler(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(0), buffer[0]);
    cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[1]);
}

static void assume_wlan_interface_is_active(void)
{
    struct register_configuration_t *config = registers_get_nonconst_data();

    config->active_interface = &config->builtin_wlan_interface;
}

static void set_wlan_security_mode(const char *requested_security_mode,
                                   const char *expected_out_security_mode)
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(92,
                                                dcpregs_read_92_wlan_security,
                                                dcpregs_write_92_wlan_security);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(requested_security_mode)), strlen(requested_security_mode)));

    mock_messages->expect_msg_info("write 53 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Writing new network configuration for MAC address BA:DD:EA:DB:EE:F1");
    mock_os->expect_os_map_file_to_memory(-1, false, expected_wlan_config_filename);
    mock_os->expect_os_file_new(expected_os_write_fd, expected_wlan_config_filename);
    for(int i = 0; i < 2 * 3 + (2 + 3) * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);

    commit_ipv4_config(false);

    static const char expected_config_file_format[] =
        "[global]\n"
        "Name = StrBo\n"
        "Description = StrBo-managed built-in wireless interface\n"
        "[service_config]\n"
        "MAC = %s\n"
        "Type = wifi\n"
        "Security = %s\n";

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format,
             wlan_mac_address, expected_out_security_mode);

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Disable WLAN security.
 */
void test_set_wlan_security_mode_none(void)
{
    set_wlan_security_mode("NONE", "none");
}

/*!\test
 * Set WLAN security mode to WPA/PSK.
 */
void test_set_wlan_security_mode_wpa_psk(void)
{
    set_wlan_security_mode("WPAPSK", "psk");
}

/*!\test
 * Set WLAN security mode to WPA2/PSK.
 */
void test_set_wlan_security_mode_wpa2_psk(void)
{
    set_wlan_security_mode("WPA2PSK", "psk");
}

/*!\test
 * Setting WLAN security mode to WEP is not implemented yet.
 */
void test_set_wlan_security_mode_wep(void)
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(92,
                                                dcpregs_read_92_wlan_security,
                                                dcpregs_write_92_wlan_security);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>("WEP")), 3));

    mock_messages->expect_msg_info("write 53 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Writing new network configuration for MAC address BA:DD:EA:DB:EE:F1");
    mock_os->expect_os_map_file_to_memory(-1, false, expected_wlan_config_filename);
    mock_messages->expect_msg_error(0, LOG_CRIT,
                                    "BUG: Support for insecure WLAN mode "
                                    "\"WEP\" not implemented yet");
    mock_messages->expect_msg_error(EINVAL, LOG_ERR,
                                    "Cannot set WLAN parameters, security mode missing");

    commit_ipv4_config(false, -1);
}

/*!\test
 * Setting invalid WLAN security mode is detected when attempting to write
 * configuration.
 */
void test_set_invalid_wlan_security_mode(void)
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(92,
                                                dcpregs_read_92_wlan_security,
                                                dcpregs_write_92_wlan_security);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>("foo")), 3));

    mock_messages->expect_msg_info("write 53 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Writing new network configuration for MAC address BA:DD:EA:DB:EE:F1");
    mock_os->expect_os_map_file_to_memory(-1, false, expected_wlan_config_filename);
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
                                              "Invalid WLAN security mode \"foo\" (Invalid argument)");
    mock_messages->expect_msg_error(EINVAL, LOG_ERR,
                                    "Cannot set WLAN parameters, security mode missing");

    commit_ipv4_config(false, -1);
}

static void get_wlan_security_mode(const char *expected_security_mode,
                                   const char *assumed_connman_security_mode,
                                   const char *expected_error_message = nullptr)
{
    assume_wlan_interface_is_active();

    static const uint8_t redzone_content[] =
    {
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
    };

    uint8_t buffer[32];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    auto *reg = lookup_register_expect_handlers(92,
                                                dcpregs_read_92_wlan_security,
                                                dcpregs_write_92_wlan_security);
    uint8_t *const dest = &buffer[sizeof(redzone_content)];

    if(expected_error_message != nullptr)
        mock_messages->expect_msg_error_formatted(0, LOG_ERR,
                                                  expected_error_message);

    mock_connman->expect_find_active_primary_interface(dummy_connman_iface,
                                                       wlan_mac_address,
                                                       ethernet_mac_address,
                                                       wlan_mac_address);
    mock_connman->expect_get_wlan_security_type_string(true,
                                                       assumed_connman_security_mode,
                                                       dummy_connman_iface,
                                                       false, 12);
    mock_connman->expect_free_interface_data(dummy_connman_iface);

    const ssize_t mode_length =
        reg->read_handler(dest, sizeof(buffer) - 2 * sizeof(redzone_content));

    cppcut_assert_operator(ssize_t(0), <, mode_length);
    cppcut_assert_equal('\0', static_cast<char>(dest[mode_length - 1]));
    cppcut_assert_equal(expected_security_mode,
                        static_cast<char *>(static_cast<void *>(dest)));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer, sizeof(redzone_content));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + sizeof(buffer) - sizeof(redzone_content),
                            sizeof(redzone_content));
}

/*!\test
 * Read out WLAN security mode when no security mode is enabled.
 */
void test_get_wlan_security_mode_assume_none(void)
{
    get_wlan_security_mode("NONE", "none");
}

/*!\test
 * Read out WLAN security mode in WEP mode.
 */
void test_get_wlan_security_mode_assume_wep(void)
{
    get_wlan_security_mode("WEP", "wep");
}

/*!\test
 * Read out WLAN security mode in WPA/WPA2 PSK mode.
 *
 * Connman does not distinguish between WPA and WPA2, so its answer is always
 * "psk", which, in turn, we always translate to DCP string "WPA2PSK"
 */
void test_get_wlan_security_mode_assume_psk(void)
{
    get_wlan_security_mode("WPA2PSK", "psk");
}

/*!\test
 * Read out WLAN security mode in WPA EAP mode ("WPA Enterprise").
 *
 * This is not supported by DCP, so we return nothing for now.
 */
void test_get_wlan_security_mode_assume_wpa_eap(void)
{
    get_wlan_security_mode("", "ieee8021x",
                          "Cannot convert Connman security type \"ieee8021x\" to DCP");
}

/*!\test
 * Read out WLAN security mode in some unknown future mode.
 */
void test_get_wlan_security_mode_assume_unknown_mode(void)
{
    get_wlan_security_mode("", "fortknox",
                           "Cannot convert Connman security type \"fortknox\" to DCP");
}

static void set_passphrase_with_security_mode(const char *passphrase,
                                              size_t passphrase_size,
                                              const char *dcp_security_mode,
                                              const char *connman_security_mode)
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(102,
                                                dcpregs_read_102_passphrase,
                                                dcpregs_write_102_passphrase);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(passphrase)), passphrase_size));

    reg = lookup_register_expect_handlers(92,
                                          dcpregs_read_92_wlan_security,
                                          dcpregs_write_92_wlan_security);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(dcp_security_mode)), strlen(dcp_security_mode)));

    mock_messages->expect_msg_info("write 53 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Writing new network configuration for MAC address BA:DD:EA:DB:EE:F1");
    mock_os->expect_os_map_file_to_memory(-1, false, expected_wlan_config_filename);
    mock_os->expect_os_file_new(expected_os_write_fd, expected_wlan_config_filename);
    for(int i = 0; i < 2 * 3 + (2 + 4) * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);

    commit_ipv4_config(false);

    static const char expected_config_file_format[] =
        "[global]\n"
        "Name = StrBo\n"
        "Description = StrBo-managed built-in wireless interface\n"
        "[service_config]\n"
        "MAC = %s\n"
        "Type = wifi\n"
        "Security = %s\n"
        "Passphrase = %s\n";

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format,
             wlan_mac_address, connman_security_mode, passphrase);

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Passphrase may be sent as ASCII string.
 */
void test_set_ascii_passphrase_with_psk_security_mode(void)
{
    static constexpr char ascii_passphrase[] = "My Secret 123&Foo~Bar";

    cppcut_assert_operator(size_t(64), >, sizeof(ascii_passphrase) - 1);
    set_passphrase_with_security_mode(ascii_passphrase, sizeof(ascii_passphrase) - 1,
                                      "WPA2PSK", "psk");
}

/*!\test
 * Passphrase may be sent as string containing only hex characters.
 */
void test_set_hex_passphrase_with_psk_security_mode(void)
{
    static constexpr char hex_passphrase[] =
        "1234567890abcdef"
        "1234567890abcdef"
        "1234567890abcdef"
        "1234567890abcdef";

    cppcut_assert_equal(size_t(64), sizeof(hex_passphrase) - 1);
    set_passphrase_with_security_mode(hex_passphrase, sizeof(hex_passphrase) - 1,
                                      "WPA2PSK", "psk");
}

/*!\test
 * ASCII passphrase lengths must be with certain limits.
 */
void test_ascii_passphrase_minimum_and_maximum_length(void)
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    static constexpr char passphrase[] =
        "12345678901234567890"
        "abcdefghijklmnopqrst"
        "12345678901234567890"
        "1234";
    static const uint8_t *passphrase_arg =
        static_cast<const uint8_t *>(static_cast<const void *>(passphrase));

    auto *reg = lookup_register_expect_handlers(102,
                                                dcpregs_read_102_passphrase,
                                                dcpregs_write_102_passphrase);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Unexpected data length 1 (expected 8...64) (Invalid argument)");
    cppcut_assert_equal(-1, reg->write_handler(passphrase_arg, 1));

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Unexpected data length 7 (expected 8...64) (Invalid argument)");
    cppcut_assert_equal(-1, reg->write_handler(passphrase_arg, 7));

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Invalid passphrase: not a hex-string (Invalid argument)");
    cppcut_assert_equal(-1, reg->write_handler(passphrase_arg, 64));
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
        string_(static_cast<const uint8_t *>(static_cast<const void *>(str)))
    {}
};

/*!\test
 * ASCII passphrase must contain characters in certain range
 */
void test_ascii_passphrase_character_set(void)
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(102,
                                                dcpregs_read_102_passphrase,
                                                dcpregs_write_102_passphrase);

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
        cppcut_assert_equal(-1, reg->write_handler(str.string_, str.length_));
    }
}

/*!\test
 * Passphrase with security mode "none" makes no sense and is rejected.
 */
void test_set_passphrase_with_security_mode_none_does_not_work(void)
{
    static constexpr char ascii_passphrase[] = "SuperSecret";

    cppcut_assert_operator(size_t(64), >, sizeof(ascii_passphrase) - 1);
    set_passphrase_with_security_mode(ascii_passphrase, sizeof(ascii_passphrase) - 1,
                                      "NONE", "none");
}

/*!\test
 * Passphrase without any security mode makes no sense and is rejected.
 */
void test_set_passphrase_without_security_mode_does_not_work(void)
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    static constexpr char passphrase[] = "SuperSecret";
    auto *reg = lookup_register_expect_handlers(102,
                                                dcpregs_read_102_passphrase,
                                                dcpregs_write_102_passphrase);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(passphrase)), sizeof(passphrase) - 1));

    mock_messages->expect_msg_info("write 53 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Writing new network configuration for MAC address BA:DD:EA:DB:EE:F1");
    mock_os->expect_os_map_file_to_memory(-1, false, expected_wlan_config_filename);
    mock_connman->expect_find_active_primary_interface(dummy_connman_iface,
                                                       wlan_mac_address,
                                                       ethernet_mac_address,
                                                       wlan_mac_address);
    mock_connman->expect_get_wlan_security_type_string(true, "", dummy_connman_iface, false, 16);
    mock_connman->expect_free_interface_data(dummy_connman_iface);
    mock_messages->expect_msg_error(EINVAL, LOG_ERR,
                                    "Cannot set WLAN parameters, security mode missing");

    commit_ipv4_config(false, -1);
}

/*!\test
 * Passphrase can be read out while the configuration is in edit mode.
 */
void test_get_wlan_passphrase_in_edit_mode(void)
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    static const uint8_t redzone_content[] =
    {
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
    };

    uint8_t buffer[64 + 2 * sizeof(redzone_content)];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    auto *reg = lookup_register_expect_handlers(102,
                                                dcpregs_read_102_passphrase,
                                                dcpregs_write_102_passphrase);

    mock_messages->expect_msg_info("No passphrase set yet");

    cppcut_assert_equal(ssize_t(0), reg->read_handler(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[0]);
    cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[sizeof(buffer) - 1]);

    /* set hex passphrase and read back */
    static const uint8_t passphrase[] =
        "12345678901234567890"
        "abcdefabcdefabcdefab"
        "12345678901234567890"
        "abcd";

    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(passphrase)), sizeof(passphrase) - 1));

    uint8_t *const dest = &buffer[sizeof(redzone_content)];
    const ssize_t passphrase_length = reg->read_handler(dest, 64);

    cppcut_assert_equal(ssize_t(64), passphrase_length);
    cut_assert_equal_memory(passphrase, sizeof(passphrase) - 1,
                            dest, 64);
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer, sizeof(redzone_content));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + sizeof(buffer) - sizeof(redzone_content),
                            sizeof(redzone_content));

    /* wipe out passphrase and read back */
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(passphrase)), 0));

    mock_messages->expect_msg_info("Passphrase set, but empty");

    memset(buffer, UINT8_MAX, sizeof(buffer));
    cppcut_assert_equal(ssize_t(0), reg->read_handler(dest, 64));
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
void test_get_wlan_passphrase_in_regular_mode(void)
{
    assume_wlan_interface_is_active();

    uint8_t buffer[64];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    auto *reg = lookup_register_expect_handlers(102,
                                                dcpregs_read_102_passphrase,
                                                dcpregs_write_102_passphrase);

    mock_messages->expect_msg_info("Passphrase cannot be read out while in non-edit mode");

    cppcut_assert_equal(ssize_t(-1), reg->read_handler(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[0]);
    cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[sizeof(buffer) - 1]);
}

/*!\test
 * In most cases, the SSID will be a rather simple ASCII string.
 *
 * Here, "simple" means regular ASCII characters and no spaces. If the SSID is
 * simple enough, it will be written to the "Name" field of the configuration
 * file, in addition to the "SSID" field (which is always written).
 *
 * The zero-terminator is usually not part of the SSID and must not be sent
 * over DCP (otherwise the SSID will be considered binary because it ends with
 * a 0 byte).
 */
void test_set_simple_ascii_wlan_ssid(void)
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(94,
                                                dcpregs_read_94_ssid,
                                                dcpregs_write_94_ssid);

    static constexpr char ssid[] = "MyNiceWLAN";
    static constexpr char ssid_as_hex_string[] = "4d794e696365574c414e";

    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(ssid)), sizeof(ssid) - 1));

    mock_messages->expect_msg_info("write 53 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Writing new network configuration for MAC address BA:DD:EA:DB:EE:F1");
    mock_os->expect_os_map_file_to_memory(-1, false, expected_wlan_config_filename);
    mock_connman->expect_find_active_primary_interface(
        dummy_connman_iface,
        wlan_mac_address, ethernet_mac_address, wlan_mac_address);
    mock_connman->expect_get_wlan_security_type_string(true, "none", dummy_connman_iface, false, 16);
    mock_connman->expect_free_interface_data(dummy_connman_iface);
    mock_os->expect_os_file_new(expected_os_write_fd, expected_wlan_config_filename);
    for(int i = 0; i < 2 * 3 + (2 + 5) * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);

    commit_ipv4_config(false);

    static const char expected_config_file_format[] =
        "[global]\n"
        "Name = StrBo\n"
        "Description = StrBo-managed built-in wireless interface\n"
        "[service_config]\n"
        "MAC = %s\n"
        "Type = wifi\n"
        "Security = none\n"
        "Name = %s\n"
        "SSID = %s\n";

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format,
             wlan_mac_address, ssid, ssid_as_hex_string);

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * An SSID may be any binary string with a length of up to 32 bytes.
 */
void test_set_binary_wlan_ssid(void)
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(94,
                                                dcpregs_read_94_ssid,
                                                dcpregs_write_94_ssid);

    static constexpr uint8_t ssid[] =
    {
        0x00, 0x08, 0xfe, 0xff, 0x41, 0x42, 0x43, 0x7f,
    };

    static constexpr char ssid_as_hex_string[] = "0008feff4142437f";

    cppcut_assert_equal(0, reg->write_handler(ssid, sizeof(ssid)));

    mock_messages->expect_msg_info("write 53 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Writing new network configuration for MAC address BA:DD:EA:DB:EE:F1");
    mock_os->expect_os_map_file_to_memory(-1, false, expected_wlan_config_filename);
    mock_connman->expect_find_active_primary_interface(
        dummy_connman_iface,
        wlan_mac_address, ethernet_mac_address, wlan_mac_address);
    mock_connman->expect_get_wlan_security_type_string(true, "none", dummy_connman_iface, false, 16);
    mock_connman->expect_free_interface_data(dummy_connman_iface);
    mock_os->expect_os_file_new(expected_os_write_fd, expected_wlan_config_filename);
    for(int i = 0; i < 2 * 3 + (2 + 4) * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);

    commit_ipv4_config(false);

    static const char expected_config_file_format[] =
        "[global]\n"
        "Name = StrBo\n"
        "Description = StrBo-managed built-in wireless interface\n"
        "[service_config]\n"
        "MAC = %s\n"
        "Type = wifi\n"
        "Security = none\n"
        "SSID = %s\n";

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format,
             wlan_mac_address, ssid_as_hex_string);

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * The empty SSID is a special wildcard SSID and cannot be used here.
 */
void test_set_empty_wlan_ssid_is_an_error(void)
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(94,
                                                dcpregs_read_94_ssid,
                                                dcpregs_write_94_ssid);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Unexpected data length 0 (expected 1...32) (Invalid argument)");

    uint8_t dummy = UINT8_MAX;
    cppcut_assert_equal(-1, reg->write_handler(&dummy, 0));

    commit_ipv4_config(true);
}

/*!\test
 * Read out the SSID for displaying purposes.
 */
void test_get_wlan_ssid_in_normal_mode(void)
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

    uint8_t buffer[32 + 2 * sizeof(redzone_content)];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    auto *reg = lookup_register_expect_handlers(94,
                                                dcpregs_read_94_ssid,
                                                dcpregs_write_94_ssid);
    uint8_t *const dest = &buffer[sizeof(redzone_content)];

    mock_connman->expect_find_active_primary_interface(dummy_connman_iface,
                                                       wlan_mac_address,
                                                       ethernet_mac_address,
                                                       wlan_mac_address);
    mock_connman->expect_get_wlan_ssid(assumed_ssid, sizeof(assumed_ssid),
                                       dummy_connman_iface, false, 32);
    mock_connman->expect_free_interface_data(dummy_connman_iface);

    const ssize_t ssid_length = reg->read_handler(dest, 32);

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
void test_get_wlan_ssid_in_edit_mode_before_any_changes(void)
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

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

    cppcut_assert_operator(size_t(32), <=, sizeof(assumed_ssid) + sizeof(redzone_content));

    uint8_t buffer[sizeof(assumed_ssid) + 2 * sizeof(redzone_content)];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    auto *reg = lookup_register_expect_handlers(94,
                                                dcpregs_read_94_ssid,
                                                dcpregs_write_94_ssid);
    uint8_t *const dest = &buffer[sizeof(redzone_content)];

    mock_connman->expect_find_interface(dummy_connman_iface, wlan_mac_address);
    mock_connman->expect_get_wlan_ssid(assumed_ssid, sizeof(assumed_ssid),
                                       dummy_connman_iface, false, 32);
    mock_connman->expect_free_interface_data(dummy_connman_iface);

    const ssize_t ssid_length = reg->read_handler(dest, 32);

    cut_assert_equal_memory(dest, ssize_t(sizeof(assumed_ssid)),
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
void test_get_wlan_ssid_in_edit_mode_after_change(void)
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(94,
                                                dcpregs_read_94_ssid,
                                                dcpregs_write_94_ssid);

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

    cppcut_assert_equal(0, reg->write_handler(ssid, sizeof(ssid)));

    uint8_t buffer[32];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    const ssize_t ssid_length = reg->read_handler(buffer, sizeof(buffer));

    cut_assert_equal_memory(ssid, ssize_t(sizeof(ssid)),
                            buffer, ssid_length);
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + ssid_length, sizeof(redzone_content));
}

/*!\test
 * Attempting to set ad-hoc mode results in an error.
 *
 * Connman does not support ad-hoc mode, so we do not either.
 */
void test_set_ibss_mode_adhoc_is_not_supported(void)
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(93,
                                                dcpregs_read_93_ibss,
                                                dcpregs_write_93_ibss);

    mock_messages->expect_msg_error(EINVAL, LOG_NOTICE,
                                    "Cannot change IBSS mode to ad-hoc, "
                                    "always using infrastructure mode");
    cppcut_assert_equal(-1, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>("true")), 4));
}

/*!\test
 * Attempting to set infrastructure mode succeeds, but the attempt is logged
 * and gets ignored.
 */
void test_set_ibss_mode_infrastructure_is_ignored(void)
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(93,
                                                dcpregs_read_93_ibss,
                                                dcpregs_write_93_ibss);

    mock_messages->expect_msg_info("Ignoring IBSS infrastructure mode request "
                                   "(always using that mode)");
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>("false")), 5));
}

/*!\test
 * Even though we do not support setting IBSS mode, it is still not allowed to
 * send junk.
 */
void test_set_junk_ibss_mode_is_an_error(void)
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

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
                                                dcpregs_read_93_ibss,
                                                dcpregs_write_93_ibss);

    for(const auto &str : junk_requests)
    {
        mock_messages->expect_msg_error(EINVAL, LOG_ERR,
                                        "Got invalid IBSS mode request");
        cppcut_assert_equal(-1, reg->write_handler(str.string_, str.length_));
    }
}

/*!\test
 * We always tell we are operating in infrastructure mode.
 */
void test_get_ibss_mode_returns_infrastructure_mode(void)
{
    assume_wlan_interface_is_active();

    auto *reg = lookup_register_expect_handlers(93,
                                                dcpregs_read_93_ibss,
                                                dcpregs_write_93_ibss);

    uint8_t response[8];
    cppcut_assert_equal(ssize_t(6), reg->read_handler(response, sizeof(response)));
    cppcut_assert_equal("false", static_cast<const char *>(static_cast<const void *>(response)));
}

/*!\test
 * Attempting to set WPA cipher mode succeeds, but the attempt is logged and
 * gets ignored.
 */
void test_set_wpa_cipher_is_ignored(void)
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(101,
                                                dcpregs_read_101_wpa_cipher,
                                                dcpregs_write_101_wpa_cipher);

    mock_messages->expect_msg_info("Ignoring setting WPA cipher (automatic, AES preferred)");
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>("TKIP")), 4));

    mock_messages->expect_msg_info("Ignoring setting WPA cipher (automatic, AES preferred)");
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>("TKIP")), 5));

    mock_messages->expect_msg_info("Ignoring setting WPA cipher (automatic, AES preferred)");
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>("AES")), 3));

    mock_messages->expect_msg_info("Ignoring setting WPA cipher (automatic, AES preferred)");
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>("AES")), 4));
}

/*!\test
 * Even though we do not support setting WPA cipher, it is still not allowed to
 * send junk.
 */
void test_set_junk_wpa_cipher_is_an_error(void)
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

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
                                                dcpregs_read_101_wpa_cipher,
                                                dcpregs_write_101_wpa_cipher);

    for(const auto &str : junk_requests)
    {
        mock_messages->expect_msg_error(EINVAL, LOG_ERR,
                                        "Got invalid WPA cipher");
        cppcut_assert_equal(-1, reg->write_handler(str.string_, str.length_));
    }
}

/*!\test
 * We always tell we are using AES.
 */
void test_get_wpa_cipher_returns_aes(void)
{
    assume_wlan_interface_is_active();

    auto *reg = lookup_register_expect_handlers(101,
                                                dcpregs_read_101_wpa_cipher,
                                                dcpregs_write_101_wpa_cipher);

    uint8_t response[8];
    cppcut_assert_equal(ssize_t(4), reg->read_handler(response, sizeof(response)));
    cppcut_assert_equal("AES", static_cast<const char *>(static_cast<const void *>(response)));
}

};

namespace spi_registers_misc
{

static MockMessages *mock_messages;
static MockOs *mock_os;

static constexpr char expected_config_filename[] = "/etc/os-release";

static constexpr int expected_os_map_file_to_memory_fd = 5;

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

    register_init(NULL, NULL, NULL, NULL);
}

void cut_teardown(void)
{
    mock_messages->check();
    mock_os->check();

    mock_messages_singleton = nullptr;
    mock_os_singleton = nullptr;

    delete mock_messages;
    delete mock_os;

    mock_messages = nullptr;
    mock_os = nullptr;
}

/*!\test
 * Register 37 cannot be written to.
 */
void test_dcp_register_37_has_no_write_handler()
{
    const auto *reg = register_lookup(37);

    cppcut_assert_not_null(reg);
    cppcut_assert_equal(37U, unsigned(reg->address));
    cut_assert(reg->read_handler != NULL);
    cut_assert(reg->write_handler == NULL);
}

static void do_test_read_image_version(const os_mapped_file_data &config_file,
                                       size_t dest_buffer_size,
                                       const char *expected_build_id,
                                       size_t expected_build_id_size)
{
    char expected_build_id_memory[dest_buffer_size];
    memset(expected_build_id_memory, 0, dest_buffer_size);

    if(expected_build_id_size > 1)
        memcpy(expected_build_id_memory, expected_build_id, expected_build_id_size - 1);

    uint8_t redzone_content[10];
    memset(redzone_content, 0xff, sizeof(redzone_content));

    uint8_t buffer[sizeof(redzone_content) + dest_buffer_size + sizeof(redzone_content)];
    memset(buffer, 0xff, sizeof(buffer));

    auto *reg = register_lookup(37);

    mock_os->expect_os_map_file_to_memory(&config_file, expected_config_filename);
    mock_os->expect_os_unmap_file(&config_file);
    mock_messages->expect_msg_info("read 37 handler %p %zu");

    cppcut_assert_equal(ssize_t(expected_build_id_size),
                        reg->read_handler(buffer + sizeof(redzone_content),
                                          sizeof(buffer) - 2 * sizeof(redzone_content)));

    cut_assert_equal_memory(redzone_content, sizeof(redzone_content), buffer,
                            sizeof(redzone_content));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + sizeof(redzone_content) + dest_buffer_size,
                            sizeof(redzone_content));
    cut_assert_equal_memory(expected_build_id_memory, dest_buffer_size,
                            buffer + sizeof(redzone_content),
                            dest_buffer_size);
}

/*!\test
 * Realistic test with real-life configuration data.
 */
void test_read_image_version()
{
    static char config_file_buffer[] =
        "ID=strbo\n"
        "NAME=StrBo (T+A Streaming Board)\n"
        "VERSION=1.0.0\n"
        "VERSION_ID=1.0.0\n"
        "PRETTY_NAME=StrBo (T+A Streaming Board) 1.0.0\n"
        "BUILD_ID=20150708122013\n"
        "BUILD_GIT_COMMIT=05f6dcd31134a3d2e9f5d0c8b78a4bab1948a4d5\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_build_id[] = "20150708122013";

    do_test_read_image_version(config_file, 20,
                               expected_build_id, sizeof(expected_build_id));
}

/*!\test
 * Build ID can be read if it appears in the first line of the config file.
 */
void test_read_image_version_with_build_id_in_first_line()
{
    static char config_file_buffer[] =
        "BUILD_ID=20150708122013\n"
        "BUILD_GIT_COMMIT=05f6dcd31134a3d2e9f5d0c8b78a4bab1948a4d5\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_build_id[] = "20150708122013";

    do_test_read_image_version(config_file, 20,
                               expected_build_id, sizeof(expected_build_id));
}

/*!\test
 * Build ID can be read if it appears in the last line of the config file.
 */
void test_read_image_version_with_build_id_in_last_line()
{
    static char config_file_buffer[] =
        "BUILD_GIT_COMMIT=05f6dcd31134a3d2e9f5d0c8b78a4bab1948a4d5\n"
        "BUILD_ID=20150708122013\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_build_id[] = "20150708122013";

    do_test_read_image_version(config_file, 20,
                               expected_build_id, sizeof(expected_build_id));
}

/*!\test
 * Build ID can be read if it appears in the last line of the config file, even
 * if not terminated with a newline character.
 */
void test_read_image_version_with_build_id_in_last_line_without_newline()
{
    static char config_file_buffer[] =
        "BUILD_GIT_COMMIT=05f6dcd31134a3d2e9f5d0c8b78a4bab1948a4d5\n"
        "BUILD_ID=20150708122013";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_build_id[] = "20150708122013";

    do_test_read_image_version(config_file, 20,
                               expected_build_id, sizeof(expected_build_id));
}

/*!\test
 * Very short build IDs are returned correctly.
 */
void test_read_image_version_with_single_character_build_id()
{
    static char config_file_buffer[] = "BUILD_ID=X\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_build_id[] = "X";

    do_test_read_image_version(config_file, 20,
                               expected_build_id, sizeof(expected_build_id));
}

/*!\test
 * The empty build ID is returned correctly.
 */
void test_read_image_version_with_empty_build_id()
{
    static char config_file_buffer[] = "BUILD_ID=\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_build_id[] = "";

    do_test_read_image_version(config_file, 20,
                               expected_build_id, sizeof(expected_build_id));
}

/*!\test
 * No buffer overflow for long build ID vs small buffer.
 */
void test_read_image_version_with_small_buffer()
{
    static char config_file_buffer[] = "BUILD_ID=20150708122013\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_build_id[] = "2015070";

    do_test_read_image_version(config_file, sizeof(expected_build_id),
                               expected_build_id, sizeof(expected_build_id));
}

/*!\test
 * No buffer overflow for long build ID vs single byte buffer.
 */
void test_read_image_version_with_very_small_buffer()
{
    static char config_file_buffer[] = "BUILD_ID=20150708122013\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_build_id[] = "";

    do_test_read_image_version(config_file, sizeof(expected_build_id),
                               expected_build_id, sizeof(expected_build_id));
}

/*!\test
 * No buffer overflow for long build ID vs no buffer.
 */
void test_read_image_version_with_zero_size_buffer()
{
    static char config_file_buffer[] = "BUILD_ID=20150708122013\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    do_test_read_image_version(config_file, 0, NULL, 0);
}

};

/*!@}*/
