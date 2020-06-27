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

#include "registers.hh"
#include "dcpregs_drcp.hh"
#include "drcp_command_codes.h"
#include "mainloop.hh"

#include "mock_messages.hh"
#include "mock_os.hh"
#include "mock_dcpd_dbus.hh"
#include "mock_logind_manager_dbus.hh"
#include "mock_audiopath_dbus.hh"
#include "mock_dbus_iface.hh"

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

#if !LOGGED_LOCKS_ENABLED

namespace spi_registers_tests_drcp
{

static MockMessages *mock_messages;
static MockOs *mock_os;
static MockDcpdDBus *mock_dcpd_dbus;
static MockLogindManagerDBus *mock_logind_manager_dbus;
static MockAudiopathDBus *mock_audiopath_dbus;
static MockDBusIface *mock_dbus_iface;

static tdbusdcpdPlayback *const dbus_dcpd_playback_iface_dummy =
    reinterpret_cast<tdbusdcpdPlayback *>(0x12345678);

static tdbusdcpdViews *const dbus_dcpd_views_iface_dummy =
    reinterpret_cast<tdbusdcpdViews *>(0x87654321);

static tdbusdcpdListNavigation *const dbus_dcpd_list_navigation_iface_dummy =
    reinterpret_cast<tdbusdcpdListNavigation *>(0x24681357);

static tdbusdcpdListItem *const dbus_dcpd_list_item_iface_dummy =
    reinterpret_cast<tdbusdcpdListItem *>(0x75318642);

static tdbuslogindManager *const dbus_logind_manager_iface_dummy =
    reinterpret_cast<tdbuslogindManager *>(0x35127956);

static tdbusaupathManager *const dbus_audiopath_manager_iface_dummy =
    reinterpret_cast<tdbusaupathManager *>(0xc0a68060);

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

    mock_dcpd_dbus = new MockDcpdDBus();
    cppcut_assert_not_null(mock_dcpd_dbus);
    mock_dcpd_dbus->init();
    mock_dcpd_dbus_singleton = mock_dcpd_dbus;

    mock_logind_manager_dbus = new MockLogindManagerDBus();
    cppcut_assert_not_null(mock_logind_manager_dbus);
    mock_logind_manager_dbus->init();
    mock_logind_manager_dbus_singleton = mock_logind_manager_dbus;

    mock_audiopath_dbus = new MockAudiopathDBus();
    cppcut_assert_not_null(mock_audiopath_dbus);
    mock_audiopath_dbus->init();
    mock_audiopath_dbus_singleton = mock_audiopath_dbus;

    mock_dbus_iface = new MockDBusIface;
    cppcut_assert_not_null(mock_dbus_iface);
    mock_dbus_iface->init();
    mock_dbus_iface_singleton = mock_dbus_iface;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);
}

void cut_teardown()
{
    mock_messages->check();
    mock_os->check();
    mock_dcpd_dbus->check();
    mock_logind_manager_dbus->check();
    mock_audiopath_dbus->check();
    mock_dbus_iface->check();

    mock_messages_singleton = nullptr;
    mock_os_singleton = nullptr;
    mock_dcpd_dbus_singleton = nullptr;
    mock_logind_manager_dbus_singleton = nullptr;
    mock_audiopath_dbus_singleton = nullptr;
    mock_dbus_iface_singleton = nullptr;

    delete mock_messages;
    delete mock_os;
    delete mock_dcpd_dbus;
    delete mock_logind_manager_dbus;
    delete mock_audiopath_dbus;
    delete mock_dbus_iface;

    mock_messages = nullptr;
    mock_os = nullptr;
    mock_dcpd_dbus = nullptr;
    mock_logind_manager_dbus = nullptr;
    mock_audiopath_dbus = nullptr;
    mock_dbus_iface = nullptr;
}

/*!\test
 * Check that writes to register 72 (DRC command) are indeed wired to calls of
 * Regs::DRCP::DCP::write_drcp_command(), and that reading from register 72 is
 * not possible.
 */
void test_dcp_register_72_calls_correct_write_handler()
{
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    Regs::init(nullptr, nullptr);

    const auto *reg = Regs::lookup(72);

    cppcut_assert_not_null(reg);
    cppcut_assert_equal(72U, unsigned(reg->address_));
    cut_assert(reg->has_handler(Regs::DRCP::DCP::write_drcp_command));
    cut_assert(reg->has_handler(static_cast<ssize_t (*)(uint8_t *, size_t)>(nullptr)));

    Regs::deinit();
}

/*!\test
 * Slave sends some unsupported DRC command over DCP.
 */
void test_slave_drc_invalid_command()
{
    static const uint8_t buffer[] = { 0xbe };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0xbe");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Received unsupported DRC command 0xbe (Invalid argument)");
    cppcut_assert_equal(-1, Regs::DRCP::DCP::write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for starting playback.
 */
void test_slave_drc_playback_start()
{
    static const uint8_t buffer[] = { DRCP_PLAYBACK_START };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0xb3");
    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_start(dbus_dcpd_playback_iface_dummy);
    cppcut_assert_equal(0, Regs::DRCP::DCP::write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for opening the view with binary ID 0.
 */
void test_slave_drc_views_goto_view_by_id_0()
{
    static const uint8_t buffer[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x00, DRCP_ACCEPT };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x9a");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_open(dbus_dcpd_views_iface_dummy, "UPnP");
    cppcut_assert_equal(0, Regs::DRCP::DCP::write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for opening the view with binary ID 1.
 */
void test_slave_drc_views_goto_view_by_id_1()
{
    static const uint8_t buffer[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x01, DRCP_ACCEPT };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x9a");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_open(dbus_dcpd_views_iface_dummy, "TuneIn");
    cppcut_assert_equal(0, Regs::DRCP::DCP::write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for opening the view with binary ID 2.
 */
void test_slave_drc_views_goto_view_by_id_2()
{
    static const uint8_t buffer[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x02, DRCP_ACCEPT };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x9a");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_open(dbus_dcpd_views_iface_dummy, "Filesystem");
    cppcut_assert_equal(0, Regs::DRCP::DCP::write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for opening a view with unknown binary ID.
 */
void test_slave_drc_views_goto_view_by_id_unknown_id()
{
    static const uint8_t buffer_lowest_unknown[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x03, DRCP_ACCEPT };
    static const uint8_t buffer_highest_unknown[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, UINT8_MAX, DRCP_ACCEPT };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x9a");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_NOTICE, "Unknown view ID 0x03 (Invalid argument)");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0x9a failed: -1");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    cppcut_assert_equal(-1, Regs::DRCP::DCP::write_drcp_command(buffer_lowest_unknown, sizeof(buffer_lowest_unknown)));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x9a");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_NOTICE, "Unknown view ID 0xff (Invalid argument)");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0x9a failed: -1");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    cppcut_assert_equal(-1, Regs::DRCP::DCP::write_drcp_command(buffer_highest_unknown, sizeof(buffer_highest_unknown)));
}

/*!\test
 * Slave sends malformed DRC command for opening a view by ID.
 */
void test_slave_drc_views_goto_view_by_id_must_be_terminated_with_accept_code()
{
    static const uint8_t buffer[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x00, DRCP_ACCEPT - 1U };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x9a");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0x9a failed: -1");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    cppcut_assert_equal(-1, Regs::DRCP::DCP::write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends too short DRC command for opening view by ID.
 */
void test_slave_drc_views_goto_view_by_id_with_too_few_data_bytes()
{
    static const uint8_t buffer[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x00 };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x9a");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_NOTICE, "Unexpected data length 1, expected 2 (Invalid argument)");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0x9a failed: -1");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    cppcut_assert_equal(-1, Regs::DRCP::DCP::write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends too long DRC command for opening view by ID.
 */
void test_slave_drc_views_goto_view_by_id_with_too_many_data_bytes()
{
    static const uint8_t buffer[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x00, DRCP_ACCEPT, 0x00 };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x9a");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_NOTICE, "Unexpected data length 3, expected 2 (Invalid argument)");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0x9a failed: -1");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    cppcut_assert_equal(-1, Regs::DRCP::DCP::write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for opening the internet radio view.
 */
void test_slave_drc_views_goto_internet_radio()
{
    static const uint8_t buffer[] = { DRCP_GOTO_INTERNET_RADIO, 0x00 };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0xaa");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_open(dbus_dcpd_views_iface_dummy, "Internet Radio");
    cppcut_assert_equal(0, Regs::DRCP::DCP::write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for toggling between browsing and playing views.
 */
void test_slave_drc_views_toggle_browse_and_play()
{
    static const uint8_t buffer[] = { DRCP_BROWSE_PLAY_VIEW_TOGGLE, 0x00 };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0xba");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_toggle(dbus_dcpd_views_iface_dummy, "Browse", "Play");
    cppcut_assert_equal(0, Regs::DRCP::DCP::write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for moving the cursor one line up.
 */
void test_slave_drc_list_navigation_scroll_one_line_up()
{
    static const uint8_t buffer[] = { DRCP_SCROLL_UP_ONE, 0x00 };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x26");
    mock_dbus_iface->expect_dbus_get_list_navigation_iface(dbus_dcpd_list_navigation_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_list_navigation_emit_move_lines(dbus_dcpd_list_navigation_iface_dummy, -1);
    cppcut_assert_equal(0, Regs::DRCP::DCP::write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for moving the cursor one page down.
 */
void test_slave_drc_list_navigation_scroll_one_page_down()
{
    static const uint8_t buffer[] = { DRCP_SCROLL_PAGE_DOWN, 0x00 };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x98");
    mock_dbus_iface->expect_dbus_get_list_navigation_iface(dbus_dcpd_list_navigation_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_list_navigation_emit_move_pages(dbus_dcpd_list_navigation_iface_dummy, 1);
    cppcut_assert_equal(0, Regs::DRCP::DCP::write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for moving the cursor 10 lines up.
 */
void test_slave_drc_list_navigation_scroll_10_lines_up()
{
    static const uint8_t buffer[] = { DRCP_SCROLL_UP_MANY, 0x0a, DRCP_ACCEPT, };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x21");
    mock_dbus_iface->expect_dbus_get_list_navigation_iface(dbus_dcpd_list_navigation_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_list_navigation_emit_move_lines(dbus_dcpd_list_navigation_iface_dummy, -10);
    cppcut_assert_equal(0, Regs::DRCP::DCP::write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for moving the cursor 8 lines down.
 */
void test_slave_drc_list_navigation_scroll_8_lines_down()
{
    static const uint8_t buffer[] = { DRCP_SCROLL_DOWN_MANY, 0x08, DRCP_ACCEPT, };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x22");
    mock_dbus_iface->expect_dbus_get_list_navigation_iface(dbus_dcpd_list_navigation_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_list_navigation_emit_move_lines(dbus_dcpd_list_navigation_iface_dummy, 8);
    cppcut_assert_equal(0, Regs::DRCP::DCP::write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Fast scrolling by zero lines has no effect whatsoever.
 */
void test_slave_drc_list_navigation_scroll_fast_by_0_lines_is_ignored()
{
    static const uint8_t buffer_up[]   = { DRCP_SCROLL_UP_MANY,   0x00, DRCP_ACCEPT, };
    static const uint8_t buffer_down[] = { DRCP_SCROLL_DOWN_MANY, 0x00, DRCP_ACCEPT, };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x21");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0x21 failed: -1");
    cppcut_assert_equal(-1, Regs::DRCP::DCP::write_drcp_command(buffer_up, sizeof(buffer_up)));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x22");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0x22 failed: -1");
    cppcut_assert_equal(-1, Regs::DRCP::DCP::write_drcp_command(buffer_down, sizeof(buffer_down)));
}

/*!\test
 * Slave sends DRC command for adding the currently selected item to the
 * favorites list.
 */
void test_slave_drc_list_item_add_to_favorites()
{
    static const uint8_t buffer[] = { DRCP_FAVORITES_ADD_ITEM, 0x00 };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x2d");
    mock_dbus_iface->expect_dbus_get_list_item_iface(dbus_dcpd_list_item_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_list_item_emit_add_to_list(dbus_dcpd_list_item_iface_dummy, "Favorites", 0);
    cppcut_assert_equal(0, Regs::DRCP::DCP::write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for power off.
 */
void test_slave_drc_power_off()
{
    static const uint8_t buffer[] = { DRCP_POWER_OFF, 0x00 };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x03");
    mock_dbus_iface->expect_dbus_get_logind_manager_iface(dbus_logind_manager_iface_dummy);
    mock_logind_manager_dbus->expect_tdbus_logind_manager_call_power_off_sync(true, dbus_logind_manager_iface_dummy, false);
    cppcut_assert_equal(0, Regs::DRCP::DCP::write_drcp_command(buffer, sizeof(buffer)));
}

}

#endif /* !LOGGED_LOCKS_ENABLED  */

/*!@}*/
