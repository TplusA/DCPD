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
#include <array>

#include "registers.hh"
#include "networkprefs.h"
#include "dcpregs_searchparameters.hh"
#include "mainloop.hh"

#include "mock_messages.hh"
#include "mock_dcpd_dbus.hh"
#include "mock_dbus_iface.hh"

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

#if !LOGGED_LOCKS_ENABLED

namespace spi_registers_search
{

static tdbusdcpdViews *const dbus_dcpd_views_iface_dummy =
    reinterpret_cast<tdbusdcpdViews *>(0x87654321);

static MockMessages *mock_messages;
static MockDcpdDBus *mock_dcpd_dbus;
static MockDBusIface *mock_dbus_iface;

void cut_setup()
{
    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_dcpd_dbus = new MockDcpdDBus();
    cppcut_assert_not_null(mock_dcpd_dbus);
    mock_dcpd_dbus->init();
    mock_dcpd_dbus_singleton = mock_dcpd_dbus;

    mock_dbus_iface = new MockDBusIface;
    cppcut_assert_not_null(mock_dbus_iface);
    mock_dbus_iface->init();
    mock_dbus_iface_singleton = mock_dbus_iface;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    network_prefs_init(nullptr, nullptr);
    Regs::init(nullptr, nullptr);
}

void cut_teardown()
{
    Regs::deinit();
    network_prefs_deinit();

    mock_messages->check();
    mock_dcpd_dbus->check();
    mock_dbus_iface->check();

    mock_messages_singleton = nullptr;
    mock_dcpd_dbus_singleton = nullptr;
    mock_dbus_iface_singleton = nullptr;

    delete mock_messages;
    delete mock_dcpd_dbus;
    delete mock_dbus_iface;

    mock_messages = nullptr;
    mock_dcpd_dbus = nullptr;
    mock_dbus_iface = nullptr;
}

/*!\test
 */
void test_start_search_in_default_context()
{
    auto *reg = lookup_register_expect_handlers(74,
                                                Regs::SearchParams::DCP::write_74_search_parameters);

    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_search_parameters(
            dbus_dcpd_views_iface_dummy, "default", nullptr);

    static const char query[] = "default";

    reg->write(reinterpret_cast<const uint8_t *>(query), sizeof(query));
}

/*!\test
 */
void test_search_single_string_in_default_context()
{
    static const char *key_value_table[] =
    {
        "text0", "Some search string",
        nullptr,
    };

    auto *reg = lookup_register_expect_handlers(74,
                                                Regs::SearchParams::DCP::write_74_search_parameters);

    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_search_parameters(
            dbus_dcpd_views_iface_dummy, "default", key_value_table);

    static const char query[] = "default\0text0=Some search string";

    reg->write(reinterpret_cast<const uint8_t *>(query), sizeof(query));
}

/*!\test
 */
void test_search_with_multiple_parameters_in_usb_context()
{
    static const char *key_value_table[] =
    {
        "text0",   "First string",
        "text3",   "Second string",
        "select0", "2",
        "text4",   "Third string",
        "select2", "yes",
        nullptr,
    };

    auto *reg = lookup_register_expect_handlers(74,
                                                Regs::SearchParams::DCP::write_74_search_parameters);

    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_search_parameters(
            dbus_dcpd_views_iface_dummy, "usb", key_value_table);

    static const char query[] =
        "usb\0"
        "text0=First string\0"
        "text3=Second string\0"
        "select0=2\0"
        "text4=Third string\0"
        "select2=yes";

    reg->write(reinterpret_cast<const uint8_t *>(query), sizeof(query));
}

/*!\test
 */
void test_search_parameter_value_must_not_be_empty()
{
    auto *reg = lookup_register_expect_handlers(74,
                                                Regs::SearchParams::DCP::write_74_search_parameters);

    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "Missing value in query");

    static const char query[] = "default\0text0=";

    write_buffer_expect_failure(reg, reinterpret_cast<const uint8_t *>(query), sizeof(query), -1);
}

/*!\test
 */
void test_search_parameter_variable_must_not_be_empty()
{
    auto *reg = lookup_register_expect_handlers(74,
                                                Regs::SearchParams::DCP::write_74_search_parameters);

    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "Missing ID in query");

    static const char query[] = "default\0=Some search string";

    write_buffer_expect_failure(reg, reinterpret_cast<const uint8_t *>(query), sizeof(query), -1);
}

/*!\test
 */
void test_context_must_not_be_empty()
{
    auto *reg = lookup_register_expect_handlers(74,
                                                Regs::SearchParams::DCP::write_74_search_parameters);

    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "No search context defined");

    static const char query[] = "\0text0=Some search string";

    write_buffer_expect_failure(reg, reinterpret_cast<const uint8_t *>(query), sizeof(query), -1);
}

/*!\test
 */
void test_context_must_not_contain_equals_character()
{
    auto *reg = lookup_register_expect_handlers(74,
                                                Regs::SearchParams::DCP::write_74_search_parameters);

    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "Invalid characters in search context");

    static const char query[] = "default=yes\0text0=Some search string";

    write_buffer_expect_failure(reg, reinterpret_cast<const uint8_t *>(query), sizeof(query), -1);
}

/*!\test
 */
void test_search_parameter_specification_must_contain_equals_character()
{
    auto *reg = lookup_register_expect_handlers(74,
                                                Regs::SearchParams::DCP::write_74_search_parameters);

    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "Missing assignment in query");

    static const char query[] = "default\0text0 Some search string";

    write_buffer_expect_failure(reg, reinterpret_cast<const uint8_t *>(query), sizeof(query), -1);
}

/*!\test
 */
void test_search_parameter_specification_must_not_be_empty()
{
    auto *reg = lookup_register_expect_handlers(74,
                                                Regs::SearchParams::DCP::write_74_search_parameters);

    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "Empty query");

    static const char query[] = "default\0";

    write_buffer_expect_failure(reg, reinterpret_cast<const uint8_t *>(query), sizeof(query), -1);
}

/*!\test
 */
void test_embedded_search_parameter_specification_must_not_be_empty()
{
    auto *reg = lookup_register_expect_handlers(74,
                                                Regs::SearchParams::DCP::write_74_search_parameters);

    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "Empty query");

    static const char query[] = "default\0text0=My Query\0";

    write_buffer_expect_failure(reg, reinterpret_cast<const uint8_t *>(query), sizeof(query), -1);
}

}

#endif /* !LOGGED_LOCKS_ENABLED  */

/*!@}*/
