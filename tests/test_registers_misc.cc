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
#include "networkprefs.h"
#include "dcpregs_status.hh"
#include "dcpregs_stream_speed.hh"
#include "mainloop.hh"

#include "mock_messages.hh"
#include "mock_os.hh"
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

namespace spi_registers_misc
{

static MockMessages *mock_messages;
static MockOs *mock_os;
static MockDcpdDBus *mock_dcpd_dbus;
static MockDBusIface *mock_dbus_iface;

static tdbusdcpdPlayback *const dbus_dcpd_playback_iface_dummy =
    reinterpret_cast<tdbusdcpdPlayback *>(0x12345678);

static constexpr char expected_os_release_filename[] = "/etc/os-release";
static constexpr char expected_strbo_release_filename[] = "/etc/strbo-release";

static constexpr int expected_os_map_file_to_memory_fd = 5;

static RegisterChangedData *register_changed_data;

static void register_changed_callback(uint8_t reg_number)
{
    register_changed_data->append(reg_number);
}

void cut_setup()
{
    register_changed_data = new RegisterChangedData;

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

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    register_changed_data->init();

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    network_prefs_init(nullptr, nullptr);
    Regs::init(register_changed_callback, nullptr);
}

void cut_teardown()
{
    Regs::deinit();
    network_prefs_deinit();

    register_changed_data->check();

    delete register_changed_data;
    register_changed_data = nullptr;

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
 * Register 37 cannot be written to.
 */
void test_dcp_register_37_has_no_write_handler()
{
    const auto *reg = Regs::lookup(37);

    cppcut_assert_not_null(reg);
    cppcut_assert_equal(37U, unsigned(reg->address_));
    cut_assert_false(reg->has_handler(static_cast<ssize_t (*)(uint8_t *, size_t)>(nullptr)));
    cut_assert_true(reg->has_handler(static_cast<int (*)(const uint8_t *, size_t)>(nullptr)));
}

static void do_test_read_image_version(const os_mapped_file_data &config_file,
                                       bool have_strbo_config_file,
                                       size_t dest_buffer_size,
                                       const char *expected_version_id,
                                       size_t expected_version_id_size,
                                       const char *expected_warning = nullptr)
{
    char expected_version_id_memory[dest_buffer_size];
    memset(expected_version_id_memory, 0, dest_buffer_size);

    if(expected_version_id_size > 1)
        memcpy(expected_version_id_memory, expected_version_id, expected_version_id_size - 1);

    uint8_t redzone_content[10];
    memset(redzone_content, 0xff, sizeof(redzone_content));

    uint8_t buffer[sizeof(redzone_content) + dest_buffer_size + sizeof(redzone_content)];
    memset(buffer, 0xff, sizeof(buffer));

    auto *reg = Regs::lookup(37);

    if(have_strbo_config_file)
        mock_os->expect_os_map_file_to_memory(0, 0, &config_file, expected_strbo_release_filename);
    else
    {
        mock_os->expect_os_map_file_to_memory(-1, ENOENT, &config_file, expected_strbo_release_filename);
        mock_os->expect_os_map_file_to_memory(0, 0, &config_file, expected_os_release_filename);
    }

    mock_os->expect_os_unmap_file(0, &config_file);

    if(expected_warning != nullptr)
        mock_messages->expect_msg_error_formatted(0, LOG_NOTICE, expected_warning);

    cppcut_assert_equal(expected_version_id_size,
                        reg->read(buffer + sizeof(redzone_content),
                                  sizeof(buffer) - 2 * sizeof(redzone_content)));

    cut_assert_equal_memory(redzone_content, sizeof(redzone_content), buffer,
                            sizeof(redzone_content));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + sizeof(redzone_content) + dest_buffer_size,
                            sizeof(redzone_content));
    cut_assert_equal_memory(expected_version_id_memory, dest_buffer_size,
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
        "VERSION=V1.0.0\n"
        "VERSION_ID=V1.0.0\n"
        "PRETTY_NAME=StrBo (T+A Streaming Board) 1.0.0\n"
        "BUILD_ID=20150708122013\n"
        "BUILD_GIT_COMMIT=05f6dcd31134a3d2e9f5d0c8b78a4bab1948a4d5\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_version_id[] = "V1.0.0";

    do_test_read_image_version(config_file, false, 20,
                               expected_version_id, sizeof(expected_version_id));
}

/*!\test
 * Realistic test with real-life configuration data, new style.
 */
void test_read_image_version_from_strbo_release()
{
    static char config_file_buffer[] =
        "STRBO_RELEASE_LINE=\"V2\"\n"
        "STRBO_FLAVOR=\"stable\"\n"
        "STRBO_VERSION=\"V2.4.3\"\n"
        "STRBO_DATETIME=\"20200529120216\"\n"
        "STRBO_GIT_COMMIT=\"149d8fbc1ca4186d30b75b2e8127b4307f48d41d\"\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_version_id[] = "V2.4.3";

    do_test_read_image_version(config_file, true, 20,
                               expected_version_id, sizeof(expected_version_id));
}

/*!\test
 * Version ID can be read if it appears in the first line of the config file.
 */
void test_read_image_version_with_version_id_in_first_line()
{
    static char config_file_buffer[] =
        "VERSION_ID=V1.0.0\n"
        "VERSION=abc\n"
        "BUILD_GIT_COMMIT=05f6dcd31134a3d2e9f5d0c8b78a4bab1948a4d5\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_version_id[] = "V1.0.0";

    do_test_read_image_version(config_file, false, 20,
                               expected_version_id, sizeof(expected_version_id));
}

/*!\test
 * Version ID can be read if it appears in the last line of the config file.
 */
void test_read_image_version_with_version_id_in_last_line()
{
    static char config_file_buffer[] =
        "BUILD_GIT_COMMIT=05f6dcd31134a3d2e9f5d0c8b78a4bab1948a4d5\n"
        "VERSION=abc\n"
        "VERSION_ID=V1.0.0\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_version_id[] = "V1.0.0";

    do_test_read_image_version(config_file, false, 20,
                               expected_version_id, sizeof(expected_version_id));
}

/*!\test
 * Version ID can be read if it appears in the last line of the config file, even
 * if not terminated with a newline character.
 */
void test_read_image_version_with_version_id_in_last_line_without_newline()
{
    static char config_file_buffer[] =
        "BUILD_GIT_COMMIT=05f6dcd31134a3d2e9f5d0c8b78a4bab1948a4d5\n"
        "VERSION_ID=V1.0.0";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_version_id[] = "V1.0.0";

    do_test_read_image_version(config_file, false, 20,
                               expected_version_id, sizeof(expected_version_id));
}

/*!\test
 * Very short version IDs are returned correctly.
 */
void test_read_image_version_with_single_character_version_id()
{
    static char config_file_buffer[] = "VERSION_ID=X\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_version_id[] = "X";

    do_test_read_image_version(config_file, false, 20,
                               expected_version_id, sizeof(expected_version_id));
}

/*!\test
 * The empty version ID is returned correctly.
 */
void test_read_image_version_with_empty_version_id()
{
    static char config_file_buffer[] = "VERSION_ID=\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_version_id[] = "";

    do_test_read_image_version(config_file, false, 20,
                               expected_version_id, sizeof(expected_version_id));
}

/*!\test
 * No buffer overflow for long version ID vs small buffer.
 */
void test_read_image_version_with_small_buffer()
{
    static char config_file_buffer[] = "VERSION_ID=beta-20.82.10524\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_version_id[] = "beta-20.8";

    do_test_read_image_version(config_file, false, sizeof(expected_version_id),
                               expected_version_id, sizeof(expected_version_id),
                               "Truncating version ID of length 16 to 9 characters");
}

/*!\test
 * No buffer overflow for long version ID vs single byte buffer.
 */
void test_read_image_version_with_very_small_buffer()
{
    static char config_file_buffer[] = "VERSION_ID=20150708122013\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_version_id[] = "";

    do_test_read_image_version(config_file, false, sizeof(expected_version_id),
                               expected_version_id, sizeof(expected_version_id),
                               "Truncating version ID of length 14 to 0 characters");
}

/*!\test
 * No buffer overflow for long version ID vs no buffer.
 */
void test_read_image_version_with_zero_size_buffer()
{
    static char config_file_buffer[] = "VERSION_ID=20150708122013\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    do_test_read_image_version(config_file, false, 0, nullptr, 0,
                               "Cannot copy version ID to zero length buffer");
}

/*!\test
 * Status byte is invalid without explicit internal ready notification.
 */
void test_status_byte_without_ready_notification_is_all_zero()
{
    auto *reg = Regs::lookup(17);
    uint8_t buffer[2];
    cppcut_assert_equal(sizeof(buffer), reg->read(buffer, sizeof(buffer)));

    static constexpr uint8_t expected_answer[2] = { 0x00, 0x00 };
    cut_assert_equal_memory(expected_answer, sizeof(expected_answer),
                            buffer, sizeof(buffer));
}

/*!\test
 * Status byte OK after explicit internal ready notification.
 */
void test_status_byte_after_ready_notification()
{
    Regs::StrBoStatus::set_ready();

    auto *reg = Regs::lookup(17);
    uint8_t buffer[2];
    cppcut_assert_equal(sizeof(buffer), reg->read(buffer, sizeof(buffer)));

    static constexpr uint8_t expected_answer[2] = { 0x21, 0x00 };
    cut_assert_equal_memory(expected_answer, sizeof(expected_answer),
                            buffer, sizeof(buffer));

    static constexpr std::array<uint8_t, 2> expected_registers = { 17, 50 };
    register_changed_data->check(expected_registers);
}

/*!\test
 * Status byte indicates power off state after explicit internal shutdown
 * notification.
 */
void test_status_byte_after_shutdown_notification()
{
    Regs::StrBoStatus::set_ready_to_shutdown();

    auto *reg = Regs::lookup(17);
    uint8_t buffer[2];
    cppcut_assert_equal(sizeof(buffer), reg->read(buffer, sizeof(buffer)));

    static constexpr uint8_t expected_answer[2] = { 0x21, 0x01 };
    cut_assert_equal_memory(expected_answer, sizeof(expected_answer),
                            buffer, sizeof(buffer));

    register_changed_data->check(17);
}

/*!\test
 * Status byte indicates system error state after corresponding explicit
 * internal notification.
 */
void test_status_byte_after_reboot_required_notification()
{
    Regs::StrBoStatus::set_reboot_required();

    auto *reg = Regs::lookup(17);
    uint8_t buffer[2];
    cppcut_assert_equal(sizeof(buffer), reg->read(buffer, sizeof(buffer)));

    static constexpr uint8_t expected_answer[2] = { 0x24, 0x00 };
    cut_assert_equal_memory(expected_answer, sizeof(expected_answer),
                            buffer, sizeof(buffer));

    register_changed_data->check(17);
}

/*!\test
 * Status byte changes are only pushed to the SPI slave if the corresponding
 * bytes have changed.
 */
void test_status_byte_updates_are_only_sent_if_changed()
{
    Regs::StrBoStatus::set_ready();
    static constexpr std::array<uint8_t, 2> expected_regs_for_ready = { 17, 50 };
    register_changed_data->check(expected_regs_for_ready);

    Regs::StrBoStatus::set_ready();
    register_changed_data->check();

    Regs::StrBoStatus::set_ready_to_shutdown();
    register_changed_data->check(17);

    Regs::StrBoStatus::set_ready_to_shutdown();
    register_changed_data->check();

    Regs::StrBoStatus::set_reboot_required();
    register_changed_data->check(17);

    Regs::StrBoStatus::set_reboot_required();
    register_changed_data->check();
}

static void set_speed_factor_successful_cases(uint8_t subcommand)
{
    const auto *reg =
        lookup_register_expect_handlers(73, Regs::PlayStream::DCP::write_73_seek_or_set_speed);
    const double sign_mul = (subcommand == 0xc1) ? 1.0 : -1.0;

    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_set_speed(dbus_dcpd_playback_iface_dummy,
                                                              sign_mul * 4.0);

    const uint8_t buffer_fraction_lower_boundary[] = { subcommand, 0x04, 0x00, };
    reg->write(buffer_fraction_lower_boundary, sizeof(buffer_fraction_lower_boundary));

    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_set_speed(dbus_dcpd_playback_iface_dummy,
                                                              sign_mul * 4.18);

    const uint8_t buffer_generic[] = { subcommand, 0x04, 0x12, };
    reg->write(buffer_generic, sizeof(buffer_generic));

    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_set_speed(dbus_dcpd_playback_iface_dummy,
                                                              sign_mul * 4.99);

    const uint8_t buffer_fraction_upper_boundary[] = { subcommand, 0x04, 0x63, };
    reg->write(buffer_fraction_upper_boundary, sizeof(buffer_fraction_upper_boundary));

    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_set_speed(dbus_dcpd_playback_iface_dummy,
                                                              sign_mul * 0.01);

    const uint8_t buffer_absolute_minimum[] = { subcommand, 0x00, 0x01, };
    reg->write(buffer_absolute_minimum, sizeof(buffer_absolute_minimum));

    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_set_speed(dbus_dcpd_playback_iface_dummy,
                                                              sign_mul * 255.99);

    const uint8_t buffer_absolute_maximum[] = { subcommand, 0xff, 0x63, };
    reg->write(buffer_absolute_maximum, sizeof(buffer_absolute_maximum));
}

static void set_speed_factor_wrong_command_format(uint8_t subcommand)
{
    const auto *reg =
        lookup_register_expect_handlers(73, Regs::PlayStream::DCP::write_73_seek_or_set_speed);

    /* too long */
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Speed factor length must be 2 (Invalid argument)");

    const uint8_t buffer_too_long[] = { subcommand, 0x04, 0x00, 0x00 };
    write_buffer_expect_failure(reg, buffer_too_long, sizeof(buffer_too_long), -1);

    mock_messages->check();

    /* too short */
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Speed factor length must be 2 (Invalid argument)");

    const uint8_t buffer_too_short[] = { subcommand, 0x04 };
    write_buffer_expect_failure(reg, buffer_too_short, sizeof(buffer_too_short), -1);
}

static void set_speed_factor_invalid_factor(uint8_t subcommand)
{
    const auto *reg =
        lookup_register_expect_handlers(73, Regs::PlayStream::DCP::write_73_seek_or_set_speed);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Speed factor invalid fraction part (Invalid argument)");

    const uint8_t buffer_first_invalid[] = { subcommand, 0x04, 0x64, };
    write_buffer_expect_failure(reg, buffer_first_invalid, sizeof(buffer_first_invalid), -1);

    mock_messages->check();

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Speed factor invalid fraction part (Invalid argument)");

    const uint8_t buffer_last_invalid[] = { subcommand, 0x04, 0xff, };
    write_buffer_expect_failure(reg, buffer_last_invalid, sizeof(buffer_last_invalid), -1);
}

static void set_speed_factor_zero(uint8_t subcommand)
{
    const auto *reg =
        lookup_register_expect_handlers(73, Regs::PlayStream::DCP::write_73_seek_or_set_speed);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Speed factor too small (Invalid argument)");

    const uint8_t buffer[] = { subcommand, 0x00, 0x00, };
    write_buffer_expect_failure(reg, buffer, sizeof(buffer), -1);
}

/*!\test
 * Slave sends command for fast forward.
 */
void test_playback_set_speed_forward()
{
    set_speed_factor_successful_cases(0xc1);
}

/*!\test
 * Slave sends fast forward command with wrong command length.
 */
void test_playback_set_speed_forward_command_has_2_bytes_of_data()
{
    set_speed_factor_wrong_command_format(0xc1);
}

/*!\test
 * Slave sends fast forward command with invalid factor.
 */
void test_playback_set_speed_forward_fraction_part_is_two_digits_decimal()
{
    set_speed_factor_invalid_factor(0xc1);
}

/*!\test
 * Slave sends fast forward command with factor 0.
 */
void test_playback_set_speed_forward_zero_factor_is_invalid()
{
    set_speed_factor_zero(0xc1);
}

/*!\test
 * Slave sends command for fast reverse.
 */
void test_playback_set_speed_reverse()
{
    set_speed_factor_successful_cases(0xc2);
}

/*!\test
 * Slave sends fast reverse command with wrong command length.
 */
void test_playback_set_speed_reverse_command_has_2_bytes_of_data()
{
    set_speed_factor_wrong_command_format(0xc2);
}

/*!\test
 * Slave sends fast reverse command with invalid factor.
 */
void test_playback_set_speed_reverse_fraction_part_is_two_digits_decimal()
{
    set_speed_factor_invalid_factor(0xc2);
}

/*!\test
 * Slave sends fast reverse command with factor 0.
 */
void test_playback_set_speed_reverse_zero_factor_is_invalid()
{
    set_speed_factor_zero(0xc2);
}

/*!\test
 * Reverting to regular speed is done via own subcommand.
 */
void test_playback_regular_speed()
{
    const auto *reg =
        lookup_register_expect_handlers(73, Regs::PlayStream::DCP::write_73_seek_or_set_speed);

    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_set_speed(dbus_dcpd_playback_iface_dummy, 0.0);

    static const uint8_t buffer[] = { 0xc3 };
    reg->write(buffer, sizeof(buffer));
}

/*!\test
 * Stream seek position is given in milliseconds as 32 bit little-endian value.
 */
void test_playback_stream_seek()
{
    const auto *reg =
        lookup_register_expect_handlers(73, Regs::PlayStream::DCP::write_73_seek_or_set_speed);

    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_seek(dbus_dcpd_playback_iface_dummy,
                                                         264781241, "ms");

    static const uint8_t buffer[] = { 0xc4, 0xb9, 0x3d, 0xc8, 0x0f };
    reg->write(buffer, sizeof(buffer));
}

/*!\test
 * Stream seek position can be any 32 bit unsigned integer value.
 */
void test_playback_stream_seek_boundaries()
{
    const auto *reg =
        lookup_register_expect_handlers(73, Regs::PlayStream::DCP::write_73_seek_or_set_speed);

    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_seek(dbus_dcpd_playback_iface_dummy,
                                                         0, "ms");

    static const uint8_t buffer_min[] = { 0xc4, 0x00, 0x00, 0x00, 0x00 };
    reg->write(buffer_min, sizeof(buffer_min));

    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_seek(dbus_dcpd_playback_iface_dummy,
                                                         UINT32_MAX, "ms");

    static const uint8_t buffer_max[] = { 0xc4, 0xff, 0xff, 0xff, 0xff };
    reg->write(buffer_max, sizeof(buffer_max));
}

}

#endif /* !LOGGED_LOCKS_ENABLED  */

/*!@}*/
