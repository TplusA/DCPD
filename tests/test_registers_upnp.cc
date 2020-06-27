/*
 * Copyright (C) 2015--2020  T+A elektroakustik GmbH & Co. KG
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
#include "dcpregs_upnpname.hh"
#include "connman_service_list.hh"
#include "network_device_list.hh"
#include "networkprefs.h"
#include "mainloop.hh"

#include "mock_messages.hh"
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

#if !LOGGED_LOCKS_ENABLED

namespace spi_registers_upnp
{

static MockMessages *mock_messages;
static MockOs *mock_os;

static std::vector<char> os_write_buffer;
static constexpr int expected_os_write_fd = 85;
static constexpr int expected_os_map_file_to_memory_fd = 67;

static const char expected_rc_path[]     = "/var/local/etc";
static const char expected_rc_filename[] = "/var/local/etc/upnp_settings.rc";

static int write_from_buffer_callback(const void *src, size_t count, int fd)
{
    cppcut_assert_equal(expected_os_write_fd, fd);
    cppcut_assert_not_null(src);
    cppcut_assert_operator(size_t(0), <, count);

    std::copy_n(static_cast<const char *>(src), count,
                std::back_inserter<std::vector<char>>(os_write_buffer));

    return 0;
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

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    Connman::ServiceList::get_singleton_for_update().first.clear();
    Connman::NetworkDeviceList::get_singleton_for_update().first.clear();

    network_prefs_init(nullptr, nullptr);
    Regs::init(nullptr, nullptr);
}

void cut_teardown()
{
    Regs::deinit();
    network_prefs_deinit();

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

void test_read_out_default_friendly_name()
{
    auto *reg = lookup_register_expect_handlers(88,
                                                Regs::UPnPName::DCP::read_88_upnp_friendly_name,
                                                Regs::UPnPName::DCP::write_88_upnp_friendly_name__v1_0_6);
    cppcut_assert_not_null(reg);

    mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, expected_rc_filename);

    uint8_t buffer[64];
    size_t bytes = reg->read(buffer, sizeof(buffer));

    static const char expected_name[] = "T+A Streaming Board";

    cppcut_assert_equal(sizeof(expected_name) - 1, bytes);
    cut_assert_equal_memory(expected_name, sizeof(expected_name) - 1,
                            buffer, bytes);
}

static void write_and_read_name(const char *name,
                                const char *expected_escaped_name,
                                const Regs::Register *reg,
                                bool send_zero_terminator = false,
                                bool expect_meaningful_given_by_user_field = false,
                                size_t sent_name_length = 0,
                                size_t stored_name_length = 0)
{
    cppcut_assert_not_null(reg);

    if(sent_name_length == 0)
        sent_name_length = strlen(name);

    size_t unescaped_name_length = sent_name_length;

    if(send_zero_terminator)
        ++sent_name_length;

    if(stored_name_length == 0)
        stored_name_length = strlen(expected_escaped_name);

    if(send_zero_terminator && !expect_meaningful_given_by_user_field)
    {
        /* this is for pre-v1.0.6 implementations which will store the trailing
         * binary 0 on file */
        ++unescaped_name_length;
        ++stored_name_length;
    }

    mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, expected_rc_filename);
    mock_os->expect_os_file_new(expected_os_write_fd, 0, expected_rc_filename);
    mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, expected_rc_path);
    mock_os->expect_os_system(EXIT_SUCCESS, 0, true, "/bin/systemctl restart flagpole");

    reg->write(reinterpret_cast<const uint8_t *>(name), sent_name_length);

    static const std::string key_fnoverride("FRIENDLY_NAME_OVERRIDE");
    static const std::string key_fngivenbyu("FRIENDLY_NAME_GIVEN_BY_USER");

    std::vector<char> config_file_buffer;

    std::copy(key_fnoverride.begin(), key_fnoverride.end(),
                std::back_inserter(config_file_buffer));
    config_file_buffer.push_back('=');
    config_file_buffer.push_back('\'');
    std::copy(expected_escaped_name, expected_escaped_name + stored_name_length,
                std::back_inserter(config_file_buffer));
    config_file_buffer.push_back('\'');
    config_file_buffer.push_back('\n');

    std::copy(key_fngivenbyu.begin(), key_fngivenbyu.end(),
                std::back_inserter(config_file_buffer));
    config_file_buffer.push_back('=');
    config_file_buffer.push_back('\'');

    static const std::string yes = "yes";
    static const std::string no  = "no";

    if(send_zero_terminator && expect_meaningful_given_by_user_field)
        std::copy(no.begin(),  no.end(),  std::back_inserter(config_file_buffer));
    else
        std::copy(yes.begin(), yes.end(), std::back_inserter(config_file_buffer));

    config_file_buffer.push_back('\'');
    config_file_buffer.push_back('\n');

    cut_assert_equal_memory(config_file_buffer.data(), config_file_buffer.size(),
                            os_write_buffer.data(), os_write_buffer.size());

    /* nice, now let's check if the code can read back what it has just
     * written */
    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer.data(),
        .length = config_file_buffer.size(),
    };

    mock_os->expect_os_map_file_to_memory(0, 0, &config_file, expected_rc_filename);
    mock_os->expect_os_unmap_file(0, &config_file);

    uint8_t buffer[1024];
    size_t bytes = reg->read(buffer, sizeof(buffer));

    cut_assert_equal_memory(name, unescaped_name_length, buffer, bytes);
}

void test_write_and_read_out_simple_friendly_name__v1_0_1()
{
    static const char simple_name[] = "UPnP name in unit test";
    auto *reg = lookup_register_expect_handlers(88, 1, 0, 5,
                                                Regs::UPnPName::DCP::read_88_upnp_friendly_name,
                                                Regs::UPnPName::DCP::write_88_upnp_friendly_name__v1_0_1);

    write_and_read_name(simple_name, simple_name, reg);
}

void test_write_and_read_out_simple_friendly_name_trailing_junk_is_accepted__v1_0_1()
{
    static const char simple_name[] = "UPnP name in unit test\x01\x02\x03";
    auto *reg = lookup_register_expect_handlers(88, 1, 0, 5,
                                                Regs::UPnPName::DCP::read_88_upnp_friendly_name,
                                                Regs::UPnPName::DCP::write_88_upnp_friendly_name__v1_0_1);

    write_and_read_name(simple_name, simple_name, reg);
}

void test_write_and_read_out_simple_friendly_name_does_not_interpret_trailing_zero__v1_0_1()
{
    static const char simple_name[] = "UPnP name in unit test";
    auto *reg = lookup_register_expect_handlers(88, 1, 0, 5,
                                                Regs::UPnPName::DCP::read_88_upnp_friendly_name,
                                                Regs::UPnPName::DCP::write_88_upnp_friendly_name__v1_0_1);

    write_and_read_name(simple_name, simple_name, reg, true);
}

void test_write_and_read_out_simple_friendly_name_trailing_junk_with_embedded_and_trailing_zero_is_accepted__v1_0_1()
{
    static const char simple_name[] = "UPnP name in unit test\0\x01\x02\x03";
    auto *reg = lookup_register_expect_handlers(88, 1, 0, 5,
                                                Regs::UPnPName::DCP::read_88_upnp_friendly_name,
                                                Regs::UPnPName::DCP::write_88_upnp_friendly_name__v1_0_1);

    write_and_read_name(simple_name, simple_name, reg, true, false,
                        sizeof(simple_name) - 1, sizeof(simple_name) - 1);
}

void test_write_and_read_out_simple_friendly_name()
{
    static const char simple_name[] = "UPnP name in unit test";
    auto *reg = lookup_register_expect_handlers(88, 1, 0, 6,
                                                Regs::UPnPName::DCP::read_88_upnp_friendly_name,
                                                Regs::UPnPName::DCP::write_88_upnp_friendly_name__v1_0_6);

    write_and_read_name(simple_name, simple_name, reg, false, true);
}

void test_write_and_read_out_simple_friendly_name_trailing_zero_is_interpreted()
{
    static const char simple_name[] = "UPnP name in unit test";
    auto *reg = lookup_register_expect_handlers(88, 1, 0, 6,
                                                Regs::UPnPName::DCP::read_88_upnp_friendly_name,
                                                Regs::UPnPName::DCP::write_88_upnp_friendly_name__v1_0_6);

    write_and_read_name(simple_name, simple_name, reg, true, true);
}

void test_write_and_read_out_simple_friendly_name_trailing_junk_is_accepted()
{
    static const char simple_name[] = "UPnP name in unit test\x01\x02\x03";
    auto *reg = lookup_register_expect_handlers(88, 1, 0, 6,
                                                Regs::UPnPName::DCP::read_88_upnp_friendly_name,
                                                Regs::UPnPName::DCP::write_88_upnp_friendly_name__v1_0_6);

    write_and_read_name(simple_name, simple_name, reg, false, true);
}

void test_write_and_read_out_simple_friendly_name_trailing_junk_including_zero_is_accepted()
{
    static const char simple_name[] = "UPnP name in unit test\0\x01\x02\x03";
    auto *reg = lookup_register_expect_handlers(88, 1, 0, 6,
                                                Regs::UPnPName::DCP::read_88_upnp_friendly_name,
                                                Regs::UPnPName::DCP::write_88_upnp_friendly_name__v1_0_6);

    write_and_read_name(simple_name, simple_name, reg, false, true,
                        sizeof(simple_name) - 1, sizeof(simple_name) - 1);
}

void test_write_and_read_out_friendly_name_with_special_characters()
{
    static const char evil_name[] = "a'b#c<d>e\"f&g%%h*i(j)k\\l/m.n^o''''p";
    static const char escaped[]   = "a'\\''b#c<d>e\"f&g%%h*i(j)k\\l/m.n^o'\\'''\\'''\\'''\\''p";
    auto *reg = lookup_register_expect_handlers(88, 1, 0, 6,
                                                Regs::UPnPName::DCP::read_88_upnp_friendly_name,
                                                Regs::UPnPName::DCP::write_88_upnp_friendly_name__v1_0_6);

    write_and_read_name(evil_name, escaped, reg, false, true);
}

void test_writing_different_friendly_name_restarts_flagpole_service()
{
    static char config_file_content[] =
        "FRIENDLY_NAME_OVERRIDE='My UPnP Device'\n"
        ;

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_content,
        .length = sizeof(config_file_content) - 1,
    };

    mock_os->expect_os_map_file_to_memory(0, 0, &config_file, expected_rc_filename);
    mock_os->expect_os_unmap_file(0, &config_file);

    mock_os->expect_os_file_new(expected_os_write_fd, 0, expected_rc_filename);
    mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, expected_rc_path);
    mock_os->expect_os_system(EXIT_SUCCESS, 0, true, "/bin/systemctl restart flagpole");

    auto *reg = lookup_register_expect_handlers(88, 1, 0, 5,
                                                Regs::UPnPName::DCP::read_88_upnp_friendly_name,
                                                Regs::UPnPName::DCP::write_88_upnp_friendly_name__v1_0_1);
    cppcut_assert_not_null(reg);

    reg->write(reinterpret_cast<const uint8_t *>("TheDevice"), 9);

    static const char expected_config_file[] =
        "FRIENDLY_NAME_OVERRIDE='TheDevice'\n"
        "FRIENDLY_NAME_GIVEN_BY_USER='yes'\n"
        ;

    cut_assert_equal_memory(expected_config_file, sizeof(expected_config_file) - 1,
                            os_write_buffer.data(), os_write_buffer.size());
}

void test_writing_same_name_does_not_change_files_nor_flagpole_service()
{
    auto *reg = lookup_register_expect_handlers(88, 1, 0, 5,
                                                Regs::UPnPName::DCP::read_88_upnp_friendly_name,
                                                Regs::UPnPName::DCP::write_88_upnp_friendly_name__v1_0_1);
    cppcut_assert_not_null(reg);

    static char config_file_content[] = "FRIENDLY_NAME_OVERRIDE='My UPnP Device'\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_content,
        .length = sizeof(config_file_content) - 1,
    };

    static const char upnp_name[] = "My UPnP Device";

    mock_os->expect_os_map_file_to_memory(0, 0, &config_file, expected_rc_filename);
    mock_os->expect_os_unmap_file(0, &config_file);
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DEBUG, "UPnP name unchanged");

    reg->write(reinterpret_cast<const uint8_t *>(upnp_name), sizeof(upnp_name));
}

void test_writing_new_appliance_id_restarts_flagpole_service()
{
    mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, expected_rc_filename);
    mock_os->expect_os_file_new(expected_os_write_fd, 0, expected_rc_filename);
    mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, expected_rc_path);
    mock_os->expect_os_system(EXIT_SUCCESS, 0, true, "/bin/systemctl restart flagpole");

    Regs::UPnPName::set_appliance_id("MY_APPLIANCE");

    static const char expected_config_file[] = "APPLIANCE_ID='MY_APPLIANCE'\n";

    cut_assert_equal_memory(expected_config_file, sizeof(expected_config_file) - 1,
                            os_write_buffer.data(), os_write_buffer.size());
}

void test_writing_new_appliance_id_leaves_other_values_untouched()
{
    static char config_file_content[] =
        "FRIENDLY_NAME_OVERRIDE='My UPnP Device'\n"
        "APPLIANCE_ID='Default'\n"
        ;

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_content,
        .length = sizeof(config_file_content) - 1,
    };

    mock_os->expect_os_map_file_to_memory(0, 0, &config_file, expected_rc_filename);
    mock_os->expect_os_unmap_file(0, &config_file);

    mock_os->expect_os_file_new(expected_os_write_fd, 0, expected_rc_filename);
    mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, expected_rc_path);
    mock_os->expect_os_system(EXIT_SUCCESS, 0, true, "/bin/systemctl restart flagpole");

    Regs::UPnPName::set_appliance_id("MyAppliance");

    static const char expected_config_file[] =
        "FRIENDLY_NAME_OVERRIDE='My UPnP Device'\n"
        "APPLIANCE_ID='MyAppliance'\n"
        ;

    cut_assert_equal_memory(expected_config_file, sizeof(expected_config_file) - 1,
                            os_write_buffer.data(), os_write_buffer.size());
}

void test_writing_same_appliance_id_does_not_change_files_nor_flagpole_service()
{
    static char config_file_content[] = "APPLIANCE_ID='UnitTestAppliance'\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_content,
        .length = sizeof(config_file_content) - 1,
    };

    mock_os->expect_os_map_file_to_memory(0, 0, &config_file, expected_rc_filename);
    mock_os->expect_os_unmap_file(0, &config_file);

    Regs::UPnPName::set_appliance_id("UnitTestAppliance");
}

void test_writing_new_different_appliance_id_restarts_flagpole_service()
{
    static char config_file_content[] =
        "APPLIANCE_ID='Whateverest'\n"
        ;

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_content,
        .length = sizeof(config_file_content) - 1,
    };

    mock_os->expect_os_map_file_to_memory(0, 0, &config_file, expected_rc_filename);
    mock_os->expect_os_unmap_file(0, &config_file);

    mock_os->expect_os_file_new(expected_os_write_fd, 0, expected_rc_filename);
    mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, expected_rc_path);
    mock_os->expect_os_system(EXIT_SUCCESS, 0, true, "/bin/systemctl restart flagpole");

    Regs::UPnPName::set_appliance_id("X 9000");

    static const char expected_config_file[] =
        "APPLIANCE_ID='X 9000'\n"
        ;

    cut_assert_equal_memory(expected_config_file, sizeof(expected_config_file) - 1,
                            os_write_buffer.data(), os_write_buffer.size());
}

void test_writing_new_device_uuid_restarts_flagpole_service()
{
    mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, expected_rc_filename);
    mock_os->expect_os_file_new(expected_os_write_fd, 0, expected_rc_filename);
    mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, expected_rc_path);
    mock_os->expect_os_system(EXIT_SUCCESS, 0, true, "/bin/systemctl restart flagpole");

    Regs::UPnPName::set_device_uuid("09AB7C8F0013");

    static const char expected_config_file[] = "UUID='09AB7C8F0013'\n";

    cut_assert_equal_memory(expected_config_file, sizeof(expected_config_file) - 1,
                            os_write_buffer.data(), os_write_buffer.size());
}

void test_writing_new_device_uuid_leaves_other_values_untouched()
{
    static char config_file_content[] =
        "FRIENDLY_NAME_OVERRIDE='My UPnP Device'\n"
        "UUID='020000000000'\n"
        "APPLIANCE_ID='Default'\n"
        ;

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_content,
        .length = sizeof(config_file_content) - 1,
    };

    mock_os->expect_os_map_file_to_memory(0, 0, &config_file, expected_rc_filename);
    mock_os->expect_os_unmap_file(0, &config_file);

    mock_os->expect_os_file_new(expected_os_write_fd, 0, expected_rc_filename);
    mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, expected_rc_path);
    mock_os->expect_os_system(EXIT_SUCCESS, 0, true, "/bin/systemctl restart flagpole");

    Regs::UPnPName::set_device_uuid("30f9e75521bb60ec05bcc4b2dc414924");

    static const char expected_config_file[] =
        "FRIENDLY_NAME_OVERRIDE='My UPnP Device'\n"
        "APPLIANCE_ID='Default'\n"
        "UUID='30f9e75521bb60ec05bcc4b2dc414924'\n"
        ;

    cut_assert_equal_memory(expected_config_file, sizeof(expected_config_file) - 1,
                            os_write_buffer.data(), os_write_buffer.size());
}

void test_writing_same_device_uuid_does_not_change_files_nor_flagpole_service()
{
    static char config_file_content[] = "UUID='UnitTestUUID'\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_content,
        .length = sizeof(config_file_content) - 1,
    };

    mock_os->expect_os_map_file_to_memory(0, 0, &config_file, expected_rc_filename);
    mock_os->expect_os_unmap_file(0, &config_file);

    Regs::UPnPName::set_device_uuid("UnitTestUUID");
}

void test_set_all_upnp_variables()
{
    /* write UUID to non-existent file */
    mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, expected_rc_filename);
    mock_os->expect_os_file_new(expected_os_write_fd, 0, expected_rc_filename);
    mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, expected_rc_path);
    mock_os->expect_os_system(EXIT_SUCCESS, 0, true, "/bin/systemctl restart flagpole");

    Regs::UPnPName::set_device_uuid("09AB7C8F0013");

    static char config_file_content_first[] =
        "UUID='09AB7C8F0013'\n"
        ;

    cut_assert_equal_memory(config_file_content_first, sizeof(config_file_content_first) - 1,
                            os_write_buffer.data(), os_write_buffer.size());
    os_write_buffer.clear();

    /* add appliance ID */
    const struct os_mapped_file_data config_file_first =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_content_first,
        .length = sizeof(config_file_content_first) - 1,
    };

    mock_os->expect_os_map_file_to_memory(0, 0, &config_file_first, expected_rc_filename);
    mock_os->expect_os_unmap_file(0, &config_file_first);
    mock_os->expect_os_file_new(expected_os_write_fd, 0, expected_rc_filename);
    mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, expected_rc_path);
    mock_os->expect_os_system(EXIT_SUCCESS, 0, true, "/bin/systemctl restart flagpole");

    Regs::UPnPName::set_appliance_id("MY_APPLIANCE");

    static char config_file_content_second[] =
        "APPLIANCE_ID='MY_APPLIANCE'\n"
        "UUID='09AB7C8F0013'\n"
        ;

    cut_assert_equal_memory(config_file_content_second, sizeof(config_file_content_second) - 1,
                            os_write_buffer.data(), os_write_buffer.size());
    os_write_buffer.clear();

    /* finally, add friendly name */
    const struct os_mapped_file_data config_file_second =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_content_second,
        .length = sizeof(config_file_content_second) - 1,
    };

    mock_os->expect_os_map_file_to_memory(0, 0, &config_file_second, expected_rc_filename);
    mock_os->expect_os_unmap_file(0, &config_file_second);
    mock_os->expect_os_file_new(expected_os_write_fd, 0, expected_rc_filename);
    mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, expected_rc_path);
    mock_os->expect_os_system(EXIT_SUCCESS, 0, true, "/bin/systemctl restart flagpole");

    auto *reg = lookup_register_expect_handlers(88, 1, 0, 5,
                                                Regs::UPnPName::DCP::read_88_upnp_friendly_name,
                                                Regs::UPnPName::DCP::write_88_upnp_friendly_name__v1_0_1);
    cppcut_assert_not_null(reg);
    reg->write(reinterpret_cast<const uint8_t *>("Unit test device"), 16);

    static char config_file_content_third[] =
        "FRIENDLY_NAME_OVERRIDE='Unit test device'\n"
        "FRIENDLY_NAME_GIVEN_BY_USER='yes'\n"
        "APPLIANCE_ID='MY_APPLIANCE'\n"
        "UUID='09AB7C8F0013'\n"
        ;

    cut_assert_equal_memory(config_file_content_third, sizeof(config_file_content_third) - 1,
                            os_write_buffer.data(), os_write_buffer.size());
}

}

#endif /* !LOGGED_LOCKS_ENABLED  */

/*!@}*/
