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
#include <memory>

#include "registers.hh"
#include "dcpregs_filetransfer.hh"
#include "dcpregs_filetransfer_priv.h"
#include "dcpregs_playstream.hh"
#include "networkprefs.h"
#include "mainloop.hh"

#include "mock_messages.hh"
#include "mock_os.hh"
#include "mock_file_transfer_dbus.hh"
#include "mock_logind_manager_dbus.hh"
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

namespace spi_registers_file_transfer
{

static MockMessages *mock_messages;
static MockOs *mock_os;
static MockFileTransferDBus *mock_file_transfer_dbus;
static MockLogindManagerDBus *mock_logind_manager_dbus;
static MockDBusIface *mock_dbus_iface;

static tdbusFileTransfer *const dbus_dcpd_file_transfer_iface_dummy =
    reinterpret_cast<tdbusFileTransfer *>(0x55990011);

static tdbuslogindManager *const dbus_logind_manager_iface_dummy =
    reinterpret_cast<tdbuslogindManager *>(0x35790011);

static RegisterChangedData *register_changed_data;

static std::vector<char> os_write_buffer;
static constexpr int expected_os_write_fd = 812;
static constexpr int expected_os_map_file_to_memory_fd = 64;
static constexpr const char feed_config_filename[] = "/var/local/etc/update_feeds.ini";
static constexpr const char feed_config_override_filename[] = "/var/local/etc/update_feeds_override.ini";
static constexpr const char feed_config_path[] = "/var/local/etc";
static constexpr const char opkg_configuration_path[] = "/etc/opkg";

std::unique_ptr<Regs::PlayStream::StreamingRegistersIface> streaming_regs;

static int write_from_buffer_callback(const void *src, size_t count, int fd)
{
    cppcut_assert_equal(expected_os_write_fd, fd);
    cppcut_assert_not_null(src);
    cppcut_assert_operator(size_t(0), <, count);

    std::copy_n(static_cast<const char *>(src), count,
                std::back_inserter<std::vector<char>>(os_write_buffer));

    return 0;
}

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

    mock_file_transfer_dbus = new MockFileTransferDBus;
    cppcut_assert_not_null(mock_file_transfer_dbus);
    mock_file_transfer_dbus->init();
    mock_file_transfer_dbus_singleton = mock_file_transfer_dbus;

    mock_logind_manager_dbus = new MockLogindManagerDBus;
    cppcut_assert_not_null(mock_logind_manager_dbus);
    mock_logind_manager_dbus->init();
    mock_logind_manager_dbus_singleton = mock_logind_manager_dbus;

    mock_dbus_iface = new MockDBusIface;
    cppcut_assert_not_null(mock_dbus_iface);
    mock_dbus_iface->init();
    mock_dbus_iface_singleton = mock_dbus_iface;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    os_write_buffer.clear();

    register_changed_data->init();

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    network_prefs_init(nullptr, nullptr);
    Regs::init(register_changed_callback, nullptr);
    streaming_regs = Regs::PlayStream::mk_streaming_registers();
    Regs::PlayStream::DCP::init(*streaming_regs);
    Regs::FileTransfer::set_picture_provider(streaming_regs->get_picture_provider());
}

void cut_teardown()
{
    Regs::deinit();
    network_prefs_deinit();
    streaming_regs = nullptr;

    register_changed_data->check();

    delete register_changed_data;
    register_changed_data = nullptr;

    os_write_buffer.clear();
    os_write_buffer.shrink_to_fit();

    mock_messages->check();
    mock_os->check();
    mock_file_transfer_dbus->check();
    mock_logind_manager_dbus->check();
    mock_dbus_iface->check();

    mock_messages_singleton = nullptr;
    mock_os_singleton = nullptr;
    mock_file_transfer_dbus_singleton = nullptr;
    mock_logind_manager_dbus_singleton = nullptr;
    mock_dbus_iface_singleton = nullptr;

    delete mock_messages;
    delete mock_os;
    delete mock_file_transfer_dbus;
    delete mock_logind_manager_dbus;
    delete mock_dbus_iface;

    mock_messages = nullptr;
    mock_os = nullptr;
    mock_file_transfer_dbus = nullptr;
    mock_logind_manager_dbus = nullptr;
    mock_dbus_iface = nullptr;
}

/*!\test
 * Download URL buffer size must be within a certain range.
 */
void test_download_url_length_restrictions()
{
    auto *reg =
        lookup_register_expect_handlers(209, Regs::FileTransfer::DCP::write_209_download_url);

    uint8_t url_buffer[8 + 1024 + 1];

    memset(url_buffer, 'x', sizeof(url_buffer));
    url_buffer[0] = HCR_FILE_TRANSFER_CRC_MODE_NONE;
    url_buffer[3] = HCR_FILE_TRANSFER_ENCRYPTION_NONE;

    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DEBUG, "Cleared URL");
    reg->write(url_buffer, 0);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Unexpected data length 1 (expected 9...1032) (Invalid argument)");
    write_buffer_expect_failure(reg, url_buffer, 1, -1);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Unexpected data length 8 (expected 9...1032) (Invalid argument)");
    write_buffer_expect_failure(reg, url_buffer, 8, -1);

    mock_messages->expect_msg_info_formatted("Set URL \"x\"");
    reg->write(url_buffer, 9);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Unexpected data length 1033 (expected 9...1032) (Invalid argument)");
    write_buffer_expect_failure(reg, url_buffer, sizeof(url_buffer), -1);

    mock_messages->expect_msg_info("Set URL \"%s\"");
    reg->write(url_buffer, sizeof(url_buffer) - 1);
}

static void start_download(const std::string &url, uint32_t download_id)
{
    uint8_t url_buffer[8 + url.length()];

    memset(url_buffer, 0, 8);
    url_buffer[3] = HCR_FILE_TRANSFER_ENCRYPTION_NONE;
    memcpy(url_buffer + 8, url.c_str(), url.length());

    auto *reg =
        lookup_register_expect_handlers(209, Regs::FileTransfer::DCP::write_209_download_url);
    mock_messages->expect_msg_info("Set URL \"%s\"");

    reg->write(url_buffer, 8 + url.length());

    static constexpr uint8_t hcr_command[] =
        { HCR_COMMAND_CATEGORY_LOAD_TO_DEVICE, HCR_COMMAND_LOAD_TO_DEVICE_DOWNLOAD };

    reg = lookup_register_expect_handlers(40, Regs::FileTransfer::DCP::write_40_download_control);

    int expected_write_handler_retval;

    if(download_id == 0)
    {
        mock_messages->expect_msg_info("Not transferring files during shutdown.");
        expected_write_handler_retval = -1;
    }
    else
    {
        mock_messages->expect_msg_info("Download started, transfer ID %u");
        mock_dbus_iface->expect_dbus_get_file_transfer_iface(dbus_dcpd_file_transfer_iface_dummy);
        mock_file_transfer_dbus->expect_tdbus_file_transfer_call_download_sync(
            TRUE, download_id, dbus_dcpd_file_transfer_iface_dummy, url.c_str(), 20);
        expected_write_handler_retval = 0;
    }

    write_buffer_expect_failure(reg, hcr_command, sizeof(hcr_command),
                                expected_write_handler_retval);
}

static void cancel_download(uint32_t download_id)
{
    auto *reg =
        lookup_register_expect_handlers(209, Regs::FileTransfer::DCP::write_209_download_url);
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DEBUG, "Cleared URL");
    mock_dbus_iface->expect_dbus_get_file_transfer_iface(dbus_dcpd_file_transfer_iface_dummy);
    mock_file_transfer_dbus->expect_tdbus_file_transfer_call_cancel_sync(
        TRUE, dbus_dcpd_file_transfer_iface_dummy, download_id);

    reg->write(nullptr, 0);

}

/*!\test
 * Request to download a URL triggers a D-Bus message to D-Bus DL.
 */
void test_download_url()
{
    start_download("http://this.is.a.test.com/releases/image_v1.0.bin", 5);
}

/*!\test
 * Request to download without setting the URL is an error.
 */
void test_download_without_url_returns_error()
{
    static constexpr uint8_t hcr_command[] =
    {
        HCR_COMMAND_CATEGORY_LOAD_TO_DEVICE,
        HCR_COMMAND_LOAD_TO_DEVICE_DOWNLOAD
    };

    auto *reg =
        lookup_register_expect_handlers(40, Regs::FileTransfer::DCP::write_40_download_control);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_NOTICE,
                                              "Download URL not configured (Invalid argument)");

    write_buffer_expect_failure(reg, hcr_command, sizeof(hcr_command), -1);
}

static void get_download_status(uint8_t (&buffer)[2])
{
    auto *reg =
        lookup_register_expect_handlers(41, Regs::FileTransfer::DCP::read_41_download_status,
                                        nullptr);

    cppcut_assert_equal(sizeof(buffer), reg->read(buffer, sizeof(buffer)));
}

/*!\test
 * Reading out the download status when idle yields plain OK code.
 */
void test_download_status_while_not_downloading_is_OK_code()
{
    uint8_t buffer[2];
    get_download_status(buffer);

    static constexpr uint8_t expected_answer[] =
        { HCR_STATUS_CATEGORY_GENERIC, HCR_STATUS_GENERIC_OK };
    cut_assert_equal_memory(expected_answer, sizeof(expected_answer),
                            buffer, sizeof(buffer));
}

/*!\test
 * Reading out the download status while download is in progress yields
 * progress percentage.
 */
void test_download_status_during_download_is_percentage()
{
    static constexpr uint32_t xfer_id = 3;
    start_download("http://download.something.com/file", xfer_id);

    uint8_t buffer[2];
    get_download_status(buffer);

    static constexpr uint8_t expected_answer_1[] =
        { HCR_STATUS_CATEGORY_PROGRESS, 0 };
    cut_assert_equal_memory(expected_answer_1, sizeof(expected_answer_1),
                            buffer, sizeof(buffer));

    /* simulate D-Bus DL progress report */
    Regs::FileTransfer::progress_notification(xfer_id, 10, 20);
    register_changed_data->check(41);

    get_download_status(buffer);

    static constexpr uint8_t expected_answer_2[] =
        { HCR_STATUS_CATEGORY_PROGRESS, 50 };
    cut_assert_equal_memory(expected_answer_2, sizeof(expected_answer_2),
                            buffer, sizeof(buffer));
}

/*!\test
 * Reading out the download status after successful download yields download
 * status code OK.
 */
void test_download_status_after_successful_download_is_status_code()
{
    static constexpr uint32_t xfer_id = 7;
    start_download("https://updates.server.com/file", xfer_id);

    uint8_t buffer[2];
    get_download_status(buffer);

    static constexpr uint8_t expected_answer_1[] =
        { HCR_STATUS_CATEGORY_PROGRESS, 0 };
    cut_assert_equal_memory(expected_answer_1, sizeof(expected_answer_1),
                            buffer, sizeof(buffer));

    /* simulate D-Bus DL progress report */
    Regs::FileTransfer::progress_notification(xfer_id, 100, 100);
    register_changed_data->check(41);

    /* progress 100% */
    get_download_status(buffer);

    static constexpr uint8_t expected_answer_2[] =
        { HCR_STATUS_CATEGORY_PROGRESS, 100 };
    cut_assert_equal_memory(expected_answer_2, sizeof(expected_answer_2),
                            buffer, sizeof(buffer));

    /* simulate D-Bus DL done report */
    Regs::FileTransfer::done_notification(xfer_id, LIST_ERROR_OK,
                                          "/some/path/0000000007.dbusdl");
    register_changed_data->check(41);

    /* Download OK status */
    get_download_status(buffer);

    static constexpr uint8_t expected_answer_3[] =
        { HCR_STATUS_CATEGORY_DOWNLOAD, HCR_STATUS_DOWNLOAD_OK };
    cut_assert_equal_memory(expected_answer_3, sizeof(expected_answer_3),
                            buffer, sizeof(buffer));

    /* Reading out the status again yields the same answer */
    get_download_status(buffer);
    cut_assert_equal_memory(expected_answer_3, sizeof(expected_answer_3),
                            buffer, sizeof(buffer));
}

/*!\test
 * Reading out the download status after failed download yields appropriate
 * download status code.
 */
void test_download_status_after_failed_download_is_status_code()
{
    static constexpr uint32_t xfer_id = 15;
    start_download("https://does.not.exist/file", xfer_id);

    uint8_t buffer[2];
    get_download_status(buffer);

    static constexpr uint8_t expected_answer_1[] =
        { HCR_STATUS_CATEGORY_PROGRESS, 0 };
    cut_assert_equal_memory(expected_answer_1, sizeof(expected_answer_1),
                            buffer, sizeof(buffer));

    /* simulate D-Bus DL done report with error */
    Regs::FileTransfer::done_notification(xfer_id, LIST_ERROR_NET_IO, nullptr);
    register_changed_data->check(41);

    /* No network connection status */
    get_download_status(buffer);

    static constexpr uint8_t expected_answer_2[] =
        { HCR_STATUS_CATEGORY_DOWNLOAD, HCR_STATUS_DOWNLOAD_NETWORK_ERROR };
    cut_assert_equal_memory(expected_answer_2, sizeof(expected_answer_2),
                            buffer, sizeof(buffer));

    /* Reading out the status again yields the same answer */
    get_download_status(buffer);
    cut_assert_equal_memory(expected_answer_2, sizeof(expected_answer_2),
                            buffer, sizeof(buffer));
}

/*!\test
 * Reading out the download status after canceling a download yields generic OK
 * status code.
 */
void test_cancel_download_resets_download_status()
{
    static constexpr uint32_t xfer_id = 23;
    start_download("ftp://short.com/f", xfer_id);

    uint8_t buffer[2];
    get_download_status(buffer);

    static constexpr uint8_t expected_answer_1[] =
        { HCR_STATUS_CATEGORY_PROGRESS, 0 };
    cut_assert_equal_memory(expected_answer_1, sizeof(expected_answer_1),
                            buffer, sizeof(buffer));

    cancel_download(xfer_id);

    get_download_status(buffer);

    static constexpr uint8_t expected_answer_2[] =
        { HCR_STATUS_CATEGORY_GENERIC, HCR_STATUS_GENERIC_OK };
    cut_assert_equal_memory(expected_answer_2, sizeof(expected_answer_2),
                            buffer, sizeof(buffer));
}

/*!\test
 * Rebooting the system via DCP command is possible.
 */
void test_send_reboot_request()
{
    auto *reg =
        lookup_register_expect_handlers(40, Regs::FileTransfer::DCP::write_40_download_control);

    static constexpr uint8_t hcr_command[] =
        { HCR_COMMAND_CATEGORY_RESET, HCR_COMMAND_REBOOT_SYSTEM };

    mock_os->expect_os_path_get_type(OS_PATH_TYPE_IO_ERROR, 0, "/tmp/do_update.sh");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
                                              "Shutdown requested via DCP command");
    mock_dbus_iface->expect_dbus_get_logind_manager_iface(dbus_logind_manager_iface_dummy);
    mock_logind_manager_dbus->expect_tdbus_logind_manager_call_reboot_sync(true, dbus_logind_manager_iface_dummy, false);
    reg->write(hcr_command, sizeof(hcr_command));
}

/*!\test
 * Rebooting the system via DCP command is blocked during updates.
 */
void test_send_reboot_request_during_update()
{
    auto *reg =
        lookup_register_expect_handlers(40, Regs::FileTransfer::DCP::write_40_download_control);

    static constexpr uint8_t hcr_command[] =
        { HCR_COMMAND_CATEGORY_RESET, HCR_COMMAND_REBOOT_SYSTEM };

    mock_os->expect_os_path_get_type(OS_PATH_TYPE_FILE, 0, "/tmp/do_update.sh");
    mock_messages->expect_msg_error(0, LOG_ERR,
        "System reboot request ignored, we are in the middle of an update");
    reg->write(hcr_command, sizeof(hcr_command));
}

/*!\test
 * Download is canceled on shutdown.
 */
void test_transfer_is_interrupted_on_shutdown()
{
    start_download("http://this.is.a.test.com/releases/image_v1.0.bin", 99);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Shutdown guard \"filetransfer\" down");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DEBUG, "Cleared URL");
    mock_dbus_iface->expect_dbus_get_file_transfer_iface(dbus_dcpd_file_transfer_iface_dummy);
    mock_file_transfer_dbus->expect_tdbus_file_transfer_call_cancel_sync(
        TRUE, dbus_dcpd_file_transfer_iface_dummy, 99);
    Regs::FileTransfer::prepare_for_shutdown();
}

/*!\test
 * Download cannot be started after shutdown.
 */
void test_new_transfer_is_blocked_after_shutdown()
{
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Shutdown guard \"filetransfer\" down");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DEBUG, "Cleared URL");
    Regs::FileTransfer::prepare_for_shutdown();

    start_download("http://this.is.a.test.com/releases/image_v1.0.bin", 0);
}

/*!\test
 * Request download of empty cover art via XMODEM.
 */
void test_download_empty_cover_art()
{
    /* no picture hash available */
    auto *reg =
        lookup_register_expect_handlers(210, Regs::PlayStream::DCP::read_210_current_cover_art_hash, nullptr);

    mock_messages->expect_msg_info("Cover art: Send empty hash to SPI slave");

    uint8_t buffer[16];
    cppcut_assert_equal(size_t(0), reg->read(buffer, sizeof(buffer)));

    mock_messages->check();

    static constexpr uint8_t hcr_command[] =
        { HCR_COMMAND_CATEGORY_LOAD_TO_DEVICE, HCR_COMMAND_LOAD_TO_DEVICE_COVER_ART };

    /* no picture available */
    reg = lookup_register_expect_handlers(40, Regs::FileTransfer::DCP::write_40_download_control);

    mock_messages->expect_msg_info("Download of cover art requested");
    mock_messages->expect_msg_info("No cover art available");

    reg->write(hcr_command, sizeof(hcr_command));
}

/*!\test
 * Attempting to shut down twice has no effect.
 */
void test_shutdown_can_be_called_only_once()
{
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Shutdown guard \"filetransfer\" down");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DEBUG, "Cleared URL");
    Regs::FileTransfer::prepare_for_shutdown();

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Shutdown guard \"filetransfer\" down");
    Regs::FileTransfer::prepare_for_shutdown();
}

static int write_feed_conf_from_buffer_callback(const void *src, size_t count, int fd,
                                                const char *expected_content)
{
    cppcut_assert_equal(expected_os_write_fd, fd);
    cppcut_assert_not_null(src);
    cppcut_assert_operator(size_t(0), <, count);

    const size_t expected_content_size = strlen(expected_content);
    cut_assert_equal_memory(expected_content, expected_content_size,
                            src, count);

    return 0;
}

static void set_update_package_feed_configuration(bool have_regular_inifile,
                                                  bool have_override_inifile)
{
    static constexpr char old_release_name[] = "oldtest";
    static constexpr char old_url[] = "http://attic.ta-hifi.de/StrBo";
    static constexpr char updated_release_name[] = "testing";
    static constexpr char updated_url[] = "http://updates.ta-hifi.de/StrBo";
    static constexpr char override_release_name[] = "experimental";
    static constexpr char override_url[] = "http://files.ta-hifi.de/override/StrBo";

    /* send new update feed configuration: opkg feed configuration files are
     * deleted and new settings are written to configuration file (in this
     * particular order!) */
    static constexpr const char url[] = "http://updates.ta-hifi.de/StrBo testing";
    uint8_t url_buffer[8 + sizeof(url) - 1];

    memset(url_buffer, 0, 8);
    url_buffer[3] = HCR_FILE_TRANSFER_ENCRYPTION_NONE;
    memcpy(url_buffer + 8, url, sizeof(url) - 1);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Set package update URL \"http://updates.ta-hifi.de/StrBo\" for release \"testing\"");

    static constexpr const char config_file_format[] =
        "[global]\n"
        "release = %s\n"
        "url = %s\n"
        "method = src/gz\n"
        "[feed all]\n"
        "[feed arm1176jzfshf-vfp]\n"
        "[feed raspberrypi]\n";

    static char existing_config_file_buffer[1024];
    const size_t existing_config_file_length =
        snprintf(existing_config_file_buffer, sizeof(existing_config_file_buffer),
                 config_file_format, old_release_name, old_url);

    const struct os_mapped_file_data existing_config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = existing_config_file_buffer,
        .length = existing_config_file_length,
    };

    if(have_regular_inifile)
    {
        mock_os->expect_os_map_file_to_memory(0, 0, &existing_config_file, feed_config_filename);
        mock_os->expect_os_unmap_file(0, &existing_config_file);
    }
    else
        mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, feed_config_filename);

    std::vector<MockOs::ForeachItemData> items_before;
    items_before.emplace_back(MockOs::ForeachItemData("somedir", true));
    items_before.emplace_back(MockOs::ForeachItemData("hello.conf"));
    items_before.emplace_back(MockOs::ForeachItemData("all-feed.conf"));
    items_before.emplace_back(MockOs::ForeachItemData("arm1176jzfshf-vfp-feed.conf"));
    items_before.emplace_back(MockOs::ForeachItemData("raspberrypi-feed.conf"));
    items_before.emplace_back(MockOs::ForeachItemData("-feed.conf"));
    items_before.emplace_back(MockOs::ForeachItemData("extra-feed.conf"));
    items_before.emplace_back(MockOs::ForeachItemData("not-a-feed.conf "));
    items_before.emplace_back(MockOs::ForeachItemData("xyzfeed.conf"));
    items_before.emplace_back(MockOs::ForeachItemData(".conf"));

    std::vector<MockOs::ForeachItemData> items_after;
    items_after.emplace_back(MockOs::ForeachItemData("somedir", true));
    items_after.emplace_back(MockOs::ForeachItemData("hello.conf"));
    items_after.emplace_back(MockOs::ForeachItemData("-feed.conf"));
    items_after.emplace_back(MockOs::ForeachItemData("not-a-feed.conf "));
    items_after.emplace_back(MockOs::ForeachItemData("xyzfeed.conf"));
    items_after.emplace_back(MockOs::ForeachItemData(".conf"));

    static constexpr std::array<const char *, 3> expected_generated_feed_file_names =
    {
        "/etc/opkg/all-feed.conf",
        "/etc/opkg/arm1176jzfshf-vfp-feed.conf",
        "/etc/opkg/raspberrypi-feed.conf",
    };

    mock_os->expect_os_foreach_in_path(0, 0, opkg_configuration_path, items_before);
    mock_os->expect_os_file_delete(0, 0, expected_generated_feed_file_names[0]);
    mock_os->expect_os_file_delete(0, 0, expected_generated_feed_file_names[1]);
    mock_os->expect_os_file_delete(0, 0, expected_generated_feed_file_names[2]);
    mock_os->expect_os_file_delete(0, 0, "/etc/opkg/extra-feed.conf");
    mock_os->expect_os_sync_dir(0, opkg_configuration_path);

    mock_os->expect_os_file_new(expected_os_write_fd, 0, feed_config_filename);
    for(unsigned int i = 0; i < (expected_generated_feed_file_names.size() + 1) * 3 + 3 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, feed_config_path);

    auto *reg = lookup_register_expect_handlers(209, Regs::FileTransfer::DCP::write_209_download_url);

    reg->write(url_buffer, sizeof(url_buffer));

    /* the data passed to the register is always written straight to the
     * regular configuration file (unless the content wasn't changed), the
     * override file does not interfere */
    static char expected_config_file_buffer[1024];
    const size_t expected_config_file_length =
        snprintf(expected_config_file_buffer, sizeof(expected_config_file_buffer),
                 config_file_format, updated_release_name, updated_url);

    cut_assert_equal_memory(expected_config_file_buffer, expected_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());

    os_write_buffer.clear();

    mock_messages->check();
    mock_os->check();


    /* probe opkg feed configuration files, then read update feed configuration
     * from our file, then generate opkg configuration files, then start the
     * update */
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                                    "Attempting to START SYSTEM UPDATE");

    mock_os->expect_os_foreach_in_path(0, 0, opkg_configuration_path, items_after);

    const struct os_mapped_file_data modified_config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = expected_config_file_buffer,
        .length = expected_config_file_length,
    };

    static char override_config_file_buffer[1024];
    const size_t override_config_file_length =
        snprintf(override_config_file_buffer, sizeof(override_config_file_buffer),
                 config_file_format, override_release_name, override_url);

    const struct os_mapped_file_data override_config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = override_config_file_buffer,
        .length = override_config_file_length,
    };

    static constexpr decltype(expected_generated_feed_file_names) expected_generated_feed_file_formats =
    {
        "# Generated file, do not edit!\n"
        "src/gz %s-all %s/%s/all\n",
        "# Generated file, do not edit!\n"
        "src/gz %s-arm1176jzfshf-vfp %s/%s/arm1176jzfshf-vfp\n",
        "# Generated file, do not edit!\n"
        "src/gz %s-raspberrypi %s/%s/raspberrypi\n",
    };

    std::array<char[512], expected_generated_feed_file_formats.size()> expected_generated_feed_file_contents;

    const char *expected_release_name =
        have_override_inifile ? override_release_name : updated_release_name;
    const char *expected_url =
        have_override_inifile ? override_url : updated_url;

    for(size_t i = 0; i < expected_generated_feed_file_formats.size(); ++i)
        snprintf(expected_generated_feed_file_contents[i],
                 sizeof(expected_generated_feed_file_contents[i]),
                 expected_generated_feed_file_formats[i],
                 expected_release_name, expected_url, expected_release_name);

    if(have_override_inifile)
    {
        mock_os->expect_os_map_file_to_memory(0, 0, &override_config_file,
                                              feed_config_override_filename);
        mock_os->expect_os_unmap_file(0, &override_config_file);
    }
    else
    {
        mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, feed_config_override_filename);
        mock_os->expect_os_map_file_to_memory(0, 0, &modified_config_file, feed_config_filename);
        mock_os->expect_os_unmap_file(0, &modified_config_file);
    }

    for(size_t i = 0; i < expected_generated_feed_file_names.size(); ++i)
    {
        mock_os->expect_os_file_new(expected_os_write_fd, 0, expected_generated_feed_file_names[i]);
        mock_os->expect_os_write_from_buffer_callback(0,
                                                      std::bind(write_feed_conf_from_buffer_callback,
                                                                std::placeholders::_1,
                                                                std::placeholders::_2,
                                                                std::placeholders::_3,
                                                                expected_generated_feed_file_contents[i]));
        mock_os->expect_os_file_close(0, expected_os_write_fd);
    }

    mock_os->expect_os_sync_dir(0, opkg_configuration_path);

    /* let's stop it at this point, we have tested what we wanted */
    mock_messages->expect_msg_info("Update in progress, not starting again");
    mock_os->expect_os_path_get_type(OS_PATH_TYPE_FILE, 0, "/tmp/do_update.sh");

    reg = lookup_register_expect_handlers(40, Regs::FileTransfer::DCP::write_40_download_control);

    static constexpr uint8_t hcr_command[] =
        { HCR_COMMAND_CATEGORY_UPDATE_FROM_INET, HCR_COMMAND_UPDATE_MAIN_SYSTEM };

    write_buffer_expect_failure(reg, hcr_command, sizeof(hcr_command), -1);
}

/*!\test
 * Update existing package feed configuration with new data from regular
 * configuration file.
 */
void test_set_update_package_feed_configuration()
{
    set_update_package_feed_configuration(true, false);
}

/*!\test
 * Update existing package feed configuration with new data, override inifile
 * is in place, but regular configuration file is not.
 */
void test_set_update_package_feed_configuration_with_override()
{
    set_update_package_feed_configuration(false, true);
}

/*!\test
 * Update existing package feed configuration with new data, no configuration
 * files exist.
 *
 * This is be similar to #test_set_update_package_feed_configuration(), but the
 * default configuration file is generated.
 */
void test_set_update_package_feed_configuration_with_no_configs()
{
    set_update_package_feed_configuration(false, false);
}

/*!\test
 * Update existing package feed configuration with new data, both override and
 * regular inifiles are in place.
 *
 * The override inifile takes precedence over the regular file and over what
 * has been written there.
 */
void test_set_update_package_feed_configuration_with_regular_and_override()
{
    set_update_package_feed_configuration(true, true);
}

static void feed_configuration_file_is_created_on_system_update(bool have_override_inifile)
{
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                                    "Attempting to START SYSTEM UPDATE");

    mock_os->expect_os_foreach_in_path(0, 0, opkg_configuration_path);

    static char override_config_file_buffer[] =
        "[global]\n"
        "release = alphaomega\n"
        "url = http://alpha.ta-hifi.de/omega\n"
        "method = src/gz\n"
        "[feed all]\n"
        "[feed arm1176jzfshf-vfp]\n"
        "[feed raspberrypi]\n";

    const struct os_mapped_file_data override_config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = override_config_file_buffer,
        .length = sizeof(override_config_file_buffer) - 1,
    };

    if(have_override_inifile)
    {
        mock_os->expect_os_map_file_to_memory(0, 0, &override_config_file,
                                              feed_config_override_filename);
        mock_os->expect_os_unmap_file(0, &override_config_file);
    }
    else
    {
        mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, feed_config_override_filename);
        mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, feed_config_filename);
    }

    static constexpr std::array<const char *, 3> expected_generated_feed_file_names =
    {
        "/etc/opkg/all-feed.conf",
        "/etc/opkg/arm1176jzfshf-vfp-feed.conf",
        "/etc/opkg/raspberrypi-feed.conf",
    };

    static constexpr decltype(expected_generated_feed_file_names) expected_generated_feed_file_formats =
    {
        "# Generated file, do not edit!\n"
        "src/gz %s-all %s/%s/all\n",
        "# Generated file, do not edit!\n"
        "src/gz %s-arm1176jzfshf-vfp %s/%s/arm1176jzfshf-vfp\n",
        "# Generated file, do not edit!\n"
        "src/gz %s-raspberrypi %s/%s/raspberrypi\n",
    };

    std::array<char[512], expected_generated_feed_file_formats.size()> expected_generated_feed_file_contents;

    const char *expected_release_name = have_override_inifile
        ? "alphaomega"
        : "stable";
    const char *expected_url = have_override_inifile
        ? "http://alpha.ta-hifi.de/omega"
        : "http://www.ta-hifi.de/fileadmin/auto_download/StrBo";

    for(size_t i = 0; i < expected_generated_feed_file_formats.size(); ++i)
        snprintf(expected_generated_feed_file_contents[i],
                 sizeof(expected_generated_feed_file_contents[i]),
                 expected_generated_feed_file_formats[i],
                 expected_release_name, expected_url, expected_release_name);

    for(size_t i = 0; i < expected_generated_feed_file_names.size(); ++i)
    {
        mock_os->expect_os_file_new(expected_os_write_fd, 0, expected_generated_feed_file_names[i]);
        mock_os->expect_os_write_from_buffer_callback(0,
                                                      std::bind(write_feed_conf_from_buffer_callback,
                                                                std::placeholders::_1,
                                                                std::placeholders::_2,
                                                                std::placeholders::_3,
                                                                expected_generated_feed_file_contents[i]));
        mock_os->expect_os_file_close(0, expected_os_write_fd);
    }

    mock_os->expect_os_sync_dir(0, opkg_configuration_path);

    /* let's stop it at this point, we have tested what we wanted */
    mock_messages->expect_msg_info("Update in progress, not starting again");
    mock_os->expect_os_path_get_type(OS_PATH_TYPE_FILE, 0, "/tmp/do_update.sh");

    auto *reg = lookup_register_expect_handlers(40, Regs::FileTransfer::DCP::write_40_download_control);

    static constexpr uint8_t hcr_command[] =
        { HCR_COMMAND_CATEGORY_UPDATE_FROM_INET, HCR_COMMAND_UPDATE_MAIN_SYSTEM };

    write_buffer_expect_failure(reg, hcr_command, sizeof(hcr_command), -1);
}

/*!\test
 * System update is possible even if neither our configuration file nor the
 * opkg feed configuraton files exist.
 *
 * In case our configuraton file does not exist yet when the system update
 * command comes in, a default file is generated in RAM. This is used to
 * generate the opkg feed configuration files so that the update request may
 * proceed.
 */
void test_feed_configuration_file_is_created_on_system_update_if_does_not_exist()
{
    feed_configuration_file_is_created_on_system_update(false);
}

/*!\test
 * System update is possible of only the override file exists, in which case
 * its values are used.
 */
void test_feed_configuration_file_is_not_created_if_override_file_exists()
{
    feed_configuration_file_is_created_on_system_update(true);
}

/*!\test
 * Setting feed configuration suceeds if there is no configuration file yet.
 *
 * In the configuration file does not exist, a default file is generated in
 * RAM. This file is then updated according to the command and written to a
 * real file.
 */
void test_feed_configuration_file_is_created_on_config_if_does_not_exist()
{
    /* send new update feed configuration: opkg feed configuration files are
     * deleted and new settings are written to configuration file (in this
     * particular order!) */
    static constexpr const char url[] = "http://dev.tua.local/Test experimental";
    uint8_t url_buffer[8 + sizeof(url) - 1];

    memset(url_buffer, 0, 8);
    url_buffer[3] = HCR_FILE_TRANSFER_ENCRYPTION_NONE;
    memcpy(url_buffer + 8, url, sizeof(url) - 1);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Set package update URL \"http://dev.tua.local/Test\" for release \"experimental\"");

    mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, feed_config_filename);
    mock_os->expect_os_foreach_in_path(0, 0, opkg_configuration_path);
    mock_os->expect_os_file_new(expected_os_write_fd, 0, feed_config_filename);
    for(unsigned int i = 0; i < 4 * 3 + 3 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, feed_config_path);

    auto *reg = lookup_register_expect_handlers(209, Regs::FileTransfer::DCP::write_209_download_url);

    reg->write(url_buffer, sizeof(url_buffer));

    static char expected_config_file[] =
        "[global]\n"
        "release = experimental\n"
        "url = http://dev.tua.local/Test\n"
        "method = src/gz\n"
        "[feed all]\n"
        "[feed arm1176jzfshf-vfp]\n"
        "[feed raspberrypi]\n";

    cut_assert_equal_memory(expected_config_file, sizeof(expected_config_file) - 1,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Any zero byte tacked to the end of the input gets ignored.
 */
void test_feed_configurations_with_trailing_zero_bytes_are_accepted()
{
    static constexpr const char url[] = "http://dev.tua.local/foo bar\0\0\0";
    uint8_t url_buffer[8 + sizeof(url) - 1];

    memset(url_buffer, 0, 8);
    url_buffer[3] = HCR_FILE_TRANSFER_ENCRYPTION_NONE;
    memcpy(url_buffer + 8, url, sizeof(url) - 1);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Set package update URL \"http://dev.tua.local/foo\" for release \"bar\"");

    mock_os->expect_os_map_file_to_memory(-1, ENOENT, false, feed_config_filename);
    mock_os->expect_os_foreach_in_path(0, 0, opkg_configuration_path);
    mock_os->expect_os_file_new(expected_os_write_fd, 0, feed_config_filename);
    for(unsigned int i = 0; i < 4 * 3 + 3 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(0, write_from_buffer_callback);
    mock_os->expect_os_file_close(0, expected_os_write_fd);
    mock_os->expect_os_sync_dir(0, feed_config_path);

    auto *reg = lookup_register_expect_handlers(209, Regs::FileTransfer::DCP::write_209_download_url);

    reg->write(url_buffer, sizeof(url_buffer));

    static char expected_config_file[] =
        "[global]\n"
        "release = bar\n"
        "url = http://dev.tua.local/foo\n"
        "method = src/gz\n"
        "[feed all]\n"
        "[feed arm1176jzfshf-vfp]\n"
        "[feed raspberrypi]\n";

    cut_assert_equal_memory(expected_config_file, sizeof(expected_config_file) - 1,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * In case the configuration is does not differ from what is already stored on
 * configuration file, the file is neither rewritten nor are the opkg files
 * deleted.
 */
void test_feed_configuration_file_remains_unchanged_if_passed_config_is_same()
{
    static constexpr const char url[] = "http://did.not.change/in/any way";
    uint8_t url_buffer[8 + sizeof(url) - 1];

    memset(url_buffer, 0, 8);
    url_buffer[3] = HCR_FILE_TRANSFER_ENCRYPTION_NONE;
    memcpy(url_buffer + 8, url, sizeof(url) - 1);

    static char config_file_buffer[] =
        "[global]\n"
        "release = way\n"
        "url = http://did.not.change/in/any\n"
        "method = src/gz\n"
        "[feed all]\n"
        "[feed arm1176jzfshf-vfp]\n"
        "[feed raspberrypi]\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    mock_os->expect_os_map_file_to_memory(0, 0, &config_file, feed_config_filename);
    mock_os->expect_os_unmap_file(0, &config_file);

    auto *reg = lookup_register_expect_handlers(209, Regs::FileTransfer::DCP::write_209_download_url);

    reg->write(url_buffer, sizeof(url_buffer));
}

/*!\test
 * For forward compatibility, multiple space-separated fields are accepted, but
 * only the first two of them are actually used.
 *
 * In this test, the configuration is not expected to be updated because the
 * first two fields are no different from what's already stored on file.
 */
void test_feed_configuration_with_more_than_two_fields_is_accepted()
{
    static constexpr const char url[] = "http://www.ta-hifi.de/StrBo testing beta";
    uint8_t url_buffer[8 + sizeof(url) - 1];

    memset(url_buffer, 0, 8);
    url_buffer[3] = HCR_FILE_TRANSFER_ENCRYPTION_NONE;
    memcpy(url_buffer + 8, url, sizeof(url) - 1);

    static char config_file_buffer[] =
        "[global]\n"
        "release = testing\n"
        "url = http://www.ta-hifi.de/StrBo\n"
        "method = src/gz\n"
        "[feed all]\n"
        "[feed arm1176jzfshf-vfp]\n"
        "[feed raspberrypi]\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    mock_os->expect_os_map_file_to_memory(0, 0, &config_file, feed_config_filename);
    mock_os->expect_os_unmap_file(0, &config_file);

    auto *reg = lookup_register_expect_handlers(209, Regs::FileTransfer::DCP::write_209_download_url);

    reg->write(url_buffer, sizeof(url_buffer));
}

}

#endif /* !LOGGED_LOCKS_ENABLED  */

/*!@}*/
