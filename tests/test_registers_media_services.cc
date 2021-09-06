/*
 * Copyright (C) 2020, 2021  T+A elektroakustik GmbH & Co. KG
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
#include "dcpregs_audiosources.hh"
#include "dcpregs_mediaservices.hh"
#include "actor_id.h"
#include "mainloop.hh"

#include "mock_messages.hh"
#include "mock_credentials_dbus.hh"
#include "mock_airable_dbus.hh"
#include "mock_dbus_iface.hh"

#include "test_registers_common.hh"

/*
 * Here. Here it is, right down there.
 *
 * It is a stupid hack to speed up development. Instead of putting this little
 * fellow into a libtool convenience library like a good developer would
 * usually do, we are simply including that little C file. It will stay that
 * little, right?
 *
 * Watch it fail later.
 */
#include "dbus_common.c"

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

namespace spi_registers_media_services
{

static tdbuscredentialsRead *const dbus_cred_read_iface_dummy =
    reinterpret_cast<tdbuscredentialsRead *>(0xf017bc12);

static tdbuscredentialsWrite *const dbus_cred_write_iface_dummy =
    reinterpret_cast<tdbuscredentialsWrite *>(0xf127ac82);

static tdbusAirable *const dbus_airable_iface_dummy =
    reinterpret_cast<tdbusAirable *>(0xf280be98);

static MockMessages *mock_messages;
static MockCredentialsDBus *mock_credentials_dbus = nullptr;
static MockAirableDBus *mock_airable_dbus = nullptr;
static MockDBusIface *mock_dbus_iface;

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

    mock_credentials_dbus = new MockCredentialsDBus;
    cppcut_assert_not_null(mock_credentials_dbus);
    mock_credentials_dbus->init();
    mock_credentials_dbus_singleton = mock_credentials_dbus;

    mock_airable_dbus = new MockAirableDBus;
    cppcut_assert_not_null(mock_airable_dbus);
    mock_airable_dbus->init();
    mock_airable_dbus_singleton = mock_airable_dbus;

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

    Regs::AudioSources::set_unit_test_mode();
}

void cut_teardown()
{
    Regs::deinit();
    network_prefs_deinit();

    register_changed_data->check();

    delete register_changed_data;
    register_changed_data = nullptr;

    mock_messages->check();
    mock_credentials_dbus->check();
    mock_airable_dbus->check();
    mock_dbus_iface->check();

    mock_messages_singleton = nullptr;
    mock_credentials_dbus_singleton = nullptr;
    mock_airable_dbus_singleton = nullptr;
    mock_dbus_iface_singleton = nullptr;

    delete mock_messages;
    delete mock_credentials_dbus;
    delete mock_airable_dbus;
    delete mock_dbus_iface;

    mock_messages = nullptr;
    mock_credentials_dbus = nullptr;
    mock_airable_dbus = nullptr;
    mock_dbus_iface = nullptr;
}

/*!\test
 * In case no services are known, an XML indication so is returned.
 */
void test_read_out_empty_external_media_services()
{
    auto *reg = lookup_register_expect_handlers(106,
                                                Regs::MediaServices::DCP::read_106_media_service_list,
                                                Regs::MediaServices::DCP::write_106_media_service_list);

    std::vector<uint8_t> buffer;
    const MockCredentialsDBus::ReadGetKnownCategoriesData categories;

    mock_dbus_iface->expect_dbus_get_credentials_read_iface(dbus_cred_read_iface_dummy);
    mock_dbus_iface->expect_dbus_get_credentials_read_iface(dbus_cred_read_iface_dummy);
    mock_credentials_dbus->expect_tdbus_credentials_read_call_get_known_categories_sync(TRUE, dbus_cred_read_iface_dummy, categories);

    reg->read(buffer);

    const std::string expected_answer = "<services count=\"0\"/>";
    cut_assert_equal_memory(expected_answer.c_str(), expected_answer.size(),
                            buffer.data(), buffer.size());
}

/*!\test
 * Read out the whole set of media services and credentials.
 */
void test_read_out_external_media_services()
{
    auto *reg = lookup_register_expect_handlers(106,
                                                Regs::MediaServices::DCP::read_106_media_service_list,
                                                Regs::MediaServices::DCP::write_106_media_service_list);

    /* survey */
    static const uint8_t dummy = 0;
    mock_dbus_iface->expect_dbus_get_credentials_write_iface(dbus_cred_write_iface_dummy);
    reg->write(&dummy, 0);

    register_changed_data->check(106);

    /* read out */
    std::vector<uint8_t> buffer;

    const MockCredentialsDBus::ReadGetKnownCategoriesData categories =
    {
        std::make_tuple("tidal",  "TIDAL", std::vector<std::string>{"oauth", "preset"}),
        std::make_tuple("qobuz",  "Qobuz", std::vector<std::string>{}),
        std::make_tuple("deezer", "Deezer", std::vector<std::string>{}),
        std::make_tuple("funny",  "Service w/o default user", std::vector<std::string>{}),
    };

    const MockCredentialsDBus::ReadGetCredentialsData accounts_tidal =
    {
        std::make_pair("tidal.user@somewhere.com", "1234qwerasdf"),
    };

    const MockCredentialsDBus::ReadGetCredentialsData accounts_qobuz =
    {
        std::make_pair("Some guy", "secret"),
        std::make_pair("qobuz.user@somewhere.com", "abcdef"),
        std::make_pair("Someone else", "password"),
    };

    const MockCredentialsDBus::ReadGetCredentialsData accounts_deezer;

    const MockCredentialsDBus::ReadGetCredentialsData accounts_funny =
    {
        std::make_pair("Not the default", "funny&\"42>"),
    };

    mock_dbus_iface->expect_dbus_get_credentials_read_iface(dbus_cred_read_iface_dummy);
    mock_dbus_iface->expect_dbus_get_credentials_read_iface(dbus_cred_read_iface_dummy);
    mock_credentials_dbus->expect_tdbus_credentials_read_call_get_known_categories_sync(TRUE, dbus_cred_read_iface_dummy, categories);
    mock_dbus_iface->expect_dbus_get_credentials_read_iface(dbus_cred_read_iface_dummy);
    mock_credentials_dbus->expect_tdbus_credentials_read_call_get_credentials_sync(
        TRUE, dbus_cred_read_iface_dummy,
        accounts_tidal, accounts_tidal[0].first);
    mock_credentials_dbus->expect_tdbus_credentials_read_call_get_credentials_sync(
        TRUE, dbus_cred_read_iface_dummy,
        accounts_qobuz, accounts_qobuz[1].first);
    mock_credentials_dbus->expect_tdbus_credentials_read_call_get_credentials_sync(
        TRUE, dbus_cred_read_iface_dummy,
        accounts_deezer, "");
    mock_credentials_dbus->expect_tdbus_credentials_read_call_get_credentials_sync(
        TRUE, dbus_cred_read_iface_dummy,
        accounts_funny, "Does not exist");

    reg->read(buffer);

    const std::string expected_answer =
        "<services count=\"4\">"
        "<service id=\"tidal\" name=\"TIDAL\" has_oauth=\"true\">"
        "<account login=\"tidal.user@somewhere.com\" password=\"1234qwerasdf\" default=\"true\"/>"
        "</service>"
        "<service id=\"qobuz\" name=\"Qobuz\" has_oauth=\"false\">"
        "<account login=\"Some guy\" password=\"secret\"/>"
        "<account login=\"qobuz.user@somewhere.com\" password=\"abcdef\" default=\"true\"/>"
        "<account login=\"Someone else\" password=\"password\"/>"
        "</service>"
        "<service id=\"deezer\" name=\"Deezer\" has_oauth=\"false\"/>"
        "<service id=\"funny\" name=\"Service w/o default user\" has_oauth=\"false\">"
        "<account login=\"Not the default\" password=\"funny&amp;&quot;42&gt;\"/>"
        "</service>"
        "</services>";
    cut_assert_equal_memory(expected_answer.c_str(), expected_answer.size(),
                            buffer.data(), buffer.size());
}

/*!\test
 * Read out the whole set of unconfigured media services.
 */
void test_read_out_unconfigured_external_media_services()
{
    auto *reg = lookup_register_expect_handlers(106,
                                                Regs::MediaServices::DCP::read_106_media_service_list,
                                                Regs::MediaServices::DCP::write_106_media_service_list);

    /* survey */
    static const uint8_t dummy = 0;
    mock_dbus_iface->expect_dbus_get_credentials_write_iface(dbus_cred_write_iface_dummy);
    reg->write(&dummy, 0);

    register_changed_data->check(106);

    /* read out */
    std::vector<uint8_t> buffer;

    const MockCredentialsDBus::ReadGetKnownCategoriesData categories =
    {
        std::make_tuple("tidal",  "TIDAL", std::vector<std::string>{"oauth", "preset"}),
        std::make_tuple("deezer", "Deezer", std::vector<std::string>{}),
    };

    const MockCredentialsDBus::ReadGetCredentialsData no_accounts;

    mock_dbus_iface->expect_dbus_get_credentials_read_iface(dbus_cred_read_iface_dummy);
    mock_credentials_dbus->expect_tdbus_credentials_read_call_get_known_categories_sync(TRUE, dbus_cred_read_iface_dummy, categories);
    mock_dbus_iface->expect_dbus_get_credentials_read_iface(dbus_cred_read_iface_dummy);
    mock_credentials_dbus->expect_tdbus_credentials_read_call_get_credentials_sync(
        TRUE, dbus_cred_read_iface_dummy,
        no_accounts, "");
    mock_credentials_dbus->expect_tdbus_credentials_read_call_get_credentials_sync(
        TRUE, dbus_cred_read_iface_dummy,
        no_accounts, "");

    mock_dbus_iface->expect_dbus_get_credentials_read_iface(dbus_cred_read_iface_dummy);
    reg->read(buffer);

    const std::string expected_answer =
        "<services count=\"2\">"
        "<service id=\"tidal\" name=\"TIDAL\" has_oauth=\"true\"/>"
        "<service id=\"deezer\" name=\"Deezer\" has_oauth=\"false\"/>"
        "</services>";
    cut_assert_equal_memory(expected_answer.c_str(), expected_answer.size(),
                            buffer.data(), buffer.size());
}

/*!\test
 * Writing nothing to the register triggers a meda services survey.
 */
void test_trigger_media_services_survey()
{
    auto *reg = lookup_register_expect_handlers(106,
                                                Regs::MediaServices::DCP::read_106_media_service_list,
                                                Regs::MediaServices::DCP::write_106_media_service_list);

    static const uint8_t dummy = 0;
    mock_dbus_iface->expect_dbus_get_credentials_write_iface(dbus_cred_write_iface_dummy);
    reg->write(&dummy, 0);

    register_changed_data->check(106);
}

/*!\test
 * Write single user credentials for specific service.
 */
void test_set_service_credentials()
{
    auto *reg = lookup_register_expect_handlers(106,
                                                Regs::MediaServices::DCP::read_106_media_service_list,
                                                Regs::MediaServices::DCP::write_106_media_service_list);

    static const uint8_t data[] = "tidal\0login email\0my password";

    mock_dbus_iface->expect_dbus_get_credentials_write_iface(dbus_cred_write_iface_dummy);
    mock_dbus_iface->expect_dbus_get_credentials_write_iface(dbus_cred_write_iface_dummy);
    mock_credentials_dbus->expect_tdbus_credentials_write_call_delete_credentials_sync(
        TRUE, dbus_cred_write_iface_dummy,
        "tidal", "", "");
    mock_dbus_iface->expect_dbus_get_airable_sec_iface(dbus_airable_iface_dummy);
    mock_dbus_iface->expect_dbus_get_airable_sec_iface(dbus_airable_iface_dummy);
    mock_airable_dbus->expect_tdbus_airable_call_external_service_logout_sync(
        TRUE, dbus_airable_iface_dummy,
        "tidal", "", TRUE, guchar(ACTOR_ID_LOCAL_UI));
    mock_dbus_iface->expect_dbus_get_credentials_write_iface(dbus_cred_write_iface_dummy);
    mock_credentials_dbus->expect_tdbus_credentials_write_call_set_credentials_sync(
        TRUE, dbus_cred_write_iface_dummy,
        "tidal", "login email", "my password", TRUE);
    mock_dbus_iface->expect_dbus_get_airable_sec_iface(dbus_airable_iface_dummy);
    mock_airable_dbus->expect_tdbus_airable_call_external_service_login_sync(
        TRUE, dbus_airable_iface_dummy,
        "tidal", "login email", TRUE, guchar(ACTOR_ID_LOCAL_UI));

    reg->write(data, sizeof(data) - 1);

    register_changed_data->check(80);
}

/*!\test
 * Password may be zero-terminated.
 */
void test_password_may_be_zero_terminated()
{
    auto *reg = lookup_register_expect_handlers(106,
                                                Regs::MediaServices::DCP::read_106_media_service_list,
                                                Regs::MediaServices::DCP::write_106_media_service_list);

    static const uint8_t data[] = "deezer\0login\0password\0";

    mock_dbus_iface->expect_dbus_get_credentials_write_iface(dbus_cred_write_iface_dummy);
    mock_dbus_iface->expect_dbus_get_credentials_write_iface(dbus_cred_write_iface_dummy);
    mock_credentials_dbus->expect_tdbus_credentials_write_call_delete_credentials_sync(
        TRUE, dbus_cred_write_iface_dummy,
        "deezer", "", "");
    mock_dbus_iface->expect_dbus_get_airable_sec_iface(dbus_airable_iface_dummy);
    mock_dbus_iface->expect_dbus_get_airable_sec_iface(dbus_airable_iface_dummy);
    mock_airable_dbus->expect_tdbus_airable_call_external_service_logout_sync(
        TRUE, dbus_airable_iface_dummy,
        "deezer", "", TRUE, guchar(ACTOR_ID_LOCAL_UI));
    mock_dbus_iface->expect_dbus_get_credentials_write_iface(dbus_cred_write_iface_dummy);
    mock_credentials_dbus->expect_tdbus_credentials_write_call_set_credentials_sync(
        TRUE, dbus_cred_write_iface_dummy,
        "deezer", "login", "password", TRUE);
    mock_dbus_iface->expect_dbus_get_airable_sec_iface(dbus_airable_iface_dummy);
    mock_airable_dbus->expect_tdbus_airable_call_external_service_login_sync(
        TRUE, dbus_airable_iface_dummy,
        "deezer", "login", TRUE, guchar(ACTOR_ID_LOCAL_UI));

    reg->write(data, sizeof(data) - 1);

    register_changed_data->check(80);
}

/*!\test
 * The service ID must always be set when writing credentials.
 */
void test_set_service_credentials_requires_service_id()
{
    auto *reg = lookup_register_expect_handlers(106,
                                                Regs::MediaServices::DCP::read_106_media_service_list,
                                                Regs::MediaServices::DCP::write_106_media_service_list);

    static const uint8_t data[] = "\0login email\0my password";

    mock_messages->expect_msg_error(0, EINVAL, "Empty service ID sent to register 106");
    mock_dbus_iface->expect_dbus_get_credentials_write_iface(dbus_cred_write_iface_dummy);

    write_buffer_expect_failure(reg, data, sizeof(data) - 1, -1);
}

/*!\test
 * If there is a password, then there must also be a login.
 */
void test_set_service_credentials_requires_login_for_password()
{
    auto *reg = lookup_register_expect_handlers(106,
                                                Regs::MediaServices::DCP::read_106_media_service_list,
                                                Regs::MediaServices::DCP::write_106_media_service_list);

    static const uint8_t data[] = "tidal\0\0my password";

    mock_messages->expect_msg_error(0, EINVAL, "Empty login sent to register 106");
    mock_dbus_iface->expect_dbus_get_credentials_write_iface(dbus_cred_write_iface_dummy);

    write_buffer_expect_failure(reg, data, sizeof(data) - 1, -1);
}

/*!\test
 * If there is a login, then there must also be a password.
 */
void test_set_service_credentials_requires_password_for_login()
{
    auto *reg = lookup_register_expect_handlers(106,
                                                Regs::MediaServices::DCP::read_106_media_service_list,
                                                Regs::MediaServices::DCP::write_106_media_service_list);

    static const uint8_t data[] = "tidal\0login\0";

    mock_messages->expect_msg_error(0, EINVAL, "Empty password sent to register 106");
    mock_dbus_iface->expect_dbus_get_credentials_write_iface(dbus_cred_write_iface_dummy);

    write_buffer_expect_failure(reg, data, sizeof(data) - 1, -1);
}

/*!\test
 * There must be no junk after a zero-terminated password.
 */
void test_no_junk_after_password_allowed()
{
    auto *reg = lookup_register_expect_handlers(106,
                                                Regs::MediaServices::DCP::read_106_media_service_list,
                                                Regs::MediaServices::DCP::write_106_media_service_list);

    static const uint8_t data[] = "tidal\0login\0password\0\0";

    mock_messages->expect_msg_error(0, EINVAL, "Malformed data written to register 106");
    mock_dbus_iface->expect_dbus_get_credentials_write_iface(dbus_cred_write_iface_dummy);

    write_buffer_expect_failure(reg, data, sizeof(data) - 1,-1);
}

}

#endif /* !LOGGED_LOCKS_ENABLED  */

/*!@}*/
