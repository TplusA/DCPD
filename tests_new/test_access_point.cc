/*
 * Copyright (C) 2018, 2019, 2020, 2022  T+A elektroakustik GmbH & Co. KG
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

#include <doctest.h>

#include "accesspoint_manager.hh"
#include "mainloop.hh"

#define MOCK_EXPECTATION_WITH_EXPECTATION_SEQUENCE_SINGLETON
#include "mock_connman_technology_registry.hh"
#include "mock_backtrace.hh"
#include "mock_messages.hh"

#if !LOGGED_LOCKS_ENABLED

std::shared_ptr<MockExpectationSequence> mock_expectation_sequence_singleton =
    std::make_shared<MockExpectationSequence>();

TEST_SUITE_BEGIN("Access point mode management");

MainLoop::Queue MainLoop::detail::queued_work;
static int queued_work_notified_;

static void process_queued_work(int expected_notifications = -1)
{
    if(expected_notifications >= 0)
        CHECK(queued_work_notified_ == expected_notifications);

    if(queued_work_notified_ > 0)
    {
        const auto &work(MainLoop::detail::queued_work.take());

        if(expected_notifications >= 0)
            CHECK(work.size() == size_t(expected_notifications));

        queued_work_notified_ = 0;

        for(const auto &fn : work)
            fn();
    }

    CHECK(MainLoop::detail::queued_work.take().empty());
}

void MainLoop::detail::notify_main_loop()
{
    ++queued_work_notified_;
}

struct RequestDoneData
{
    bool called_;
    Network::AccessPoint::RequestResult result_;
    Network::AccessPoint::Error error_;
    Network::AccessPoint::Status status_;

    RequestDoneData(const RequestDoneData &) = delete;
    RequestDoneData(RequestDoneData &&) = default;
    RequestDoneData &operator=(const RequestDoneData &) = delete;
    RequestDoneData &operator=(RequestDoneData &&) = default;

    explicit RequestDoneData(): called_(false) {}

    void reset() { called_ = false; }

    void set(Network::AccessPoint::RequestResult result,
             Network::AccessPoint::Error error,
             Network::AccessPoint::Status status)
    {
        called_ = true;
        result_ = result;
        error_ = error;
        status_ = status;
    }
};

/*!
 * Test fixture: access point instance, D-Bus connection not setup yet.
 *
 * This fixture is for early startup tests or for tests that do not require an
 * initialized technology registry.
 */
class AccessPointModeTestsBasicFixture
{
  protected:
    Connman::TechnologyRegistry tech_reg;
    Network::AccessPoint ap;
    std::unique_ptr<MockMessages::Mock> mock_messages;
    std::unique_ptr<MockBacktrace::Mock> mock_backtrace;
    std::unique_ptr<MockConnmanTechnologyRegistry::Wifi::Mock> mock_techreg_wifi;

  public:
    explicit AccessPointModeTestsBasicFixture():
        ap(tech_reg),
        mock_messages(std::make_unique<MockMessages::Mock>()),
        mock_backtrace(std::make_unique<MockBacktrace::Mock>()),
        mock_techreg_wifi(std::make_unique<MockConnmanTechnologyRegistry::Wifi::Mock>(tech_reg))
    {
        mock_expectation_sequence_singleton->reset();
        queued_work_notified_ = 0;
        MockMessages::singleton = mock_messages.get();
        MockBacktrace::singleton = mock_backtrace.get();
        MockConnmanTechnologyRegistry::Wifi::singleton = mock_techreg_wifi.get();

        REQUIRE(queued_work_notified_ == 0);
        REQUIRE(MainLoop::detail::queued_work.take().empty());
    }

    virtual ~AccessPointModeTestsBasicFixture()
    {
        process_queued_work(0);

        try
        {
            mock_expectation_sequence_singleton->done();
            mock_messages->done();
            mock_backtrace->done();
            mock_techreg_wifi->done();
        }
        catch(...)
        {
            /* no throwing from dtors */
        }

        MockMessages::singleton = nullptr;
        MockBacktrace::singleton = nullptr;
        MockConnmanTechnologyRegistry::Wifi::singleton = nullptr;
    }
};

/*!
 * Fixture: D-Bus connection established, WLAN is powered, AP started.
 */
class AccessPointModeTestsWifiPoweredFixture: public AccessPointModeTestsBasicFixture
{
  protected:
    MockConnmanTechnologyRegistry::FixtureSetupData sd;

  public:
    explicit AccessPointModeTestsWifiPoweredFixture()
    {
        sd.wifi_tech_proxy = reinterpret_cast<struct _tdbusconnmanTechnology *>(0xf00f1234);
        sd.wifi_is_powered = true;
        tech_reg.connect_to_connman(&sd);
        ap.start();
        process_queued_work(7);
    }
};

/*!
 * Fixture: Access point manager fully set up, WLAN connected, AP disabled.
 */
class AccessPointManagerAPDisabledFixture: public AccessPointModeTestsBasicFixture
{
  private:
    struct ExpectationInjector
    {
        ExpectationInjector(MockMessages::Mock &mock_messages)
        {
            mock_messages.expect(
                std::make_unique<MockMessages::MsgInfo>("Access point status UNKNOWN -> UNKNOWN", false));
        }
    };

    ExpectationInjector injector;

  protected:
    MockConnmanTechnologyRegistry::FixtureSetupData sd;
    Network::AccessPointManager apman;

  public:
    explicit AccessPointManagerAPDisabledFixture():
        injector(*mock_messages),
        apman(ap)
    {
        mock_messages->done();
        sd.wifi_tech_proxy = reinterpret_cast<struct _tdbusconnmanTechnology *>(0xb3019ac7);
        sd.wifi_is_powered = true;
        sd.wifi_is_connected = true;
        tech_reg.connect_to_connman(&sd);
        mock_messages->expect(
            std::make_unique<MockMessages::MsgInfo>("Access point status UNKNOWN -> DISABLED", false));
        apman.start();
        process_queued_work(7);
        mock_messages->done();
    }
};

/*!
 * Fixture: Access point manager fully set up, AP enabled.
 */
class AccessPointManagerAPEnabledFixture: public AccessPointModeTestsBasicFixture
{
  private:
    struct ExpectationInjector
    {
        ExpectationInjector(MockMessages::Mock &mock_messages)
        {
            mock_messages.expect(
                std::make_unique<MockMessages::MsgInfo>("Access point status UNKNOWN -> UNKNOWN", false));
        }
    };

    ExpectationInjector injector;

  protected:
    MockConnmanTechnologyRegistry::FixtureSetupData sd;
    Network::AccessPointManager apman;

  public:
    explicit AccessPointManagerAPEnabledFixture():
        injector(*mock_messages),
        apman(ap)
    {
        sd.wifi_tech_proxy = reinterpret_cast<struct _tdbusconnmanTechnology *>(0xb3019ac7);
        sd.wifi_is_powered = true;
        sd.wifi_is_connected = true;

        tech_reg.connect_to_connman(&sd);

        mock_messages->done();
        mock_messages->expect(
            std::make_unique<MockMessages::MsgInfo>("Access point status UNKNOWN -> DISABLED", false));
        process_queued_work(7);
        mock_messages->done();

        apman.start();

        mock_techreg_wifi->simulate_property_changed_signal("TetheringIdentifier",
                                                            std::string("Hello World!"));
        mock_techreg_wifi->simulate_property_changed_signal("TetheringPassphrase",
                                                            std::string("start123"));
        mock_techreg_wifi->simulate_property_changed_signal("Tethering", true);

        mock_messages->done();
        mock_messages->expect(
            std::make_unique<MockMessages::MsgInfo>("Access point status DISABLED -> ACTIVE", false));
        mock_messages->expect(
            std::make_unique<MockMessages::MsgInfo>("Access point SSID \"Hello World!\"", false));
        mock_messages->expect(
            std::make_unique<MockMessages::MsgInfo>("Access point passphrase \"start123\"", false));
        process_queued_work(3);
        mock_techreg_wifi->done();
    }
};

TEST_CASE_FIXTURE(AccessPointModeTestsBasicFixture,
                  "Register status watcher after construction")
{
    bool called = false;

    ap.register_status_watcher(
        [this, &called]
        (Connman::TechnologyRegistry &tr,
         Network::AccessPoint::Status old_status,
         Network::AccessPoint::Status new_status)
        {
            called = true;
            CHECK(&tr == &this->tech_reg);
            CHECK(old_status == Network::AccessPoint::Status::UNKNOWN);
            CHECK(new_status == Network::AccessPoint::Status::UNKNOWN);
        });

    CHECK(called);
}

TEST_CASE_FIXTURE(AccessPointModeTestsBasicFixture,
                  "Cannot spawn access point without D-Bus connectivity")
{
    mock_messages->expect(
        std::make_unique<MockMessages::MsgError>(0, LOG_CRIT,
                                                 "BUG: Technology registry unavailable (no D-Bus connection)",
                                                 true));
    ap.start();
}

TEST_CASE_FIXTURE(AccessPointModeTestsBasicFixture,
                  "Cannot spawn access point before starting it")
{
    Network::AccessPoint::Status watched_status;

    ap.register_status_watcher(
        [&watched_status]
        (Connman::TechnologyRegistry &tr,
         Network::AccessPoint::Status old_status,
         Network::AccessPoint::Status new_status)
        {
            watched_status = new_status;
        });

    RequestDoneData done_data;

    mock_messages->expect(
        std::make_unique<MockMessages::MsgError>(0, LOG_CRIT, "BUG: AP spawn request before start", true));

    const bool spawning = ap.spawn_request("MyAccessPoint", "super secret",
        [&done_data]
        (Network::AccessPoint::RequestResult result,
         Network::AccessPoint::Error error,
         Network::AccessPoint::Status status)
        {
            done_data.set(result, error, status);
        });
    CHECK_FALSE(spawning);

    REQUIRE(done_data.called_);
    CHECK(int(done_data.result_) == int(Network::AccessPoint::RequestResult::FAILED));
    CHECK(int(done_data.error_) == int(Network::AccessPoint::Error::BUSY));
    CHECK(int(done_data.status_) == int(Network::AccessPoint::Status::UNKNOWN));
}

TEST_CASE_FIXTURE(AccessPointModeTestsBasicFixture,
                  "Access point manager gets initialized from access point instance")
{
    MockConnmanTechnologyRegistry::FixtureSetupData sd;
    sd.wifi_tech_proxy = reinterpret_cast<struct _tdbusconnmanTechnology *>(0x9821abcd);
    sd.wifi_properties_are_initialized = false;
    tech_reg.connect_to_connman(&sd);

    mock_messages->expect(std::make_unique<MockMessages::MsgInfo>("Access point status UNKNOWN -> UNKNOWN", false));
    Network::AccessPointManager apman(ap);
}

TEST_CASE("Access point manager gets update from access point when started")
{
    process_queued_work(0);

    Connman::TechnologyRegistry tech_reg;
    std::unique_ptr<MockMessages::Mock> mock_messages(std::make_unique<MockMessages::Mock>());
    std::unique_ptr<MockConnmanTechnologyRegistry::Wifi::Mock> mock_techreg_wifi(std::make_unique<MockConnmanTechnologyRegistry::Wifi::Mock>(tech_reg));
    MockMessages::singleton = mock_messages.get();
    MockConnmanTechnologyRegistry::Wifi::singleton = mock_techreg_wifi.get();

    MockConnmanTechnologyRegistry::FixtureSetupData sd;
    sd.wifi_tech_proxy = reinterpret_cast<struct _tdbusconnmanTechnology *>(0x19283746);
    sd.wifi_is_powered = true;
    sd.wifi_is_connected = true;
    sd.wifi_is_tethering = true;
    sd.wifi_tethering_identifier = "Hello World!";
    sd.wifi_tethering_passphrase = "start123";

    try
    {
        tech_reg.connect_to_connman(&sd);
        process_queued_work(7);

        Network::AccessPoint ap(tech_reg);

        mock_messages->expect(
            std::make_unique<MockMessages::MsgInfo>("Access point status UNKNOWN -> UNKNOWN", false));
        Network::AccessPointManager apman(ap);
        mock_messages->done();

        mock_messages->expect(
            std::make_unique<MockMessages::MsgInfo>("Access point status UNKNOWN -> ACTIVE", false));
        mock_messages->expect(
            std::make_unique<MockMessages::MsgInfo>("Access point SSID \"Hello World!\"", false));
        mock_messages->expect(
            std::make_unique<MockMessages::MsgInfo>("Access point passphrase \"start123\"", false));
        apman.start();

        mock_messages->done();
        mock_techreg_wifi->done();
        MockMessages::singleton = nullptr;
        MockConnmanTechnologyRegistry::Wifi::singleton = nullptr;
    }
    catch(...)
    {
        MockMessages::singleton = nullptr;
        MockConnmanTechnologyRegistry::Wifi::singleton = nullptr;
        throw;
    }

    CHECK(MainLoop::detail::queued_work.take().empty());
}

TEST_CASE_FIXTURE(AccessPointModeTestsWifiPoweredFixture,
                  "Spawn access point")
{
    mock_techreg_wifi->ignore(
        std::make_unique<MockConnmanTechnologyRegistry::Wifi::EnsureDBusProxy>(true, sd.wifi_tech_proxy));

    Network::AccessPoint::Status watched_status = Network::AccessPoint::Status::UNKNOWN;

    ap.register_status_watcher(
        [&watched_status]
        (Connman::TechnologyRegistry &tr,
         Network::AccessPoint::Status old_status,
         Network::AccessPoint::Status new_status)
        {
            watched_status = new_status;
        });

    REQUIRE(int(watched_status) == int(Network::AccessPoint::Status::DISABLED));

    mock_techreg_wifi->expect(
        std::make_unique<MockConnmanTechnologyRegistry::Wifi::SendPropertyOverDBus<std::string>>(
                Connman::TechnologyPropertiesWIFI::Property::TETHERING_IDENTIFIER,
                "MyAccessPoint"));
    mock_techreg_wifi->expect(
        std::make_unique<MockConnmanTechnologyRegistry::Wifi::SendPropertyOverDBus<std::string>>(
                Connman::TechnologyPropertiesWIFI::Property::TETHERING_PASSPHRASE,
                "super secret"));
    mock_techreg_wifi->expect(
        std::make_unique<MockConnmanTechnologyRegistry::Wifi::SendPropertyOverDBus<bool>>(
                Connman::TechnologyPropertiesWIFI::Property::TETHERING, true));

    RequestDoneData done_data;

    const bool spawning = ap.spawn_request("MyAccessPoint", "super secret",
        [&done_data, &watched_status]
        (Network::AccessPoint::RequestResult result,
         Network::AccessPoint::Error error,
         Network::AccessPoint::Status status)
        {
            CHECK(int(status) == int(Network::AccessPoint::Status::ACTIVE));
            done_data.set(result, error, status);

            /* AP status update follows request done notification */
            CHECK(int(watched_status) == int(Network::AccessPoint::Status::ACTIVATING));
        });
    CHECK(spawning);

    process_queued_work(0);
    REQUIRE(int(watched_status) == int(Network::AccessPoint::Status::ACTIVATING));
    REQUIRE_FALSE(done_data.called_);

    /* simulate D-Bus method call completions from Connman */
    mock_techreg_wifi->simulate_send_property_over_dbus_done<std::string>(
            Connman::TechnologyPropertiesWIFI::Property::TETHERING_IDENTIFIER, false);
    mock_techreg_wifi->simulate_send_property_over_dbus_done<std::string>(
            Connman::TechnologyPropertiesWIFI::Property::TETHERING_PASSPHRASE, false);
    mock_techreg_wifi->simulate_send_property_over_dbus_done<bool>(
            Connman::TechnologyPropertiesWIFI::Property::TETHERING, false);

    REQUIRE_FALSE(done_data.called_);
    process_queued_work(3);
    REQUIRE(done_data.called_);

    /* all the callbacks have been called, we are ready for take off */
    CHECK(int(done_data.result_) == int(Network::AccessPoint::RequestResult::OK));
    CHECK(int(done_data.error_) == int(Network::AccessPoint::Error::OK));
    CHECK(int(done_data.status_) == int(Network::AccessPoint::Status::ACTIVE));
    CHECK(int(watched_status) == int(Network::AccessPoint::Status::ACTIVE));

    /* this one will be sent in by Connman as well */
    mock_techreg_wifi->simulate_property_changed_signal("Tethering", true);

    REQUIRE(int(watched_status) == int(Network::AccessPoint::Status::ACTIVE));
}

TEST_CASE_FIXTURE(AccessPointModeTestsWifiPoweredFixture,
                  "Spawn access point fails")
{
    mock_techreg_wifi->ignore(
        std::make_unique<MockConnmanTechnologyRegistry::Wifi::EnsureDBusProxy>(true, sd.wifi_tech_proxy));

    mock_techreg_wifi->expect(
        std::make_unique<MockConnmanTechnologyRegistry::Wifi::SendPropertyOverDBus<std::string>>(
                Connman::TechnologyPropertiesWIFI::Property::TETHERING_IDENTIFIER,
                "MyAccessPoint"));
    mock_techreg_wifi->expect(
        std::make_unique<MockConnmanTechnologyRegistry::Wifi::SendPropertyOverDBus<std::string>>(
                Connman::TechnologyPropertiesWIFI::Property::TETHERING_PASSPHRASE,
                "super secret"));
    mock_techreg_wifi->expect(
        std::make_unique<MockConnmanTechnologyRegistry::Wifi::SendPropertyOverDBus<bool>>(
                Connman::TechnologyPropertiesWIFI::Property::TETHERING, true));

    RequestDoneData done_data;

    const bool spawning = ap.spawn_request("MyAccessPoint", "super secret",
        [&done_data]
        (Network::AccessPoint::RequestResult result,
         Network::AccessPoint::Error error,
         Network::AccessPoint::Status status)
        {
            done_data.set(result, error, status);
        });
    CHECK(spawning);

    REQUIRE_FALSE(done_data.called_);

    /* simulate D-Bus method call completions from Connman */
    mock_techreg_wifi->simulate_send_property_over_dbus_done<std::string>(
            Connman::TechnologyPropertiesWIFI::Property::TETHERING_IDENTIFIER, false);
    mock_techreg_wifi->simulate_send_property_over_dbus_done<std::string>(
            Connman::TechnologyPropertiesWIFI::Property::TETHERING_PASSPHRASE, false);
    mock_techreg_wifi->simulate_send_property_over_dbus_done<bool>(
            Connman::TechnologyPropertiesWIFI::Property::TETHERING, true);

    REQUIRE_FALSE(done_data.called_);
    process_queued_work(3);
    REQUIRE(done_data.called_);

    /* uh oh, a D-Bus failure */
    CHECK(int(done_data.result_) == int(Network::AccessPoint::RequestResult::FAILED));
    CHECK(int(done_data.error_) == int(Network::AccessPoint::Error::DBUS_FAILURE));
    CHECK(int(done_data.status_) == int(Network::AccessPoint::Status::DISABLED));
}

TEST_CASE_FIXTURE(AccessPointManagerAPEnabledFixture,
                  "Shut down active access point via AP manager")
{
    CHECK(int(apman.get_status()) == int(Network::AccessPoint::Status::ACTIVE));

    mock_techreg_wifi->ignore(
        std::make_unique<MockConnmanTechnologyRegistry::Wifi::EnsureDBusProxy>(true, sd.wifi_tech_proxy));

    mock_techreg_wifi->expect(
        std::make_unique<MockConnmanTechnologyRegistry::Wifi::SendPropertyOverDBus<bool>>(
                Connman::TechnologyPropertiesWIFI::Property::TETHERING, false));
    mock_techreg_wifi->expect(
        std::make_unique<MockConnmanTechnologyRegistry::Wifi::SendPropertyOverDBus<std::string>>(
                Connman::TechnologyPropertiesWIFI::Property::TETHERING_PASSPHRASE, ""));
    mock_techreg_wifi->expect(
        std::make_unique<MockConnmanTechnologyRegistry::Wifi::SendPropertyOverDBus<std::string>>(
                Connman::TechnologyPropertiesWIFI::Property::TETHERING_IDENTIFIER, ""));

    CHECK(apman.deactivate());

    /* simulate D-Bus method call completions from Connman */
    mock_messages->expect(
        std::make_unique<MockMessages::MsgVinfo>(MESSAGE_LEVEL_DEBUG,
                                                 "Access point shutdown request result: OK (OK) -> DISABLED",
                                                 false));
    CHECK(int(apman.get_status()) == int(Network::AccessPoint::Status::ACTIVE));
    mock_techreg_wifi->simulate_send_property_over_dbus_done<bool>(
            Connman::TechnologyPropertiesWIFI::Property::TETHERING, false);
    mock_messages->expect(
        std::make_unique<MockMessages::MsgInfo>("Access point status ACTIVE -> DISABLED", false));
    process_queued_work(1);
    CHECK(int(apman.get_status()) == int(Network::AccessPoint::Status::DISABLED));
    mock_messages->done();

    mock_techreg_wifi->simulate_send_property_over_dbus_done<std::string>(
            Connman::TechnologyPropertiesWIFI::Property::TETHERING_IDENTIFIER, false);
    mock_techreg_wifi->simulate_send_property_over_dbus_done<std::string>(
            Connman::TechnologyPropertiesWIFI::Property::TETHERING_PASSPHRASE, false);
    process_queued_work(2);
}

TEST_CASE_FIXTURE(AccessPointManagerAPDisabledFixture,
                  "Spawn access point via AP manager")
{
    CHECK(int(apman.get_status()) == int(Network::AccessPoint::Status::DISABLED));

    mock_techreg_wifi->ignore(
        std::make_unique<MockConnmanTechnologyRegistry::Wifi::EnsureDBusProxy>(true, sd.wifi_tech_proxy));

    mock_messages->expect(
        std::make_unique<MockMessages::MsgInfo>("Access point status DISABLED -> ACTIVATING", false));
    mock_techreg_wifi->expect(
        std::make_unique<MockConnmanTechnologyRegistry::Wifi::SendPropertyOverDBus<std::string>>(
                Connman::TechnologyPropertiesWIFI::Property::TETHERING_IDENTIFIER,
                "MyNet"));
    mock_techreg_wifi->expect(
        std::make_unique<MockConnmanTechnologyRegistry::Wifi::SendPropertyOverDBus<std::string>>(
                Connman::TechnologyPropertiesWIFI::Property::TETHERING_PASSPHRASE,
                "12345678"));
    mock_techreg_wifi->expect(
        std::make_unique<MockConnmanTechnologyRegistry::Wifi::SendPropertyOverDBus<bool>>(
                Connman::TechnologyPropertiesWIFI::Property::TETHERING, true));

    CHECK(int(apman.get_status()) == int(Network::AccessPoint::Status::DISABLED));
    CHECK(apman.activate("MyNet", "12345678"));

    /* simulate D-Bus method call completions from Connman */
    mock_techreg_wifi->simulate_send_property_over_dbus_done<std::string>(
            Connman::TechnologyPropertiesWIFI::Property::TETHERING_IDENTIFIER, false);
    mock_techreg_wifi->simulate_send_property_over_dbus_done<std::string>(
            Connman::TechnologyPropertiesWIFI::Property::TETHERING_PASSPHRASE, false);
    mock_techreg_wifi->simulate_send_property_over_dbus_done<bool>(
            Connman::TechnologyPropertiesWIFI::Property::TETHERING, false);

    mock_messages->expect(
        std::make_unique<MockMessages::MsgVinfo>(MESSAGE_LEVEL_DEBUG,
                                                 "Access point spawn request result: OK (OK) -> ACTIVE",
                                                 false));
    mock_messages->expect(
        std::make_unique<MockMessages::MsgInfo>("Access point status ACTIVATING -> ACTIVE", false));
    mock_messages->expect(
        std::make_unique<MockMessages::MsgInfo>("Access point SSID \"MyNet\"", false));
    mock_messages->expect(
        std::make_unique<MockMessages::MsgInfo>("Access point passphrase \"12345678\"", false));
    CHECK(int(apman.get_status()) == int(Network::AccessPoint::Status::ACTIVATING));
    process_queued_work(3);
    CHECK(int(apman.get_status()) == int(Network::AccessPoint::Status::ACTIVE));
}

TEST_CASE_FIXTURE(AccessPointManagerAPDisabledFixture,
                  "SSID must not be empty")
{
    CHECK(apman.get_status() == Network::AccessPoint::Status::DISABLED);
    mock_messages->expect(
        std::make_unique<MockMessages::MsgError>(EINVAL, LOG_ERR,
                                                 "The access point SSID must not be empty (Invalid argument)",
                                                 false));
    CHECK_FALSE(apman.activate("", "12345678"));
    CHECK(apman.get_status() == Network::AccessPoint::Status::DISABLED);
}

TEST_CASE_FIXTURE(AccessPointManagerAPDisabledFixture,
                  "Minimum passphrase length is 8 characters")
{
    CHECK(apman.get_status() == Network::AccessPoint::Status::DISABLED);
    mock_messages->expect(
        std::make_unique<MockMessages::MsgError>(EINVAL, LOG_ERR,
                                                 "The access point passphrase must be no shorter than 8 characters (Invalid argument)",
                                                 false));
    CHECK_FALSE(apman.activate("MyNet", "1234567"));
    CHECK(apman.get_status() == Network::AccessPoint::Status::DISABLED);
}

TEST_SUITE_END();

#endif /* !LOGGED_LOCKS_ENABLED */
