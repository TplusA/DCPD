/*
 * Copyright (C) 2018  T+A elektroakustik GmbH & Co. KG
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

#include <doctest.h>

#include "accesspoint.hh"

#include "mock_connman_technology_registry.hh"
#include "mock_messages.hh"

TEST_SUITE_BEGIN("Access point mode management");

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
    std::unique_ptr<MockConnmanTechnologyRegistry::Wifi::Mock> mock_techreg_wifi;

  public:
    explicit AccessPointModeTestsBasicFixture():
        ap(tech_reg),
        mock_messages(new MockMessages::Mock),
        mock_techreg_wifi(new MockConnmanTechnologyRegistry::Wifi::Mock(tech_reg))
    {
        MockMessages::singleton = mock_messages.get();
        MockConnmanTechnologyRegistry::Wifi::singleton = mock_techreg_wifi.get();
    }

    virtual ~AccessPointModeTestsBasicFixture()
    {
        try
        {
            mock_messages->done();
            mock_techreg_wifi->done();
        }
        catch(...)
        {
            /* no throwing from dtors */
        }

        MockMessages::singleton = nullptr;
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
    }
};

TEST_CASE_FIXTURE(AccessPointModeTestsBasicFixture,
                  "Register status watcher after construction")
{
    bool called = false;

    ap.register_status_watcher(
        [this, &called]
        (Connman::TechnologyRegistry &tech_reg,
         Network::AccessPoint::Status old_status,
         Network::AccessPoint::Status new_status)
        {
            called = true;
            CHECK(&tech_reg == &this->tech_reg);
            CHECK(old_status == Network::AccessPoint::Status::UNKNOWN);
            CHECK(new_status == Network::AccessPoint::Status::UNKNOWN);
        });

    CHECK(called);
}

TEST_CASE_FIXTURE(AccessPointModeTestsBasicFixture,
                  "Cannot spawn access point without D-Bus connectivity")
{
    mock_messages->expect(
        new MockMessages::MsgError(0, LOG_CRIT,
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
        (Connman::TechnologyRegistry &tech_reg,
         Network::AccessPoint::Status old_status,
         Network::AccessPoint::Status new_status)
        {
            watched_status = new_status;
        });

    RequestDoneData done_data;

    mock_messages->expect(
        new MockMessages::MsgError(0, LOG_CRIT, "BUG: AP spawn request before start", true));

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

TEST_CASE_FIXTURE(AccessPointModeTestsWifiPoweredFixture,
                  "Spawn access point")
{
    mock_techreg_wifi->ignore(
        new MockConnmanTechnologyRegistry::Wifi::EnsureDBusProxy(true, sd.wifi_tech_proxy));

    Network::AccessPoint::Status watched_status = Network::AccessPoint::Status::UNKNOWN;

    ap.register_status_watcher(
        [&watched_status]
        (Connman::TechnologyRegistry &tech_reg,
         Network::AccessPoint::Status old_status,
         Network::AccessPoint::Status new_status)
        {
            watched_status = new_status;
        });

    REQUIRE(int(watched_status) == int(Network::AccessPoint::Status::DISABLED));

    mock_techreg_wifi->expect(
        new MockConnmanTechnologyRegistry::Wifi::SendPropertyOverDBus<std::string>(
                Connman::TechnologyPropertiesWIFI::Property::TETHERING_IDENTIFIER,
                "MyAccessPoint"));
    mock_techreg_wifi->expect(
        new MockConnmanTechnologyRegistry::Wifi::SendPropertyOverDBus<std::string>(
                Connman::TechnologyPropertiesWIFI::Property::TETHERING_PASSPHRASE,
                "super secret"));
    mock_techreg_wifi->expect(
        new MockConnmanTechnologyRegistry::Wifi::SendPropertyOverDBus<bool>(
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
            CHECK(int(watched_status) == int(Network::AccessPoint::Status::DISABLED));
        });
    CHECK(spawning);

    REQUIRE(int(watched_status) == int(Network::AccessPoint::Status::DISABLED));
    REQUIRE_FALSE(done_data.called_);

    /* simulate D-Bus method call completions from Connman */
    mock_techreg_wifi->simulate_send_property_over_dbus_done<std::string>(
            Connman::TechnologyPropertiesWIFI::Property::TETHERING_IDENTIFIER, false);
    mock_techreg_wifi->simulate_send_property_over_dbus_done<std::string>(
            Connman::TechnologyPropertiesWIFI::Property::TETHERING_PASSPHRASE, false);

    REQUIRE_FALSE(done_data.called_);
    mock_techreg_wifi->simulate_send_property_over_dbus_done<bool>(
            Connman::TechnologyPropertiesWIFI::Property::TETHERING, false);
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
        new MockConnmanTechnologyRegistry::Wifi::EnsureDBusProxy(true, sd.wifi_tech_proxy));

    mock_techreg_wifi->expect(
        new MockConnmanTechnologyRegistry::Wifi::SendPropertyOverDBus<std::string>(
                Connman::TechnologyPropertiesWIFI::Property::TETHERING_IDENTIFIER,
                "MyAccessPoint"));
    mock_techreg_wifi->expect(
        new MockConnmanTechnologyRegistry::Wifi::SendPropertyOverDBus<std::string>(
                Connman::TechnologyPropertiesWIFI::Property::TETHERING_PASSPHRASE,
                "super secret"));
    mock_techreg_wifi->expect(
        new MockConnmanTechnologyRegistry::Wifi::SendPropertyOverDBus<bool>(
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

    REQUIRE_FALSE(done_data.called_);
    mock_techreg_wifi->simulate_send_property_over_dbus_done<bool>(
            Connman::TechnologyPropertiesWIFI::Property::TETHERING, true);
    REQUIRE(done_data.called_);

    /* uh oh, a D-Bus failure */
    CHECK(int(done_data.result_) == int(Network::AccessPoint::RequestResult::FAILED));
    CHECK(int(done_data.error_) == int(Network::AccessPoint::Error::DBUS_FAILURE));
    CHECK(int(done_data.status_) == int(Network::AccessPoint::Status::DISABLED));
}

TEST_SUITE_END();
