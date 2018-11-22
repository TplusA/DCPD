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

#include "connman_service.hh"

#include "mock_messages.hh"
#include "mock_os.hh"

#include <iostream>

TEST_SUITE_BEGIN("Parsing ConnMan service names");

TEST_CASE("Exception on nullptr")
{
    CHECK_THROWS_AS(Connman::ServiceNameComponents::from_service_name(nullptr),
                    std::domain_error);
}

TEST_CASE("Exception on empty name")
{
    CHECK_THROWS_AS(Connman::ServiceNameComponents::from_service_name(""),
                    std::domain_error);
}

TEST_CASE("Wireless services")
{
    auto first(Connman::ServiceNameComponents::from_service_name(
            "wifi_82b01c771c09_4d794e6574776f726b_managed_psk"));
    CHECK(first.technology_ == Connman::Technology::WLAN);
    CHECK(first.mac_address_ == "82:B0:1C:77:1C:09");
    CHECK(first.ssid_ == "4d794e6574776f726b");
    CHECK(first.security_ == "psk");

    auto second(Connman::ServiceNameComponents::from_service_name(
            "wifi_a215a909cbee_4f75725072657474794e6574776f726b486173414c6f6e674e616d65_managed_ieee8021x"));

    CHECK(second.technology_ == Connman::Technology::WLAN);
    CHECK(second.mac_address_ == "A2:15:A9:09:CB:EE");
    CHECK(second.ssid_ == "4f75725072657474794e6574776f726b486173414c6f6e674e616d65");
    CHECK(second.security_ == "ieee8021x");
}

TEST_CASE("Wired services")
{
    auto first(Connman::ServiceNameComponents::from_service_name(
            "ethernet_92b01c771c08_cable"));
    CHECK(first.technology_ == Connman::Technology::ETHERNET);
    CHECK(first.mac_address_ == "92:B0:1C:77:1C:08");
    CHECK(first.ssid_.empty());
    CHECK(first.security_.empty());

    auto second(Connman::ServiceNameComponents::from_service_name(
            "ethernet_52cb81bea82b_cable"));
    CHECK(second.technology_ == Connman::Technology::ETHERNET);
    CHECK(second.mac_address_ == "52:CB:81:BE:A8:2B");
    CHECK(second.ssid_.empty());
    CHECK(second.security_.empty());
}

TEST_CASE("Exception on unsupported technology")
{
    CHECK_THROWS_AS(Connman::ServiceNameComponents::from_service_name(
                        "wifix_82b01c771c09_4d794e6574776f726b_managed_psk"),
                    std::domain_error);
}

TEST_CASE("Exception on empty tokens")
{
    CHECK_THROWS_AS(Connman::ServiceNameComponents::from_service_name(
                        "wifi_82b01c771c09__psk"),
                    std::domain_error);
}

TEST_CASE("Exception on last empty token")
{
    CHECK_THROWS_AS(Connman::ServiceNameComponents::from_service_name(
                        "wifi_82b01c771c09_4d794e6574776f726b_managed_"),
                    std::domain_error);
}

TEST_SUITE_END();


TEST_SUITE_BEGIN("ConnMan MAC addresses");

class ConnmanMACAddressTestsFixture
{
  protected:
    std::unique_ptr<MockMessages::Mock> mock_messages;
    std::unique_ptr<MockOS::Mock> mock_os;

  public:
    explicit ConnmanMACAddressTestsFixture():
        mock_messages(new MockMessages::Mock),
        mock_os(new MockOS::Mock)
    {
        MockMessages::singleton = mock_messages.get();
        MockOS::singleton = mock_os.get();
    }

    ~ConnmanMACAddressTestsFixture()
    {
        mock_messages->done();
        MockMessages::singleton = nullptr;

        mock_os->done();
        MockOS::singleton = nullptr;
    }
};

TEST_CASE_FIXTURE(ConnmanMACAddressTestsFixture, "Addresses are converted to upper case")
{
    Connman::Address<Connman::AddressType::MAC> address("aA:Bb:cc:DD:e0:0f");
    CHECK(address == "AA:BB:CC:DD:E0:0F");
}

TEST_CASE_FIXTURE(ConnmanMACAddressTestsFixture, "Addresses without colons are converted")
{
    Connman::Address<Connman::AddressType::MAC> address("ffbbccdde00a");
    CHECK(address == "FF:BB:CC:DD:E0:0A");
}

TEST_CASE_FIXTURE(ConnmanMACAddressTestsFixture, "Addresses must have expected length")
{
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("ffbbccdde0"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("ffbbccdde00"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("ffbbccdde00aa"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("ffbbccdde00aaa"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("aA:Bb:cc:DD:e0"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("aA:Bb:cc:DD:e0:0f:00"),
                    std::domain_error);
}

TEST_CASE_FIXTURE(ConnmanMACAddressTestsFixture, "Addresses must have valid format")
{
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("aA:Bb:cc:D:De0:0f"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address(":aA:Bb:cc:DDe0:0f"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("aA:Bb:cc:DDe0:0f:"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("aA:Bb:cc:DD:e0;0f"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("aA0Bb0cc0DD0e000f"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("aA:Bb:cc:DD:e::0f"),
                    std::domain_error);
}

TEST_CASE_FIXTURE(ConnmanMACAddressTestsFixture, "Addresses must contain hexadecimal characters")
{
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("@A:Bb:cc:DD:e0:0f"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("`A:Bb:cc:DD:e0:0f"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("/A:Bb:cc:DD:e0:0f"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("GA:Bb:cc:DD:e0:0f"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("gA:Bb:cc:DD:e0:0f"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address(":A:Bb:cc:DD:e0:0f"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("aA:Bb:cc:DD:e0:0@"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("aA:Bb:cc:DD:e0:0`"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("aA:Bb:cc:DD:e0:0/"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("aA:Bb:cc:DD:e0:0G"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("aA:Bb:cc:DD:e0:0g"),
                    std::domain_error);
    CHECK_THROWS_AS(Connman::Address<Connman::AddressType::MAC> address("aA:Bb:cc:DD:e0:0:"),
                    std::domain_error);
}

TEST_CASE_FIXTURE(ConnmanMACAddressTestsFixture, "Locally administered address can be detected")
{
    Connman::Address<Connman::AddressType::MAC> first("02:bb:cc:dd:e0:0a");
    CHECK(is_locally_administered_mac_address(first));

    Connman::Address<Connman::AddressType::MAC> second("ff:bb:cc:dd:e0:0a");
    CHECK(is_locally_administered_mac_address(second));

    Connman::Address<Connman::AddressType::MAC> third("23:bb:cc:dd:e0:0a");
    CHECK(is_locally_administered_mac_address(third));
}

TEST_CASE_FIXTURE(ConnmanMACAddressTestsFixture, "Official address can be detected")
{
    Connman::Address<Connman::AddressType::MAC> first("00:bb:cc:dd:e0:0a");
    CHECK_FALSE(is_locally_administered_mac_address(first));

    Connman::Address<Connman::AddressType::MAC> second("fd:bb:cc:dd:e0:0a");
    CHECK_FALSE(is_locally_administered_mac_address(second));

    Connman::Address<Connman::AddressType::MAC> third("25:bb:cc:dd:e0:0a");
    CHECK_FALSE(is_locally_administered_mac_address(third));
}

TEST_CASE_FIXTURE(ConnmanMACAddressTestsFixture, "Set address can be unset")
{
    Connman::Address<Connman::AddressType::MAC> mac("80:90:b1:c2:fe:ed");
    CHECK_FALSE(mac.empty());
    mac.unset();
    CHECK(mac.empty());
}

TEST_CASE_FIXTURE(ConnmanMACAddressTestsFixture, "Overwriting set address with empty address works")
{
    Connman::Address<Connman::AddressType::MAC> mac("80:90:b1:c2:fe:ed");
    CHECK_FALSE(mac.empty());
    mac.set("");
    CHECK(mac.empty());
}

TEST_CASE_FIXTURE(ConnmanMACAddressTestsFixture, "Overwriting empty address with empty address works")
{
    Connman::Address<Connman::AddressType::MAC> mac;
    CHECK(mac.empty());
    mac.set("");
    CHECK(mac.empty());
}

TEST_CASE_FIXTURE(ConnmanMACAddressTestsFixture, "Overwriting set address with different address works")
{
    Connman::Address<Connman::AddressType::MAC> mac("80:90:b1:c2:fe:ed");
    CHECK(mac == "80:90:B1:C2:FE:ED");
    mac.set("17:6b:7a:8c:12:09");
    CHECK(mac == "17:6B:7A:8C:12:09");
}

TEST_SUITE_END();
