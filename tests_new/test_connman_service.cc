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

TEST_SUITE("parsing ConnMan service names")
{

TEST_CASE("exception on nullptr")
{
    CHECK_THROWS_AS(Connman::ServiceNameComponents::from_service_name(nullptr),
                    std::domain_error);
}

TEST_CASE("exception on empty name")
{
    CHECK_THROWS_AS(Connman::ServiceNameComponents::from_service_name(""),
                    std::domain_error);
}

TEST_CASE("wireless services")
{
    auto first(Connman::ServiceNameComponents::from_service_name(
            "wifi_82b01c771c09_4d794e6574776f726b_managed_psk"));
    CHECK(first.technology_ == Connman::Technology::WLAN);
    CHECK(first.mac_address_ == "82b01c771c09");
    CHECK(first.ssid_ == "4d794e6574776f726b");
    CHECK(first.security_ == "psk");

    auto second(Connman::ServiceNameComponents::from_service_name(
            "wifi_a215a909cbee_4f75725072657474794e6574776f726b486173414c6f6e674e616d65_managed_ieee8021x"));

    CHECK(second.technology_ == Connman::Technology::WLAN);
    CHECK(second.mac_address_ == "a215a909cbee");
    CHECK(second.ssid_ == "4f75725072657474794e6574776f726b486173414c6f6e674e616d65");
    CHECK(second.security_ == "ieee8021x");
}

TEST_CASE("wired services")
{
    auto first(Connman::ServiceNameComponents::from_service_name(
            "ethernet_92b01c771c08_cable"));
    CHECK(first.technology_ == Connman::Technology::ETHERNET);
    CHECK(first.mac_address_ == "92b01c771c08");
    CHECK(first.ssid_.empty());
    CHECK(first.security_.empty());

    auto second(Connman::ServiceNameComponents::from_service_name(
            "ethernet_52cb81bea82b_cable"));
    CHECK(second.technology_ == Connman::Technology::ETHERNET);
    CHECK(second.mac_address_ == "52cb81bea82b");
    CHECK(second.ssid_.empty());
    CHECK(second.security_.empty());
}

TEST_CASE("exception on unsupported technology")
{
    CHECK_THROWS_AS(Connman::ServiceNameComponents::from_service_name(
                        "wifix_82b01c771c09_4d794e6574776f726b_managed_psk"),
                    std::domain_error);
}

TEST_CASE("exception on empty tokens")
{
    CHECK_THROWS_AS(Connman::ServiceNameComponents::from_service_name(
                        "wifi_82b01c771c09__psk"),
                    std::domain_error);
}

TEST_CASE("exception on last empty token")
{
    CHECK_THROWS_AS(Connman::ServiceNameComponents::from_service_name(
                        "wifi_82b01c771c09_4d794e6574776f726b_managed_"),
                    std::domain_error);
}

}
