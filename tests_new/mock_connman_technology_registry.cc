/*
 * Copyright (C) 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#include "mock_connman_technology_registry.hh"

#include "mainloop.hh"

#if !LOGGED_LOCKS_ENABLED

#include <iostream>

MockConnmanTechnologyRegistry::Wifi::Mock *MockConnmanTechnologyRegistry::Wifi::singleton = nullptr;


namespace Connman
{

const std::array<const std::string, size_t(TechnologyPropertiesWIFI::Property::LAST_PROPERTY) + 1>
TechnologyPropertiesWIFI::Containers::keys
{
    "Powered",
    "Connected",
    "Name",
    "Type",
    "Tethering",
    "TetheringIdentifier",
    "TetheringPassphrase",
};

TechnologyPropertiesWIFI::~TechnologyPropertiesWIFI() {};

template <>
void TechnologyPropertiesWIFI::send_property_over_dbus<bool>(Property key, const bool &value)
{
    std::lock_guard<LoggedLock::RecMutex> lock(lock_);
    MockConnmanTechnologyRegistry::Wifi::singleton->check_next<MockConnmanTechnologyRegistry::Wifi::SendPropertyOverDBus<bool>>(key, value);
}

template <>
void TechnologyPropertiesWIFI::send_property_over_dbus<std::string>(Property key, const std::string &value)
{
    std::lock_guard<LoggedLock::RecMutex> lock(lock_);
    MockConnmanTechnologyRegistry::Wifi::singleton->check_next<MockConnmanTechnologyRegistry::Wifi::SendPropertyOverDBus<std::string>>(key, value);
}

}

void Connman::TechnologyPropertiesWIFI::set_dbus_object_path(std::string &&path)
{
    std::lock_guard<LoggedLock::RecMutex> lock(lock_);

    proxy_ = MockConnmanTechnologyRegistry::Wifi::singleton->check_next<MockConnmanTechnologyRegistry::Wifi::SetDBusObjectPath>(path);
    dbus_object_path_ = std::move(path);
}

void Connman::TechnologyPropertiesWIFI::register_property_watcher(WatcherFn &&fn)
{
    if(fn != nullptr)
    {
        std::lock_guard<LoggedLock::RecMutex> lock(lock_);
        watchers_.emplace_back(fn);
    }
}

bool Connman::TechnologyPropertiesWIFI::ensure_dbus_proxy()
{
    auto temp(MockConnmanTechnologyRegistry::Wifi::singleton->check_next<MockConnmanTechnologyRegistry::Wifi::EnsureDBusProxy>());
    proxy_ = temp.second;
    return temp.first;
}

void Connman::TechnologyPropertiesWIFI::technology_signal(
        struct _GDBusProxy *proxy, const char *sender_name, const char *signal_name,
        _GVariant *parameters)
{
    FAIL("unexpected call");
}

void Connman::TechnologyPropertiesWIFI::notify_watchers(Property property, StoreResult result)
{
    std::lock_guard<LoggedLock::Mutex> lock(watchers_lock_);

    MainLoop::post(
        [this, property, result] ()
        {
            std::lock_guard<LoggedLock::Mutex> lk(watchers_lock_);

            for(const auto &fn : watchers_)
                fn(property, result, *this);
        });
}

void Connman::TechnologyRegistry::connect_to_connman(const void *data)
{
    REQUIRE(MockConnmanTechnologyRegistry::Wifi::singleton != nullptr);
    REQUIRE(data != nullptr);
    const auto &sd(*static_cast<const MockConnmanTechnologyRegistry::FixtureSetupData *>(data));
    REQUIRE(sd.wifi_tech_proxy != nullptr);

    if(!sd.wifi_is_powered)
    {
        REQUIRE_FALSE(sd.wifi_is_connected);
        REQUIRE_FALSE(sd.wifi_is_tethering);
    }
    else if(!sd.wifi_is_connected)
        REQUIRE_FALSE(sd.wifi_is_tethering);

    const char path[] = "mock_wifi_path";
    MockConnmanTechnologyRegistry::Wifi::singleton->expect(
        new MockConnmanTechnologyRegistry::Wifi::SetDBusObjectPath(path, sd.wifi_tech_proxy));
    wifi_properties_.set_dbus_object_path(path);
    MockConnmanTechnologyRegistry::Wifi::singleton->done();

    if(sd.wifi_properties_are_initialized)
    {
        wifi_properties_.cache_value_by_name("Powered",   bool(sd.wifi_is_powered));
        wifi_properties_.cache_value_by_name("Connected", bool(sd.wifi_is_connected));
        wifi_properties_.cache_value_by_name("Name",      std::string("wifi"));
        wifi_properties_.cache_value_by_name("Type",      std::string("wifi"));
        wifi_properties_.cache_value_by_name("Tethering", bool(sd.wifi_is_tethering));
        wifi_properties_.cache_value_by_name("TetheringIdentifier",
                                             std::string(sd.wifi_tethering_identifier));
        wifi_properties_.cache_value_by_name("TetheringPassphrase",
                                             std::string(sd.wifi_tethering_passphrase));
    }
}

#endif /* !LOGGED_LOCKS_ENABLED */
