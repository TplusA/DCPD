/*
 * Copyright (C) 2018, 2019, 2023  T+A elektroakustik GmbH & Co. KG
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

#include "accesspoint_manager.hh"
#include "dump_enum_value.hh"

static const char *to_string(Network::AccessPoint::Status status)
{
    static const std::array<const char *const, 5> names
    {
        "UNKNOWN",
        "PROBING_STATUS",
        "DISABLED",
        "ACTIVATING",
        "ACTIVE",
    };
    return enum_to_string(names, status);
}

static const char *to_string(Network::AccessPoint::RequestResult rr)
{
    static const std::array<const char *const, 4> names
    {
        "OK",
        "BLOCKED_BY_POLICY",
        "BLOCKED_BUSY",
        "FAILED",
    };
    return enum_to_string(names, rr);
}

static const char *to_string(Network::AccessPoint::Error err)
{
    static const std::array<const char *const, 7> names
    {
        "OK",
        "UNKNOWN",
        "DBUS_FAILURE",
        "BUSY",
        "ALREADY_ACTIVATING",
        "ALREADY_ACTIVE",
        "ALREADY_DISABLED",
    };
    return enum_to_string(names, err);
}

void Network::AccessPointManager::status_watcher(Connman::TechnologyRegistry &reg,
                                                 Network::AccessPoint::Status old_status,
                                                 Network::AccessPoint::Status new_status)
{
    msg_info("Access point status %s -> %s",
             to_string(old_status), to_string(new_status));

    if(old_status == new_status)
        return;

    switch(new_status)
    {
      case Network::AccessPoint::Status::UNKNOWN:
      case Network::AccessPoint::Status::PROBING_STATUS:
        break;

      case Network::AccessPoint::Status::DISABLED:
        {
            LOGGED_LOCK_CONTEXT_HINT;
            const std::lock_guard<LoggedLock::Mutex> lock(cache_lock_);
            cached_network_devices_.clear();
            cached_network_services_.clear();
            break;
        }

      case Network::AccessPoint::Status::ACTIVATING:
        {
            LOGGED_LOCK_CONTEXT_HINT;
            const std::lock_guard<LoggedLock::Mutex> lock(cache_lock_);
            LOGGED_LOCK_CONTEXT_HINT;
            const auto locked_services(Connman::ServiceList::get_singleton_const());
            LOGGED_LOCK_CONTEXT_HINT;
            const auto locked_devices(Connman::NetworkDeviceList::get_singleton_const());

            cached_network_devices_.copy_from(locked_devices.first);
            cached_network_services_.copy_from(locked_services.first);
        }

        break;

      case Network::AccessPoint::Status::ACTIVE:
        try
        {
            LOGGED_LOCK_CONTEXT_HINT;
            const auto tech_lock(reg.locked());

            msg_info("Access point SSID \"%s\"",
                     reg.wifi().get<Connman::TechnologyPropertiesWIFI::Property::TETHERING_IDENTIFIER>().c_str());
            msg_info("Access point passphrase \"%s\"",
                     reg.wifi().get<Connman::TechnologyPropertiesWIFI::Property::TETHERING_PASSPHRASE>().c_str());
        }
        catch(...)
        {
            msg_error(0, LOG_ERR, "Failed retrieving access point parameters");
        }

        break;
    }
}

Network::AccessPointManager::AccessPointManager(Network::AccessPoint &ap):
    ap_(ap)
{
    LoggedLock::configure(cache_lock_, "Network::AccessPointManager", MESSAGE_LEVEL_DEBUG);

    ap_.register_status_watcher(
        [this]
        (Connman::TechnologyRegistry &reg,
         Network::AccessPoint::Status old_status,
         Network::AccessPoint::Status new_status)
        {
            ap_status_ = new_status;
            status_watcher(reg, old_status, new_status);
        });
}

void Network::AccessPointManager::start()
{
    ap_.start();
}

bool Network::AccessPointManager::activate(std::string &&ssid, std::string &&passphrase)
{
    if(ssid.empty())
    {
        msg_error(EINVAL, LOG_ERR, "The access point SSID must not be empty");
        return false;
    }

    if(passphrase.length() < 8)
    {
        /* there is minimum required length for any passphrase; note that the
         * value 8 is hardcoded into wpa_supplicant and is not configurable */
        msg_error(EINVAL, LOG_ERR,
                  "The access point passphrase must be no shorter than 8 characters");
        return false;
    }

    return ap_.spawn_request(std::move(ssid), std::move(passphrase),
        [this]
        (Network::AccessPoint::RequestResult result, Network::AccessPoint::Error error,
         Network::AccessPoint::Status status)
        {
            if(error == Network::AccessPoint::Error::OK)
                msg_vinfo(MESSAGE_LEVEL_DEBUG,
                          "Access point spawn request result: %s (%s) -> %s",
                          to_string(result), to_string(error), to_string(status));
            else
                msg_error(0, LOG_NOTICE,
                          "Access point spawn request error: %s (%s) -> %s",
                          to_string(result), to_string(error), to_string(status));
        });
}

bool Network::AccessPointManager::deactivate(AccessPoint::DoneFn &&done)
{
    return ap_.shutdown_request(
        [this, done]
        (Network::AccessPoint::RequestResult result, Network::AccessPoint::Error error,
         Network::AccessPoint::Status status)
        {
            if(error == Network::AccessPoint::Error::OK)
                msg_vinfo(MESSAGE_LEVEL_DEBUG,
                          "Access point shutdown request result: %s (%s) -> %s",
                          to_string(result), to_string(error), to_string(status));
            else
                msg_error(0, LOG_NOTICE,
                          "Access point shutdown request error: %s (%s) -> %s",
                          to_string(result), to_string(error), to_string(status));

            if(done != nullptr)
                done(result, error, status);
        });
}
