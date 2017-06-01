/*
 * Copyright (C) 2017  T+A elektroakustik GmbH & Co. KG
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

#include <string>
#include <array>
#include <algorithm>

#include "dcpregs_appliance.h"
#include "networkprefs.h"
#include "dbus_handlers_connman_manager_glue.h"
#include "network_device_list.hh"
#include "configproxy.h"
#include "messages.h"

enum class Appliance
{
    R1000E,
    CALA_BERBEL,
    FALLBACK,

    LAST_APPLIANCE = FALLBACK,

    UNDEFINED,
};

static const char appliance_id_key[]        = "@dcpd:appliance:appliance:id";
static const char appliance_device_id_key[] = "@dcpd:appliance:appliance:device_id";

static void set_device_id_by_mac(const Connman::Technology tech)
{
    const auto locked_devices(Connman::NetworkDeviceList::get_singleton_for_update());
    auto &devices(locked_devices.first);

    configproxy_set_string(nullptr, appliance_device_id_key,
                           devices.get_auto_select_mac_address(tech).get_string().c_str());
}

static void set_device_id_none()
{
    configproxy_set_string(nullptr, appliance_device_id_key, "");
}

/*
 * TODO: This is just a quick hack to get anything to work. The hardcoded
 *       strings and enum will be replaced by SQLite databases (named after the
 *       appliance ID) that contain all appliance-specific data in a common DB
 *       schema. Thus, no code changes will be required to support new
 *       appliances in the future.
 */
static void setup_primary_network_devices_for_appliance(Appliance appliance,
                                                        bool is_reconfiguration)
{
    switch(appliance)
    {
      case Appliance::R1000E:
      case Appliance::FALLBACK:
        network_prefs_update_primary_network_devices("/sys/bus/usb/devices/1-1.1:1.0",
                                                     "/sys/bus/usb/devices/1-1.2:1.0",
                                                     is_reconfiguration);
        set_device_id_by_mac(Connman::Technology::ETHERNET);
        break;

      case Appliance::CALA_BERBEL:
        network_prefs_update_primary_network_devices(nullptr,
                                                     "/sys/bus/usb/devices/1-1:1.0",
                                                     is_reconfiguration);
        set_device_id_by_mac(Connman::Technology::WLAN);
        break;

      case Appliance::UNDEFINED:
        network_prefs_update_primary_network_devices(nullptr, nullptr,
                                                     is_reconfiguration);
        set_device_id_none();
        break;
    }
}

static Appliance map_appliance_id(const char *name)
{
    static const std::array<std::pair<const std::string, const Appliance>,
                            size_t(Appliance::LAST_APPLIANCE) + 1> names
    {
        std::move(std::make_pair("R1000E",     Appliance::R1000E)),
        std::move(std::make_pair("CalaBerbel", Appliance::CALA_BERBEL)),
        std::move(std::make_pair("!unknown!",  Appliance::FALLBACK)),
    };

    if(name == nullptr || name[0] == '\0')
        return Appliance::UNDEFINED;

    for(const auto &a : names)
        if(a.first == name)
            return a.second;

    msg_error(0, LOG_ERR, "Appliance ID \"%s\" is NOT SUPPORTED, "
              "using generic fallback configuration", name);

    return Appliance::FALLBACK;
}

struct ApplianceData
{
    bool is_initialized;
    Appliance id;

    ApplianceData(const ApplianceData &) = delete;
    ApplianceData &operator=(const ApplianceData &) = delete;

    explicit ApplianceData():
        is_initialized(false),
        id(Appliance::UNDEFINED)
    {}
};

static ApplianceData global_appliance_data;

bool dcpregs_appliance_id_init()
{
    char appliance_id[64];
    auto prev_id = global_appliance_data.id;

    if(configproxy_get_value_as_string(appliance_id_key,
                                       appliance_id, sizeof(appliance_id),
                                       nullptr) > 0)
        global_appliance_data.id = map_appliance_id(appliance_id);
    else
    {
        BUG("Have no appliance ID, system may not work");
        global_appliance_data.id = Appliance::UNDEFINED;
    }

    const bool changed = global_appliance_data.id != prev_id;

    if(changed || !global_appliance_data.is_initialized)
    {
        msg_info("Set up system for appliance \"%s\"", appliance_id);
        setup_primary_network_devices_for_appliance(global_appliance_data.id,
                                                    global_appliance_data.is_initialized);
    }

    global_appliance_data.is_initialized = true;

    return changed;
}

void dcpregs_appliance_id_configure()
{
    dbussignal_connman_manager_refresh_services(true);
}

ssize_t dcpregs_read_87_appliance_id(uint8_t *response, size_t length)
{
    return configproxy_get_value_as_string(appliance_id_key,
                                           (char *)response, length,
                                           nullptr);
}

int dcpregs_write_87_appliance_id(const uint8_t *data, size_t length)
{
    if(length == 0 || data[0] == '\0')
        return -1;

    static const char log_message[] = "Appliance ID: \"%s\"";

    if(data[length - 1] == '\0')
    {
        msg_vinfo(MESSAGE_LEVEL_IMPORTANT, log_message, data);
        configproxy_set_string(nullptr, appliance_id_key, (const char *)data);
    }
    else
    {
        char buffer[length + 1];

        std::copy(data, data + length, buffer);
        buffer[length] = '\0';

        msg_vinfo(MESSAGE_LEVEL_IMPORTANT, log_message, buffer);
        configproxy_set_string(nullptr, appliance_id_key, buffer);
    }

    if(dcpregs_appliance_id_init())
        dcpregs_appliance_id_configure();

    return 0;
}
