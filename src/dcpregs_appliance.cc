/*
 * Copyright (C) 2017, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#include "dcpregs_appliance.hh"
#include "dbus_handlers_connman_manager.hh"
#include "network_device_list.hh"
#include "dcpregs_networkconfig.hh"
#include "configproxy.h"
#include "dbus_iface_deep.h"
#include "maybe.hh"
#include "registers_priv.hh"

/*!
 * Predefined appliances.
 *
 * \attention
 *     This enumeration must be kept in sync with #map_appliance_id().
 */
enum class ApplianceID
{
    R1000E,
    MP1000E,
    MP2000R,
    MP2500R,
    MP3100HV,
    MP8,
    SD3100HV,
    SDV3100HV,
    CALA_CDR,
    CALA_SR,
    CALA_BERBEL,
    LINUX_PC,
    FALLBACK,

    LAST_APPLIANCE = FALLBACK,

    UNDEFINED,
};

static const char appliance_id_key[]        = "@dcpd:appliance:appliance:id";
static const char appliance_device_id_key[] = "@dcpd:appliance:appliance:device_id";

static constexpr uint16_t APPLIANCE_STATUS_BIT_AUDIO_PATH_READY = (1U << 0);
static constexpr uint16_t APPLIANCE_STATUS_BIT_IS_IN_STANDBY    = (1U << 1);
static constexpr uint16_t APPLIANCE_STATUS_BIT_IS_VALID         = (1U << 15);

static void set_device_id_by_mac(const Connman::Technology tech)
{
    const auto locked_devices(Connman::NetworkDeviceList::get_singleton_for_update());
    auto &devices(locked_devices.first);

    configproxy_set_string(nullptr, appliance_device_id_key,
                           devices.get_auto_select_mac_address(tech).get_string().c_str());
}

static void set_device_id_for_testing()
{
    /* ID was generated from 1 MiB of random data */
    configproxy_set_string(nullptr, appliance_device_id_key,
                           "4203b53e75db97e29fabd27cf1a6e9f2");
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
static void setup_primary_network_devices_for_appliance(ApplianceID appliance,
                                                        bool is_reconfiguration)
{
    switch(appliance)
    {
      case ApplianceID::R1000E:
      case ApplianceID::MP1000E:
      case ApplianceID::MP2000R:
      case ApplianceID::MP2500R:
      case ApplianceID::MP3100HV:
      case ApplianceID::SD3100HV:
      case ApplianceID::SDV3100HV:
      case ApplianceID::CALA_CDR:
      case ApplianceID::CALA_SR:
      case ApplianceID::FALLBACK:
        Regs::NetworkConfig::set_primary_technology(Connman::Technology::ETHERNET);
        network_prefs_update_primary_network_devices("/sys/bus/usb/devices/1-1.1:1.0",
                                                     "/sys/bus/usb/devices/1-1.2:1.0",
                                                     is_reconfiguration);
        set_device_id_by_mac(Connman::Technology::ETHERNET);
        break;

      case ApplianceID::MP8:
        Regs::NetworkConfig::set_primary_technology(Connman::Technology::ETHERNET);
        network_prefs_update_primary_network_devices("/sys/bus/usb/devices/1-1.1:1.0",
                                                     "/sys/bus/usb/devices/1-1.4:1.0",
                                                     is_reconfiguration);
        set_device_id_by_mac(Connman::Technology::ETHERNET);
        break;

      case ApplianceID::CALA_BERBEL:
        Regs::NetworkConfig::set_primary_technology(Connman::Technology::WLAN);
        network_prefs_update_primary_network_devices(nullptr,
                                                     "/sys/bus/usb/devices/1-1:1.0",
                                                     is_reconfiguration);
        set_device_id_by_mac(Connman::Technology::WLAN);
        break;

      case ApplianceID::LINUX_PC:
        Regs::NetworkConfig::set_primary_technology(Connman::Technology::ETHERNET);
        network_prefs_update_primary_network_devices(nullptr, nullptr,
                                                     is_reconfiguration);
        set_device_id_for_testing();
        break;

      case ApplianceID::UNDEFINED:
        Regs::NetworkConfig::set_primary_technology(Connman::Technology::UNKNOWN_TECHNOLOGY);
        network_prefs_update_primary_network_devices(nullptr, nullptr,
                                                     is_reconfiguration);
        set_device_id_none();
        break;
    }
}

/*!
 * Map appliance string ID to appliance enumeration value.
 *
 * \attention
 *     The array defined inside this function must be kept in sync with the
 *     #ApplianceID enumeration.
 */
static ApplianceID map_appliance_id(const char *name)
{
    static const std::array<std::pair<const std::string, const ApplianceID>,
                            size_t(ApplianceID::LAST_APPLIANCE) + 1> names
    {
        std::move(std::make_pair("R1000E",     ApplianceID::R1000E)),
        std::move(std::make_pair("MP1000E",    ApplianceID::MP1000E)),
        std::move(std::make_pair("MP2000R",    ApplianceID::MP2000R)),
        std::move(std::make_pair("MP2500R",    ApplianceID::MP2500R)),
        std::move(std::make_pair("MP3100HV",   ApplianceID::MP3100HV)),
        std::move(std::make_pair("MP8",        ApplianceID::MP8)),
        std::move(std::make_pair("SD3100HV",   ApplianceID::SD3100HV)),
        std::move(std::make_pair("SDV3100HV",  ApplianceID::SDV3100HV)),
        std::move(std::make_pair("CalaCDR",    ApplianceID::CALA_CDR)),
        std::move(std::make_pair("CalaSR",     ApplianceID::CALA_SR)),
        std::move(std::make_pair("CalaBerbel", ApplianceID::CALA_BERBEL)),
        std::move(std::make_pair("LinuxPC",    ApplianceID::LINUX_PC)),
        std::move(std::make_pair("!unknown!",  ApplianceID::FALLBACK)),
    };

    if(name == nullptr || name[0] == '\0')
        return ApplianceID::UNDEFINED;

    for(const auto &a : names)
        if(a.first == name)
            return a.second;

    msg_error(0, LOG_ERR, "Appliance ID \"%s\" is NOT SUPPORTED, "
              "using generic fallback configuration", name);

    return ApplianceID::FALLBACK;
}

struct ApplianceData
{
    bool is_initialized;
    ApplianceID id;

    std::mutex lock;
    Maybe<bool> cached_standby_state;

    uint16_t request_control_mask;
    uint16_t request_control_bits;

    ApplianceData(const ApplianceData &) = delete;
    ApplianceData &operator=(const ApplianceData &) = delete;

    explicit ApplianceData():
        is_initialized(false),
        id(ApplianceID::UNDEFINED),
        request_control_mask(0),
        request_control_bits(0)
    {}
};

static ApplianceData global_appliance_data;

bool Regs::Appliance::init()
{
    Regs::NetworkConfig::init();

    std::lock_guard<std::mutex> lock(global_appliance_data.lock);

    char appliance_id[64];
    auto prev_id = global_appliance_data.id;

    if(configproxy_get_value_as_string(appliance_id_key,
                                       appliance_id, sizeof(appliance_id),
                                       nullptr) > 0)
        global_appliance_data.id = map_appliance_id(appliance_id);
    else
    {
        BUG("Have no appliance ID, system may not work");
        global_appliance_data.id = ApplianceID::UNDEFINED;
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

void Regs::Appliance::configure()
{
    Connman::refresh_services(true);
}

ssize_t Regs::Appliance::DCP::read_87_appliance_id(uint8_t *response, size_t length)
{
    return configproxy_get_value_as_string(appliance_id_key,
                                           (char *)response, length,
                                           nullptr);
}

int Regs::Appliance::DCP::write_87_appliance_id(const uint8_t *data, size_t length)
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

    if(init())
        configure();

    return 0;
}

enum class AppliancePowerState
{
    UNKNOWN,
    STANDBY,
    UP_AND_RUNNING,
    MAX_VALUE = UP_AND_RUNNING,
};

static AppliancePowerState standby_state_flag_to_dbus_value(bool is_valid, bool state)
{
    return is_valid
        ? (state ? AppliancePowerState::STANDBY : AppliancePowerState::UP_AND_RUNNING)
        : AppliancePowerState::UNKNOWN;
}

static AppliancePowerState standby_state_flag_to_dbus_value(const Maybe<bool> &state)
{
    return state.is_known()
        ? (state.get() ? AppliancePowerState::STANDBY : AppliancePowerState::UP_AND_RUNNING)
        : AppliancePowerState::UNKNOWN;
}

int Regs::Appliance::DCP::write_18_appliance_status(const uint8_t *data, size_t length)
{
    if(length < 2)
    {
        msg_error(EINVAL, LOG_INFO, "Input too short for register 18");
        return -1;
    }

    const uint16_t status = (data[0] << 8) | data[1];

    const bool is_valid = (status & APPLIANCE_STATUS_BIT_IS_VALID) != 0;
    const bool is_audio_path_usable = (status & APPLIANCE_STATUS_BIT_AUDIO_PATH_READY) != 0;
    const bool is_in_standby        = (status & APPLIANCE_STATUS_BIT_IS_IN_STANDBY) != 0;
    const uint8_t audio_state = is_valid ? (is_audio_path_usable ? 1 : 0) : 2;
    const auto power_state = standby_state_flag_to_dbus_value(is_valid, is_in_standby);
    AppliancePowerState old_power_state;

    if(is_valid && is_in_standby && is_audio_path_usable)
        APPLIANCE_BUG("Indicating usable audio path in standby mode (0x%04x)",
                      status);

    {
        std::lock_guard<std::mutex> lock(global_appliance_data.lock);

        old_power_state =
            standby_state_flag_to_dbus_value(global_appliance_data.cached_standby_state);

        if(is_valid)
            global_appliance_data.cached_standby_state = is_in_standby;
        else
            global_appliance_data.cached_standby_state.set_unknown();
    }

    if(power_state != old_power_state)
        tdbus_appliance_power_emit_state_changed(dbus_appliance_get_power_iface(),
                                                 uint8_t(old_power_state),
                                                 uint8_t(power_state));

    tdbus_aupath_appliance_call_set_ready_state(dbus_audiopath_get_appliance_iface(),
                                                audio_state,
                                                nullptr, nullptr, nullptr);

    return 0;
}

ssize_t Regs::Appliance::DCP::read_19_appliance_control(uint8_t *response, size_t length)
{
    static constexpr size_t register_size =
        sizeof(global_appliance_data.request_control_mask) +
        sizeof(global_appliance_data.request_control_bits);

    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 19 handler %p %zu", response, length);

    std::lock_guard<std::mutex> lock(global_appliance_data.lock);

    if(length < register_size)
        return -1;

    if(global_appliance_data.request_control_mask == 0)
    {
        BUG("Have no pending appliance control requests");
        return -1;
    }

    if(((global_appliance_data.request_control_mask |
         global_appliance_data.request_control_bits) & APPLIANCE_STATUS_BIT_IS_VALID) != 0)
        BUG("Appliance control is-valid flag must be 0");

    response[0] = global_appliance_data.request_control_mask >> 8;
    response[1] = global_appliance_data.request_control_mask & 0xff;
    response[2] = global_appliance_data.request_control_bits >> 8;
    response[3] = global_appliance_data.request_control_bits & 0xff;

    global_appliance_data.request_control_mask = 0;
    global_appliance_data.request_control_bits = 0;

    return register_size;
}

uint8_t Regs::Appliance::get_standby_state_for_dbus()
{
    std::lock_guard<std::mutex> lock(global_appliance_data.lock);
    return uint8_t(standby_state_flag_to_dbus_value(global_appliance_data.cached_standby_state));
}

bool Regs::Appliance::request_standby_state(uint8_t state, uint8_t &current_state,
                                            bool &is_pending)
{
    current_state = get_standby_state_for_dbus();
    is_pending = false;

    if(state > uint8_t(AppliancePowerState::MAX_VALUE))
        return false;

    const auto requested_state = AppliancePowerState(state);

    switch(requested_state)
    {
      case AppliancePowerState::UNKNOWN:
        break;

      case AppliancePowerState::STANDBY:
      case AppliancePowerState::UP_AND_RUNNING:
        is_pending = state != current_state;

        if(!is_pending)
            return true;

        std::lock_guard<std::mutex> lock(global_appliance_data.lock);
        const bool is_notification_needed = global_appliance_data.request_control_mask == 0;

        global_appliance_data.request_control_mask |= APPLIANCE_STATUS_BIT_IS_IN_STANDBY;
        global_appliance_data.request_control_bits |= APPLIANCE_STATUS_BIT_IS_IN_STANDBY;

        if(is_notification_needed)
            Regs::get_data().register_changed_notification_fn(19);

        return true;
    }

    return false;
}
