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

#include "dcpregs_accesspoint.hh"
#include "accesspoint_manager.hh"
#include "registers_priv.hh"

#include <algorithm>

enum class WriteCommand
{
    ENABLE_WITH_PARAMETERS,
    SHUTDOWN,

    LAST_WRITE_COMMAND = SHUTDOWN,
};

static Network::AccessPointManager *dcpregs_access_point_manager;
static const Connman::TechnologyRegistry *dcpregs_technology_registry;

void Regs::WLANAccessPoint::init(Network::AccessPointManager &apman,
                                 const Connman::TechnologyRegistry &tech_reg)
{
    dcpregs_access_point_manager = &apman;
    dcpregs_technology_registry = &tech_reg;

    apman.register_status_watcher(
        []
        (Connman::TechnologyRegistry &,
         Network::AccessPoint::Status old_status,
         Network::AccessPoint::Status new_status)
        {
            if(old_status != new_status)
                Regs::get_data().register_changed_notification_fn(107);
        });
}

void Regs::WLANAccessPoint::deinit()
{
    dcpregs_access_point_manager = nullptr;
    dcpregs_technology_registry = nullptr;
}

int Regs::WLANAccessPoint::DCP::write_107_access_point(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 81 handler %p %zu", data, length);

    if(data[0] > uint8_t(WriteCommand::LAST_WRITE_COMMAND))
    {
        APPLIANCE_BUG("Invalid AP subcommand %u", data[0]);
        return -1;
    }

    switch(WriteCommand(data[0]))
    {
      case WriteCommand::ENABLE_WITH_PARAMETERS:
        {
            auto str(reinterpret_cast<const char *>(data + 1));
            auto str_end(str + length - 1);

            const auto ssid(str);
            const auto ssid_end(std::find(ssid, str_end, '\0'));
            if(ssid_end >= str_end)
                break;

            const auto pass(ssid_end + 1);
            const auto pass_end(std::find(pass, str_end, '\0'));
            if(pass_end >= str_end)
                break;

            if(dcpregs_access_point_manager->activate(std::string(ssid, ssid_end),
                                                      std::string(pass, pass_end)))
            {
                msg_info("Access point activation requested via SPI");
                return 0;
            }
        }

        break;

      case WriteCommand::SHUTDOWN:
        if(dcpregs_access_point_manager->deactivate())
        {
            msg_info("Access point shutdown initiated via SPI");
            return 0;
        }

        break;
    }

    msg_error(EINVAL, LOG_ERR,
              "Access point control command 0x%02x failed", data[0]);

    return -1;
}

bool Regs::WLANAccessPoint::DCP::read_107_access_point(std::vector<uint8_t> &buffer)
{
    switch(dcpregs_access_point_manager->get_status())
    {
      case Network::AccessPoint::Status::UNKNOWN:
        buffer.push_back(0x00);
        break;

      case Network::AccessPoint::Status::PROBING_STATUS:
        buffer.push_back(0x01);
        break;

      case Network::AccessPoint::Status::DISABLED:
      case Network::AccessPoint::Status::ACTIVATING:
        buffer.push_back(0x02);
        break;

      case Network::AccessPoint::Status::ACTIVE:
        try
        {
            LOGGED_LOCK_CONTEXT_HINT;
            const auto tech_lock(dcpregs_technology_registry->locked());
            const auto &wifi(dcpregs_technology_registry->wifi());

            const std::string &ssid(wifi.get<Connman::TechnologyPropertiesWIFI::Property::TETHERING_IDENTIFIER>());
            const std::string &pass(wifi.get<Connman::TechnologyPropertiesWIFI::Property::TETHERING_PASSPHRASE>());

            buffer.push_back(0x03);
            std::copy(ssid.begin(), ssid.end(), std::back_inserter(buffer));
            std::copy(pass.begin(), pass.end(), std::back_inserter(buffer));
        }
        catch(...)
        {
            buffer.clear();
            buffer.push_back(0x00);
        }

        break;
    }

    return true;
}
