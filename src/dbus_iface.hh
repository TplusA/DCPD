/*
 * Copyright (C) 2015--2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef DBUS_IFACE_HH
#define DBUS_IFACE_HH

namespace Connman { class WLANManager; }
namespace Configuration
{
    struct ApplianceValues;
    template <typename ValuesT> class ConfigManager;
}
namespace Network { class AccessPointManager; }
namespace Applink { class AppConnections; }
namespace Regs { namespace PlayStream { class StreamingRegistersIface; }}

namespace DBus
{

int setup(bool connect_to_session_bus, bool with_connman,
          Applink::AppConnections &appconn,
          Connman::WLANManager &connman_wlan,
          Configuration::ConfigManager<Configuration::ApplianceValues> &config_man,
          Network::AccessPointManager &access_point,
          Regs::PlayStream::StreamingRegistersIface &streaming_regs,
          void (*content_manager_iface_available_notification)(bool),
          void (*credentials_read_iface_available_notification)());
void shutdown();

void lock_shutdown_sequence(const char *why);
void unlock_shutdown_sequence();

}

#endif /* !DBUS_IFACE_HH */
