/*
 * Copyright (C) 2016, 2017, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef DBUS_HANDLERS_CONNMAN_MANAGER_HH
#define DBUS_HANDLERS_CONNMAN_MANAGER_HH

#include "networkprefs.h"

#include <functional>

/*!
 * \addtogroup dbus_handlers
 */
/*!@{*/

struct _GDBusProxy;
struct _GVariant;

namespace Connman
{

class WLANTools;
class WLANManager;

WLANManager *
init_wlan_manager(std::function<void()> &&schedule_connect_to_wlan_fn,
                  std::function<void()> &&schedule_refresh_connman_services_fn,
                  WLANTools *wlan_tools, bool is_enabled);

/*!
 * Tell ConnMan to connect to WLAN service with name stored in passed data.
 *
 * This function blocks until the service is fully connected or until
 * connection fails.
 *
 * Usually called from main context.
 *
 * \see
 *     #Connman::WLANManager::schedule_connect_to_wlan()
 */
bool connect_our_wlan(WLANManager &wman);

void connect_to_service(enum NetworkPrefsTechnology tech,
                        const char *service_to_be_disabled,
                        bool immediate_activation, bool force_reconnect);

void connect_to_wps_service(const char *network_name, const char *network_ssid,
                            const char *service_to_be_disabled);
void cancel_wps(void);

bool is_connecting(bool *is_wps);
void refresh_services(bool force_refresh_all = false);

/*!
 * Called once at startup from D-Bus initialization function.
 */
void about_to_connect_dbus_signals();

/*!
 * D-Bus signal handing function.
 *
 * Called in D-Bus context.
 */
extern "C"
void dbussignal_connman_manager(struct _GDBusProxy *proxy, const char *sender_name,
                                const char *signal_name, struct _GVariant *parameters,
                                void *user_data);

}

/*!@}*/

#endif /* !DBUS_HANDLERS_CONNMAN_MANAGER_HH */
