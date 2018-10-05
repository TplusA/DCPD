/*
 * Copyright (C) 2016, 2017, 2018  T+A elektroakustik GmbH & Co. KG
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

#ifndef DBUS_HANDLERS_CONNMAN_MANAGER_GLUE_H
#define DBUS_HANDLERS_CONNMAN_MANAGER_GLUE_H

#include "networkprefs.h"

#include <stdbool.h>

/*!
 * \addtogroup dbus_handlers
 */
/*!@{*/

#ifdef __cplusplus
extern "C" {
#endif

struct DBusSignalManagerData;

struct DBusSignalManagerData *
dbussignal_connman_manager_init(void (*schedule_connect_to_wlan_fn)(void),
                                void (*schedule_refresh_connman_services_fn)(void),
                                bool is_enabled);

/*!
 * Tell ConnMan to connect to WLAN service with name stored in passed data.
 *
 * This function blocks until the service is fully connected or until
 * connection fails.
 *
 * Usually called from main context.
 *
 * \see
 *     #DBusSignalManagerData::schedule_connect_to_wlan()
 */
bool dbussignal_connman_manager_connect_our_wlan(struct DBusSignalManagerData *data);

void dbussignal_connman_manager_connect_to_service(enum NetworkPrefsTechnology tech,
                                                   const char *service_to_be_disabled,
                                                   bool immediate_activation);

void dbussignal_connman_manager_connect_to_wps_service(const char *network_name,
                                                       const char *network_ssid,
                                                       const char *service_to_be_disabled);
void dbussignal_connman_manager_cancel_wps(void);

bool dbussignal_connman_manager_is_connecting(bool *is_wps);
void dbussignal_connman_manager_refresh_services(bool force_refresh_all = false);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !DBUS_HANDLERS_CONNMAN_MANAGER_GLUE_H */
