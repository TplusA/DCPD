/*
 * Copyright (C) 2015--2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef DBUS_IFACE_H
#define DBUS_IFACE_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct DBusSignalManagerData;
struct ConfigurationManagementData;
struct AccessPointData;

int dbus_setup(bool connect_to_session_bus, bool with_connman,
               void *appconn_data,
               struct DBusSignalManagerData *connman_manager_data,
               struct ConfigurationManagementData *configuration_data,
               struct AccessPointData *access_point_data,
               void (*content_manager_iface_available_notification)(bool),
               void (*credentials_read_iface_available_notification)(void));
void dbus_shutdown(void);

void dbus_lock_shutdown_sequence(const char *why);
void dbus_unlock_shutdown_sequence(void);

#ifdef __cplusplus
}
#endif

#endif /* !DBUS_IFACE_H */
