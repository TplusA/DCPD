/*
 * Copyright (C) 2016  T+A elektroakustik GmbH & Co. KG
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

/*!
 * \addtogroup dbus_handlers
 */
/*!@{*/

#ifdef __cplusplus
extern "C" {
#endif

struct dbussignal_connman_manager_data;

struct dbussignal_connman_manager_data *
dbussignal_connman_manager_init(void (*schedule_connect_to_wlan_fn)(void));

/*!
 * Tell ConnMan to connect to WLAN service with name stored in passed data.
 *
 * This function blocks until the service is fully connected or until
 * connection fails.
 *
 * Usually called from main context.
 *
 * \see
 *     #dbussignal_connman_manager_data::schedule_connect_to_wlan()
 */
void dbussignal_connman_manager_connect_our_wlan(struct dbussignal_connman_manager_data *data);

void dbussignal_connman_manager_connect_to_service(enum NetworkPrefsTechnology tech);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !DBUS_HANDLERS_CONNMAN_MANAGER_GLUE_H */
