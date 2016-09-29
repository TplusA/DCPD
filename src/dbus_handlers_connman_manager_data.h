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

#ifndef DBUS_HANDLERS_CONNMAN_MANAGER_DATA_H
#define DBUS_HANDLERS_CONNMAN_MANAGER_DATA_H

#include <glib.h>

/*!
 * \addtogroup dbus_handlers
 */
/*!@{*/

struct dbussignal_connman_manager_data
{
    GMutex lock;
    char wlan_service_name[512];
    void (*schedule_connect_to_wlan)(void);
};

#ifdef __cplusplus
extern "C" {
#endif

void dbussignal_connman_manager_init(struct dbussignal_connman_manager_data *data,
                                     void (*schedule_connect_to_wlan_fn)(void));
void dbussignal_connman_manager_connect_our_wlan(struct dbussignal_connman_manager_data *data);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !DBUS_HANDLERS_CONNMAN_MANAGER_DATA_H */