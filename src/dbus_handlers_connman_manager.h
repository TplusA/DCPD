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

#ifndef DBUS_HANDLERS_CONNMAN_MANAGER_H
#define DBUS_HANDLERS_CONNMAN_MANAGER_H

#include <gio/gio.h>

/*!
 * \addtogroup dbus_handlers
 */
/*!@{*/

#ifdef __cplusplus
extern "C" {
#endif

void dbussignal_connman_manager(GDBusProxy *proxy, const gchar *sender_name,
                                const gchar *signal_name, GVariant *parameters,
                                gpointer user_data);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !DBUS_HANDLERS_CONNMAN_MANAGER_H */
