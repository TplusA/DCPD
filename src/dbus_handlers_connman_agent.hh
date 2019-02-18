/*
 * Copyright (C) 2016, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef DBUS_HANDLERS_CONNMAN_AGENT_HH
#define DBUS_HANDLERS_CONNMAN_AGENT_HH

#include "connman_dbus.h"

#include <stdbool.h>
#include <gio/gio.h>

/*!
 * \addtogroup dbus_handlers
 */
/*!@{*/

#ifdef __cplusplus
extern "C" {
#endif

gboolean dbusmethod_connman_agent_release(tdbusconnmanAgent *object,
                                          GDBusMethodInvocation *invocation,
                                          void *user_data);
gboolean dbusmethod_connman_agent_report_error(tdbusconnmanAgent *object,
                                               GDBusMethodInvocation *invocation,
                                               const gchar *arg_service,
                                               const gchar *arg_error,
                                               void *user_data);
gboolean dbusmethod_connman_agent_report_peer_error(tdbusconnmanAgent *object,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *arg_peer,
                                                    const gchar *arg_error,
                                                    void *user_data);
gboolean dbusmethod_connman_agent_request_browser(tdbusconnmanAgent *object,
                                                  GDBusMethodInvocation *invocation,
                                                  const gchar *arg_service,
                                                  const gchar *arg_url,
                                                  void *user_data);
gboolean dbusmethod_connman_agent_request_input(tdbusconnmanAgent *object,
                                                GDBusMethodInvocation *invocation,
                                                const gchar *arg_service,
                                                GVariant *arg_fields,
                                                void *user_data);
gboolean dbusmethod_connman_agent_request_peer_authorization(tdbusconnmanAgent *object,
                                                             GDBusMethodInvocation *invocation,
                                                             const gchar *arg_peer,
                                                             GVariant *arg_fields,
                                                             void *user_data);
gboolean dbusmethod_connman_agent_cancel(tdbusconnmanAgent *object,
                                         GDBusMethodInvocation *invocation,
                                         void *user_data);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !DBUS_HANDLERS_CONNMAN_AGENT_HH */
