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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "dbus_handlers_connman_agent.h"
#include "messages.h"

#define NET_CONNMAN_AGENT_ERROR (net_connman_agent_error_quark())

enum NetConnmanAgentError
{
    NET_CONNMAN_AGENT_ERROR_CANCELED,
    NET_CONNMAN_AGENT_ERROR_REJECTED,
    NET_CONNMAN_AGENT_ERROR_RETRY,
    NET_CONNMAN_AGENT_ERROR_LAUNCH_BROWSER,
    NET_CONNMAN_AGENT_N_ERRORS,
};

static const GDBusErrorEntry net_connman_agent_error_entries[] =
{
    { NET_CONNMAN_AGENT_ERROR_CANCELED,       "net.connman.Agent.Error.Canceled" },
    { NET_CONNMAN_AGENT_ERROR_REJECTED,       "net.connman.Agent.Error.Rejected" },
    { NET_CONNMAN_AGENT_ERROR_RETRY,          "net.connman.Agent.Error.Retry" },
    { NET_CONNMAN_AGENT_ERROR_LAUNCH_BROWSER, "net.connman.Agent.Error.LaunchBrowser" },
};

G_STATIC_ASSERT(G_N_ELEMENTS(net_connman_agent_error_entries) == NET_CONNMAN_AGENT_N_ERRORS);

static GQuark net_connman_agent_error_quark(void)
{
    static volatile gsize quark_volatile = 0;
    g_dbus_error_register_error_domain("net-connman-agent-error-quark",
                                       &quark_volatile,
                                       net_connman_agent_error_entries,
                                       G_N_ELEMENTS(net_connman_agent_error_entries));
    return (GQuark)quark_volatile;
}

static bool send_error_if_possible(GDBusMethodInvocation *invocation,
                                   const char *error_message)
{
    if(error_message == NULL)
        return false;

    g_dbus_method_invocation_return_error_literal(invocation,
                                                  NET_CONNMAN_AGENT_ERROR,
                                                  NET_CONNMAN_AGENT_ERROR_CANCELED,
                                                  error_message);

    return true;
}

static void enter_agent_handler(GDBusMethodInvocation *invocation)
{
    static const char iface_name[] = "net.connman.Manager";

    msg_info("%s method invocation from '%s': %s",
             iface_name, g_dbus_method_invocation_get_sender(invocation),
             g_dbus_method_invocation_get_method_name(invocation));
}

gboolean dbusmethod_connman_agent_release(tdbusconnmanAgent *object,
                                          GDBusMethodInvocation *invocation,
                                          void *user_data)
{
    enter_agent_handler(invocation);

    BUG("%s(): not implemented yet", __func__);
    tdbus_connman_agent_complete_release(object, invocation);

    return TRUE;
}

gboolean dbusmethod_connman_agent_report_error(tdbusconnmanAgent *object,
                                               GDBusMethodInvocation *invocation,
                                               const gchar *arg_service,
                                               const gchar *arg_error,
                                               void *user_data)
{
    enter_agent_handler(invocation);

    BUG("%s(): not implemented yet", __func__);
    tdbus_connman_agent_complete_report_error(object, invocation);

    return TRUE;
}

gboolean dbusmethod_connman_agent_report_peer_error(tdbusconnmanAgent *object,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *arg_peer,
                                                    const gchar *arg_error,
                                                    void *user_data)
{
    enter_agent_handler(invocation);

    BUG("%s(): not implemented yet", __func__);
    tdbus_connman_agent_complete_report_peer_error(object, invocation);

    return TRUE;
}

gboolean dbusmethod_connman_agent_request_browser(tdbusconnmanAgent *object,
                                                  GDBusMethodInvocation *invocation,
                                                  const gchar *arg_service,
                                                  const gchar *arg_url,
                                                  void *user_data)
{
    enter_agent_handler(invocation);

    BUG("%s(): not implemented yet", __func__);
    send_error_if_possible(invocation, "We do not have any browser");

    return TRUE;
}

gboolean dbusmethod_connman_agent_request_input(tdbusconnmanAgent *object,
                                                GDBusMethodInvocation *invocation,
                                                const gchar *arg_service,
                                                GVariant *arg_fields,
                                                void *user_data)
{
    enter_agent_handler(invocation);

    BUG("%s(): not implemented yet", __func__);
    send_error_if_possible(invocation, "Not implemented yet");

    return TRUE;
}

gboolean dbusmethod_connman_agent_request_peer_authorization(tdbusconnmanAgent *object,
                                                             GDBusMethodInvocation *invocation,
                                                             const gchar *arg_peer,
                                                             GVariant *arg_fields,
                                                             void *user_data)
{
    enter_agent_handler(invocation);

    BUG("%s(): not implemented yet", __func__);
    send_error_if_possible(invocation, "Peer authorization not supported");

    return TRUE;
}

gboolean dbusmethod_connman_agent_cancel(tdbusconnmanAgent *object,
                                         GDBusMethodInvocation *invocation,
                                         void *user_data)
{
    enter_agent_handler(invocation);

    BUG("%s(): not implemented yet", __func__);
    tdbus_connman_agent_complete_cancel(object, invocation);

    return TRUE;
}
