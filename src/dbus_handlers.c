/*
 * Copyright (C) 2015  T+A elektroakustik GmbH & Co. KG
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

#include <string.h>
#include <errno.h>

#include "dbus_handlers.h"
#include "dcpregs_networking.h"
#include "messages.h"

static void unknown_signal(const char *iface_name, const char *signal_name,
                           const char *sender_name)
{
    msg_error(ENOSYS, LOG_NOTICE, "Got unknown signal %s.%s from %s",
              iface_name, signal_name, sender_name);
}

static void check_parameter_assertions(GVariant *parameters,
                                       guint expected_number_of_parameters)
{
    /* we may use #log_assert() here because the GDBus code is supposed to do
     * any type checks before calling us---here, we just make sure we can
     * trust those type checks */
    log_assert(g_variant_type_is_tuple(g_variant_get_type(parameters)));
    log_assert(g_variant_n_children(parameters) == expected_number_of_parameters);
}

void dbussignal_connman_manager(GDBusProxy *proxy, const gchar *sender_name,
                                const gchar *signal_name, GVariant *parameters,
                                gpointer user_data)
{
    static const char iface_name[] = "net.connman.Manager";

    msg_info("%s signal from '%s': %s", iface_name, sender_name, signal_name);

    if(strcmp(signal_name, "ServicesChanged") == 0)
    {
        check_parameter_assertions(parameters, 2);
        dcpregs_networking_interfaces_changed();
    }
    else if(strcmp(signal_name, "PropertyChanged") == 0)
    {
        check_parameter_assertions(parameters, 2);

        GVariant *name = g_variant_get_child_value(parameters, 0);
        log_assert(name != NULL);

        if(strcmp(g_variant_get_string(name, NULL), "State") == 0)
            dcpregs_networking_interfaces_changed();

        g_variant_unref(name);
    }
    else
        unknown_signal(iface_name, signal_name, sender_name);
}
