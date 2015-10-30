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
#include "dcpregs_networkconfig.h"
#include "dcpregs_filetransfer.h"
#include "dcpregs_status.h"
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
        dcpregs_networkconfig_interfaces_changed();
    }
    else if(strcmp(signal_name, "PropertyChanged") == 0)
    {
        check_parameter_assertions(parameters, 2);

        GVariant *name = g_variant_get_child_value(parameters, 0);
        log_assert(name != NULL);

        if(strcmp(g_variant_get_string(name, NULL), "State") == 0)
            dcpregs_networkconfig_interfaces_changed();

        g_variant_unref(name);
    }
    else
        unknown_signal(iface_name, signal_name, sender_name);
}

void dbussignal_logind_manager(GDBusProxy *proxy, const gchar *sender_name,
                               const gchar *signal_name, GVariant *parameters,
                               gpointer user_data)
{
    static const char iface_name[] = "org.freedesktop.login1.Manager";

    msg_info("%s signal from '%s': %s", iface_name, sender_name, signal_name);

    if(strcmp(signal_name, "PrepareForShutdown") == 0)
    {
        check_parameter_assertions(parameters, 1);

        GVariant *val = g_variant_get_child_value(parameters, 0);
        gboolean is_active = g_variant_get_boolean(val);
        g_variant_unref(val);

        const struct dbussignal_shutdown_iface *const iface = user_data;

        if(!iface->is_inhibitor_lock_taken())
            msg_info("Shutting down, but having no inhibit lock");

        dcpregs_filetransfer_prepare_for_shutdown();
        dcpregs_networkconfig_prepare_for_shutdown();

        if(!is_active)
        {
            msg_error(0, LOG_NOTICE,
                      "Funny PrepareForShutdown message, asking for restart");
            dcpregs_status_set_reboot_required();
        }

        iface->allow_shutdown();
    }
    else if(strcmp(signal_name, "SeatNew") == 0)
    {
        /* actively ignore irrelevant known signals */
    }
    else
        unknown_signal(iface_name, signal_name, sender_name);
}

void dbussignal_file_transfer(GDBusProxy *proxy, const gchar *sender_name,
                              const gchar *signal_name, GVariant *parameters,
                              gpointer user_data)
{
    static const char iface_name[] = "de.tahifi.FileTransfer";

    msg_info("%s signal from '%s': %s", iface_name, sender_name, signal_name);

    if(strcmp(signal_name, "Progress") == 0)
    {
        check_parameter_assertions(parameters, 3);

        GVariant *val = g_variant_get_child_value(parameters, 0);
        uint32_t xfer_id = g_variant_get_uint32(val);
        g_variant_unref(val);

        val = g_variant_get_child_value(parameters, 1);
        uint32_t tick = g_variant_get_uint32(val);
        g_variant_unref(val);

        val = g_variant_get_child_value(parameters, 2);
        uint32_t total_ticks = g_variant_get_uint32(val);
        g_variant_unref(val);

        dcpregs_filetransfer_progress_notification(xfer_id, tick, total_ticks);
    }
    else if(strcmp(signal_name, "Done") == 0)
    {
        check_parameter_assertions(parameters, 3);

        GVariant *val = g_variant_get_child_value(parameters, 0);
        uint32_t xfer_id = g_variant_get_uint32(val);
        g_variant_unref(val);

        val = g_variant_get_child_value(parameters, 1);
        uint8_t error_code_raw = g_variant_get_byte(val);
        g_variant_unref(val);

        val = g_variant_get_child_value(parameters, 2);
        gsize path_length;
        const gchar *path = g_variant_get_string(val, &path_length);

        enum DBusListsErrorCode error_code =
            (error_code_raw <= LIST_ERROR_LAST_ERROR_CODE
             ? (enum DBusListsErrorCode)error_code_raw
             : LIST_ERROR_INTERNAL);

        dcpregs_filetransfer_done_notification(xfer_id, error_code,
                                               path_length > 0 ? path : NULL);

        g_variant_unref(val);
    }
    else
        unknown_signal(iface_name, signal_name, sender_name);
}
