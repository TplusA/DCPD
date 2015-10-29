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

#include "dbus_iface.h"
#include "dbus_iface_deep.h"
#include "dbus_handlers.h"
#include "dcpd_dbus.h"
#include "connman_dbus.h"
#include "messages.h"

struct dbus_data
{
    guint owner_id;
    int acquired;
};

struct dbus_process_data
{
    GThread *thread;
    GMainLoop *loop;
};

static struct dbus_data dbus_data_system_bus;
static struct dbus_data dbus_data_session_bus;

static struct
{
    bool connect_to_session_bus;
    tdbusdcpdPlayback *playback_iface;
    tdbusdcpdViews *views_iface;
    tdbusdcpdListNavigation *list_navigation_iface;
    tdbusdcpdListItem *list_item_iface;
}
dcpd_iface_data;

static struct
{
    bool connect_to_session_bus;
    tdbusFileTransfer *iface;
}
filetransfer_iface_data;

static struct
{
    bool is_enabled;
    tdbusconnmanManager *connman_manager_iface;
}
connman_iface_data;

static gpointer process_dbus(gpointer user_data)
{
    struct dbus_process_data *data = user_data;

    log_assert(data->loop != NULL);

    g_main_loop_run(data->loop);
    return NULL;
}

static int handle_dbus_error(GError **error)
{
    if(*error == NULL)
        return 0;

    msg_error(0, LOG_EMERG, "%s", (*error)->message);
    g_error_free(*error);
    *error = NULL;

    return -1;
}

static void try_export_iface(GDBusConnection *connection,
                             GDBusInterfaceSkeleton *iface)
{
    GError *error = NULL;

    g_dbus_interface_skeleton_export(iface, connection, "/de/tahifi/Dcpd", &error);

    (void)handle_dbus_error(&error);
}

static void bus_acquired(GDBusConnection *connection,
                         const gchar *name, gpointer user_data)
{
    struct dbus_data *data = user_data;

    const bool is_session_bus = (data == &dbus_data_session_bus);

    msg_info("D-Bus \"%s\" acquired (%s bus)",
             name, is_session_bus ? "session" : "system");

    if(is_session_bus == dcpd_iface_data.connect_to_session_bus)
    {
        dcpd_iface_data.playback_iface = tdbus_dcpd_playback_skeleton_new();
        dcpd_iface_data.views_iface = tdbus_dcpd_views_skeleton_new();
        dcpd_iface_data.list_navigation_iface = tdbus_dcpd_list_navigation_skeleton_new();
        dcpd_iface_data.list_item_iface = tdbus_dcpd_list_item_skeleton_new();

        try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(dcpd_iface_data.playback_iface));
        try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(dcpd_iface_data.views_iface));
        try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(dcpd_iface_data.list_navigation_iface));
        try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(dcpd_iface_data.list_item_iface));
    }
}

static void name_acquired(GDBusConnection *connection,
                          const gchar *name, gpointer user_data)
{
    struct dbus_data *data = user_data;

    const bool is_session_bus = (data == &dbus_data_session_bus);

    msg_info("D-Bus name \"%s\" acquired (%s bus)",
             name, is_session_bus ? "session" : "system");
    data->acquired = 1;

    if(is_session_bus == filetransfer_iface_data.connect_to_session_bus)
    {
        GError *error = NULL;

        filetransfer_iface_data.iface =
            tdbus_file_transfer_proxy_new_sync(connection,
                                               G_DBUS_PROXY_FLAGS_NONE,
                                               "de.tahifi.DBusDL", "/de/tahifi/DBusDL",
                                               NULL, &error);
        (void)handle_dbus_error(&error);
    }

    if(!is_session_bus)
    {
        /* Connman is always on system bus */
        GError *error = NULL;

        if(connman_iface_data.is_enabled)
        {
            connman_iface_data.connman_manager_iface =
                tdbus_connman_manager_proxy_new_sync(connection,
                                                     G_DBUS_PROXY_FLAGS_NONE,
                                                     "net.connman", "/",
                                                     NULL, &error);
            (void)handle_dbus_error(&error);
        }
    }
}

static void name_lost(GDBusConnection *connection,
                      const gchar *name, gpointer user_data)
{
    struct dbus_data *data = user_data;

    msg_info("D-Bus name \"%s\" lost", name);
    data->acquired = -1;
}

static void destroy_notification(gpointer data)
{
    msg_info("Bus destroyed.");
}

static struct dbus_process_data process_data;

int dbus_setup(bool connect_to_session_bus, bool with_connman)
{
#if !GLIB_CHECK_VERSION(2, 36, 0)
    g_type_init();
#endif

    memset(&dbus_data_system_bus, 0, sizeof(dbus_data_system_bus));
    memset(&dbus_data_session_bus, 0, sizeof(dbus_data_session_bus));
    memset(&dcpd_iface_data, 0, sizeof(dcpd_iface_data));
    memset(&filetransfer_iface_data, 0, sizeof(filetransfer_iface_data));
    memset(&connman_iface_data, 0, sizeof(connman_iface_data));
    memset(&process_data, 0, sizeof(process_data));

    connman_iface_data.is_enabled = with_connman;

    process_data.loop = g_main_loop_new(NULL, FALSE);
    if(process_data.loop == NULL)
    {
        msg_error(ENOMEM, LOG_EMERG, "Failed creating GLib main loop");
        return -1;
    }

    dcpd_iface_data.connect_to_session_bus = connect_to_session_bus;
    filetransfer_iface_data.connect_to_session_bus = connect_to_session_bus;

    static const char bus_name[] = "de.tahifi.Dcpd";

    if(connman_iface_data.is_enabled || !connect_to_session_bus)
        dbus_data_system_bus.owner_id =
            g_bus_own_name(G_BUS_TYPE_SYSTEM, bus_name,
                           G_BUS_NAME_OWNER_FLAGS_NONE,
                           bus_acquired, name_acquired, name_lost,
                           &dbus_data_system_bus, destroy_notification);

    if(connect_to_session_bus)
        dbus_data_session_bus.owner_id =
            g_bus_own_name(G_BUS_TYPE_SESSION, bus_name,
                           G_BUS_NAME_OWNER_FLAGS_NONE,
                           bus_acquired, name_acquired, name_lost,
                           &dbus_data_session_bus, destroy_notification);

    log_assert(dbus_data_system_bus.owner_id != 0 ||
               dbus_data_session_bus.owner_id != 0);

    while((dbus_data_system_bus.owner_id != 0 && dbus_data_system_bus.acquired == 0) ||
          (dbus_data_session_bus.owner_id != 0 && dbus_data_session_bus.acquired == 0))
    {
        /* do whatever has to be done behind the scenes until all of the
         * guaranteed callbacks gets called */
        g_main_context_iteration(NULL, TRUE);
    }

    bool failed = false;

    if(dbus_data_system_bus.owner_id > 0 && dbus_data_system_bus.acquired < 0)
    {
        msg_error(EPIPE, LOG_EMERG, "Failed acquiring D-Bus name on system bus");
        failed = true;
    }

    if(dbus_data_session_bus.owner_id > 0 && dbus_data_session_bus.acquired < 0)
    {
        msg_error(EPIPE, LOG_EMERG, "Failed acquiring D-Bus name on session bus");
        failed = true;
    }

    if(failed)
        return -1;

    log_assert(dcpd_iface_data.playback_iface != NULL);
    log_assert(dcpd_iface_data.views_iface != NULL);
    log_assert(dcpd_iface_data.list_navigation_iface != NULL);
    log_assert(dcpd_iface_data.list_item_iface != NULL);
    log_assert(filetransfer_iface_data.iface != NULL);

    g_signal_connect(filetransfer_iface_data.iface, "g-signal",
                     G_CALLBACK(dbussignal_file_transfer), NULL);

    if(connman_iface_data.is_enabled)
    {
        log_assert(connman_iface_data.connman_manager_iface != NULL);

        g_signal_connect(connman_iface_data.connman_manager_iface, "g-signal",
                         G_CALLBACK(dbussignal_connman_manager), NULL);
    }

    process_data.thread = g_thread_new("D-Bus I/O", process_dbus, &process_data);
    if(process_data.thread == NULL)
    {
        msg_error(EAGAIN, LOG_EMERG, "Failed spawning D-Bus I/O thread");
        return -1;
    }

    return 0;
}

void dbus_shutdown(void)
{
    if(process_data.loop == NULL)
        return;

    if(dbus_data_system_bus.owner_id > 0)
        g_bus_unown_name(dbus_data_system_bus.owner_id);

    if(dbus_data_session_bus.owner_id)
        g_bus_unown_name(dbus_data_session_bus.owner_id);

    g_main_loop_quit(process_data.loop);
    (void)g_thread_join(process_data.thread);
    g_main_loop_unref(process_data.loop);

    g_object_unref(dcpd_iface_data.playback_iface);
    g_object_unref(dcpd_iface_data.views_iface);
    g_object_unref(dcpd_iface_data.list_navigation_iface);
    g_object_unref(dcpd_iface_data.list_item_iface);

    g_object_unref(filetransfer_iface_data.iface);

    if(connman_iface_data.connman_manager_iface != NULL)
        g_object_unref(connman_iface_data.connman_manager_iface);

    process_data.loop = NULL;
}

tdbusdcpdPlayback *dbus_get_playback_iface(void)
{
    return dcpd_iface_data.playback_iface;
}

tdbusdcpdViews *dbus_get_views_iface(void)
{
    return dcpd_iface_data.views_iface;
}

tdbusdcpdListNavigation *dbus_get_list_navigation_iface(void)
{
    return dcpd_iface_data.list_navigation_iface;
}

tdbusdcpdListItem *dbus_get_list_item_iface(void)
{
    return dcpd_iface_data.list_item_iface;
}

tdbusFileTransfer *dbus_get_file_transfer_iface(void)
{
    return filetransfer_iface_data.iface;
}

tdbusconnmanManager *dbus_get_connman_manager_iface(void)
{
    return connman_iface_data.connman_manager_iface;
}
