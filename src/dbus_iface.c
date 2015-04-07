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
#include "dcpd_dbus.h"
#include "messages.h"

struct dbus_data
{
    GThread *thread;
    GMainLoop *loop;
    guint owner_id;
    int acquired;
    tdbusdcpdPlayback *playback_iface;
    tdbusdcpdViews *views_iface;
    tdbusdcpdListNavigation *list_navigation_iface;
    tdbusdcpdListItem *list_item_iface;
};

static gpointer process_dbus(gpointer user_data)
{
    struct dbus_data *data = user_data;

    log_assert(data->loop != NULL);

    g_main_loop_run(data->loop);
    return NULL;
}

static void try_export_iface(GDBusConnection *connection,
                             GDBusInterfaceSkeleton *iface)
{
    GError *error = NULL;

    g_dbus_interface_skeleton_export(iface, connection, "/de/tahifi/Dcpd", &error);

    if(error)
    {
        msg_error(0, LOG_EMERG, "%s", error->message);
        g_error_free(error);
    }
}

static void bus_acquired(GDBusConnection *connection,
                         const gchar *name, gpointer user_data)
{
    struct dbus_data *data = user_data;

    data->playback_iface = tdbus_dcpd_playback_skeleton_new();
    data->views_iface = tdbus_dcpd_views_skeleton_new();
    data->list_navigation_iface = tdbus_dcpd_list_navigation_skeleton_new();
    data->list_item_iface = tdbus_dcpd_list_item_skeleton_new();

    try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(data->playback_iface));
    try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(data->views_iface));
    try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(data->list_navigation_iface));
    try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(data->list_item_iface));
}

static void name_acquired(GDBusConnection *connection,
                          const gchar *name, gpointer user_data)
{
    struct dbus_data *data = user_data;

    msg_info("D-Bus name \"%s\" acquired", name);
    data->acquired = 1;
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

static struct dbus_data dbus_data;

int dbus_setup(bool connect_to_session_bus)
{
#if !GLIB_CHECK_VERSION(2, 36, 0)
    g_type_init();
#endif

    memset(&dbus_data, 0, sizeof(dbus_data));

    dbus_data.loop = g_main_loop_new(NULL, FALSE);
    if(dbus_data.loop == NULL)
    {
        msg_error(ENOMEM, LOG_EMERG, "Failed creating GLib main loop");
        return -1;
    }

    GBusType bus_type =
        connect_to_session_bus ? G_BUS_TYPE_SESSION : G_BUS_TYPE_SYSTEM;

    static const char bus_name[] = "de.tahifi.Dcpd";

    dbus_data.owner_id =
        g_bus_own_name(bus_type, bus_name, G_BUS_NAME_OWNER_FLAGS_NONE,
                       bus_acquired, name_acquired, name_lost, &dbus_data,
                       destroy_notification);

    while(dbus_data.acquired == 0)
    {
        /* do whatever has to be done behind the scenes until one of the
         * guaranteed callbacks gets called */
        g_main_context_iteration(NULL, TRUE);
    }

    if(dbus_data.acquired < 0)
    {
        msg_error(EPIPE, LOG_EMERG, "Failed acquiring D-Bus name");
        return -1;
    }

    log_assert(dbus_data.playback_iface != NULL);
    log_assert(dbus_data.views_iface != NULL);
    log_assert(dbus_data.list_navigation_iface != NULL);
    log_assert(dbus_data.list_item_iface != NULL);

    dbus_data.thread = g_thread_new("D-Bus I/O", process_dbus, &dbus_data);
    if(dbus_data.thread == NULL)
    {
        msg_error(EAGAIN, LOG_EMERG, "Failed spawning D-Bus I/O thread");
        return -1;
    }

    return 0;
}

void dbus_shutdown(void)
{
    if(dbus_data.loop == NULL)
        return;

    g_bus_unown_name(dbus_data.owner_id);

    g_main_loop_quit(dbus_data.loop);
    (void)g_thread_join(dbus_data.thread);
    g_main_loop_unref(dbus_data.loop);

    g_object_unref(dbus_data.playback_iface);
    g_object_unref(dbus_data.views_iface);
    g_object_unref(dbus_data.list_navigation_iface);
    g_object_unref(dbus_data.list_item_iface);

    dbus_data.loop = NULL;
}

tdbusdcpdPlayback *dbus_get_playback_iface(void)
{
    return dbus_data.playback_iface;
}

tdbusdcpdViews *dbus_get_views_iface(void)
{
    return dbus_data.views_iface;
}

tdbusdcpdListNavigation *dbus_get_list_navigation_iface(void)
{
    return dbus_data.list_navigation_iface;
}

tdbusdcpdListItem *dbus_get_list_item_iface(void)
{
    return dbus_data.list_item_iface;
}