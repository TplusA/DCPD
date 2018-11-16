/*
 * Copyright (C) 2015, 2016, 2017, 2018  T+A elektroakustik GmbH & Co. KG
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

#include "dbus_iface.h"
#include "dbus_iface_deep.h"
#include "dbus_handlers.h"
#include "dbus_handlers_connman_manager.h"
#include "dbus_handlers_connman_agent.h"
#include "dbus_common.h"
#include "dcpd_dbus.h"
#include "streamplayer_dbus.h"
#include "mixer_dbus.h"
#include "artcache_dbus.h"
#include "airable_dbus.h"
#include "credentials_dbus.h"
#include "configuration_dbus.h"
#include "appliance_dbus.h"
#include "connman_dbus.h"
#include "logind_dbus.h"
#include "systemd_dbus.h"
#include "messages.h"

#include <string.h>
#include <errno.h>

#include <gio/gunixfdlist.h>

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

    struct ConfigurationManagementData *config_management_data;

    tdbusdcpdPlayback *playback_iface;
    tdbusdcpdViews *views_iface;
    tdbusdcpdListNavigation *list_navigation_iface;
    tdbusdcpdListItem *list_item_iface;
    tdbusdcpdNetwork *network_config_iface;
    tdbusaupathSource *audiopath_source_iface;
    tdbusmixerVolume *mixer_volume_iface;
    tdbusappliancePower *appliance_power_iface;
    tdbusConfigurationProxy *configproxy_iface;
    tdbusConfigurationRead *configuration_read_iface;
    tdbusConfigurationMonitor *configuration_monitor_iface;
    tdbusdebugLogging *debug_logging_iface;
    tdbusdebugLoggingConfig *debug_logging_config_iface;
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
    bool connect_to_session_bus;
    tdbussplayPlayback *playback_iface;
    tdbussplayURLFIFO *urlfifo_iface;
}
streamplayer_iface_data;

static struct
{
    bool connect_to_session_bus;
    tdbussplayPlayback *playback_iface;
}
roonplayer_iface_data;

static struct airable_iface_data
{
    bool connect_to_session_bus;
    tdbusAirable *airable_sec_iface;
    void *appconn_data;
}
airable_iface_data;

static struct
{
    bool connect_to_session_bus;
    tdbusartcacheRead *artcache_read_iface;
    tdbusartcacheMonitor *artcache_monitor_iface;
}
artcache_iface_data;

static struct
{
    bool connect_to_session_bus;
    tdbusaupathManager *audiopath_manager_proxy;
    tdbusaupathAppliance *audiopath_appliance_proxy;
}
audiopath_iface_data;

static struct credentials_iface_data
{
    bool connect_to_session_bus;
    tdbuscredentialsRead *cred_read_iface;
    tdbuscredentialsWrite *cred_write_iface;
    void (*read_iface_available_notification)(void);
}
credentials_iface_data;

static struct
{
    bool is_enabled;
    tdbusconnmanManager *connman_manager_iface;
    tdbusconnmanAgent *connman_agent_iface;
}
connman_iface_data;

static struct
{
    int lock_fd;
    tdbuslogindManager *login1_manager_iface;
}
login1_iface_data;

static struct
{
    tdbussystemdManager *systemd1_manager_iface;
}
systemd1_iface_data;

static gpointer process_dbus(gpointer user_data)
{
    struct dbus_process_data *data = user_data;

    log_assert(data->loop != NULL);

    g_main_loop_run(data->loop);
    return NULL;
}

static void try_export_iface(GDBusConnection *connection,
                             GDBusInterfaceSkeleton *iface)
{
    GError *error = NULL;

    g_dbus_interface_skeleton_export(iface, connection, "/de/tahifi/Dcpd", &error);

    (void)dbus_common_handle_dbus_error(&error, "Export D-Bus interface");
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
        dcpd_iface_data.network_config_iface = tdbus_dcpd_network_skeleton_new();
        dcpd_iface_data.audiopath_source_iface = tdbus_aupath_source_skeleton_new();
        dcpd_iface_data.mixer_volume_iface = tdbus_mixer_volume_skeleton_new();
        dcpd_iface_data.appliance_power_iface = tdbus_appliance_power_skeleton_new();
        dcpd_iface_data.configproxy_iface = tdbus_configuration_proxy_skeleton_new();
        dcpd_iface_data.configuration_read_iface = tdbus_configuration_read_skeleton_new();
        dcpd_iface_data.configuration_monitor_iface = tdbus_configuration_monitor_skeleton_new();
        dcpd_iface_data.debug_logging_iface = tdbus_debug_logging_skeleton_new();
        dcpd_iface_data.debug_logging_config_iface = tdbus_debug_logging_config_skeleton_new();

        g_signal_connect(dcpd_iface_data.playback_iface, "handle-set-stream-info",
                         G_CALLBACK(dbusmethod_set_stream_info), NULL);

        g_signal_connect(dcpd_iface_data.network_config_iface, "handle-get-all",
                         G_CALLBACK(dbusmethod_network_get_all), NULL);
        g_signal_connect(dcpd_iface_data.network_config_iface, "handle-set-service-configuration",
                         G_CALLBACK(dbusmethod_network_set_service_configuration), NULL);

        g_signal_connect(dcpd_iface_data.audiopath_source_iface, "handle-selected",
                         G_CALLBACK(dbusmethod_audiopath_source_selected), NULL);
        g_signal_connect(dcpd_iface_data.audiopath_source_iface, "handle-deselected",
                         G_CALLBACK(dbusmethod_audiopath_source_deselected), NULL);

        g_signal_connect(dcpd_iface_data.mixer_volume_iface, "handle-get-controls",
                         G_CALLBACK(dbusmethod_mixer_get_controls), NULL);
        g_signal_connect(dcpd_iface_data.mixer_volume_iface, "handle-get-master",
                         G_CALLBACK(dbusmethod_mixer_get_master), NULL);
        g_signal_connect(dcpd_iface_data.mixer_volume_iface, "handle-set",
                         G_CALLBACK(dbusmethod_mixer_set), NULL);
        g_signal_connect(dcpd_iface_data.mixer_volume_iface, "handle-get",
                         G_CALLBACK(dbusmethod_mixer_get), NULL);

        g_signal_connect(dcpd_iface_data.appliance_power_iface, "handle-request-state",
                         G_CALLBACK(dbusmethod_appliance_request_power_state_change), NULL);
        g_signal_connect(dcpd_iface_data.appliance_power_iface, "handle-get-state",
                         G_CALLBACK(dbusmethod_appliance_get_power_state), NULL);

        g_signal_connect(dcpd_iface_data.configproxy_iface, "handle-register",
                         G_CALLBACK(dbusmethod_configproxy_register), NULL);
        g_signal_connect(dcpd_iface_data.configuration_read_iface, "handle-get-all-keys",
                         G_CALLBACK(dbusmethod_config_get_all_keys),
                         dcpd_iface_data.config_management_data);
        g_signal_connect(dcpd_iface_data.configuration_read_iface, "handle-get-value",
                         G_CALLBACK(dbusmethod_config_get_value),
                         dcpd_iface_data.config_management_data);
        g_signal_connect(dcpd_iface_data.configuration_read_iface, "handle-get-all-values",
                         G_CALLBACK(dbusmethod_config_get_all_values),
                         dcpd_iface_data.config_management_data);

        g_signal_connect(dcpd_iface_data.debug_logging_iface,
                         "handle-debug-level",
                         G_CALLBACK(dbusmethod_debug_logging_debug_level), NULL);
        g_signal_connect(dcpd_iface_data.debug_logging_config_iface,
                         "handle-set-global-debug-level",
                         G_CALLBACK(dbusmethod_debug_logging_config_set_level), NULL);

        try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(dcpd_iface_data.playback_iface));
        try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(dcpd_iface_data.views_iface));
        try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(dcpd_iface_data.list_navigation_iface));
        try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(dcpd_iface_data.list_item_iface));
        try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(dcpd_iface_data.network_config_iface));
        try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(dcpd_iface_data.audiopath_source_iface));
        try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(dcpd_iface_data.mixer_volume_iface));
        try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(dcpd_iface_data.appliance_power_iface));
        try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(dcpd_iface_data.configproxy_iface));
        try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(dcpd_iface_data.configuration_read_iface));
        try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(dcpd_iface_data.configuration_monitor_iface));
        try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(dcpd_iface_data.debug_logging_iface));
        try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(dcpd_iface_data.debug_logging_config_iface));
    }

    if(!is_session_bus)
    {
        connman_iface_data.connman_agent_iface = tdbus_connman_agent_skeleton_new();

        g_signal_connect(connman_iface_data.connman_agent_iface, "handle-release",
                         G_CALLBACK(dbusmethod_connman_agent_release), NULL);
        g_signal_connect(connman_iface_data.connman_agent_iface, "handle-report-error",
                         G_CALLBACK(dbusmethod_connman_agent_report_error), NULL);
        g_signal_connect(connman_iface_data.connman_agent_iface, "handle-report-peer-error",
                         G_CALLBACK(dbusmethod_connman_agent_report_peer_error), NULL);
        g_signal_connect(connman_iface_data.connman_agent_iface, "handle-request-browser",
                         G_CALLBACK(dbusmethod_connman_agent_request_browser), NULL);
        g_signal_connect(connman_iface_data.connman_agent_iface, "handle-request-input",
                         G_CALLBACK(dbusmethod_connman_agent_request_input), NULL);
        g_signal_connect(connman_iface_data.connman_agent_iface, "handle-request-peer-authorization",
                         G_CALLBACK(dbusmethod_connman_agent_request_peer_authorization), NULL);
        g_signal_connect(connman_iface_data.connman_agent_iface, "handle-cancel",
                         G_CALLBACK(dbusmethod_connman_agent_cancel), NULL);

        try_export_iface(connection, G_DBUS_INTERFACE_SKELETON(connman_iface_data.connman_agent_iface));
    }
}

static void created_airable_proxy(GObject *source_object, GAsyncResult *res,
                                  gpointer user_data)
{
    struct airable_iface_data *data = user_data;
    GError *error = NULL;

    data->airable_sec_iface = tdbus_airable_proxy_new_finish(res, &error);

    if(dbus_common_handle_dbus_error(&error, "Create Airable sec proxy") == 0)
        g_signal_connect(data->airable_sec_iface, "g-signal",
                         G_CALLBACK(dbussignal_airable), data->appconn_data);
}

static void created_cred_read_proxy(GObject *source_object, GAsyncResult *res,
                                    gpointer user_data)
{
    struct credentials_iface_data *data = user_data;
    GError *error = NULL;

    data->cred_read_iface =
        tdbus_credentials_read_proxy_new_finish(res, &error);

    if(dbus_common_handle_dbus_error(&error, "Create Airable credread proxy") == 0)
        data->read_iface_available_notification();
}

static void created_cred_write_proxy(GObject *source_object, GAsyncResult *res,
                                     gpointer user_data)
{
    struct credentials_iface_data *data = user_data;
    GError *error = NULL;

    data->cred_write_iface =
        tdbus_credentials_write_proxy_new_finish(res, &error);

    (void)dbus_common_handle_dbus_error(&error, "Create Airable credwrite proxy");
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
        (void)dbus_common_handle_dbus_error(&error, "Create DBusDL proxy");
    }

    if(is_session_bus == streamplayer_iface_data.connect_to_session_bus)
    {
        GError *error = NULL;

        streamplayer_iface_data.playback_iface =
            tdbus_splay_playback_proxy_new_sync(connection,
                                                G_DBUS_PROXY_FLAGS_NONE,
                                                "de.tahifi.Streamplayer",
                                                "/de/tahifi/Streamplayer",
                                                NULL, &error);
        (void)dbus_common_handle_dbus_error(&error, "Create Streamplayer playback proxy");

        streamplayer_iface_data.urlfifo_iface =
            tdbus_splay_urlfifo_proxy_new_sync(connection,
                                               G_DBUS_PROXY_FLAGS_NONE,
                                               "de.tahifi.Streamplayer",
                                               "/de/tahifi/Streamplayer",
                                               NULL, &error);
        (void)dbus_common_handle_dbus_error(&error, "Create Streamplayer URLFIFO proxy");
    }

    if(is_session_bus == roonplayer_iface_data.connect_to_session_bus)
    {
        GError *error = NULL;

        roonplayer_iface_data.playback_iface =
            tdbus_splay_playback_proxy_new_sync(connection,
                                                G_DBUS_PROXY_FLAGS_NONE,
                                                "de.tahifi.Roon",
                                                "/de/tahifi/Roon",
                                                NULL, &error);
        (void)dbus_common_handle_dbus_error(&error, "Create Roon playback proxy");
    }

    if(is_session_bus == airable_iface_data.connect_to_session_bus)
        tdbus_airable_proxy_new(connection, G_DBUS_PROXY_FLAGS_NONE,
                                "de.tahifi.TuneInBroker",
                                "/de/tahifi/TuneInBroker", NULL,
                                created_airable_proxy, &airable_iface_data);

    if(is_session_bus == artcache_iface_data.connect_to_session_bus)
    {
        GError *error = NULL;

        artcache_iface_data.artcache_read_iface =
            tdbus_artcache_read_proxy_new_sync(connection,
                                               G_DBUS_PROXY_FLAGS_NONE,
                                               "de.tahifi.TACAMan",
                                               "/de/tahifi/TACAMan",
                                               NULL, &error);
        (void)dbus_common_handle_dbus_error(&error, "Create tacaman read proxy");

        artcache_iface_data.artcache_monitor_iface =
            tdbus_artcache_monitor_proxy_new_sync(connection,
                                                  G_DBUS_PROXY_FLAGS_NONE,
                                                  "de.tahifi.TACAMan",
                                                  "/de/tahifi/TACAMan",
                                                  NULL, &error);
        (void)dbus_common_handle_dbus_error(&error, "Create tacaman monitor proxy");
    }

    if(is_session_bus == audiopath_iface_data.connect_to_session_bus)
    {
        GError *error = NULL;

        audiopath_iface_data.audiopath_manager_proxy =
            tdbus_aupath_manager_proxy_new_sync(connection,
                                                G_DBUS_PROXY_FLAGS_NONE,
                                                "de.tahifi.TAPSwitch",
                                                "/de/tahifi/TAPSwitch",
                                                NULL, &error);
        (void)dbus_common_handle_dbus_error(&error, "Create tapswitch manager proxy");

        audiopath_iface_data.audiopath_appliance_proxy =
            tdbus_aupath_appliance_proxy_new_sync(connection,
                                                  G_DBUS_PROXY_FLAGS_NONE,
                                                  "de.tahifi.TAPSwitch",
                                                  "/de/tahifi/TAPSwitch",
                                                  NULL, &error);
        (void)dbus_common_handle_dbus_error(&error, "Create tapswitch appliance proxy");
    }

    if(is_session_bus == credentials_iface_data.connect_to_session_bus)
    {
        tdbus_credentials_read_proxy_new(connection,
                                         G_DBUS_PROXY_FLAGS_NONE,
                                         "de.tahifi.TuneInBroker",
                                         "/de/tahifi/TuneInBroker", NULL,
                                         created_cred_read_proxy,
                                         &credentials_iface_data);

        tdbus_credentials_write_proxy_new(connection,
                                          G_DBUS_PROXY_FLAGS_NONE,
                                          "de.tahifi.TuneInBroker",
                                          "/de/tahifi/TuneInBroker", NULL,
                                          created_cred_write_proxy,
                                          &credentials_iface_data);
    }

    if(!is_session_bus)
    {
        /* Connman, logind, and systemd are always on system bus */
        GError *error = NULL;

        if(connman_iface_data.is_enabled)
        {
            connman_iface_data.connman_manager_iface =
                tdbus_connman_manager_proxy_new_sync(connection,
                                                     G_DBUS_PROXY_FLAGS_NONE,
                                                     "net.connman", "/",
                                                     NULL, &error);
            (void)dbus_common_handle_dbus_error(&error, "Create ConnMan manager proxy");

            msg_vinfo(MESSAGE_LEVEL_DEBUG, "Register as ConnMan agent");

            tdbus_connman_manager_call_register_agent_sync(connman_iface_data.connman_manager_iface,
                                                           "/de/tahifi/Dcpd",
                                                           NULL, &error);
            (void)dbus_common_handle_dbus_error(&error, "Create ConnMan agent proxy");
        }

        systemd1_iface_data.systemd1_manager_iface =
            tdbus_systemd_manager_proxy_new_sync(connection,
                                                 G_DBUS_PROXY_FLAGS_NONE,
                                                 "org.freedesktop.systemd1",
                                                 "/org/freedesktop/systemd1",
                                                 NULL, &error);
        (void)dbus_common_handle_dbus_error(&error, "Create systemd1 proxy");

        login1_iface_data.login1_manager_iface =
            tdbus_logind_manager_proxy_new_sync(connection,
                                                G_DBUS_PROXY_FLAGS_NONE,
                                                "org.freedesktop.login1",
                                                "/org/freedesktop/login1",
                                                NULL, &error);
        (void)dbus_common_handle_dbus_error(&error, "Create login1 proxy");
    }
}

static void name_lost(GDBusConnection *connection,
                      const gchar *name, gpointer user_data)
{
    struct dbus_data *data = user_data;

    msg_vinfo(MESSAGE_LEVEL_IMPORTANT, "D-Bus name \"%s\" lost", name);
    data->acquired = -1;
}

static void destroy_notification(gpointer data)
{
    msg_vinfo(MESSAGE_LEVEL_IMPORTANT, "Bus destroyed.");
}

static bool is_shutdown_inhibited(void)
{
    return login1_iface_data.lock_fd >= 0;
}

static const struct dbussignal_shutdown_iface logind_shutdown_functions =
{
    .is_inhibitor_lock_taken = is_shutdown_inhibited,
    .allow_shutdown = dbus_unlock_shutdown_sequence,
};

static struct dbus_process_data process_data;

int dbus_setup(bool connect_to_session_bus, bool with_connman,
               void *appconn_data,
               struct DBusSignalManagerData *connman_data,
               struct ConfigurationManagementData *configuration_data,
               void (*credentials_read_iface_available_notification)(void))
{
#if !GLIB_CHECK_VERSION(2, 36, 0)
    g_type_init();
#endif

    memset(&dbus_data_system_bus, 0, sizeof(dbus_data_system_bus));
    memset(&dbus_data_session_bus, 0, sizeof(dbus_data_session_bus));
    memset(&dcpd_iface_data, 0, sizeof(dcpd_iface_data));
    memset(&filetransfer_iface_data, 0, sizeof(filetransfer_iface_data));
    memset(&streamplayer_iface_data, 0, sizeof(streamplayer_iface_data));
    memset(&roonplayer_iface_data, 0, sizeof(roonplayer_iface_data));
    memset(&airable_iface_data, 0, sizeof(airable_iface_data));
    memset(&artcache_iface_data, 0, sizeof(artcache_iface_data));
    memset(&audiopath_iface_data, 0, sizeof(audiopath_iface_data));
    memset(&credentials_iface_data, 0, sizeof(credentials_iface_data));
    memset(&connman_iface_data, 0, sizeof(connman_iface_data));
    memset(&login1_iface_data, 0, sizeof(login1_iface_data));
    memset(&systemd1_iface_data, 0, sizeof(systemd1_iface_data));
    memset(&process_data, 0, sizeof(process_data));

    connman_iface_data.is_enabled = with_connman;
    login1_iface_data.lock_fd = -1;

    process_data.loop = g_main_loop_new(NULL, FALSE);
    if(process_data.loop == NULL)
    {
        msg_error(ENOMEM, LOG_EMERG, "Failed creating GLib main loop");
        return -1;
    }

    dcpd_iface_data.connect_to_session_bus = connect_to_session_bus;
    dcpd_iface_data.config_management_data = configuration_data;
    filetransfer_iface_data.connect_to_session_bus = connect_to_session_bus;
    streamplayer_iface_data.connect_to_session_bus = connect_to_session_bus;
    roonplayer_iface_data.connect_to_session_bus = connect_to_session_bus;
    airable_iface_data.connect_to_session_bus = connect_to_session_bus;
    airable_iface_data.appconn_data = appconn_data;
    artcache_iface_data.connect_to_session_bus = connect_to_session_bus;
    audiopath_iface_data.connect_to_session_bus = connect_to_session_bus;
    credentials_iface_data.connect_to_session_bus = connect_to_session_bus;
    credentials_iface_data.read_iface_available_notification =
        credentials_read_iface_available_notification;

    static const char bus_name[] = "de.tahifi.Dcpd";

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
    log_assert(dcpd_iface_data.network_config_iface != NULL);
    log_assert(dcpd_iface_data.audiopath_source_iface != NULL);
    log_assert(dcpd_iface_data.mixer_volume_iface != NULL);
    log_assert(dcpd_iface_data.appliance_power_iface != NULL);
    log_assert(dcpd_iface_data.configproxy_iface != NULL);
    log_assert(dcpd_iface_data.configuration_read_iface != NULL);
    log_assert(dcpd_iface_data.configuration_monitor_iface != NULL);
    log_assert(dcpd_iface_data.debug_logging_iface != NULL);
    log_assert(dcpd_iface_data.debug_logging_config_iface != NULL);
    log_assert(filetransfer_iface_data.iface != NULL);
    log_assert(streamplayer_iface_data.playback_iface != NULL);
    log_assert(streamplayer_iface_data.urlfifo_iface != NULL);
    log_assert(roonplayer_iface_data.playback_iface != NULL);
    log_assert(artcache_iface_data.artcache_read_iface != NULL);
    log_assert(artcache_iface_data.artcache_monitor_iface != NULL);
    log_assert(audiopath_iface_data.audiopath_manager_proxy != NULL);
    log_assert(audiopath_iface_data.audiopath_appliance_proxy != NULL);
    log_assert(connman_iface_data.connman_agent_iface != NULL);

    g_signal_connect(audiopath_iface_data.audiopath_manager_proxy, "g-signal",
                     G_CALLBACK(dbussignal_audiopath_manager), NULL);

    g_signal_connect(filetransfer_iface_data.iface, "g-signal",
                     G_CALLBACK(dbussignal_file_transfer), NULL);

    g_signal_connect(streamplayer_iface_data.playback_iface, "g-signal",
                     G_CALLBACK(dbussignal_splay_playback), NULL);

    g_signal_connect(roonplayer_iface_data.playback_iface, "g-signal",
                     G_CALLBACK(dbussignal_splay_playback), NULL);

    g_signal_connect(artcache_iface_data.artcache_monitor_iface, "g-signal",
                     G_CALLBACK(dbussignal_artcache_monitor), NULL);

    if(connman_iface_data.is_enabled)
    {
        log_assert(connman_iface_data.connman_manager_iface != NULL);

        dbussignal_connman_manager_about_to_connect_signals();
        g_signal_connect(connman_iface_data.connman_manager_iface, "g-signal",
                         G_CALLBACK(dbussignal_connman_manager), connman_data);
    }

    log_assert(login1_iface_data.login1_manager_iface != NULL);
    g_signal_connect(login1_iface_data.login1_manager_iface, "g-signal",
                     G_CALLBACK(dbussignal_logind_manager),
                     (gpointer)&logind_shutdown_functions);

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
    if(process_data.thread != NULL)
        (void)g_thread_join(process_data.thread);
    g_main_loop_unref(process_data.loop);

    g_object_unref(dcpd_iface_data.playback_iface);
    g_object_unref(dcpd_iface_data.views_iface);
    g_object_unref(dcpd_iface_data.list_navigation_iface);
    g_object_unref(dcpd_iface_data.list_item_iface);
    g_object_unref(dcpd_iface_data.network_config_iface);
    g_object_unref(dcpd_iface_data.audiopath_source_iface);
    g_object_unref(dcpd_iface_data.mixer_volume_iface);
    g_object_unref(dcpd_iface_data.appliance_power_iface);
    g_object_unref(dcpd_iface_data.configproxy_iface);
    g_object_unref(dcpd_iface_data.configuration_read_iface);
    g_object_unref(dcpd_iface_data.configuration_monitor_iface);
    g_object_unref(dcpd_iface_data.debug_logging_iface);
    g_object_unref(dcpd_iface_data.debug_logging_config_iface);

    g_object_unref(filetransfer_iface_data.iface);
    g_object_unref(streamplayer_iface_data.playback_iface);
    g_object_unref(streamplayer_iface_data.urlfifo_iface);
    g_object_unref(roonplayer_iface_data.playback_iface);

    if(airable_iface_data.airable_sec_iface != NULL)
        g_object_unref(airable_iface_data.airable_sec_iface);

    g_object_unref(artcache_iface_data.artcache_read_iface);
    g_object_unref(artcache_iface_data.artcache_monitor_iface);
    g_object_unref(audiopath_iface_data.audiopath_manager_proxy);
    g_object_unref(audiopath_iface_data.audiopath_appliance_proxy);

    if(credentials_iface_data.cred_read_iface != NULL)
        g_object_unref(credentials_iface_data.cred_read_iface);

    if(credentials_iface_data.cred_write_iface != NULL)
        g_object_unref(credentials_iface_data.cred_write_iface);

    g_object_unref(connman_iface_data.connman_agent_iface);

    if(connman_iface_data.connman_manager_iface != NULL)
        g_object_unref(connman_iface_data.connman_manager_iface);

    g_object_unref(login1_iface_data.login1_manager_iface);
    g_object_unref(systemd1_iface_data.systemd1_manager_iface);

    process_data.loop = NULL;
}

void dbus_lock_shutdown_sequence(const char *why)
{
    if(is_shutdown_inhibited())
    {
        BUG("D-Bus shutdown inhibitor lock already taken");
        return;
    }

    GVariant *out_fd = NULL;
    GUnixFDList *out_fd_list = NULL;
    GError *error = NULL;

    tdbus_logind_manager_call_inhibit_sync(dbus_get_logind_manager_iface(),
        "shutdown", PACKAGE, why, "delay",
        NULL, &out_fd, &out_fd_list, NULL, &error);

    if(dbus_common_handle_dbus_error(&error, "Shutdown request") < 0)
        return;

    if(out_fd == NULL)
        msg_error(EINVAL, LOG_ERR, "Got NULL lock fd");
    else
    {
        if(!g_variant_is_of_type(out_fd, G_VARIANT_TYPE_HANDLE))
            msg_error(EINVAL, LOG_ERR, "Unexpected lock fd type %s",
                      g_variant_get_type_string(out_fd));
        g_variant_unref(out_fd);
    }

    if(out_fd_list == NULL)
        msg_error(EINVAL, LOG_ERR, "Got NULL lock fd list");
    else
    {
        gint count = g_unix_fd_list_get_length(out_fd_list);

        if(count != 1)
            msg_error(EINVAL, LOG_ERR,
                      "Unexpected lock fd list length %d", count);

        if(count >= 1)
        {
            login1_iface_data.lock_fd =
                g_unix_fd_list_get(out_fd_list, 0, &error);

            if(dbus_common_handle_dbus_error(&error, "FD list get (not a D-Bus error)"))
                login1_iface_data.lock_fd = -1;
        }

        g_object_unref(out_fd_list);
    }

    if(is_shutdown_inhibited())
        msg_vinfo(MESSAGE_LEVEL_DEBUG,
                  "D-Bus inhibitor lock fd is %d", login1_iface_data.lock_fd);
    else
        msg_error(0, LOG_CRIT, "Failed taking inhibitor lock");
}

void dbus_unlock_shutdown_sequence(void)
{
    if(is_shutdown_inhibited())
    {
        os_file_close(login1_iface_data.lock_fd);
        login1_iface_data.lock_fd = -1;
    }
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

tdbusdcpdNetwork *dbus_get_network_config_iface(void)
{
    return dcpd_iface_data.network_config_iface;
}

tdbusmixerVolume *dbus_mixer_get_volume_iface(void)
{
    return dcpd_iface_data.mixer_volume_iface;
}

tdbusappliancePower *dbus_appliance_get_power_iface(void)
{
    return dcpd_iface_data.appliance_power_iface;
}

tdbusConfigurationProxy *dbus_get_configuration_proxy_iface(void)
{
    return dcpd_iface_data.configproxy_iface;
}

tdbusFileTransfer *dbus_get_file_transfer_iface(void)
{
    return filetransfer_iface_data.iface;
}

tdbussplayPlayback *dbus_get_streamplayer_playback_iface(void)
{
    return streamplayer_iface_data.playback_iface;
}

tdbussplayURLFIFO *dbus_get_streamplayer_urlfifo_iface(void)
{
    return streamplayer_iface_data.urlfifo_iface;
}

tdbussplayPlayback *dbus_get_roonplayer_playback_iface(void)
{
    return roonplayer_iface_data.playback_iface;
}

tdbusAirable *dbus_get_airable_sec_iface(void)
{
    return airable_iface_data.airable_sec_iface;
}

tdbusartcacheRead *dbus_get_artcache_read_iface(void)
{
    return artcache_iface_data.artcache_read_iface;
}

tdbusaupathManager *dbus_audiopath_get_manager_iface(void)
{
    return audiopath_iface_data.audiopath_manager_proxy;
}

tdbusaupathAppliance *dbus_audiopath_get_appliance_iface(void)
{
    return audiopath_iface_data.audiopath_appliance_proxy;
}

tdbuscredentialsRead *dbus_get_credentials_read_iface(void)
{
    return credentials_iface_data.cred_read_iface;
}

tdbuscredentialsWrite *dbus_get_credentials_write_iface(void)
{
    return credentials_iface_data.cred_write_iface;
}

tdbusConfigurationRead *dbus_new_configuration_read_iface(const char *dest, const char *path)
{
    GDBusConnection *connection =
        g_dbus_interface_skeleton_get_connection(G_DBUS_INTERFACE_SKELETON(dbus_get_configuration_proxy_iface()));

    GError *error = NULL;

    tdbusConfigurationRead *proxy =
        tdbus_configuration_read_proxy_new_sync(connection,
                                                G_DBUS_PROXY_FLAGS_NONE,
                                                dest, path,
                                                NULL, &error);
    (void)dbus_common_handle_dbus_error(&error, "Create Configuration.Read proxy");

    return proxy;
}

tdbusConfigurationWrite *dbus_new_configuration_write_iface(const char *dest, const char *path)
{
    GDBusConnection *connection =
        g_dbus_interface_skeleton_get_connection(G_DBUS_INTERFACE_SKELETON(dbus_get_configuration_proxy_iface()));

    GError *error = NULL;

    tdbusConfigurationWrite *proxy =
        tdbus_configuration_write_proxy_new_sync(connection,
                                                 G_DBUS_PROXY_FLAGS_NONE,
                                                 dest, path,
                                                 NULL, &error);
    (void)dbus_common_handle_dbus_error(&error, "Create Configuration.Write proxy");

    return proxy;
}

tdbusConfigurationMonitor *dbus_get_configuration_monitor_iface(void)
{
    return dcpd_iface_data.configuration_monitor_iface;
}

tdbusconnmanManager *dbus_get_connman_manager_iface(void)
{
    return connman_iface_data.connman_manager_iface;
}

tdbusconnmanTechnology *dbus_new_connman_technology_proxy_for_object_path(const char *path)
{
    GDBusConnection *connection =
        g_dbus_proxy_get_connection(G_DBUS_PROXY(dbus_get_connman_manager_iface()));

    GError *error = NULL;

    tdbusconnmanTechnology *proxy =
        tdbus_connman_technology_proxy_new_sync(connection,
                                                G_DBUS_PROXY_FLAGS_NONE,
                                                "net.connman", strdup(path),
                                                NULL, &error);
    (void)dbus_common_handle_dbus_error(&error, "Create ConnMan tech proxy");

    return proxy;
}

tdbusconnmanService *dbus_new_connman_service_proxy_for_object_path(const char *path,
                                                                    gint timeout_sec)
{
    GDBusConnection *connection =
        g_dbus_proxy_get_connection(G_DBUS_PROXY(dbus_get_connman_manager_iface()));

    GError *error = NULL;

    tdbusconnmanService *proxy =
        tdbus_connman_service_proxy_new_sync(connection,
                                             G_DBUS_PROXY_FLAGS_NONE,
                                             "net.connman", strdup(path),
                                             NULL, &error);

    if(dbus_common_handle_dbus_error(&error, "Create ConnMan service proxy") == 0)
    {
        if(timeout_sec > 0 && timeout_sec <= 600)
            g_dbus_proxy_set_default_timeout(G_DBUS_PROXY(proxy),
                                             timeout_sec * 1000);
    }

    return proxy;
}

tdbuslogindManager *dbus_get_logind_manager_iface(void)
{
    return login1_iface_data.login1_manager_iface;
}

tdbussystemdManager *dbus_get_systemd_manager_iface(void)
{
    return systemd1_iface_data.systemd1_manager_iface;
}
