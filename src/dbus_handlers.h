/*
 * Copyright (C) 2015--2019  T+A elektroakustik GmbH & Co. KG
 *
 * This file is part of DCPD.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 */

#ifndef DBUS_HANDLERS_H
#define DBUS_HANDLERS_H

#include "dcpd_dbus.h"
#include "audiopath_dbus.h"
#include "mixer_dbus.h"
#include "appliance_dbus.h"
#include "configuration_dbus.h"
#include "jsonio_dbus.h"
#include "debug_dbus.h"

/*!
 * \addtogroup dbus_handlers DBus handlers for signals
 * \ingroup dbus
 */
/*!@{*/

struct dbussignal_shutdown_iface
{
    bool (*const is_inhibitor_lock_taken)(void);
    void (*const allow_shutdown)(void);
};

#ifdef __cplusplus
extern "C" {
#endif

void dbussignal_splay_playback(GDBusProxy *proxy, const gchar *sender_name,
                               const gchar *signal_name, GVariant *parameters,
                               gpointer user_data);
void dbussignal_logind_manager(GDBusProxy *proxy, const gchar *sender_name,
                               const gchar *signal_name, GVariant *parameters,
                               gpointer user_data);
void dbussignal_file_transfer(GDBusProxy *proxy, const gchar *sender_name,
                              const gchar *signal_name, GVariant *parameters,
                              gpointer user_data);
void dbussignal_airable(GDBusProxy *proxy, const gchar *sender_name,
                        const gchar *signal_name, GVariant *parameters,
                        gpointer user_data);
void dbussignal_artcache_monitor(GDBusProxy *proxy, const gchar *sender_name,
                                 const gchar *signal_name, GVariant *parameters,
                                 gpointer user_data);

gboolean dbusmethod_set_stream_info(tdbusdcpdPlayback *object,
                                    GDBusMethodInvocation *invocation,
                                    guint16 raw_stream_id,
                                    const gchar *title, const gchar *url,
                                    gpointer user_data);

gboolean dbusmethod_network_get_all(tdbusdcpdNetwork *object,
                                    GDBusMethodInvocation *invocation,
                                    const gchar *have_version,
                                    gpointer user_data);
gboolean
dbusmethod_network_set_service_configuration(tdbusdcpdNetwork *object,
                                             GDBusMethodInvocation *invocation,
                                             const gchar *service_name,
                                             const gchar *configuration,
                                             gpointer user_data);

void dbussignal_audiopath_manager(GDBusProxy *proxy, const gchar *sender_name,
                                  const gchar *signal_name, GVariant *parameters,
                                  gpointer user_data);
gboolean dbusmethod_audiopath_source_selected(tdbusaupathSource *object,
                                              GDBusMethodInvocation *invocation,
                                              const char *source_id,
                                              GVariant *request_data,
                                              gpointer user_data);
gboolean dbusmethod_audiopath_source_deselected(tdbusaupathSource *object,
                                                GDBusMethodInvocation *invocation,
                                                const char *source_id,
                                                GVariant *request_data,
                                                gpointer user_data);

gboolean dbusmethod_mixer_get_controls(tdbusmixerVolume *object,
                                       GDBusMethodInvocation *invocation,
                                       gpointer user_data);
gboolean dbusmethod_mixer_get_master(tdbusmixerVolume *object,
                                     GDBusMethodInvocation *invocation,
                                     gpointer user_data);
gboolean dbusmethod_mixer_set(tdbusmixerVolume *object,
                              GDBusMethodInvocation *invocation,
                              guint16 id, gdouble volume, gboolean is_muted,
                              gpointer user_data);
gboolean dbusmethod_mixer_get(tdbusmixerVolume *object,
                              GDBusMethodInvocation *invocation,
                              guint16 id, gpointer user_data);

gboolean dbusmethod_appliance_request_power_state_change(tdbusappliancePower *object,
                                                         GDBusMethodInvocation *invocation,
                                                         guchar state, gpointer user_data);
gboolean dbusmethod_appliance_get_power_state(tdbusappliancePower *object,
                                              GDBusMethodInvocation *invocation,
                                              gpointer user_data);

gboolean dbusmethod_configproxy_register(tdbusConfigurationProxy *object,
                                         GDBusMethodInvocation *invocation,
                                         const gchar *id, const gchar *path,
                                         void *user_data);

gboolean dbusmethod_debug_logging_debug_level(tdbusdebugLogging *object,
                                              GDBusMethodInvocation *invocation,
                                              const gchar *arg_new_level,
                                              void *user_data);
gboolean dbusmethod_debug_logging_config_set_level(tdbusdebugLoggingConfig *object,
                                                   GDBusMethodInvocation *invocation,
                                                   const gchar *arg_new_level,
                                                   void *user_data);

gboolean dbusmethod_config_get_all_keys(tdbusConfigurationRead *object,
                                        GDBusMethodInvocation *invocation,
                                        gpointer user_data);
gboolean dbusmethod_config_get_value(tdbusConfigurationRead *object,
                                     GDBusMethodInvocation *invocation,
                                     const gchar *key, gpointer user_data);
gboolean dbusmethod_config_get_all_values(tdbusConfigurationRead *object,
                                          GDBusMethodInvocation *invocation,
                                          const gchar *database, gpointer user_data);

gboolean dbusmethod_audiopath_jsonreceiver_notify(tdbusJSONReceiver *object,
                                                  GDBusMethodInvocation *invocation,
                                                  const gchar *json,
                                                  const gchar *const *extra,
                                                  gpointer user_data);
gboolean dbusmethod_audiopath_jsonreceiver_tell(tdbusJSONReceiver *object,
                                                GDBusMethodInvocation *invocation,
                                                const gchar *json,
                                                const gchar *const *extra,
                                                gpointer user_data);

void dbussignal_gerbera(GDBusProxy *proxy, const gchar *sender_name,
                        const gchar *signal_name, GVariant *parameters,
                        gpointer user_data);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !DBUS_HANDLERS_H */
