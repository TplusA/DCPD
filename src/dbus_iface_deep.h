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

#ifndef DBUS_IFACE_DEEP_H
#define DBUS_IFACE_DEEP_H

#include "de_tahifi_dcpd.h"
#include "de_tahifi_filetransfer.h"
#include "de_tahifi_streamplayer.h"
#include "de_tahifi_airable.h"
#include "de_tahifi_artcache.h"
#include "de_tahifi_audiopath.h"
#include "de_tahifi_mixer.h"
#include "de_tahifi_credentials.h"
#include "de_tahifi_configuration.h"
#include "de_tahifi_jsonio.h"
#include "de_tahifi_appliance.h"
#include "net_connman.h"
#include "io_gerbera.h"
#include "org_freedesktop_login1.h"
#include "org_freedesktop_systemd1.h"

#ifdef __cplusplus
extern "C" {
#endif

tdbusdcpdPlayback *dbus_get_playback_iface(void);
tdbusdcpdViews *dbus_get_views_iface(void);
tdbusdcpdListNavigation *dbus_get_list_navigation_iface(void);
tdbusdcpdListItem *dbus_get_list_item_iface(void);
tdbusdcpdNetwork *dbus_get_network_config_iface(void);
tdbusmixerVolume *dbus_mixer_get_volume_iface(void);
tdbusaupathManager *dbus_audiopath_get_manager_iface(void);
tdbusaupathAppliance *dbus_audiopath_get_appliance_iface(void);
tdbusJSONEmitter *dbus_audiopath_get_config_update_iface(void);
tdbusGerberaContentManager *dbus_get_gerbera_content_manager_iface(void);
tdbusappliancePower *dbus_appliance_get_power_iface(void);
tdbusConfigurationProxy *dbus_get_configuration_proxy_iface(void);

tdbusFileTransfer *dbus_get_file_transfer_iface(void);

tdbussplayURLFIFO *dbus_get_streamplayer_urlfifo_iface(void);
tdbussplayPlayback *dbus_get_streamplayer_playback_iface(void);

tdbussplayPlayback *dbus_get_roonplayer_playback_iface(void);

tdbusAirable *dbus_get_airable_sec_iface(void);

tdbusartcacheRead *dbus_get_artcache_read_iface(void);

tdbuscredentialsRead *dbus_get_credentials_read_iface(void);
tdbuscredentialsWrite *dbus_get_credentials_write_iface(void);

tdbusConfigurationRead *dbus_new_configuration_read_iface(const char *dest, const char *path);
tdbusConfigurationWrite *dbus_new_configuration_write_iface(const char *dest, const char *path);
tdbusConfigurationMonitor *dbus_get_configuration_monitor_iface(void);

tdbusconnmanManager *dbus_get_connman_manager_iface(void);
tdbusconnmanTechnology *
dbus_new_connman_technology_proxy_for_object_path(const char *path,
                                                  GCallback signal_handler, void *user_data);
tdbusconnmanService *dbus_new_connman_service_proxy_for_object_path(const char *path, gint timeout_sec);

tdbuslogindManager *dbus_get_logind_manager_iface(void);

tdbussystemdManager *dbus_get_systemd_manager_iface(void);

#ifdef __cplusplus
}
#endif

#endif /* !DBUS_IFACE_DEEP_H */
