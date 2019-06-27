/*
 * Copyright (C) 2015--2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef DBUS_IFACE_DEEP_H
#define DBUS_IFACE_DEEP_H

#include "dcpd_dbus.h"
#include "dbusdl_dbus.h"
#include "streamplayer_dbus.h"
#include "airable_dbus.h"
#include "artcache_dbus.h"
#include "audiopath_dbus.h"
#include "mixer_dbus.h"
#include "credentials_dbus.h"
#include "configuration_dbus.h"
#include "jsonio_dbus.h"
#include "appliance_dbus.h"
#include "connman_dbus.h"
#include "gerbera_dbus.h"
#include "logind_dbus.h"
#include "systemd_dbus.h"

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
