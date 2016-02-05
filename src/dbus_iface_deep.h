/*
 * Copyright (C) 2015, 2016  T+A elektroakustik GmbH & Co. KG
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
#include "credentials_dbus.h"
#include "connman_dbus.h"
#include "logind_dbus.h"

#ifdef __cplusplus
extern "C" {
#endif

tdbusdcpdPlayback *dbus_get_playback_iface(void);
tdbusdcpdViews *dbus_get_views_iface(void);
tdbusdcpdListNavigation *dbus_get_list_navigation_iface(void);
tdbusdcpdListItem *dbus_get_list_item_iface(void);

tdbusFileTransfer *dbus_get_file_transfer_iface(void);

tdbussplayURLFIFO *dbus_get_streamplayer_urlfifo_iface(void);
tdbussplayPlayback *dbus_get_streamplayer_playback_iface(void);

tdbusAirable *dbus_get_airable_sec_iface(void);

tdbuscredentialsRead *dbus_get_credentials_read_iface(void);
tdbuscredentialsWrite *dbus_get_credentials_write_iface(void);

tdbusconnmanManager *dbus_get_connman_manager_iface(void);
tdbusconnmanTechnology *dbus_get_connman_technology_proxy_for_object_path(const char *path);

tdbuslogindManager *dbus_get_logind_manager_iface(void);

#ifdef __cplusplus
}
#endif

#endif /* !DBUS_IFACE_DEEP_H */
