#ifndef DBUS_IFACE_DEEP_H
#define DBUS_IFACE_DEEP_H

#include "dcpd_dbus.h"

tdbusdcpdPlayback *dbus_get_playback_iface(void);
tdbusdcpdViews *dbus_get_views_iface(void);
tdbusdcpdList_navigation *dbus_get_list_navigation_iface(void);
tdbusdcpdList_item *dbus_get_list_item_iface(void);

#endif /* !DBUS_IFACE_DEEP_H */
