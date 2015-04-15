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

#ifndef CONNMAN_H
#define CONNMAN_H

#include <stdbool.h>

/*!
 * Internal type for Connman interface code for storing D-Bus results.
 *
 * This is just a GLib \c GVariant, but to keep unit testing smooth and easy,
 * we don't want anything to depend on GLib that doesn't have to. Neither do we
 * want to pull in the whole \c glib.h insanity just for a typedef.
 */
struct ConnmanInterfaceData;

#ifdef __cplusplus
extern "C" {
#endif

struct ConnmanInterfaceData *connman_find_interface(const char *mac_address);

struct ConnmanInterfaceData *
connman_find_active_primary_interface(const char *default_mac_address,
                                      const char *wired_mac_address,
                                      const char *wireless_mac_address);

bool connman_get_dhcp_mode(struct ConnmanInterfaceData *iface_data);
void connman_get_ipv4_address_string(struct ConnmanInterfaceData *iface_data,
                                     char *dest, size_t dest_size);
void connman_get_ipv4_netmask_string(struct ConnmanInterfaceData *iface_data,
                                     char *dest, size_t dest_size);
void connman_get_ipv4_gateway_string(struct ConnmanInterfaceData *iface_data,
                                     char *dest, size_t dest_size);
void connman_free_interface_data(struct ConnmanInterfaceData *iface_data);

#ifdef __cplusplus
}
#endif

#endif /* !CONNMAN_H */
