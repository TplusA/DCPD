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
#include <stdint.h>
#include <unistd.h>

/*!
 * Internal type for Connman interface code for storing D-Bus results.
 *
 * This is just a GLib \c GVariant, but to keep unit testing smooth and easy,
 * we don't want anything to depend on GLib that doesn't have to. Neither do we
 * want to pull in the whole \c glib.h insanity just for a typedef.
 */
struct ConnmanInterfaceData;

enum ConnmanConnectionType
{
    CONNMAN_CONNECTION_TYPE_UNKNOWN,
    CONNMAN_CONNECTION_TYPE_ETHERNET,
    CONNMAN_CONNECTION_TYPE_WLAN,
};

/*!
 * WLAN site survey result.
 */
enum ConnmanSiteScanResult
{
    CONNMAN_SITE_SCAN_OK,
    CONNMAN_SITE_SCAN_CONNMAN_ERROR,
    CONNMAN_SITE_SCAN_DBUS_ERROR,
    CONNMAN_SITE_SCAN_NO_HARDWARE,

    CONNMAN_SITE_SCAN_RESULT_LAST = CONNMAN_SITE_SCAN_NO_HARDWARE,
};

typedef void (*ConnmanSurveyDoneFn)(enum ConnmanSiteScanResult result);

#ifdef __cplusplus
extern "C" {
#endif

struct ConnmanInterfaceData *connman_find_interface(const char *mac_address);

struct ConnmanInterfaceData *
connman_find_active_primary_interface(const char *default_mac_address,
                                      const char *wired_mac_address,
                                      const char *wireless_mac_address);

bool connman_get_dhcp_mode(struct ConnmanInterfaceData *iface_data);
enum ConnmanConnectionType connman_get_connection_type(struct ConnmanInterfaceData *iface_data);
void connman_get_ipv4_address_string(struct ConnmanInterfaceData *iface_data,
                                     char *dest, size_t dest_size);
void connman_get_ipv4_netmask_string(struct ConnmanInterfaceData *iface_data,
                                     char *dest, size_t dest_size);
void connman_get_ipv4_gateway_string(struct ConnmanInterfaceData *iface_data,
                                     char *dest, size_t dest_size);
void connman_get_ipv4_primary_dns_string(struct ConnmanInterfaceData *iface_data,
                                         char *dest, size_t dest_size);
void connman_get_ipv4_secondary_dns_string(struct ConnmanInterfaceData *iface_data,
                                           char *dest, size_t dest_size);
bool connman_get_wlan_security_type_string(struct ConnmanInterfaceData *iface_data,
                                           char *dest, size_t dest_size);
size_t connman_get_wlan_ssid(struct ConnmanInterfaceData *iface_data,
                             uint8_t *dest, size_t dest_size);
void connman_free_interface_data(struct ConnmanInterfaceData *iface_data);
bool connman_start_wlan_site_survey(ConnmanSurveyDoneFn callback);

#ifdef __cplusplus
}
#endif

#endif /* !CONNMAN_H */
