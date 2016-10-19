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

enum ConnmanReadConfigSource
{
    CONNMAN_READ_CONFIG_SOURCE_CURRENT,
    CONNMAN_READ_CONFIG_SOURCE_REQUESTED,
};

/*!
 * WLAN site survey result.
 *
 * \attention
 *     This enumeration must match the array in #survey_result_to_string().
 */
enum ConnmanSiteScanResult
{
    CONNMAN_SITE_SCAN_OK,
    CONNMAN_SITE_SCAN_CONNMAN_ERROR,
    CONNMAN_SITE_SCAN_DBUS_ERROR,
    CONNMAN_SITE_SCAN_OUT_OF_MEMORY,
    CONNMAN_SITE_SCAN_NO_HARDWARE,

    CONNMAN_SITE_SCAN_RESULT_LAST = CONNMAN_SITE_SCAN_NO_HARDWARE,
};

typedef void (*ConnmanSurveyDoneFn)(enum ConnmanSiteScanResult result);

enum ConnmanDHCPMode
{
    CONNMAN_DHCP_NOT_SPECIFIED,
    CONNMAN_DHCP_ON,
    CONNMAN_DHCP_OFF,
    CONNMAN_DHCP_MANUAL,
    CONNMAN_DHCP_FIXED,
};

enum ConnmanServiceState
{
    CONNMAN_STATE_NOT_SPECIFIED,
    CONNMAN_STATE_IDLE,
    CONNMAN_STATE_FAILURE,
    CONNMAN_STATE_ASSOCIATION,
    CONNMAN_STATE_CONFIGURATION,
    CONNMAN_STATE_READY,
    CONNMAN_STATE_DISCONNECT,
    CONNMAN_STATE_ONLINE,
};

struct ConnmanServiceIterator;
struct ConnmanServiceSecurityIterator;

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Find information about NIC with given MAC address, regardless of state.
 */
struct ConnmanInterfaceData *connman_find_interface(const char *mac_address);
struct ConnmanInterfaceData *connman_find_interface_by_object_path(const char *path);

/*!
 * Find active NIC with MAC address matching one of the given ones.
 *
 * In case both, the wired and the wireless, NICs are found and both are
 * active, then the NIC with the MAC address given in \p default_mac_address is
 * returned (making it a tiebreaker).
 *
 * In case any of the NICs is found, but all of them are in inactive
 * (unconfigured) state, then (and only then) the first discovered device will
 * be returned in \p fallback.
 */
struct ConnmanInterfaceData *
connman_find_active_primary_interface(const char *default_mac_address,
                                      const char *wired_mac_address,
                                      const char *wireless_mac_address,
                                      struct ConnmanInterfaceData **fallback);

bool connman_get_favorite(struct ConnmanInterfaceData *iface_data);
bool connman_get_auto_connect_mode(struct ConnmanInterfaceData *iface_data);
enum ConnmanDHCPMode connman_get_dhcp_mode(struct ConnmanInterfaceData *iface_data,
                                           enum ConnmanReadConfigSource src);
enum ConnmanConnectionType connman_get_connection_type(struct ConnmanInterfaceData *iface_data);
enum ConnmanServiceState connman_get_state(struct ConnmanInterfaceData *iface_data);
bool connman_get_ipv4_address_string(struct ConnmanInterfaceData *iface_data,
                                     enum ConnmanReadConfigSource src,
                                     char *dest, size_t dest_size);
bool connman_get_ipv4_netmask_string(struct ConnmanInterfaceData *iface_data,
                                     enum ConnmanReadConfigSource src,
                                     char *dest, size_t dest_size);
bool connman_get_ipv4_gateway_string(struct ConnmanInterfaceData *iface_data,
                                     enum ConnmanReadConfigSource src,
                                     char *dest, size_t dest_size);
bool connman_get_primary_dns_string(struct ConnmanInterfaceData *iface_data,
                                    char *dest, size_t dest_size);
bool connman_get_secondary_dns_string(struct ConnmanInterfaceData *iface_data,
                                      char *dest, size_t dest_size);
bool connman_get_wlan_security_type_string(struct ConnmanInterfaceData *iface_data,
                                           char *dest, size_t dest_size);
size_t connman_get_wlan_ssid(struct ConnmanInterfaceData *iface_data,
                             uint8_t *dest, size_t dest_size);
void connman_free_interface_data(struct ConnmanInterfaceData *iface_data);

struct ConnmanServiceIterator *connman_service_iterator_get(void);
void connman_service_iterator_rewind(struct ConnmanServiceIterator *iter);
bool connman_service_iterator_next(struct ConnmanServiceIterator *iter);
void connman_service_iterator_free(struct ConnmanServiceIterator *iter);
const char *connman_service_iterator_get_technology_type(struct ConnmanServiceIterator *iter);
const char *connman_service_iterator_get_ssid(struct ConnmanServiceIterator *iter);
int connman_service_iterator_get_strength(struct ConnmanServiceIterator *iter);
struct ConnmanServiceSecurityIterator *
connman_service_iterator_get_security_iterator(struct ConnmanServiceIterator *iter,
                                               size_t *count);
bool connman_security_iterator_next(struct ConnmanServiceSecurityIterator *iter);
void connman_security_iterator_free(struct ConnmanServiceSecurityIterator *iter);
const char *connman_security_iterator_get_security(struct ConnmanServiceSecurityIterator *iter);

void connman_wlan_power_on(void);
bool connman_start_wlan_site_survey(ConnmanSurveyDoneFn callback);

#ifdef __cplusplus
}
#endif

#endif /* !CONNMAN_H */
