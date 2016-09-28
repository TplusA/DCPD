/*
 * Copyright (C) 2016  T+A elektroakustik GmbH & Co. KG
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

#ifndef NETWORKPREFS_H
#define NETWORKPREFS_H

#include <unistd.h>
#include <stdbool.h>

#define NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE  ((size_t)512)

struct network_prefs_handle;
struct network_prefs;

enum NetworkPrefsTechnology
{
    NWPREFSTECH_UNKNOWN,
    NWPREFSTECH_ETHERNET,
    NWPREFSTECH_WLAN,
};

#ifdef __cplusplus
extern "C" {
#endif

enum NetworkPrefsTechnology
network_prefs_get_technology_from_service_name(const char *name);

void network_prefs_init(const char *ethernet_mac_address,
                        const char *wlan_mac_address,
                        const char *network_config_path,
                        const char *network_config_file);

struct network_prefs_handle *
network_prefs_open_ro(const struct network_prefs **ethernet,
                      const struct network_prefs **wlan);
void network_prefs_close(struct network_prefs_handle *handle);

size_t network_prefs_generate_service_name(const struct network_prefs *prefs,
                                           char *buffer, size_t buffer_size);
const char *network_prefs_get_name(const struct network_prefs *prefs);
const char *network_prefs_get_ssid(const struct network_prefs *prefs);
const char *network_prefs_get_passphrase(const struct network_prefs *prefs);
bool network_prefs_get_ipv4_settings(const struct network_prefs *prefs,
                                     bool *with_dhcp, const char **address,
                                     const char **netmask,
                                     const char **gateway,
                                     const char **dns1, const char **dns2);

#ifdef __cplusplus
}
#endif

#endif /* !NETWORKPREFS_H */
