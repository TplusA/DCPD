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

struct network_prefs_mac_address
{
    char address[6 * 3];
};

#ifdef __cplusplus
extern "C" {
#endif

enum NetworkPrefsTechnology
network_prefs_get_technology_by_service_name(const char *name);

enum NetworkPrefsTechnology
network_prefs_get_technology_by_prefs(const struct network_prefs *prefs);

void network_prefs_init(const char *ethernet_mac_address,
                        const char *wlan_mac_address,
                        const char *network_config_path,
                        const char *network_config_file);
void network_prefs_deinit(void);

struct network_prefs_handle *
network_prefs_open_ro(const struct network_prefs **ethernet,
                      const struct network_prefs **wlan);
struct network_prefs_handle *
network_prefs_open_rw(struct network_prefs **ethernet,
                      struct network_prefs **wlan);
void network_prefs_close(struct network_prefs_handle *handle);
struct network_prefs *network_prefs_add_prefs(struct network_prefs_handle *handle,
                                              enum NetworkPrefsTechnology tech);
int network_prefs_write_to_file(struct network_prefs_handle *handle);

const struct network_prefs_mac_address *
network_prefs_get_mac_address_by_prefs(const struct network_prefs *prefs);

const struct network_prefs_mac_address *
network_prefs_get_mac_address_by_tech(enum NetworkPrefsTechnology tech);

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

void network_prefs_put_dhcp_mode(struct network_prefs *prefs, bool with_dhcp,
                                 bool wipe_out_nameservers);
void network_prefs_put_ipv4_config(struct network_prefs *prefs,
                                   const char *address, const char *netmask,
                                   const char *gateway);
void network_prefs_put_nameservers(struct network_prefs *prefs,
                                   const char *primary, const char *secondary);
void network_prefs_put_wlan_config(struct network_prefs *prefs,
                                   const char *network_name, const char *ssid,
                                   const char *security,
                                   const char *passphrase);
void network_prefs_disable_ipv4(struct network_prefs *prefs);

#ifdef __cplusplus
}
#endif

#endif /* !NETWORKPREFS_H */
