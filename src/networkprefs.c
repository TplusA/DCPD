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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <inttypes.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <glib.h>

#include "networkprefs.h"
#include "inifile.h"
#include "messages.h"

static const char service_prefix[] = "/net/connman/service/";

enum NetworkPrefsTechnology
network_prefs_get_technology_by_service_name(const char *name)
{
    log_assert(name != NULL);

    if(strncmp(name, service_prefix, sizeof(service_prefix) - 1) != 0)
        return NWPREFSTECH_UNKNOWN;

    name += sizeof(service_prefix) - 1;

    if(strncmp(name, "ethernet_", 9) == 0)
        return NWPREFSTECH_ETHERNET;
    else if(strncmp(name, "wifi_", 5) == 0)
        return NWPREFSTECH_WLAN;

    return NWPREFSTECH_UNKNOWN;
}

static char nibble_to_char(uint8_t nibble)
{
    if(nibble < 10)
        return '0' + nibble;
    else
        return 'a' + nibble - 10;
}

static size_t generate_service_name(char *const buffer,
                                    const size_t buffer_size,
                                    const size_t tech_offset,
                                    const size_t start_offset,
                                    const struct ini_key_value_pair *mac,
                                    const struct ini_key_value_pair *network_name,
                                    const struct ini_key_value_pair *network_ssid,
                                    const struct ini_key_value_pair *network_security)
{
    static const char buffer_too_small_error[] = "Internal error: buffer too small";

#define APPEND_TO_BUFFER(CH) \
    do \
    { \
        if(offset >= buffer_size) \
        { \
            msg_error(ENOMEM, LOG_ERR, buffer_too_small_error); \
            return 0; \
        } \
        \
        buffer[offset++] = (CH); \
    } \
    while(0)

    if(mac == NULL)
    {
        msg_error(0, LOG_ERR, "No MAC configured");
        return 0;
    }

    bool is_wlan;

    if(strcmp(buffer + tech_offset, "wifi") == 0)
    {
        if(network_name == NULL && network_ssid == NULL)
        {
            msg_error(0, LOG_ERR, "No network name configured");
            return 0;
        }

        if(network_security == NULL)
        {
            msg_error(0, LOG_ERR, "No network security configured");
            return 0;
        }

        is_wlan = true;
    }
    else if(strcmp(buffer + tech_offset, "ethernet") == 0)
        is_wlan = false;
    else
    {
        msg_error(0, LOG_ERR, "Unknown technology name");
        return 0;
    }

    size_t offset = start_offset;

    APPEND_TO_BUFFER('_');

    for(size_t input_offset = 0; /* nothing */; ++input_offset)
    {
        const char ch = tolower(mac->value[input_offset]);

        if(ch == '\0')
            break;

        if(isdigit(ch) || (ch >= 'a' && ch <= 'f'))
            APPEND_TO_BUFFER(ch);
    }

    APPEND_TO_BUFFER('_');

    if(is_wlan)
    {
        if(network_ssid != NULL)
        {
            for(size_t input_offset = 0; /* nothing */; ++input_offset)
            {
                const char ch = tolower(network_ssid->value[input_offset]);

                if(ch == '\0')
                    break;

                APPEND_TO_BUFFER(ch);
            }
        }
        else
        {
            for(size_t input_offset = 0; /* nothing */; ++input_offset)
            {
                const char ch = network_name->value[input_offset];

                if(ch == '\0')
                    break;

                APPEND_TO_BUFFER(nibble_to_char(ch >> 4));
                APPEND_TO_BUFFER(nibble_to_char(ch & 0x0f));
            }
        }

        APPEND_TO_BUFFER('_');

        static const char first_suffix[] = "managed_";
        const size_t new_offset =
            offset + (sizeof(first_suffix) - 1) + strlen(network_security->value);

        if(new_offset >= buffer_size)
        {
            msg_error(0, LOG_ERR, buffer_too_small_error);
            return 0;
        }

        strcpy(buffer + offset, first_suffix);
        strcpy(buffer + offset + sizeof(first_suffix) - 1, network_security->value);
        offset = new_offset;
    }
    else
    {
        static const char suffix[] = "cable";

        if(offset + sizeof(suffix) > buffer_size)
        {
            msg_error(0, LOG_ERR, buffer_too_small_error);
            return 0;
        }

        strcpy(buffer + offset, suffix);
        offset += sizeof(suffix) - 1;
    }

    return offset;

#undef APPEND_TO_BUFFER
}

static inline const char *get_pref(const struct ini_section *prefs,
                                   const char *key)
{
    const struct ini_key_value_pair *const key_value =
        inifile_section_lookup_kv_pair(prefs, key, 0);

    return (key_value != NULL && key_value->value[0] != '\0')
        ? key_value->value
        : NULL;
}

static bool add_new_section_with_defaults(struct ini_file *inifile,
                                          enum NetworkPrefsTechnology tech,
                                          const char *mac_address)
{
    log_assert(inifile != NULL);
    log_assert(mac_address != NULL);

    struct ini_section *section = NULL;

    switch(tech)
    {
      case NWPREFSTECH_UNKNOWN:
        BUG("Attempted to create network configuration section for unknown technology");
        return false;

      case NWPREFSTECH_ETHERNET:
        section = inifile_new_section(inifile, "ethernet", 8);
        break;

      case NWPREFSTECH_WLAN:
        section = inifile_new_section(inifile, "wifi", 4);
        break;
    }

    if(section == NULL ||
       inifile_section_store_value(section, "MAC", 3, mac_address, 0) == NULL ||
       inifile_section_store_value(section, "DHCP", 4, "yes", 3) == NULL)
    {
        msg_out_of_memory("network preferences file");
        return false;
    }

    return true;
}

static void write_default_preferences(const char *filename,
                                      const char *containing_directory,
                                      const char *ethernet_mac_address)
{
    msg_info("Creating default network preferences file");

    struct ini_file inifile;

    inifile_new(&inifile);

    if(add_new_section_with_defaults(&inifile, NWPREFSTECH_ETHERNET,
                                     ethernet_mac_address))
    {
        if(inifile_write_to_file(&inifile, filename) == 0)
            os_sync_dir(containing_directory);
    }

    inifile_free(&inifile);
}

static const char *check_mac_address(const char *mac_address,
                                     size_t required_length, bool is_wired)
{
    if(mac_address == NULL ||
       strlen(mac_address) != required_length)
    {
        /* locally administered address, invalid in the wild */
        return is_wired ? "02:00:00:00:00:00" : "03:00:00:00:00:00";
    }
    else
        return mac_address;
}

static void copy_mac_address(char *dest, size_t dest_size, const char *src)
{
    strncpy(dest, src, dest_size);
    dest[dest_size - 1] = '\0';
}

struct network_prefs_handle
{
    struct ini_file *file;
};

struct network_prefs
{
    struct ini_section *section;
    enum NetworkPrefsTechnology technology;
};

static struct
{
    struct network_prefs_mac_address ethernet_mac;
    struct network_prefs_mac_address wlan_mac;
    const char *preferences_path;
    const char *preferences_filename;

    GMutex lock;
    bool is_writable;
    struct ini_file file;

    struct network_prefs_handle handle;
    struct network_prefs network_ethernet_prefs;
    struct network_prefs network_wlan_prefs;
}
networkprefs_data;

enum NetworkPrefsTechnology
network_prefs_get_technology_by_prefs(const struct network_prefs *prefs)
{
    log_assert(prefs != NULL);

    return prefs->technology;
}

void network_prefs_init(const char *ethernet_mac_address,
                        const char *wlan_mac_address,
                        const char *network_config_path,
                        const char *network_config_file)
{
    memset(&networkprefs_data, 0, sizeof(networkprefs_data));

    const char *temp;
    temp = check_mac_address(ethernet_mac_address,
                             sizeof(networkprefs_data.ethernet_mac.address) - 1,
                             true);
    copy_mac_address(networkprefs_data.ethernet_mac.address,
                     sizeof(networkprefs_data.ethernet_mac.address), temp);
    temp = check_mac_address(wlan_mac_address,
                             sizeof(networkprefs_data.wlan_mac.address) - 1,
                             false);
    copy_mac_address(networkprefs_data.wlan_mac.address,
                     sizeof(networkprefs_data.wlan_mac.address), temp);

    networkprefs_data.preferences_path = network_config_path;
    networkprefs_data.preferences_filename = network_config_file;

    networkprefs_data.network_ethernet_prefs.technology = NWPREFSTECH_ETHERNET;
    networkprefs_data.network_wlan_prefs.technology = NWPREFSTECH_WLAN;

    g_mutex_init(&networkprefs_data.lock);
}

void network_prefs_deinit(void)
{
    g_mutex_clear(&networkprefs_data.lock);
}

static struct network_prefs_handle *open_prefs_file(bool is_writable,
                                                    struct network_prefs **ethernet,
                                                    struct network_prefs **wlan)
{
    g_mutex_lock(&networkprefs_data.lock);

    networkprefs_data.is_writable = is_writable;

    for(int try = 0; try < 2; ++try)
    {
        int ret = inifile_parse_from_file(&networkprefs_data.file,
                                          networkprefs_data.preferences_filename);

        if(ret < 0)
        {
            msg_error(0, LOG_ERR, "Failed parsing network preferences");
            return NULL;
        }
        else if(ret > 0)
        {
            if(try == 0)
                write_default_preferences(networkprefs_data.preferences_filename,
                                          networkprefs_data.preferences_path,
                                          networkprefs_data.ethernet_mac.address);
            else
            {
                msg_error(0, LOG_ERR, "Network preferences file not found");
                return NULL;
            }
        }
        else
            break;
    }

    networkprefs_data.handle.file = &networkprefs_data.file;
    networkprefs_data.network_ethernet_prefs.section =
        inifile_find_section(&networkprefs_data.file, "ethernet", 8);
    networkprefs_data.network_wlan_prefs.section =
        inifile_find_section(&networkprefs_data.file, "wifi", 4);

    *ethernet = (networkprefs_data.network_ethernet_prefs.section != NULL)
        ? &networkprefs_data.network_ethernet_prefs
        : NULL;
    *wlan = (networkprefs_data.network_wlan_prefs.section != NULL)
        ? &networkprefs_data.network_wlan_prefs
        : NULL;

    return &networkprefs_data.handle;
}

struct network_prefs_handle *
network_prefs_open_ro(const struct network_prefs **ethernet,
                      const struct network_prefs **wlan)
{
    /* use locals to avoid stupid type casts */
    struct network_prefs *ethernet_nonconst;
    struct network_prefs *wlan_nonconst;

    struct network_prefs_handle *const handle =
        open_prefs_file(false, &ethernet_nonconst, &wlan_nonconst);

    *ethernet = ethernet_nonconst;
    *wlan = wlan_nonconst;

    return handle;
}

struct network_prefs_handle *
network_prefs_open_rw(struct network_prefs **ethernet,
                      struct network_prefs **wlan)
{
    return open_prefs_file(true, ethernet, wlan);
}

void network_prefs_close(struct network_prefs_handle *handle)
{
    log_assert(handle == &networkprefs_data.handle);
    log_assert(handle->file != NULL);

    inifile_free(handle->file);
    handle->file = NULL;
    networkprefs_data.network_ethernet_prefs.section = NULL;
    networkprefs_data.network_wlan_prefs.section = NULL;

    g_mutex_unlock(&networkprefs_data.lock);
}

static inline void assert_writable_file(const struct network_prefs_handle *handle)
{
    log_assert(handle == &networkprefs_data.handle);
    log_assert(handle->file != NULL);
    log_assert(networkprefs_data.is_writable);
}

struct network_prefs *network_prefs_add_prefs(struct network_prefs_handle *handle,
                                              enum NetworkPrefsTechnology tech)
{
    assert_writable_file(handle);

    struct network_prefs *prefs = NULL;
    const char *mac_address = NULL;

    switch(tech)
    {
      case NWPREFSTECH_UNKNOWN:
        break;

      case NWPREFSTECH_ETHERNET:
        log_assert(networkprefs_data.network_ethernet_prefs.section == NULL);
        networkprefs_data.network_ethernet_prefs.section =
            inifile_new_section(&networkprefs_data.file, "ethernet", 8);
        prefs = &networkprefs_data.network_ethernet_prefs;
        mac_address = networkprefs_data.ethernet_mac.address;
        break;

      case NWPREFSTECH_WLAN:
        log_assert(networkprefs_data.network_wlan_prefs.section == NULL);
        networkprefs_data.network_wlan_prefs.section =
            inifile_new_section(&networkprefs_data.file, "wifi", 4);
        prefs = &networkprefs_data.network_wlan_prefs;
        mac_address = networkprefs_data.wlan_mac.address;
        break;
    }

    if(prefs == NULL || prefs->section == NULL)
        return NULL;

    if(add_new_section_with_defaults(&networkprefs_data.file, tech, mac_address))
        return prefs;

    if(prefs->section != NULL)
    {
        BUG("Error occurred, should remove section from file");
        prefs->section = NULL;
    }

    return NULL;
}

int network_prefs_write_to_file(struct network_prefs_handle *handle)
{
    assert_writable_file(handle);

    if(inifile_write_to_file(&networkprefs_data.file,
                             networkprefs_data.preferences_filename) < 0)
        return -1;

    os_sync_dir(networkprefs_data.preferences_path);

    return 0;
}

const struct network_prefs_mac_address *
network_prefs_get_mac_address_by_prefs(const struct network_prefs *prefs)
{
    log_assert(prefs != NULL);

    return network_prefs_get_mac_address_by_tech(prefs->technology);
}

const struct network_prefs_mac_address *
network_prefs_get_mac_address_by_tech(enum NetworkPrefsTechnology tech)
{
    switch(tech)
    {
      case NWPREFSTECH_UNKNOWN:
        break;

      case NWPREFSTECH_ETHERNET:
        return &networkprefs_data.ethernet_mac;

      case NWPREFSTECH_WLAN:
        return &networkprefs_data.wlan_mac;
    }

    return NULL;
}

size_t network_prefs_generate_service_name(const struct network_prefs *prefs,
                                           char *buffer, size_t buffer_size)
{
    if(buffer_size > 0)
        buffer[0] = '\0';
    else
        return 0;

    if(prefs == NULL)
        return 0;

    log_assert(prefs->section != NULL);

    static const size_t tech_offset = sizeof(service_prefix) - 1;

    const struct ini_section *const section = prefs->section;
    const size_t namelen = strlen(section->name);
    const size_t start_offset = tech_offset + namelen;

    if(start_offset >= buffer_size)
        return 0;

    memcpy(buffer, service_prefix, tech_offset);
    memcpy(buffer + tech_offset, section->name, namelen + 1);

    return
        generate_service_name(buffer, buffer_size, tech_offset, start_offset,
                              inifile_section_lookup_kv_pair(section, "MAC", 3),
                              inifile_section_lookup_kv_pair(section, "NetworkName", 11),
                              inifile_section_lookup_kv_pair(section, "SSID", 4),
                              inifile_section_lookup_kv_pair(section, "Security", 8));
}

const char *network_prefs_get_name(const struct network_prefs *prefs)
{
    return get_pref(prefs->section, "NetworkName");
}

const char *network_prefs_get_ssid(const struct network_prefs *prefs)
{
    return get_pref(prefs->section, "SSID");
}

const char *network_prefs_get_passphrase(const struct network_prefs *prefs)
{
    return get_pref(prefs->section, "Passphrase");
}

bool network_prefs_get_ipv4_settings(const struct network_prefs *prefs,
                                     bool *with_dhcp, const char **address,
                                     const char **netmask,
                                     const char **gateway,
                                     const char **dns1, const char **dns2)
{
    bool is_consistent = true;

    const char *temp = get_pref(prefs->section, "DHCP");

    if(temp != NULL)
        *with_dhcp = strcmp(temp, "yes") == 0;
    else
    {
        *with_dhcp = false;
        is_consistent = false;
    }

    *address = get_pref(prefs->section, "IPv4Address");
    *netmask = get_pref(prefs->section, "IPv4Netmask");
    *gateway = get_pref(prefs->section, "IPv4Gateway");
    *dns1 = get_pref(prefs->section, "PrimaryDNS");
    *dns2 = get_pref(prefs->section, "SecondaryDNS");

    if(is_consistent)
    {
        if(*with_dhcp)
            is_consistent = (*address == NULL && *netmask == NULL &&
                             *gateway == NULL);
        else
            is_consistent = (*address != NULL && *netmask != NULL &&
                             *gateway != NULL);
    }

    if(is_consistent)
        is_consistent = (*dns1 != NULL || *dns2 == NULL);

    return is_consistent;
}

enum ModifyResult
{
    MODIFY_UNTOUCHED_DEFINED,
    MODIFY_UNTOUCHED_UNDEFINED,
    MODIFY_ADDED,
    MODIFY_REMOVED,
    MODIFY_FAILED_ADD,
    MODIFY_FAILED_REMOVE,
};

static enum ModifyResult modify_pref(struct ini_section *section,
                                     const char *key, const char *value)
{
    log_assert(section != NULL);
    log_assert(key != NULL);

    if(value == NULL)
    {
        return (inifile_section_lookup_kv_pair(section, key, 0) != NULL)
            ? MODIFY_UNTOUCHED_DEFINED
            : MODIFY_UNTOUCHED_UNDEFINED;
    }

    if(value[0] != '\0')
    {
        return (inifile_section_store_value(section, key, 0, value, 0) != NULL)
            ? MODIFY_ADDED
            : MODIFY_FAILED_ADD;
    }
    else
    {
        return inifile_section_remove_value(section, key, 0)
            ? MODIFY_REMOVED
            : MODIFY_FAILED_REMOVE;
    }
}

void network_prefs_put_dhcp_mode(struct network_prefs *prefs, bool with_dhcp)
{
    modify_pref(prefs->section, "DHCP", with_dhcp ? "yes" : "no");

    if(with_dhcp)
    {
        modify_pref(prefs->section, "IPv4Address", "");
        modify_pref(prefs->section, "IPv4Netmask", "");
        modify_pref(prefs->section, "IPv4Gateway", "");
    }
}

void network_prefs_put_ipv4_config(struct network_prefs *prefs,
                                   const char *address, const char *netmask,
                                   const char *gateway)
{
    modify_pref(prefs->section, "DHCP", "no");
    modify_pref(prefs->section, "IPv4Address", address);
    modify_pref(prefs->section, "IPv4Netmask", netmask);
    modify_pref(prefs->section, "IPv4Gateway", gateway);
}

void network_prefs_put_nameservers(struct network_prefs *prefs,
                                   const char *primary, const char *secondary)
{
    modify_pref(prefs->section, "PrimaryDNS", primary);
    modify_pref(prefs->section, "SecondaryDNS", secondary);
}

void network_prefs_put_wlan_config(struct network_prefs *prefs,
                                   const char *network_name, const char *ssid,
                                   const char *security,
                                   const char *passphrase)
{
    modify_pref(prefs->section, "NetworkName", network_name);
    modify_pref(prefs->section, "SSID", ssid);
    modify_pref(prefs->section, "Security", security);
    modify_pref(prefs->section, "Passphrase", passphrase);
}

void network_prefs_disable_ipv4(struct network_prefs *prefs)
{
    network_prefs_put_dhcp_mode(prefs, true);
    modify_pref(prefs->section, "DHCP", "");
}
