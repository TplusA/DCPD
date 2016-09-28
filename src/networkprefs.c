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
network_prefs_get_technology_from_service_name(const char *name)
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

static void write_default_preferences(const char *filename,
                                      const char *ethernet_mac_address)
{
    msg_info("Creating default network preferences file");

    struct ini_file inifile;

    inifile_new(&inifile);

    struct ini_section *section = inifile_new_section(&inifile, "ethernet", 8);

    if(section == NULL)
        goto error_oom_exit;

    if(inifile_section_store_value(section, "MAC", 3, ethernet_mac_address, 0) == NULL ||
       inifile_section_store_value(section, "DHCP", 4, "yes", 3) == NULL)
        goto error_oom_exit;

    inifile_write_to_file(&inifile, filename);
    inifile_free(&inifile);

    return;

error_oom_exit:
    msg_out_of_memory("network preferences file");
    inifile_free(&inifile);
}

/* TODO: Remove duplicate from registers.c */
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

/* TODO: Remove duplicate from registers.c */
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
};

static struct
{
    char ethernet_mac_address_string[6 * 3];
    char wlan_mac_address_string[6 * 3];
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

void network_prefs_init(const char *ethernet_mac_address,
                        const char *wlan_mac_address,
                        const char *network_config_path,
                        const char *network_config_file)
{
    memset(&networkprefs_data, 0, sizeof(networkprefs_data));

    const char *temp;
    temp = check_mac_address(ethernet_mac_address,
                             sizeof(networkprefs_data.ethernet_mac_address_string) - 1,
                             true);
    copy_mac_address(networkprefs_data.ethernet_mac_address_string,
                     sizeof(networkprefs_data.ethernet_mac_address_string), temp);
    temp = check_mac_address(wlan_mac_address,
                             sizeof(networkprefs_data.wlan_mac_address_string) - 1,
                             false);
    copy_mac_address(networkprefs_data.wlan_mac_address_string,
                     sizeof(networkprefs_data.wlan_mac_address_string), temp);

    networkprefs_data.preferences_path = network_config_path;
    networkprefs_data.preferences_filename = network_config_file;
    g_mutex_init(&networkprefs_data.lock);
}

struct network_prefs_handle *
network_prefs_open_ro(const struct network_prefs **ethernet,
                      const struct network_prefs **wlan)
{
    g_mutex_lock(&networkprefs_data.lock);

    networkprefs_data.is_writable = false;

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
                                          networkprefs_data.ethernet_mac_address_string);
            else
            {
                msg_error(0, LOG_ERR, "Network preferences file not found");
                return NULL;
            }
        }
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

void network_prefs_close(struct network_prefs_handle *handle)
{
    log_assert(handle->file != NULL);
    log_assert(handle == &networkprefs_data.handle);

    inifile_free(handle->file);
    handle->file = NULL;
    networkprefs_data.network_ethernet_prefs.section = NULL;
    networkprefs_data.network_wlan_prefs.section = NULL;

    g_mutex_unlock(&networkprefs_data.lock);
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
    *dns1 = get_pref(prefs->section, "IPv4PrimaryDNS");
    *dns2 = get_pref(prefs->section, "IPv4SecondaryDNS");

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
