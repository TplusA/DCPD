/*
 * Copyright (C) 2016, 2017  T+A elektroakustik GmbH & Co. KG
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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <glib.h>

#include "networkprefs.h"
#include "inifile.h"
#include "dbus_iface_deep.h"
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

    msg_vinfo(MESSAGE_LEVEL_TRACE, "Generated service name: \"%s\"", buffer);

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
    msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
              "Creating default network preferences file");

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

static void patch_mac_address(struct ini_section *section,
                              const char *mac_address)
{
    if(section != NULL && mac_address[0] != '\0')
        inifile_section_store_value(section, "MAC", 3, mac_address, 0);
}

static struct network_prefs_handle *open_prefs_file(bool is_writable,
                                                    struct network_prefs **ethernet,
                                                    struct network_prefs **wlan)
{
    g_mutex_lock(&networkprefs_data.lock);

    *ethernet = NULL;
    *wlan = NULL;

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

    /*
     * This is kind of a hack that demands some explanation. It can be tracked
     * down, once again, to the broken system design that requires there can be
     * only a single "primary" Ethernet adapter or a single "primary" WLAN USB
     * dongle in the system.
     *
     * To keep things generic and extensible, we store the MAC address along
     * with our WLAN configuration. This allows representation of different
     * settings organized by MAC address, regardless of devices present in the
     * system at any time. We need the MAC address to generate service names
     * for ConnMan, by the way. Safe, nice, well-organized.
     *
     * By system design, however, there can be only one fixed, known MAC for
     * the Ethernet adapter and one for the WLAN adapter. Thus, storing the MAC
     * address inside our configuration file is redundant and should actually
     * be avoided. I, however, do not allow such poor design decisions to leak
     * all the way down into our configuration files. Therefore, the MAC
     * address stays right there. This simply works as long as the MAC
     * addresses never change.
     *
     * Now, if a network adapter is replaced by another one (maybe because the
     * old one has broken or there the new one provides better connectivity),
     * the MAC address changes as well. Our configuration file still only knows
     * about the old address in this case, so we are generating wrong service
     * names and therefore fail to make any connection.
     *
     * Following the system design, it is safe to just always replace the
     * stored MAC addresses by whatever non-empty address we got from the
     * launcher script. This is hack, of course. A good fix would allow the
     * user to select the exact networking adapter he wants to use. Changing
     * the networking adapter could be supported by allowing the user to copy
     * configuration settings.
     */
    patch_mac_address(networkprefs_data.network_ethernet_prefs.section,
                      networkprefs_data.ethernet_mac.address);
    patch_mac_address(networkprefs_data.network_wlan_prefs.section,
                      networkprefs_data.wlan_mac.address);

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

    const size_t len =
        generate_service_name(buffer, buffer_size, tech_offset, start_offset,
                              inifile_section_lookup_kv_pair(section, "MAC", 3),
                              inifile_section_lookup_kv_pair(section, "NetworkName", 11),
                              inifile_section_lookup_kv_pair(section, "SSID", 4),
                              inifile_section_lookup_kv_pair(section, "Security", 8));

    if(len == 0)
        buffer[0] = '\0';

    return len;
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

void network_prefs_put_dhcp_mode(struct network_prefs *prefs, bool with_dhcp,
                                 bool wipe_out_nameservers)
{
    modify_pref(prefs->section, "DHCP", with_dhcp ? "yes" : "no");

    if(with_dhcp)
    {
        modify_pref(prefs->section, "IPv4Address", "");
        modify_pref(prefs->section, "IPv4Netmask", "");
        modify_pref(prefs->section, "IPv4Gateway", "");
    }

    if(wipe_out_nameservers)
    {
        modify_pref(prefs->section, "PrimaryDNS", "");
        modify_pref(prefs->section, "SecondaryDNS", "");
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
    network_prefs_put_dhcp_mode(prefs, true, true);
    modify_pref(prefs->section, "DHCP", "");
}

/* taken from versions before f03d914 */
struct config_filename_template
{
    const char *const template;
    const size_t size_including_zero_terminator;
    const size_t replacement_start_offset;
};

static const char config_filename_template_for_builtin_interfaces[] =
    "builtin_xxxxxxxxxxxx.config";

static char *generate_network_config_file_name(const char *connman_config_path,
                                               const char *ethernet_mac)
{
    static const char fixed_name_for_wlan_config[] = "wlan_device.config";

    const bool is_wired = (ethernet_mac != NULL);
    static const struct config_filename_template cfg_template =
    {
        .template = config_filename_template_for_builtin_interfaces,
        .size_including_zero_terminator = sizeof(config_filename_template_for_builtin_interfaces),
        .replacement_start_offset = 8,
    };

    const size_t prefix_length = strlen(connman_config_path);
    const size_t total_length =
        prefix_length + 1 + (is_wired
                             ? cfg_template.size_including_zero_terminator
                             : sizeof(fixed_name_for_wlan_config));

    char *filename = malloc(total_length);

    if(filename == NULL)
    {
        msg_out_of_memory("network configuration filename");
        return NULL;
    }

    memcpy(filename, connman_config_path, prefix_length);
    filename[prefix_length] = '/';

    if(is_wired)
        memcpy(filename + prefix_length + 1, cfg_template.template,
               cfg_template.size_including_zero_terminator);
    else
    {
        memcpy(filename + prefix_length + 1, fixed_name_for_wlan_config,
               sizeof(fixed_name_for_wlan_config));

        return filename;
    }

    char *const dest =
        filename + prefix_length + 1 + cfg_template.replacement_start_offset;

    for(size_t i = 0, j = 0; i < 6 * 2; i += 2, j += 3)
    {
        log_assert(dest[i + 0] == 'x');
        log_assert(dest[i + 1] == 'x');

        dest[i + 0] = tolower(ethernet_mac[j + 0]);
        dest[i + 1] = tolower(ethernet_mac[j + 1]);
    }

    return filename;
}

struct Token
{
    char *token;
    size_t length;
};

static void free_tokens(struct Token *tokens, size_t tokens_count)
{
    for(size_t i = 0; i < tokens_count; ++i)
    {
        free(tokens[i].token);
        tokens[i].token = NULL;
    }
}

static size_t tokenize_string(const char *key_name, const char *value,
                              const char delim, struct Token *tokens,
                              size_t min_tokens_count, size_t max_tokens_count,
                              bool is_max_tokens_hard_limit)
{
    log_assert(value != 0);
    log_assert(tokens != NULL);
    log_assert(min_tokens_count > 0);
    log_assert(max_tokens_count > 0);
    log_assert(max_tokens_count >= min_tokens_count);

    memset(tokens, 0, max_tokens_count * sizeof(tokens[0]));

    size_t start = 0;
    size_t idx = 0;

    for(size_t i = 0; /* nothing */; ++i)
    {
        const char ch = value[i];

        if(ch != delim && ch != '\0')
            continue;

        if(idx >= max_tokens_count)
        {
            idx = SIZE_MAX;

            if(!is_max_tokens_hard_limit)
                break;

            msg_error(0, LOG_ERR,
                      "Value for %s contains more than %zu tokens",
                      key_name, max_tokens_count);

            free_tokens(tokens, max_tokens_count);

            break;
        }

        struct Token *t = &tokens[idx++];

        t->length = i - start;

        if(t->length == 0)
            t->token = NULL;
        else
        {
            t->token = malloc(t->length + 1);

            if(t->token == NULL)
                msg_out_of_memory("network config token");
            else
            {
                memcpy(t->token, &value[start], t->length);
                t->token[t->length] = '\0';
            }
        }

        if(ch == '\0')
            break;

        start = i + 1;
    }

    if(idx >= min_tokens_count)
        return idx;

    msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
              "Value for %s contains fewer than %zu tokens",
              key_name, min_tokens_count);

    free_tokens(tokens, max_tokens_count);

    return 0;
}

static const char *get_value_or_empty(const struct ini_key_value_pair *kv)
{
    static const char empty[] = "";
    return kv != NULL && kv->value != NULL ? kv->value : empty;
}

static void migrate_old_config(struct network_prefs_handle *prefs,
                               struct network_prefs *prefs_section,
                               struct ini_file *old_config, bool is_wired,
                               const char *old_config_name)
{
    msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
              "Migrating network configuration file: \"%s\"", old_config_name);

    if(prefs_section == NULL)
    {
        prefs_section = network_prefs_add_prefs(prefs,
                                                is_wired
                                                ? NWPREFSTECH_ETHERNET
                                                : NWPREFSTECH_WLAN);

        if(prefs_section == NULL)
        {
            msg_error(0, LOG_ERR, "Adding section for %s network failed",
                      is_wired ? "wired" : "wireless");
            return;
        }
    }

    const struct ini_section *const old_data =
        inifile_find_section(old_config, "service_config", 0);

    if(old_data == NULL)
    {
        msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                  "File \"%s\" contains no configuration (ignored)",
                  old_config_name);
        return;
    }

    const struct ini_key_value_pair *kv;

    kv = inifile_section_lookup_kv_pair(old_data, "IPv4", 4);

    if(kv == NULL || strcmp(kv->value, "off") == 0)
        network_prefs_disable_ipv4(prefs_section);
    else if(strcmp(kv->value, "dhcp") == 0)
        network_prefs_put_dhcp_mode(prefs_section, true, true);
    else
    {
        struct Token tokens[3];
        const size_t count =
            tokenize_string(kv->key, kv->value, '/', tokens, 3, 3, true);
        bool failed = true;

        if(count >= 3)
        {
            if(count == 3 &&
               tokens[0].token != NULL && tokens[1].token != NULL &&
               tokens[2].token != NULL)
            {
                network_prefs_put_ipv4_config(prefs_section, tokens[0].token,
                                              tokens[1].token, tokens[2].token);
                failed = false;
            }

            free_tokens(tokens, sizeof(tokens) / sizeof(tokens[0]));
        }

        if(failed)
        {
            msg_error(0, LOG_ERR,
                      "Failed migrating IPv4 configuration from \"%s\"",
                      old_config_name);
            msg_vinfo(MESSAGE_LEVEL_IMPORTANT, "Resorting to DHCP");
            network_prefs_put_dhcp_mode(prefs_section, true, true);
        }
    }

    kv = inifile_section_lookup_kv_pair(old_data, "Nameservers", 11);

    if(kv == NULL || kv->value[0] == '\0')
        network_prefs_put_nameservers(prefs_section, "", "");
    else
    {
        struct Token tokens[2];
        const size_t count =
            tokenize_string(kv->key, kv->value, ',', tokens, 1, 2, false);
        bool failed = true;

        if(count >= 1)
        {
            if(count == SIZE_MAX)
                msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                         "Dropping excess name servers, taking only two of them");

            failed = (tokens[0].token == NULL && tokens[1].token == NULL);

            if(tokens[0].token != NULL && tokens[1].token != NULL)
                network_prefs_put_nameservers(prefs_section, tokens[0].token, tokens[1].token);
            else if(tokens[0].token != NULL && tokens[1].token == NULL)
                network_prefs_put_nameservers(prefs_section, tokens[0].token, "");
            else if(tokens[0].token == NULL && tokens[1].token != NULL)
                network_prefs_put_nameservers(prefs_section, tokens[1].token, "");

            free_tokens(tokens, sizeof(tokens) / sizeof(tokens[0]));
        }

        if(failed)
        {
            msg_error(0, LOG_ERR,
                      "Failed migrating name server configuration from \"%s\"",
                      old_config_name);
            network_prefs_put_nameservers(prefs_section, "", "");
        }
    }

    if(!is_wired)
    {
        const struct ini_key_value_pair *const wlan_security_kv =
            inifile_section_lookup_kv_pair(old_data, "Security", 0);
        const struct ini_key_value_pair *const wlan_name_kv =
            inifile_section_lookup_kv_pair(old_data, "Name", 0);
        const struct ini_key_value_pair *const wlan_ssid_kv =
            inifile_section_lookup_kv_pair(old_data, "SSID", 0);
        const struct ini_key_value_pair *const wlan_passphrase_kv =
            inifile_section_lookup_kv_pair(old_data, "Passphrase", 0);

        const char *const network_name = get_value_or_empty(wlan_name_kv);
        const char *const ssid = get_value_or_empty(wlan_ssid_kv);
        const char *const security = get_value_or_empty(wlan_security_kv);
        const char *const passphrase = get_value_or_empty(wlan_passphrase_kv);

        network_prefs_put_wlan_config(prefs_section, network_name, ssid,
                                      security, passphrase);
    }

    msg_vinfo(MESSAGE_LEVEL_IMPORTANT,  "Converted \"%s\"", old_config_name);
}

/*!
 * Callback for #os_foreach_in_path().
 */
static int delete_old_config(const char *path, unsigned char dtype,
                             void *user_data)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE,
              "Check whether to delete file \"%s\"", path);

    const char *name = strrchr(path, '/');
    name = (name != NULL) ? name + 1 : path;

    const char required_prefix[] = "builtin_";
    const char required_suffix[] = ".config";
    const size_t name_length = strlen(name);

    if(name_length != sizeof(config_filename_template_for_builtin_interfaces) - 1)
        return 0;

    if(strncmp(name, required_prefix, sizeof(required_prefix) - 1) != 0)
        return 0;

    if(strcmp(name + name_length - (sizeof(required_suffix) - 1),
              required_suffix) != 0)
        return 0;

    msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
              "Deleting residual configuration file: \"%s\"", name);

    os_file_delete(path);

    return 0;
}

static void delete_old_config_files(const char *connman_config_path,
                                    const char *ethernet_config,
                                    const char *wlan_config)
{
    msg_vinfo(MESSAGE_LEVEL_IMPORTANT, "Deleting old network configuration files");

    if(ethernet_config != NULL)
        os_file_delete(ethernet_config);

    if(wlan_config != NULL)
        os_file_delete(wlan_config);

    os_foreach_in_path(connman_config_path, delete_old_config, NULL);

    os_sync_dir(connman_config_path);
}

void network_prefs_migrate_old_network_configuration_files(const char *connman_config_path,
                                                           const char *ethernet_mac)
{
    char *old_ethernet_config_filename =
        (ethernet_mac != NULL)
        ? generate_network_config_file_name(connman_config_path, ethernet_mac)
        : NULL;
    char *old_wlan_config_filename =
        generate_network_config_file_name(connman_config_path, NULL);

    if(old_ethernet_config_filename == NULL && old_wlan_config_filename == NULL)
    {
        msg_vinfo(MESSAGE_LEVEL_DIAG,
                  "No need to migrate old network configuration");
        return;
    }

    struct ini_file old_ethernet_config;
    struct ini_file old_wlan_config;

    const bool have_old_ethernet_config =
        (old_ethernet_config_filename != NULL)
        ? (inifile_parse_from_file(&old_ethernet_config, old_ethernet_config_filename) == 0)
        : false;
    const bool have_old_wlan_config =
        (old_wlan_config_filename != NULL)
        ? (inifile_parse_from_file(&old_wlan_config, old_wlan_config_filename) == 0)
        : false;

    if(have_old_ethernet_config || have_old_wlan_config)
    {
        msg_vinfo(MESSAGE_LEVEL_IMPORTANT, "MIGRATING OLD NETWORK CONFIGURATION");

        struct network_prefs *ethernet_prefs;
        struct network_prefs *wlan_prefs;
        struct network_prefs_handle *prefs =
            network_prefs_open_rw(&ethernet_prefs, &wlan_prefs);

        bool succeeded = false;

        if(prefs == NULL)
            msg_error(0, LOG_ERR,
                      "Failed reading or creating new configuration file");
        else
        {
            if(have_old_ethernet_config)
                migrate_old_config(prefs, ethernet_prefs,
                                   &old_ethernet_config, true,
                                   old_ethernet_config_filename);

            if(have_old_wlan_config)
                migrate_old_config(prefs, wlan_prefs,
                                   &old_wlan_config, false,
                                   old_wlan_config_filename);

            msg_vinfo(MESSAGE_LEVEL_IMPORTANT,  "Writing new network configuration file");
            succeeded = (network_prefs_write_to_file(prefs) == 0);

            network_prefs_close(prefs);

            if(succeeded)
                delete_old_config_files(connman_config_path,
                                        old_ethernet_config_filename,
                                        old_wlan_config_filename);
        }

        if(succeeded)
            msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                      "Migrated old network configuration");
        else
            msg_error(0, LOG_ERR,
                      "Migration of old network configuration FAILED");
    }

    if(have_old_ethernet_config)
        inifile_free(&old_ethernet_config);

    if(have_old_wlan_config)
        inifile_free(&old_wlan_config);

    free(old_ethernet_config_filename);
    free(old_wlan_config_filename);
}
