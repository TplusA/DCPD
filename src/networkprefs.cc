/*
 * Copyright (C) 2016--2020, 2022  T+A elektroakustik GmbH & Co. KG
 *
 * This file is part of DCPD.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "networkprefs.h"
#include "inifile.h"
#include "network_device_list.hh"
#include "dbus_handlers_connman_manager.hh"
#include "messages.h"
#include "guard.hh"

#include <dirent.h>

#include <fstream>
#include <cstring>

static const char service_prefix[] = "/net/connman/service/";

enum NetworkPrefsTechnology
network_prefs_get_technology_by_service_name(const char *name)
{
    msg_log_assert(name != NULL);

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
        return 0;

    bool is_wlan;

    if(strcmp(buffer + tech_offset, "wifi") == 0)
    {
        if(network_name == NULL && network_ssid == NULL)
            return 0;

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
                                          Connman::Technology tech,
                                          const Connman::Address<Connman::AddressType::MAC> &mac_address)
{
    msg_log_assert(inifile != NULL);

    struct ini_section *section = NULL;

    switch(tech)
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
        MSG_BUG("Attempted to create network configuration section for unknown technology");
        return false;

      case Connman::Technology::ETHERNET:
        section = inifile_new_section(inifile, "ethernet", 8);
        break;

      case Connman::Technology::WLAN:
        section = inifile_new_section(inifile, "wifi", 4);
        break;
    }

    if(mac_address.empty())
    {
        /* just empty section then */
        return true;
    }

    if(section == NULL ||
       inifile_section_store_value(section, "MAC", 3, mac_address.get_string().c_str(), 0) == NULL ||
       inifile_section_store_value(section, "DHCP", 4, "yes", 3) == NULL)
    {
        msg_out_of_memory("network preferences file");
        return false;
    }

    return true;
}

static void write_default_preferences(const char *filename,
                                      const char *containing_directory,
                                      const Connman::Address<Connman::AddressType::MAC> &ethernet_mac_address,
                                      const Connman::Address<Connman::AddressType::MAC> &wlan_mac_address)
{
    msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
              "Creating default network preferences file");

    struct ini_file inifile;

    inifile_new(&inifile);

    if(add_new_section_with_defaults(&inifile, Connman::Technology::ETHERNET,
                                     ethernet_mac_address) &&
       add_new_section_with_defaults(&inifile, Connman::Technology::WLAN,
                                     wlan_mac_address))
    {
        if(inifile_write_to_file(&inifile, filename) == 0)
            os_sync_dir(containing_directory);
    }

    inifile_free(&inifile);
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

struct NetworkPrefsData
{
    const char *preferences_path;
    const char *preferences_filename;

    /* TODO: There should be a std::unique_lock in #network_prefs_handle, and
     *       the #network_prefs_handle should be allocated dynamically as a
     *       proper object. */
    LoggedLock::Mutex lock;
    bool is_writable;
    struct ini_file file;

    struct network_prefs_handle handle;
    struct network_prefs network_ethernet_prefs;
    struct network_prefs network_wlan_prefs;

    NetworkPrefsData():
        preferences_path(nullptr),
        preferences_filename(nullptr),
        is_writable(false),
        file{},
        handle{},
        network_ethernet_prefs{},
        network_wlan_prefs{}
    {
        LoggedLock::configure(lock, "NetworkPrefsData", MESSAGE_LEVEL_DEBUG);
    }
};

static NetworkPrefsData networkprefs_data;

enum NetworkPrefsTechnology
network_prefs_get_technology_by_prefs(const struct network_prefs *prefs)
{
    msg_log_assert(prefs != NULL);

    return prefs->technology;
}

void network_prefs_init(const char *network_config_path,
                        const char *network_config_file)
{
    networkprefs_data.preferences_path = network_config_path;
    networkprefs_data.preferences_filename = network_config_file;
    networkprefs_data.is_writable = false;
    memset(&networkprefs_data.file, 0, sizeof(networkprefs_data.file));
    memset(&networkprefs_data.handle, 0, sizeof(networkprefs_data.handle));
    memset(&networkprefs_data.network_ethernet_prefs, 0, sizeof(networkprefs_data.network_ethernet_prefs));
    memset(&networkprefs_data.network_wlan_prefs, 0, sizeof(networkprefs_data.network_wlan_prefs));

    networkprefs_data.network_ethernet_prefs.technology = NWPREFSTECH_ETHERNET;
    networkprefs_data.network_wlan_prefs.technology = NWPREFSTECH_WLAN;
}

void network_prefs_deinit() {}

static int find_nic_name(const char *path, unsigned char dtype, void *user_data)
{
    if(dtype != DT_DIR)
        return 0;

    *static_cast<std::string *>(user_data) = path;

    return 1;
}

static Connman::Address<Connman::AddressType::MAC>
read_out_mac_address(const char *sysfs_path, Connman::Technology tech)
{
    switch(Connman::get_networking_mode())
    {
      case Connman::Mode::REGULAR:
        break;

      case Connman::Mode::NONE:
        sysfs_path = nullptr;
        break;

      case Connman::Mode::FAKE_CONNMAN:
        switch(tech)
        {
          case Connman::Technology::ETHERNET:
            return Connman::Address<Connman::AddressType::MAC>("11:22:33:44:55:66");

          case Connman::Technology::WLAN:
            return Connman::Address<Connman::AddressType::MAC>("66:55:44:33:22:11");

          case Connman::Technology::UNKNOWN_TECHNOLOGY:
            sysfs_path = nullptr;
            break;
        }
    }

    if(sysfs_path == nullptr)
        return Connman::Address<Connman::AddressType::MAC>();

    std::string p(sysfs_path);
    p += "/net";

    std::string nic;
    std::string mac;

    if(os_foreach_in_path(p.c_str(), find_nic_name, &nic) > 0)
    {
        p += "/" + nic + "/address";

        std::ifstream f(p);

        while(f.good())
        {
            const int ch = f.get();

            if(ch != f.eof() && ch != '\n')
                mac.push_back(ch);
            else
                break;
        }
    }

    if(mac.empty())
        msg_error(0, LOG_NOTICE, "No NIC at %s", sysfs_path);

    return Connman::Address<Connman::AddressType::MAC>(std::move(mac));
}

static struct network_prefs_handle *
open_prefs_write_defaults_if_necessary(bool is_writable,
                                       struct network_prefs *&ethernet,
                                       struct network_prefs *&wlan,
                                       bool &written_defaults)
{
    ethernet = NULL;
    wlan = NULL;
    written_defaults = false;

    networkprefs_data.is_writable = is_writable;

    for(int try_count = 0; try_count < 2; ++try_count)
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
            if(try_count == 0)
            {
                LOGGED_LOCK_CONTEXT_HINT;
                const auto locked_devices(Connman::NetworkDeviceList::get_singleton_const());
                const auto &devices(locked_devices.first);

                write_default_preferences(networkprefs_data.preferences_filename,
                                          networkprefs_data.preferences_path,
                                          devices.get_auto_select_mac_address(Connman::Technology::ETHERNET),
                                          devices.get_auto_select_mac_address(Connman::Technology::WLAN));
                written_defaults = true;
            }
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

    ethernet = (networkprefs_data.network_ethernet_prefs.section != NULL)
        ? &networkprefs_data.network_ethernet_prefs
        : NULL;
    wlan = (networkprefs_data.network_wlan_prefs.section != NULL)
        ? &networkprefs_data.network_wlan_prefs
        : NULL;

    return &networkprefs_data.handle;
}

static void patch_mac_address(struct ini_section *section,
                              const Connman::Address<Connman::AddressType::MAC> &mac_address)
{
    if(section != NULL && !mac_address.empty())
        inifile_section_store_value(section, "MAC", 3,
                                    mac_address.get_string().c_str(),
                                    mac_address.get_string().length());
}

static void patch_prefs(struct network_prefs_handle *handle,
                        struct network_prefs *prefs,
                        const Connman::Address<Connman::AddressType::MAC> &mac_address,
                        bool remove_prefs_for_missing_devices)
{
    if(prefs == nullptr)
        return;

    if((mac_address.empty() && remove_prefs_for_missing_devices) ||
       inifile_section_lookup_kv_pair(prefs->section, "MAC", 3) == nullptr ||
       inifile_section_lookup_kv_pair(prefs->section, "DHCP", 4) == nullptr)
    {
        network_prefs_remove_prefs(handle, prefs->technology);
        network_prefs_add_prefs(handle, prefs->technology);
    }
    else
        patch_mac_address(prefs->section, mac_address);
}

void network_prefs_update_primary_network_devices(const char *ethernet_sysfs_path,
                                                  const char *wlan_sysfs_path,
                                                  bool remove_prefs_for_missing_devices)
{
    Connman::Address<Connman::AddressType::MAC> ethernet_mac(
        read_out_mac_address(ethernet_sysfs_path, Connman::Technology::ETHERNET));
    Connman::Address<Connman::AddressType::MAC> wlan_mac(
        read_out_mac_address(wlan_sysfs_path, Connman::Technology::WLAN));

    if(ethernet_mac.empty())
        msg_vinfo(MESSAGE_LEVEL_IMPORTANT, "No Ethernet NIC found");
    else
        msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                  "Ethernet MAC %s", ethernet_mac.get_string().c_str());

    if(wlan_mac.empty())
        msg_vinfo(MESSAGE_LEVEL_IMPORTANT, "No WLAN NIC found");
    else
        msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                  "WLAN MAC %s", wlan_mac.get_string().c_str());

    {
        LOGGED_LOCK_CONTEXT_HINT;
        const auto locked_devices(Connman::NetworkDeviceList::get_singleton_for_update());
        auto &devices(locked_devices.first);

        devices.set_auto_select_mac_address(Connman::Technology::ETHERNET, ethernet_mac);
        devices.set_auto_select_mac_address(Connman::Technology::WLAN, wlan_mac);
    }

    /* patch changed MAC addresses into the configuration file */
    LOGGED_LOCK_CONTEXT_HINT;
    networkprefs_data.lock.lock();

    struct network_prefs *ethernet_prefs;
    struct network_prefs *wlan_prefs;
    bool written_defaults;
    auto *prefs =
        open_prefs_write_defaults_if_necessary(true, ethernet_prefs,
                                               wlan_prefs, written_defaults);

    if(prefs == nullptr)
    {
        LOGGED_LOCK_CONTEXT_HINT;
        networkprefs_data.lock.unlock();
        return;
    }

    if(!written_defaults)
    {
        /* defaults will be fine, but here we have an existing file with
         * content that we have to patch now */
        patch_prefs(prefs, ethernet_prefs, ethernet_mac, remove_prefs_for_missing_devices);
        patch_prefs(prefs, wlan_prefs, wlan_mac, remove_prefs_for_missing_devices);
    }

    network_prefs_write_to_file(prefs);
    network_prefs_close(prefs);
}

static struct network_prefs_handle *open_prefs_file(bool is_writable,
                                                    struct network_prefs **ethernet,
                                                    struct network_prefs **wlan)
{
    LOGGED_LOCK_CONTEXT_HINT;
    networkprefs_data.lock.lock();

    bool dummy;
    auto *prefs =
        open_prefs_write_defaults_if_necessary(is_writable, *ethernet, *wlan,
                                               dummy);

    if(prefs == nullptr)
    {
        LOGGED_LOCK_CONTEXT_HINT;
        networkprefs_data.lock.unlock();
        return nullptr;
    }

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
     * old one is broken or the new one provides better connectivity),
     * the MAC address changes as well. Our configuration file still only knows
     * about the old address in this case, so we are generating wrong service
     * names and therefore fail to make any connection.
     *
     * Following the system design, it is safe to just always replace the
     * stored MAC addresses by whatever non-empty address we extracted from the
     * system. This is a hack, of course. A good fix would allow the
     * user to select the exact networking adapter he wants to use. Changing
     * the networking adapter could be supported by allowing the user to copy
     * configuration settings.
     */
    LOGGED_LOCK_CONTEXT_HINT;
    const auto locked_devices(Connman::NetworkDeviceList::get_singleton_const());
    const auto &devices(locked_devices.first);

    patch_mac_address(networkprefs_data.network_ethernet_prefs.section,
                      devices.get_auto_select_mac_address(Connman::Technology::ETHERNET));
    patch_mac_address(networkprefs_data.network_wlan_prefs.section,
                      devices.get_auto_select_mac_address(Connman::Technology::WLAN));

    return prefs;
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
    msg_log_assert(handle == &networkprefs_data.handle);
    msg_log_assert(handle->file != NULL);

    inifile_free(handle->file);
    handle->file = NULL;
    networkprefs_data.network_ethernet_prefs.section = NULL;
    networkprefs_data.network_wlan_prefs.section = NULL;

    LOGGED_LOCK_CONTEXT_HINT;
    networkprefs_data.lock.unlock();
}

static inline void assert_writable_file(const struct network_prefs_handle *handle)
{
    msg_log_assert(handle == &networkprefs_data.handle);
    msg_log_assert(handle->file != NULL);
    msg_log_assert(networkprefs_data.is_writable);
}

struct network_prefs *network_prefs_add_prefs(struct network_prefs_handle *handle,
                                              enum NetworkPrefsTechnology tech)
{
    assert_writable_file(handle);

    struct network_prefs *prefs = NULL;

    LOGGED_LOCK_CONTEXT_HINT;
    const auto locked_devices(Connman::NetworkDeviceList::get_singleton_const());
    const auto &devices(locked_devices.first);
    Connman::Technology connman_tech = Connman::Technology::UNKNOWN_TECHNOLOGY;

    switch(tech)
    {
      case NWPREFSTECH_UNKNOWN:
        break;

      case NWPREFSTECH_ETHERNET:
        msg_log_assert(networkprefs_data.network_ethernet_prefs.section == NULL);
        networkprefs_data.network_ethernet_prefs.section =
            inifile_new_section(&networkprefs_data.file, "ethernet", 8);
        prefs = &networkprefs_data.network_ethernet_prefs;
        connman_tech = Connman::Technology::ETHERNET;
        break;

      case NWPREFSTECH_WLAN:
        msg_log_assert(networkprefs_data.network_wlan_prefs.section == NULL);
        networkprefs_data.network_wlan_prefs.section =
            inifile_new_section(&networkprefs_data.file, "wifi", 4);
        prefs = &networkprefs_data.network_wlan_prefs;
        connman_tech = Connman::Technology::WLAN;
        break;
    }

    if(prefs == NULL || prefs->section == NULL)
        return NULL;

    if(add_new_section_with_defaults(&networkprefs_data.file, connman_tech,
                                     devices.get_auto_select_mac_address(connman_tech)))
        return prefs;

    if(prefs->section != NULL)
    {
        MSG_BUG("Error occurred, should remove section from file");
        prefs->section = NULL;
    }

    return NULL;
}

bool network_prefs_remove_prefs(struct network_prefs_handle *handle,
                                enum NetworkPrefsTechnology tech)
{
    assert_writable_file(handle);

    bool retval = false;

    switch(tech)
    {
      case NWPREFSTECH_UNKNOWN:
        MSG_BUG("Attempted to remove preferences for unknown technology %d", tech);
        break;

      case NWPREFSTECH_ETHERNET:
        retval = inifile_remove_section(handle->file,
                                        networkprefs_data.network_ethernet_prefs.section);
        networkprefs_data.network_ethernet_prefs.section = NULL;
        break;

      case NWPREFSTECH_WLAN:
        retval = inifile_remove_section(handle->file,
                                        networkprefs_data.network_wlan_prefs.section);
        networkprefs_data.network_wlan_prefs.section = NULL;
        break;
    }

    return retval;
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

size_t network_prefs_generate_service_name(const struct network_prefs *prefs,
                                           char *buffer, size_t buffer_size,
                                           bool with_service_prefix)
{
    if(buffer_size > 0)
        buffer[0] = '\0';
    else
        return 0;

    if(prefs == NULL)
        return 0;

    msg_log_assert(prefs->section != NULL);

    const size_t tech_offset =
        with_service_prefix ? sizeof(service_prefix) - 1 : 0;

    const struct ini_section *const section = prefs->section;

    if(section->values_head == NULL)
        return 0;

    const size_t namelen = strlen(section->name);
    const size_t start_offset = tech_offset + namelen;

    if(start_offset >= buffer_size)
        return 0;

    if(with_service_prefix)
        memcpy(buffer, service_prefix, sizeof(service_prefix) - 1);

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

const char *network_prefs_get_mac(const struct network_prefs *prefs)
{
    return get_pref(prefs->section, "MAC");
}

const char *network_prefs_get_name(const struct network_prefs *prefs)
{
    return get_pref(prefs->section, "NetworkName");
}

const char *network_prefs_get_ssid(const struct network_prefs *prefs)
{
    return get_pref(prefs->section, "SSID");
}

const char *network_prefs_get_security(const struct network_prefs *prefs)
{
    return get_pref(prefs->section, "Security");
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
    msg_log_assert(section != NULL);
    msg_log_assert(key != NULL);

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
                                   const char *passphrase,
                                   bool *have_new_passphrase)
{
    if(network_name != nullptr || ssid != nullptr)
    {
        modify_pref(prefs->section, "NetworkName",
                    network_name != nullptr ? network_name : "");
        modify_pref(prefs->section, "SSID", ssid != nullptr ? ssid : "");
    }

    modify_pref(prefs->section, "Security", security);

    switch(modify_pref(prefs->section, "Passphrase", passphrase))
    {
      case MODIFY_UNTOUCHED_DEFINED:
      case MODIFY_UNTOUCHED_UNDEFINED:
      case MODIFY_FAILED_ADD:
      case MODIFY_FAILED_REMOVE:
        if(have_new_passphrase != NULL)
            *have_new_passphrase = false;
        break;

      case MODIFY_ADDED:
      case MODIFY_REMOVED:
        if(have_new_passphrase != NULL)
            *have_new_passphrase = true;
        break;
    }
}

void network_prefs_disable_ipv4(struct network_prefs *prefs)
{
    network_prefs_put_dhcp_mode(prefs, true, true);
    modify_pref(prefs->section, "DHCP", "");
}
