/*
 * Copyright (C) 2016, 2017, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#include "networkprefs.h"
#include "inifile.h"
#include "network_device_list.hh"
#include "dbus_handlers_connman_manager.hh"
#include "messages.h"

#include <dirent.h>

#include <fstream>
#include <cstring>

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
    log_assert(inifile != NULL);

    struct ini_section *section = NULL;

    switch(tech)
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
        BUG("Attempted to create network configuration section for unknown technology");
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
        file{0},
        handle{0},
        network_ethernet_prefs{0},
        network_wlan_prefs{0}
    {
        LoggedLock::configure(lock, "NetworkPrefsData", MESSAGE_LEVEL_DEBUG);
    }
};

static NetworkPrefsData networkprefs_data;

enum NetworkPrefsTechnology
network_prefs_get_technology_by_prefs(const struct network_prefs *prefs)
{
    log_assert(prefs != NULL);

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
    log_assert(handle == &networkprefs_data.handle);
    log_assert(handle->file != NULL);

    inifile_free(handle->file);
    handle->file = NULL;
    networkprefs_data.network_ethernet_prefs.section = NULL;
    networkprefs_data.network_wlan_prefs.section = NULL;

    LOGGED_LOCK_CONTEXT_HINT;
    networkprefs_data.lock.unlock();
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

    LOGGED_LOCK_CONTEXT_HINT;
    const auto locked_devices(Connman::NetworkDeviceList::get_singleton_const());
    const auto &devices(locked_devices.first);
    Connman::Technology connman_tech = Connman::Technology::UNKNOWN_TECHNOLOGY;

    switch(tech)
    {
      case NWPREFSTECH_UNKNOWN:
        break;

      case NWPREFSTECH_ETHERNET:
        log_assert(networkprefs_data.network_ethernet_prefs.section == NULL);
        networkprefs_data.network_ethernet_prefs.section =
            inifile_new_section(&networkprefs_data.file, "ethernet", 8);
        prefs = &networkprefs_data.network_ethernet_prefs;
        connman_tech = Connman::Technology::ETHERNET;
        break;

      case NWPREFSTECH_WLAN:
        log_assert(networkprefs_data.network_wlan_prefs.section == NULL);
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
        BUG("Error occurred, should remove section from file");
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
        BUG("Attempted to remove preferences for unknown technology %d", tech);
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

    log_assert(prefs->section != NULL);

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

/* taken from versions before f03d914 */
struct config_filename_template
{
    const char *const config_template;
    const size_t size_including_zero_terminator;
    const size_t replacement_start_offset;
};

static const char config_filename_template_for_builtin_interfaces[] =
    "builtin_xxxxxxxxxxxx.config";

static char *generate_network_config_file_name(const char *connman_config_path,
                                               const Connman::Address<Connman::AddressType::MAC> *const ethernet_mac)
{
    static const char fixed_name_for_wlan_config[] = "wlan_device.config";

    const bool is_wired = (ethernet_mac != nullptr);
    static const struct config_filename_template cfg_template =
    {
        .config_template = config_filename_template_for_builtin_interfaces,
        .size_including_zero_terminator = sizeof(config_filename_template_for_builtin_interfaces),
        .replacement_start_offset = 8,
    };

    const size_t prefix_length = strlen(connman_config_path);
    const size_t total_length =
        prefix_length + 1 + (is_wired
                             ? cfg_template.size_including_zero_terminator
                             : sizeof(fixed_name_for_wlan_config));

    char *filename = static_cast<char *>(malloc(total_length));

    if(filename == nullptr)
    {
        msg_out_of_memory("network configuration filename");
        return nullptr;
    }

    memcpy(filename, connman_config_path, prefix_length);
    filename[prefix_length] = '/';

    if(is_wired)
        memcpy(filename + prefix_length + 1, cfg_template.config_template,
               cfg_template.size_including_zero_terminator);
    else
    {
        memcpy(filename + prefix_length + 1, fixed_name_for_wlan_config,
               sizeof(fixed_name_for_wlan_config));

        return filename;
    }

    char *const dest =
        filename + prefix_length + 1 + cfg_template.replacement_start_offset;

    const auto mac_string(ethernet_mac->get_string());

    for(size_t i = 0, j = 0; i < 6 * 2; i += 2, j += 3)
    {
        log_assert(dest[i + 0] == 'x');
        log_assert(dest[i + 1] == 'x');

        dest[i + 0] = tolower(mac_string[j + 0]);
        dest[i + 1] = tolower(mac_string[j + 1]);
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
            t->token = static_cast<char *>(malloc(t->length + 1));

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
                                      security, passphrase, nullptr);
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

void network_prefs_migrate_old_network_configuration_files(const char *connman_config_path)
{
    LOGGED_LOCK_CONTEXT_HINT;
    const auto locked_devices(Connman::NetworkDeviceList::get_singleton_const());
    const auto &devices(locked_devices.first);
    const auto ethernet_mac(devices.get_auto_select_mac_address(Connman::Technology::ETHERNET));

    char *old_ethernet_config_filename =
        (ethernet_mac.empty()
         ? nullptr
         : generate_network_config_file_name(connman_config_path, &ethernet_mac));
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
