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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>

#include "dcpregs_networking.h"
#include "registers_priv.h"
#include "inifile.h"
#include "connman.h"
#include "messages.h"

#define REQ_DHCP_MODE_55                ((uint32_t)(1U << 0))
#define REQ_IP_ADDRESS_56               ((uint32_t)(1U << 1))
#define REQ_NETMASK_57                  ((uint32_t)(1U << 2))
#define REQ_DEFAULT_GATEWAY_58          ((uint32_t)(1U << 3))
#define REQ_PROXY_MODE_59               ((uint32_t)(1U << 4))
#define REQ_PROXY_SERVER_60             ((uint32_t)(1U << 5))
#define REQ_PROXY_PORT_61               ((uint32_t)(1U << 6))
#define REQ_DNS_SERVER1_62              ((uint32_t)(1U << 7))
#define REQ_DNS_SERVER2_63              ((uint32_t)(1U << 8))
#define REQ_WLAN_SECURITY_MODE_92       ((uint32_t)(1U << 9))
#define REQ_WLAN_SSID_94                ((uint32_t)(1U << 10))
#define REQ_WLAN_WEP_MODE_95            ((uint32_t)(1U << 11))
#define REQ_WLAN_WEP_KEY_INDEX_96       ((uint32_t)(1U << 12))
#define REQ_WLAN_WEP_KEY0_97            ((uint32_t)(1U << 13))
#define REQ_WLAN_WEP_KEY1_98            ((uint32_t)(1U << 14))
#define REQ_WLAN_WEP_KEY2_99            ((uint32_t)(1U << 15))
#define REQ_WLAN_WEP_KEY3_100           ((uint32_t)(1U << 16))
#define REQ_WLAN_WPA_PASSPHRASE_102     ((uint32_t)(1U << 17))

static const uint32_t req_wireless_only_parameters =
    REQ_WLAN_SECURITY_MODE_92 | REQ_WLAN_SSID_94 |
    REQ_WLAN_WEP_MODE_95 | REQ_WLAN_WEP_KEY_INDEX_96 | REQ_WLAN_WEP_KEY0_97 |
    REQ_WLAN_WEP_KEY1_98 | REQ_WLAN_WEP_KEY2_99 | REQ_WLAN_WEP_KEY3_100 |
    REQ_WLAN_WPA_PASSPHRASE_102;

#define SIZE_OF_IPV4_ADDRESS_STRING     (4U * 3U + 3U + 1U)
#define SIZE_OF_WLAN_SECURITY_MODE      8U

/*!
 * Minimum size of an IPv4 address in bytes, not including zero-terminator.
 *
 * The shortest valid address contains only single digits, such as "8.8.8.8".
 */
#define MINIMUM_IPV4_ADDRESS_STRING_LENGTH     7U

#define IS_REQUESTED(R) \
    ((nwconfig_write_data.requested_changes & (R)) != 0)

#define ALL_REQUESTED(R) \
    ((nwconfig_write_data.requested_changes & (R)) == (R))

static const char global_section_name[]  = "global";
static const char service_section_name[] = "service_config";

/*!
 * Network configuration change requests.
 *
 * It is necessary to store all configuration changes in RAM before writing
 * them to file because updating each value immediately would cause pointless
 * file writes and trigger reconfiguration attempts on behalf of Connman.
 *
 * All configuration changes are recorded in the #nwconfig_write_data structure
 * after the client has written a 0 to the \c SELECTED_IP_PROFILE register
 * (DCP register 54). Without this, no changes are recorded. Writing a 0 to the
 * \c SELECTED_IP_PROFILE deletes all requested changes. All configuration
 * changes are applied when the client writes a 0 to the \c ACTIVE_IP_PROFILE
 * register (DCP register 53).
 */
static struct
{
    /*!
     * Active interface at the time the change request was commenced.
     */
    const struct register_network_interface_t *selected_interface;

    /*!
     * Which configuration settings to change.
     *
     * \see \c REQ_* definitions (for instance, #REQ_DHCP_MODE_55)
     */
    uint32_t requested_changes;

    bool dhcpv4_mode;
    char ipv4_address[SIZE_OF_IPV4_ADDRESS_STRING];
    char ipv4_netmask[SIZE_OF_IPV4_ADDRESS_STRING];
    char ipv4_gateway[SIZE_OF_IPV4_ADDRESS_STRING];
    char ipv4_dns_server1[SIZE_OF_IPV4_ADDRESS_STRING];
    char ipv4_dns_server2[SIZE_OF_IPV4_ADDRESS_STRING];

    bool proxy_mode;
    char *proxy_server_name;
    uint16_t proxy_server_port;

    char wlan_security_mode[SIZE_OF_WLAN_SECURITY_MODE];

    size_t wlan_ssid_length;
    uint8_t wlan_ssid[32];

    bool wlan_wep_mode_is_open;
    uint8_t wlan_wep_key_index;
    uint8_t wlan_wep_keys[4][28];

    bool wlan_wpa_passphrase_is_ascii;
    uint8_t wlan_wpa_passphrase[64];
}
nwconfig_write_data;

void dcpregs_networking_init(void)
{
    nwconfig_write_data.selected_interface = NULL;
}

struct config_filename_template
{
    const char *const template;
    const size_t size_including_zero_terminator;
    const size_t replacement_start_offset;
};

static const struct config_filename_template *get_filename_template(bool is_builtin)
{
    static const char config_filename_for_builtin_interfaces[] =
        "builtin_xxxxxxxxxxxx.config";
    static const char config_filename_for_external_interfaces[] =
        "external_xxxxxxxxxxxx.config";

    static const struct config_filename_template config_for_builtin =
    {
        .template = config_filename_for_builtin_interfaces,
        .size_including_zero_terminator = sizeof(config_filename_for_builtin_interfaces),
        .replacement_start_offset = 8,
    };

    static const struct config_filename_template config_for_external =
    {
        .template = config_filename_for_external_interfaces,
        .size_including_zero_terminator = sizeof(config_filename_for_external_interfaces),
        .replacement_start_offset = 9,
    };

    return is_builtin ? &config_for_builtin : &config_for_external;
}

static char *generate_network_config_file_name(const struct register_network_interface_t *iface,
                                               const char *connman_config_path)
{
    const struct config_filename_template *const cfg_template =
        get_filename_template(iface->is_builtin);
    const size_t prefix_length = strlen(connman_config_path);
    const size_t total_length =
        prefix_length + 1 + cfg_template->size_including_zero_terminator;

    char *filename = malloc(total_length);

    if(filename == NULL)
    {
        msg_error(errno, LOG_ERR,
                  "Failed to allocate %zu bytes for network configuration filename",
                  total_length);
        return NULL;
    }

    memcpy(filename, connman_config_path, prefix_length);
    filename[prefix_length] = '/';
    memcpy(filename + prefix_length + 1, cfg_template->template,
           cfg_template->size_including_zero_terminator);

    char *const dest =
        filename + prefix_length + 1 + cfg_template->replacement_start_offset;

    for(size_t i = 0, j = 0; i < 6 * 2; i += 2, j += 3)
    {
        log_assert(dest[i + 0] == 'x');
        log_assert(dest[i + 1] == 'x');

        dest[i + 0] = tolower(iface->mac_address_string[j + 0]);
        dest[i + 1] = tolower(iface->mac_address_string[j + 1]);
    }

    return filename;
}

static int complement_inifile_with_boilerplate(struct ini_file *ini,
                                               const struct register_network_interface_t *iface)
{
    struct ini_section *section =
        inifile_find_section(ini, global_section_name, sizeof(global_section_name) - 1);

    if(section == NULL)
        section = inifile_new_section(ini, global_section_name, sizeof(global_section_name) - 1);

    if(section == NULL)
        return -1;

    if(inifile_section_store_value(section, "Name", 4, "StrBo", 0) == NULL)
        return -1;

    char string_buffer[128];

    snprintf(string_buffer, sizeof(string_buffer),
             "StrBo-managed %s %s interface",
             iface->is_builtin ? "built-in" : "external",
             iface->is_wired ? "wired" : "wireless");

    if(inifile_section_store_value(section, "Description", 11,
                                   string_buffer, 0) == NULL)
        return -1;


    section = inifile_find_section(ini, service_section_name, sizeof(service_section_name) - 1);

    if(section == NULL)
        section = inifile_new_section(ini, service_section_name, sizeof(service_section_name) - 1);

    if(section == NULL)
        return -1;

    if(inifile_section_store_value(section, "MAC", 3, iface->mac_address_string, 0) == NULL)
        return -1;

    if(iface->is_builtin &&
       inifile_section_store_value(section, "Type", 4,
                                   iface->is_wired ? "ethernet" : "wifi", 0) == NULL)
        return -1;

    return 0;
}

static bool in_edit_mode(void)
{
    return nwconfig_write_data.selected_interface != NULL;
}

static const struct register_network_interface_t *
get_network_iface_data(const struct register_configuration_t *config)
{
    return (config->active_interface != NULL)
        ? config->active_interface
        : &config->builtin_ethernet_interface;
}

static struct ConnmanInterfaceData *get_connman_iface_data(void)
{
    const struct register_configuration_t *config = registers_get_data();

    if(in_edit_mode())
        return connman_find_interface(
                   nwconfig_write_data.selected_interface->mac_address_string);
    else
        return connman_find_active_primary_interface(
                   get_network_iface_data(config)->mac_address_string,
                   config->builtin_ethernet_interface.mac_address_string,
                   config->builtin_wlan_interface.mac_address_string);

}

/*!
 * \todo Not implemented
 */
static bool is_valid_ip_address_string(const char *string, bool is_empty_ok)
{
    return true;
}

static int fill_in_missing_ipv4_config_requests(void)
{
    log_assert(IS_REQUESTED(REQ_IP_ADDRESS_56 | REQ_NETMASK_57 | REQ_DEFAULT_GATEWAY_58));

    if(ALL_REQUESTED(REQ_IP_ADDRESS_56 | REQ_NETMASK_57 | REQ_DEFAULT_GATEWAY_58))
        return
            (is_valid_ip_address_string(nwconfig_write_data.ipv4_address, false) &&
             is_valid_ip_address_string(nwconfig_write_data.ipv4_netmask, false) &&
             is_valid_ip_address_string(nwconfig_write_data.ipv4_gateway, false))
            ? 0
            : -1;

    BUG("%s(): not implemented", __func__);

    return -1;
}

/*!
 * Short helper for improving code readability.
 */
static void copy_as_primary_dns(const char *src)
{
    memcpy(nwconfig_write_data.ipv4_dns_server1, src,
           sizeof(nwconfig_write_data.ipv4_dns_server1));

    nwconfig_write_data.ipv4_dns_server1[sizeof(nwconfig_write_data.ipv4_dns_server1) - 1] = '\0';
}

/*!
 * Short helper for improving code readability.
 */
static void copy_as_secondary_dns(const char *src)
{
    memcpy(nwconfig_write_data.ipv4_dns_server2, src,
           sizeof(nwconfig_write_data.ipv4_dns_server2));

    nwconfig_write_data.ipv4_dns_server2[sizeof(nwconfig_write_data.ipv4_dns_server2) - 1] = '\0';
}

/*!
 * Move secondary DNS to primary slot.
 */
static void shift_dns_servers(void)
{
    copy_as_primary_dns(nwconfig_write_data.ipv4_dns_server2);
    nwconfig_write_data.ipv4_dns_server2[0] = '\0';
}

/*!
 * Move secondary DNS to primary slot in case the primary slot is empty.
 */
static void shift_dns_servers_if_necessary(void)
{
    if(nwconfig_write_data.ipv4_dns_server1[0] == '\0')
        shift_dns_servers();
}

/*!
 * Merge existing DNS server list with newly set servers.
 *
 * Because of the poor DCP design, this function is much more complicated that
 * it should be.
 *
 * There are several cases to consider:
 * - One or both servers could have been explicitly removed by sending an empty
 *   string.
 * - One or both servers could have been replaced by new servers.
 * - In case only a secondary server was sent,
 *   - it becomes the secondary DNS in case a primary DNS was already defined;
 *   - it may replace the previously defined secondary DNS in case there was
 *     one defined already;
 *   - it becomes the primary one if no DNS servers were defined before.
 */
static void fill_in_missing_dns_server_config_requests(void)
{
    log_assert(IS_REQUESTED(REQ_DNS_SERVER1_62 | REQ_DNS_SERVER2_63));

    if(ALL_REQUESTED(REQ_DNS_SERVER1_62 | REQ_DNS_SERVER2_63))
    {
        shift_dns_servers_if_necessary();
        return;
    }

    /* at this point we know that only one DNS server was sent to us, either a
     * "primary" one or a "secondary" */

    char previous_primary[SIZE_OF_IPV4_ADDRESS_STRING];
    char previous_secondary[SIZE_OF_IPV4_ADDRESS_STRING];

    struct ConnmanInterfaceData *iface_data = get_connman_iface_data();

    if(iface_data == NULL)
        previous_primary[0] = previous_secondary[0] = '\0';
    else
    {
        connman_get_ipv4_primary_dns_string(iface_data, previous_primary,
                                            sizeof(previous_primary));
        connman_get_ipv4_secondary_dns_string(iface_data, previous_secondary,
                                              sizeof(previous_secondary));
        connman_free_interface_data(iface_data);
    }

    const bool have_dns_servers =
        previous_primary[0] != '\0' || previous_secondary[0] != '\0';

    if(!have_dns_servers)
    {
        /*
         * There are no previously defined DNS servers, and only one DNS server
         * was sent. If the sent DNS was meant to be the secondary one, we
         * silently make it the new primary one.
         */
        if(IS_REQUESTED(REQ_DNS_SERVER2_63))
            shift_dns_servers();
    }
    else
    {
        /*
         * So we have two lists. For sure there must be a primary DNS server in
         * the \c previous_primary buffer (otherwise \c kv would have been
         * \c NULL). There might be a secondary DNS in \c previous_secondary as
         * well. */
        log_assert(previous_primary[0] != '\0');

        if(IS_REQUESTED(REQ_DNS_SERVER1_62))
        {
            /* have new primary server, now copy over the previously defined,
             * secondary one (if any) */
            copy_as_secondary_dns(previous_secondary);
            shift_dns_servers_if_necessary();
        }
        else
        {
            /* have new secondary server, now copy over the previously defined,
             * primary one */
            copy_as_primary_dns(previous_primary);
        }
    }
}

static bool query_dhcp_mode(void)
{
    struct ConnmanInterfaceData *iface_data = get_connman_iface_data();
    bool ret = (iface_data != NULL) ? connman_get_dhcp_mode(iface_data) : false;
    connman_free_interface_data(iface_data);

    return ret;
}

static int handle_set_dhcp_mode(struct ini_section *section,
                                const struct register_network_interface_t *selected)
{
    if(!IS_REQUESTED(REQ_DHCP_MODE_55))
        return 0;

    if(nwconfig_write_data.dhcpv4_mode)
    {
        if(inifile_section_store_value(section, "IPv4", 0, "dhcp", 0) == NULL)
            return -1;

        nwconfig_write_data.requested_changes &=
            ~(REQ_IP_ADDRESS_56 | REQ_NETMASK_57 | REQ_DEFAULT_GATEWAY_58 |
              REQ_DNS_SERVER1_62 | REQ_DNS_SERVER2_63);
    }
    else if(!IS_REQUESTED(REQ_IP_ADDRESS_56 | REQ_NETMASK_57 | REQ_DEFAULT_GATEWAY_58))
    {
        msg_error(0, LOG_WARNING,
                  "Disabling IPv4 on interface %s because DHCPv4 was "
                  "disabled and static IPv4 configuration was not sent",
                  selected->mac_address_string);

        if(inifile_section_store_value(section, "IPv4", 0, "off", 0) == NULL)
            return -1;

        nwconfig_write_data.requested_changes &=
            ~(REQ_DNS_SERVER1_62 | REQ_DNS_SERVER2_63);
    }

    return 0;
}

static int handle_set_static_ipv4_config(struct ini_section *section,
                                         const struct register_network_interface_t *selected)
{
    if(!IS_REQUESTED(REQ_IP_ADDRESS_56 | REQ_NETMASK_57 | REQ_DEFAULT_GATEWAY_58))
        return 0;

    if(fill_in_missing_ipv4_config_requests() < 0)
    {
        msg_error(0, LOG_ERR,
                  "IPv4 data incomplete, cannot set interface configuration");
        return -1;
    }

    if(nwconfig_write_data.ipv4_address[0] != '\0')
    {
        char string_buffer[128];
        snprintf(string_buffer, sizeof(string_buffer), "%s/%s/%s",
                 nwconfig_write_data.ipv4_address,
                 nwconfig_write_data.ipv4_netmask,
                 nwconfig_write_data.ipv4_gateway);

        if(inifile_section_store_value(section, "IPv4", 0, string_buffer, 0) == NULL)
            return -1;
    }
    else
    {
        msg_info("Disabling IPv4 on interface %s",
                 selected->mac_address_string);

        if(inifile_section_store_value(section, "IPv4", 0, "off", 0) == NULL)
            return -1;
    }

    return 0;
}

static int handle_set_dns_servers(struct ini_section *section,
                                  const struct register_network_interface_t *selected)
{
    if(!IS_REQUESTED(REQ_DNS_SERVER1_62 | REQ_DNS_SERVER2_63))
        return 0;

    fill_in_missing_dns_server_config_requests();

    if(nwconfig_write_data.ipv4_dns_server1[0] != '\0')
    {
        const bool have_second =
            (nwconfig_write_data.ipv4_dns_server2[0] != '\0');

        char string_buffer[128];
        snprintf(string_buffer, sizeof(string_buffer), "%s%s%s",
                 nwconfig_write_data.ipv4_dns_server1,
                 have_second ? "," : "",
                 have_second ? nwconfig_write_data.ipv4_dns_server2 : "");

        if(inifile_section_store_value(section, "Nameservers", 0, string_buffer, 0) == NULL)
            return -1;
    }
    else
    {
        msg_info("No nameservers on interface %s",
                 selected->mac_address_string);

        (void)inifile_section_remove_value(section, "Nameservers", 0);
    }

    return 0;
}

static char nibble_to_char(uint8_t nibble)
{
    if(nibble < 10)
        return '0' + nibble;
    else
        return 'a' + nibble - 10;
}

static void binary_to_hexdump(char *dest, const uint8_t *src, size_t len)
{
    size_t j = 0;

    for(size_t i = 0; i < len; ++i)
    {
        const uint8_t byte = nwconfig_write_data.wlan_ssid[i];

        dest[j++] = nibble_to_char(byte >> 4);
        dest[j++] = nibble_to_char(byte & 0x0f);
    }

    dest[j] = '\0';
}

static bool is_wlan_ssid_simple_ascii(const uint8_t *ssid, size_t len)
{
    log_assert(len > 0);
    log_assert(len <= 32);

    for(size_t i = 0; i < len; ++i)
    {
        const uint8_t ch = ssid[i];

        if(ch <= ' ')
            return false;

        if(ch > 0x7e)
            return false;
    }

    return true;
}

static int handle_set_wireless_config(struct ini_section *section,
                                      const struct register_network_interface_t *selected)
{
    if(!IS_REQUESTED(req_wireless_only_parameters))
        return 0;

    if(selected->is_wired)
    {
        msg_info("Ignoring wireless parameters for active wired interface");
        return 0;
    }

    char security_type[16];
    security_type[0] = '\0';

    if(IS_REQUESTED(REQ_WLAN_SECURITY_MODE_92))
    {
        if(strcmp(nwconfig_write_data.wlan_security_mode, "NONE") == 0)
            strcpy(security_type, "none");
        else if(strcmp(nwconfig_write_data.wlan_security_mode, "WPAPSK") == 0 ||
                strcmp(nwconfig_write_data.wlan_security_mode, "WPA2PSK") == 0)
            strcpy(security_type, "psk");
        else if(strcmp(nwconfig_write_data.wlan_security_mode, "WEP") == 0)
            BUG("Support for insecure WLAN mode \"WEP\" not implemented yet");
        else
            msg_error(EINVAL, LOG_ERR, "Invalid WLAN security mode \"%s\"",
                      nwconfig_write_data.wlan_security_mode);
    }
    else
    {
        struct ConnmanInterfaceData *iface_data = get_connman_iface_data();

        if(iface_data != NULL)
        {
            connman_get_wlan_security_type_string(iface_data, security_type,
                                                  sizeof(security_type));
            connman_free_interface_data(iface_data);
        }
    }

    if(security_type[0] == '\0')
    {
        msg_error(EINVAL, LOG_ERR,
                  "Cannot set WLAN parameters, security mode missing");
        return -1;
    }

    if(inifile_section_store_value(section, "Security", 0,
                                   security_type, 0) == NULL)
        return -1;

    if(IS_REQUESTED(REQ_WLAN_SSID_94) &&
       nwconfig_write_data.wlan_ssid_length > 0)
    {
        if(is_wlan_ssid_simple_ascii(nwconfig_write_data.wlan_ssid,
                                     nwconfig_write_data.wlan_ssid_length))
        {
            if(inifile_section_store_value(section, "Name", 0,
                                           (char *)nwconfig_write_data.wlan_ssid,
                                           nwconfig_write_data.wlan_ssid_length) == NULL)
                return -1;
        }

        char buffer[2 * sizeof(nwconfig_write_data.wlan_ssid) + 1];

        binary_to_hexdump(buffer, nwconfig_write_data.wlan_ssid,
                          nwconfig_write_data.wlan_ssid_length);

        if(inifile_section_store_value(section, "SSID", 0,
                                       buffer, 0) == NULL)
            return -1;
    }

    if(IS_REQUESTED(REQ_WLAN_WPA_PASSPHRASE_102))
    {
        const size_t passphrase_length =
            nwconfig_write_data.wlan_wpa_passphrase_is_ascii
            ? 0
            : sizeof(nwconfig_write_data.wlan_wpa_passphrase);

        if(inifile_section_store_value(section, "Passphrase", 0,
                                       (const char *)nwconfig_write_data.wlan_wpa_passphrase,
                                       passphrase_length) == NULL)
            return -1;
    }

    return 0;
}

static int apply_changes_to_inifile(struct ini_file *ini,
                                    const struct register_network_interface_t *selected)
{
    struct ini_section *section =
        inifile_find_section(ini, service_section_name, sizeof(service_section_name) - 1);

    log_assert(section != NULL);

    if(handle_set_dhcp_mode(section, selected) < 0)
        return -1;

    if(handle_set_static_ipv4_config(section, selected) < 0)
        return -1;

    if(handle_set_dns_servers(section, selected) < 0)
        return -1;

    if(handle_set_wireless_config(section, selected) < 0)
        return -1;

    static const uint32_t not_implemented =
        REQ_PROXY_MODE_59 |
        REQ_PROXY_SERVER_60 |
        REQ_PROXY_PORT_61 |
        REQ_WLAN_WEP_MODE_95 |
        REQ_WLAN_WEP_KEY_INDEX_96 |
        REQ_WLAN_WEP_KEY0_97 |
        REQ_WLAN_WEP_KEY1_98 |
        REQ_WLAN_WEP_KEY2_99 |
        REQ_WLAN_WEP_KEY3_100;

    if((nwconfig_write_data.requested_changes & not_implemented) != 0)
    {
        BUG("Unsupported change requests: 0x%08x",
            nwconfig_write_data.requested_changes & not_implemented);
        return -1;
    }

    return 0;
}

static int modify_network_configuration(const struct register_network_interface_t *selected)
{
    char *filename =
        generate_network_config_file_name(selected, registers_get_data()->connman_config_path);

    if(filename == NULL)
        return -1;

    struct ini_file ini;
    int ret = inifile_parse_from_file(&ini, filename);

    if(ret < 0)
        goto exit_error_free_filename;

    ret = -1;

    if(complement_inifile_with_boilerplate(&ini, selected) < 0)
        goto exit_error_free_inifile;

    if(apply_changes_to_inifile(&ini, selected) < 0)
        goto exit_error_free_inifile;

    ret = inifile_write_to_file(&ini, filename);

exit_error_free_inifile:
    inifile_free(&ini);

exit_error_free_filename:
    free(filename);

    return ret;
}

static bool may_change_config(void)
{
    if(in_edit_mode())
        return true;

    msg_error(0, LOG_ERR,
              "Network configuration may not be changed without prior "
              "request for changing the configuration");

    return false;
}

static bool data_length_is_unexpected(size_t length, size_t expected)
{
    if(length == expected)
        return false;

    msg_error(EINVAL, LOG_ERR,
              "Unexpected data length %zu (expected %zu)", length, expected);

    return true;
}

static bool data_length_is_in_unexpected_range(size_t length,
                                               size_t expected_min,
                                               size_t expected_max)
{
    if(length >= expected_min && length <= expected_max)
        return false;

    msg_error(EINVAL, LOG_ERR,
              "Unexpected data length %zu (expected %zu...%zu)",
              length, expected_min, expected_max);

    return true;
}

static bool data_length_is_unexpectedly_small(size_t length,
                                              size_t expected_min)
{
    if(length >= expected_min)
        return false;

    msg_error(EINVAL, LOG_ERR,
              "Unexpected data length %zu (expected minimum of %zu)",
              length, expected_min);

    return true;
}

int dcpregs_write_53_active_ip_profile(const uint8_t *data, size_t length)
{
    msg_info("write 53 handler %p %zu", data, length);

    if(data_length_is_unexpected(length, 1))
        return -1;

    if(data[0] != 0)
        return -1;

    if(!may_change_config())
        return -1;

    const struct register_network_interface_t *selected =
        nwconfig_write_data.selected_interface;

    nwconfig_write_data.selected_interface = NULL;

    if(nwconfig_write_data.requested_changes == 0)
    {
        /* nothing to do */
        return 0;
    }

    msg_info("Writing new network configuration for MAC address %s",
             selected->mac_address_string);

    return modify_network_configuration(selected);
}

int dcpregs_write_54_selected_ip_profile(const uint8_t *data, size_t length)
{
    msg_info("write 54 handler %p %zu", data, length);

    if(data_length_is_unexpected(length, 1))
        return -1;

    if(data[0] != 0)
        return -1;

    memset(&nwconfig_write_data, 0, sizeof(nwconfig_write_data));

    nwconfig_write_data.selected_interface =
        get_network_iface_data(registers_get_data());
    log_assert(nwconfig_write_data.selected_interface != NULL);

    return 0;
}

ssize_t dcpregs_read_51_mac_address(uint8_t *response, size_t length)
{
    msg_info("read 51 handler %p %zu", response, length);

    const struct register_network_interface_t *const iface =
        get_network_iface_data(registers_get_data());

    if(data_length_is_unexpected(length, sizeof(iface->mac_address_string)))
        return -1;

    if(length <  sizeof(iface->mac_address_string))
        return -1;

    memcpy(response, iface->mac_address_string, sizeof(iface->mac_address_string));

    return sizeof(iface->mac_address_string);
}

ssize_t dcpregs_read_55_dhcp_enabled(uint8_t *response, size_t length)
{
    msg_info("read 55 handler %p %zu", response, length);

    if(data_length_is_unexpected(length, 1))
        return -1;

    if(in_edit_mode() && IS_REQUESTED(REQ_DHCP_MODE_55))
        response[0] = nwconfig_write_data.dhcpv4_mode;
    else
        response[0] = query_dhcp_mode();

    return length;
}

int dcpregs_write_55_dhcp_enabled(const uint8_t *data, size_t length)
{
    msg_info("write 55 handler %p %zu", data, length);

    if(data_length_is_unexpected(length, 1))
        return -1;

    if(!may_change_config())
        return -1;

    if(data[0] > 1)
    {
        msg_error(EINVAL, LOG_ERR,
                  "Received invalid DHCP configuration parameter 0x%02x",
                  data[0]);
        return -1;
    }

    msg_info("%sable DHCP", data[0] == 0 ? "Dis" : "En");

    if(data[0] == 0)
    {
        nwconfig_write_data.requested_changes |= REQ_DHCP_MODE_55;
        nwconfig_write_data.dhcpv4_mode = false;
    }
    else
    {
        nwconfig_write_data.requested_changes |=
            REQ_DHCP_MODE_55 | REQ_IP_ADDRESS_56 | REQ_NETMASK_57 |
            REQ_DEFAULT_GATEWAY_58 | REQ_DNS_SERVER1_62 | REQ_DNS_SERVER2_63;
        nwconfig_write_data.dhcpv4_mode = true;
        nwconfig_write_data.ipv4_address[0] = '\0';
        nwconfig_write_data.ipv4_netmask[0] = '\0';
        nwconfig_write_data.ipv4_gateway[0] = '\0';
        nwconfig_write_data.ipv4_dns_server1[0] = '\0';
        nwconfig_write_data.ipv4_dns_server2[0] = '\0';
    }

    return 0;
}

static ssize_t
read_ipv4_parameter(uint32_t requested_mask,
                    const char edited_ipv4_parameter[static SIZE_OF_IPV4_ADDRESS_STRING],
                    void (*connman_query_fn)(struct ConnmanInterfaceData *, char *, size_t),
                    uint8_t *response, size_t length)
{
    if(data_length_is_unexpectedly_small(length, SIZE_OF_IPV4_ADDRESS_STRING))
        return -1;

    if(in_edit_mode() && IS_REQUESTED(requested_mask))
        memcpy(response, edited_ipv4_parameter, SIZE_OF_IPV4_ADDRESS_STRING);
    else
    {
        struct ConnmanInterfaceData *iface_data = get_connman_iface_data();

        if(iface_data != NULL)
            connman_query_fn(iface_data, (char *)response, length);
        else
            response[0] = '\0';

        connman_free_interface_data(iface_data);
    }

    return strlen((char *)response) + 1;
}

ssize_t dcpregs_read_56_ipv4_address(uint8_t *response, size_t length)
{
    msg_info("read 56 handler %p %zu", response, length);

    return read_ipv4_parameter(REQ_IP_ADDRESS_56,
                               nwconfig_write_data.ipv4_address,
                               connman_get_ipv4_address_string,
                               response, length);
}

ssize_t dcpregs_read_57_ipv4_netmask(uint8_t *response, size_t length)
{
    msg_info("read 57 handler %p %zu", response, length);

    return read_ipv4_parameter(REQ_NETMASK_57,
                               nwconfig_write_data.ipv4_netmask,
                               connman_get_ipv4_netmask_string,
                               response, length);
}

ssize_t dcpregs_read_58_ipv4_gateway(uint8_t *response, size_t length)
{
    msg_info("read 58 handler %p %zu", response, length);

    return read_ipv4_parameter(REQ_DEFAULT_GATEWAY_58,
                               nwconfig_write_data.ipv4_gateway,
                               connman_get_ipv4_gateway_string,
                               response, length);
}

ssize_t dcpregs_read_62_primary_dns(uint8_t *response, size_t length)
{
    msg_info("read 62 handler %p %zu", response, length);

    return read_ipv4_parameter(REQ_DNS_SERVER1_62,
                               nwconfig_write_data.ipv4_dns_server1,
                               connman_get_ipv4_primary_dns_string,
                               response, length);
}

ssize_t dcpregs_read_63_secondary_dns(uint8_t *response, size_t length)
{
    msg_info("read 63 handler %p %zu", response, length);

    return read_ipv4_parameter(REQ_DNS_SERVER2_63,
                               nwconfig_write_data.ipv4_dns_server2,
                               connman_get_ipv4_secondary_dns_string,
                               response, length);
}

static size_t trim_trailing_zero_padding(const uint8_t *data, size_t length)
{
    while(length > 0 && data[length - 1] == '\0')
        --length;

    return length;
}

static int copy_ipv4_address(char *dest, const uint32_t requested_change,
                             const uint8_t *data, size_t length,
                             bool is_empty_ok)
{
    length = trim_trailing_zero_padding(data, length);

    if(length == 0)
    {
        if(!is_empty_ok)
            return -1;
    }
    else if(length < MINIMUM_IPV4_ADDRESS_STRING_LENGTH ||
            length > SIZE_OF_IPV4_ADDRESS_STRING - 1)
        return -1;

    if(length > 0)
        memcpy(dest, data, length);

    dest[length] = '\0';

    if(!is_valid_ip_address_string(dest, is_empty_ok))
        return -1;

    nwconfig_write_data.requested_changes |= requested_change;

    return 0;
}

int dcpregs_write_56_ipv4_address(const uint8_t *data, size_t length)
{
    if(data_length_is_in_unexpected_range(length,
                                          MINIMUM_IPV4_ADDRESS_STRING_LENGTH,
                                          SIZE_OF_IPV4_ADDRESS_STRING))
        return -1;

    if(!may_change_config())
        return -1;

    return copy_ipv4_address(nwconfig_write_data.ipv4_address,
                             REQ_IP_ADDRESS_56, data, length, false);
}

int dcpregs_write_57_ipv4_netmask(const uint8_t *data, size_t length)
{
    if(data_length_is_in_unexpected_range(length,
                                          MINIMUM_IPV4_ADDRESS_STRING_LENGTH,
                                          SIZE_OF_IPV4_ADDRESS_STRING))
        return -1;

    if(!may_change_config())
        return -1;

    return copy_ipv4_address(nwconfig_write_data.ipv4_netmask,
                             REQ_NETMASK_57, data, length, false);
}

int dcpregs_write_58_ipv4_gateway(const uint8_t *data, size_t length)
{
    if(data_length_is_in_unexpected_range(length,
                                          MINIMUM_IPV4_ADDRESS_STRING_LENGTH,
                                          SIZE_OF_IPV4_ADDRESS_STRING))
       return -1;

    if(!may_change_config())
        return -1;

    return copy_ipv4_address(nwconfig_write_data.ipv4_gateway,
                             REQ_DEFAULT_GATEWAY_58, data, length, false);
}

int dcpregs_write_62_primary_dns(const uint8_t *data, size_t length)
{
    if(length > 0 &&
       data_length_is_in_unexpected_range(length,
                                          MINIMUM_IPV4_ADDRESS_STRING_LENGTH,
                                          SIZE_OF_IPV4_ADDRESS_STRING))
        return -1;

    if(!may_change_config())
        return -1;

    return copy_ipv4_address(nwconfig_write_data.ipv4_dns_server1,
                             REQ_DNS_SERVER1_62, data, length, true);
}

int dcpregs_write_63_secondary_dns(const uint8_t *data, size_t length)
{
    if(length > 0 &&
       data_length_is_in_unexpected_range(length,
                                          MINIMUM_IPV4_ADDRESS_STRING_LENGTH,
                                          SIZE_OF_IPV4_ADDRESS_STRING))
        return -1;

    if(!may_change_config())
        return -1;

    return copy_ipv4_address(nwconfig_write_data.ipv4_dns_server2,
                             REQ_DNS_SERVER2_63, data, length, true);
}

ssize_t dcpregs_read_92_wlan_security(uint8_t *response, size_t length)
{
    if(data_length_is_unexpectedly_small(length, SIZE_OF_WLAN_SECURITY_MODE))
        return -1;

    bool failed = false;

    if(in_edit_mode() && IS_REQUESTED(REQ_WLAN_SECURITY_MODE_92))
        memcpy(response, nwconfig_write_data.wlan_security_mode,
               SIZE_OF_WLAN_SECURITY_MODE);
    else
    {
        response[0] = '\0';

        struct ConnmanInterfaceData *iface_data = get_connman_iface_data();

        if(iface_data != NULL)
        {
            char buffer[12];

            if(connman_get_wlan_security_type_string(iface_data, buffer, sizeof(buffer)))
            {
                if(strcmp(buffer, "none") == 0)
                    strcpy((char *)response, "NONE");
                else if(strcmp(buffer, "psk") == 0)
                    strcpy((char *)response, "WPA2PSK");
                else if(strcmp(buffer, "wep") == 0)
                    strcpy((char *)response, "WEP");
                else
                    msg_error(0, LOG_ERR,
                              "Cannot convert Connman security type \"%s\" to DCP",
                              buffer);
            }
            else
                failed = true;

            connman_free_interface_data(iface_data);
        }
        else
            failed = true;
    }

    if(failed)
    {
        msg_error(EINVAL, LOG_ERR,
                  "No Connman security type set for active interface");
        return -1;
    }

    return strlen((char *)response) + 1;
}

int dcpregs_write_92_wlan_security(const uint8_t *data, size_t length)
{
    if(data_length_is_in_unexpected_range(length,
                                          3, SIZE_OF_WLAN_SECURITY_MODE))
        return -1;

    if(!may_change_config())
        return -1;

    memcpy(nwconfig_write_data.wlan_security_mode, data, length);
    nwconfig_write_data.wlan_security_mode[length] = '\0';
    nwconfig_write_data.requested_changes |= REQ_WLAN_SECURITY_MODE_92;

    return 0;
}

ssize_t dcpregs_read_93_ibss(uint8_t *response, size_t length)
{
    if(data_length_is_unexpectedly_small(length, 8))
        return -1;

    strcpy((char *)response, "false");

    return 6;
}

int dcpregs_write_93_ibss(const uint8_t *data, size_t length)
{
    if(data_length_is_in_unexpected_range(length, 4, 8))
        return -1;

    char buffer[9];
    memcpy(buffer, data, length);
    buffer[length] = '\0';

    if(strcmp(buffer, "false") == 0)
    {
        msg_info("Ignoring IBSS infrastructure mode request (always using that mode)");
        return 0;
    }
    else if(strcmp(buffer, "true") == 0)
        msg_error(EINVAL, LOG_NOTICE,
                  "Cannot change IBSS mode to ad-hoc, always using infrastructure mode");
    else
        msg_error(EINVAL, LOG_ERR, "Got invalid IBSS mode request");

    return -1;
}

ssize_t dcpregs_read_94_ssid(uint8_t *response, size_t length)
{
    if(data_length_is_unexpectedly_small(length, 32))
        return -1;

    ssize_t retval;

    if(in_edit_mode() && IS_REQUESTED(REQ_WLAN_SSID_94))
    {
        if(nwconfig_write_data.wlan_ssid_length > 0)
            memcpy(response, nwconfig_write_data.wlan_ssid, nwconfig_write_data.wlan_ssid_length);

        retval = nwconfig_write_data.wlan_ssid_length;
    }
    else
    {
        struct ConnmanInterfaceData *iface_data = get_connman_iface_data();

        if(iface_data != NULL)
        {
            retval = connman_get_wlan_ssid(iface_data, response, length);
            connman_free_interface_data(iface_data);
        }
        else
            retval = 0;
    }

    return retval;
}

int dcpregs_write_94_ssid(const uint8_t *data, size_t length)
{
    if(data_length_is_in_unexpected_range(length, 1, 32))
        return -1;

    if(!may_change_config())
        return -1;

    memcpy(nwconfig_write_data.wlan_ssid, data, length);
    nwconfig_write_data.wlan_ssid_length = length;
    nwconfig_write_data.requested_changes |= REQ_WLAN_SSID_94;

    return 0;
}

ssize_t dcpregs_read_101_wpa_cipher(uint8_t *response, size_t length)
{
    if(data_length_is_unexpectedly_small(length, 8))
        return -1;

    strcpy((char *)response, "AES");

    return 4;
}

int dcpregs_write_101_wpa_cipher(const uint8_t *data, size_t length)
{
    if(data_length_is_in_unexpected_range(length, 3, 8))
        return -1;

    char buffer[9];
    memcpy(buffer, data, length);
    buffer[length] = '\0';

    if(strcmp(buffer, "AES") == 0 || strcmp(buffer, "TKIP") == 0)
    {
        msg_info("Ignoring setting WPA cipher (automatic, AES preferred)");
        return 0;
   }

    msg_error(EINVAL, LOG_ERR, "Got invalid WPA cipher");

    return -1;
}

ssize_t dcpregs_read_102_passphrase(uint8_t *response, size_t length)
{
    if(data_length_is_unexpectedly_small(length, sizeof(nwconfig_write_data.wlan_wpa_passphrase)))
        return -1;

    if(!in_edit_mode())
    {
        msg_info("Passphrase cannot be read out while in non-edit mode");
        return -1;
    }

    ssize_t copied_bytes;

    if(IS_REQUESTED(REQ_WLAN_WPA_PASSPHRASE_102))
    {
        copied_bytes = (nwconfig_write_data.wlan_wpa_passphrase_is_ascii
                        ? ((nwconfig_write_data.wlan_wpa_passphrase[0] == '\0')
                           ? 0
                           : strlen((const char *)nwconfig_write_data.wlan_wpa_passphrase) - 1)
                        : sizeof(nwconfig_write_data.wlan_wpa_passphrase));

        if(copied_bytes > 0)
            memcpy(response, nwconfig_write_data.wlan_wpa_passphrase,
                   copied_bytes);
        else
        {
            msg_info("Passphrase set, but empty");
            copied_bytes = 0;
        }
    }
    else
    {
        msg_info("No passphrase set yet");
        copied_bytes = 0;
    }

    return copied_bytes;
}

int dcpregs_write_102_passphrase(const uint8_t *data, size_t length)
{
    if(length > 0 &&
       data_length_is_in_unexpected_range(length,
                                          8,
                                          sizeof(nwconfig_write_data.wlan_wpa_passphrase)))
        return -1;

    if(!may_change_config())
        return -1;

    if(length > 0)
    {
        bool passphrase_is_hex = true;
        nwconfig_write_data.wlan_wpa_passphrase_is_ascii = true;

        for(size_t i = 0; i < length; ++i)
        {
            uint8_t ch = nwconfig_write_data.wlan_wpa_passphrase[i] = data[i];

            if(ch < (uint8_t)' ' || ch > (uint8_t)'~')
                nwconfig_write_data.wlan_wpa_passphrase_is_ascii = false;
            else
            {
                ch = tolower(ch);

                if(!isdigit(ch) && !(ch >= 'a' && ch <= 'f'))
                    passphrase_is_hex = false;
            }
        }

        static const char invalid_passphrase_fmt[] = "Invalid passphrase: %s";

        if(length == sizeof(nwconfig_write_data.wlan_wpa_passphrase))
        {
            if(!passphrase_is_hex)
            {
                msg_error(EINVAL, LOG_ERR, invalid_passphrase_fmt,
                          "not a hex-string");
                return -1;
            }

            nwconfig_write_data.wlan_wpa_passphrase_is_ascii = false;
        }
        else
        {
            if(!nwconfig_write_data.wlan_wpa_passphrase_is_ascii)
            {
                msg_error(EINVAL, LOG_ERR, invalid_passphrase_fmt,
                          "expected ASCII passphrase");
                return -1;
            }

            nwconfig_write_data.wlan_wpa_passphrase[length] = '\0';
        }
    }
    else
    {
        nwconfig_write_data.wlan_wpa_passphrase[0] = '\0';
        nwconfig_write_data.wlan_wpa_passphrase_is_ascii = true;
    }

    nwconfig_write_data.requested_changes |= REQ_WLAN_WPA_PASSPHRASE_102;

    return 0;
}
