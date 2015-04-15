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

#define REQ_MAC_ADDRESS_51              ((uint32_t)(1U << 0))
#define REQ_DHCP_MODE_55                ((uint32_t)(1U << 1))
#define REQ_IP_ADDRESS_56               ((uint32_t)(1U << 2))
#define REQ_NETMASK_57                  ((uint32_t)(1U << 3))
#define REQ_DEFAULT_GATEWAY_58          ((uint32_t)(1U << 4))
#define REQ_PROXY_MODE_59               ((uint32_t)(1U << 5))
#define REQ_PROXY_SERVER_60             ((uint32_t)(1U << 6))
#define REQ_PROXY_PORT_61               ((uint32_t)(1U << 7))
#define REQ_DNS_SERVER1_62              ((uint32_t)(1U << 8))
#define REQ_DNS_SERVER2_63              ((uint32_t)(1U << 9))
#define REQ_WLAN_SECURITY_MODE_92       ((uint32_t)(1U << 10))
#define REQ_WLAN_IBSS_MODE_93           ((uint32_t)(1U << 11))
#define REQ_WLAN_SSID_94                ((uint32_t)(1U << 12))
#define REQ_WLAN_WEP_MODE_95            ((uint32_t)(1U << 13))
#define REQ_WLAN_WEP_KEY_INDEX_96       ((uint32_t)(1U << 14))
#define REQ_WLAN_WEP_KEY0_97            ((uint32_t)(1U << 15))
#define REQ_WLAN_WEP_KEY1_98            ((uint32_t)(1U << 16))
#define REQ_WLAN_WEP_KEY2_99            ((uint32_t)(1U << 17))
#define REQ_WLAN_WEP_KEY3_100           ((uint32_t)(1U << 18))
#define REQ_WLAN_WPA_CIPHER_TYPE_101    ((uint32_t)(1U << 19))
#define REQ_WLAN_WPA_PASSPHRASE_102     ((uint32_t)(1U << 20))

#define SIZE_OF_IPV4_ADDRESS_STRING     (4U * 3U + 3U + 1U)

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
    char wlan_security_mode[9];
    bool wlan_ibss_mode_is_ad_hoc;
    char wlan_ssid[33];
    bool wlan_wep_mode_is_open;
    uint8_t wlan_wep_key_index;
    uint8_t wlan_wep_keys[4][28];
    char wlan_wpa_cipher[9];
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

/*!
 * \todo Not implemented
 */
static bool is_valid_ip_address_string(const char *string)
{
    return true;
}

static int fill_in_missing_ipv4_config_requests(void)
{
    if(ALL_REQUESTED(REQ_IP_ADDRESS_56 | REQ_NETMASK_57 | REQ_DEFAULT_GATEWAY_58))
        return
            (is_valid_ip_address_string(nwconfig_write_data.ipv4_address) &&
             is_valid_ip_address_string(nwconfig_write_data.ipv4_netmask) &&
             is_valid_ip_address_string(nwconfig_write_data.ipv4_gateway))
            ? 0
            : -1;

    BUG("%s(): not implemented", __func__);

    return -1;
}

static int fill_in_missing_dns_server_config_requests(void)
{
    if(ALL_REQUESTED(REQ_DNS_SERVER1_62 | REQ_DNS_SERVER2_63))
        return 0;

    BUG("%s(): not implemented", __func__);

    return -1;
}

static int apply_changes_to_inifile(struct ini_file *ini,
                                    const struct register_network_interface_t *selected)
{
    struct ini_section *section =
        inifile_find_section(ini, service_section_name, sizeof(service_section_name) - 1);

    log_assert(section != NULL);

    if(IS_REQUESTED(REQ_DHCP_MODE_55) != 0)
    {
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
        }
    }

    if(IS_REQUESTED(REQ_IP_ADDRESS_56 | REQ_NETMASK_57 | REQ_DEFAULT_GATEWAY_58))
    {
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
    }

    if(IS_REQUESTED(REQ_DNS_SERVER1_62 | REQ_DNS_SERVER2_63))
    {
        if(fill_in_missing_dns_server_config_requests() < 0)
        {
            msg_error(0, LOG_ERR,
                      "DNS server data incomplete, cannot set interface configuration");
            return -1;
        }

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
    }

    static const uint32_t not_implemented =
        REQ_MAC_ADDRESS_51 |
        REQ_PROXY_MODE_59 |
        REQ_PROXY_SERVER_60 |
        REQ_PROXY_PORT_61 |
        REQ_DNS_SERVER1_62 |
        REQ_DNS_SERVER2_63 |
        REQ_WLAN_SECURITY_MODE_92 |
        REQ_WLAN_IBSS_MODE_93 |
        REQ_WLAN_SSID_94 |
        REQ_WLAN_WEP_MODE_95 |
        REQ_WLAN_WEP_KEY_INDEX_96 |
        REQ_WLAN_WEP_KEY0_97 |
        REQ_WLAN_WEP_KEY1_98 |
        REQ_WLAN_WEP_KEY2_99 |
        REQ_WLAN_WEP_KEY3_100 |
        REQ_WLAN_WPA_CIPHER_TYPE_101 |
        REQ_WLAN_WPA_PASSPHRASE_102;

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

static bool in_edit_mode(void)
{
    return nwconfig_write_data.selected_interface != NULL;
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

static const struct register_network_interface_t *
get_network_iface_data(const struct register_configuration_t *config)
{
    return (config->active_interface != NULL)
        ? config->active_interface
        : &config->builtin_ethernet_interface;
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

int dcpregs_write_51_mac_address(const uint8_t *data, size_t length)
{
    msg_info("write 51 handler %p %zu", data, length);

    const struct register_network_interface_t *const iface =
        get_network_iface_data(registers_get_data());

    if(data_length_is_unexpected(length, sizeof(iface->mac_address_string)))
        return -1;

    if(data[sizeof(iface->mac_address_string) - 1] != '\0')
    {
        msg_error(EINVAL, LOG_ERR,
                  "Received MAC address not zero-terminated");
        return -1;
    }

    msg_info("Received MAC address \"%s\", should validate address and "
             "configure adapter", (const char *)data);

    return 0;
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

ssize_t dcpregs_read_55_dhcp_enabled(uint8_t *response, size_t length)
{
    msg_info("read 55 handler %p %zu", response, length);

    if(data_length_is_unexpected(length, 1))
        return -1;

    if(in_edit_mode() && IS_REQUESTED(REQ_DHCP_MODE_55))
        response[0] = nwconfig_write_data.dhcpv4_mode;
    else
    {
        struct ConnmanInterfaceData *iface_data = get_connman_iface_data();

        response[0] =
            (iface_data != NULL) ? connman_get_dhcp_mode(iface_data) : 0;

        connman_free_interface_data(iface_data);
    }

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

static size_t trim_trailing_zero_padding(const uint8_t *data, size_t length)
{
    while(length > 0 && data[length - 1] == '\0')
        --length;

    return length;
}

static int copy_ipv4_address(char *dest, const uint32_t requested_change,
                             const uint8_t *data, size_t length)
{
    length = trim_trailing_zero_padding(data, length);

    if(length < 7 || length > SIZE_OF_IPV4_ADDRESS_STRING - 1)
        return -1;

    memcpy(dest, data, length);
    dest[length] = '\0';

    if(!is_valid_ip_address_string(dest))
        return -1;

    nwconfig_write_data.requested_changes |= requested_change;

    return 0;
}

int dcpregs_write_56_ipv4_address(const uint8_t *data, size_t length)
{
    if(data_length_is_in_unexpected_range(length,
                                          7, SIZE_OF_IPV4_ADDRESS_STRING))
        return -1;

    if(!may_change_config())
        return -1;

    return copy_ipv4_address(nwconfig_write_data.ipv4_address,
                             REQ_IP_ADDRESS_56, data, length);
}

int dcpregs_write_57_ipv4_netmask(const uint8_t *data, size_t length)
{
    if(data_length_is_in_unexpected_range(length,
                                          7, SIZE_OF_IPV4_ADDRESS_STRING))
        return -1;

    if(!may_change_config())
        return -1;

    return copy_ipv4_address(nwconfig_write_data.ipv4_netmask,
                             REQ_NETMASK_57, data, length);
}

int dcpregs_write_58_ipv4_gateway(const uint8_t *data, size_t length)
{
    if(data_length_is_in_unexpected_range(length,
                                          7, SIZE_OF_IPV4_ADDRESS_STRING))
       return -1;

    if(!may_change_config())
        return -1;

    return copy_ipv4_address(nwconfig_write_data.ipv4_gateway,
                             REQ_DEFAULT_GATEWAY_58, data, length);
}
