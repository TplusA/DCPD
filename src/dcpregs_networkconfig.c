/*
 * Copyright (C) 2015, 2016, 2017  T+A elektroakustik GmbH & Co. KG
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

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>

#include "dcpregs_networkconfig.h"
#include "dcpregs_common.h"
#include "registers_priv.h"
#include "connman.h"
#include "dbus_handlers_connman_manager_glue.h"
#include "shutdown_guard.h"
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
#define SIZE_OF_WLAN_SECURITY_MODE      12U

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

    char wlan_security_mode[SIZE_OF_WLAN_SECURITY_MODE];

    size_t wlan_ssid_length;
    uint8_t wlan_ssid[32 + 1];

    bool wlan_wpa_passphrase_is_ascii;
    uint8_t wlan_wpa_passphrase[64 + 1];
}
nwconfig_write_data;

/*!
 * Network status register data.
 */
static struct
{
    struct ShutdownGuard *shutdown_guard;

    /*!
     * The status last communicated to the slave device.
     *
     * Status changes are only sent to the slave if the information represented
     * by the status register actually changed.
     */
    uint8_t previous_response[2];
}
nwstatus_data;

void dcpregs_networkconfig_init(void)
{
    nwconfig_write_data.selected_interface = NULL;

    nwstatus_data.shutdown_guard = shutdown_guard_alloc("networkconfig");
    nwstatus_data.previous_response[0] = UINT8_MAX;
    nwstatus_data.previous_response[1] = UINT8_MAX;
}

void dcpregs_networkconfig_deinit(void)
{
    shutdown_guard_free(&nwstatus_data.shutdown_guard);
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

static struct ConnmanInterfaceData *
find_active_primary_interface(const struct register_configuration_t *config,
                              struct ConnmanInterfaceData **fallback)
{
    const enum NetworkPrefsTechnology default_tech =
        get_network_iface_data(config)->is_wired
        ? NWPREFSTECH_ETHERNET
        : NWPREFSTECH_WLAN;

    return connman_find_active_primary_interface(
                network_prefs_get_mac_address_by_tech(default_tech)->address,
                network_prefs_get_mac_address_by_tech(NWPREFSTECH_ETHERNET)->address,
                network_prefs_get_mac_address_by_tech(NWPREFSTECH_WLAN)->address,
                fallback);
}

static struct ConnmanInterfaceData *get_connman_iface_data(void)
{
    const struct register_configuration_t *config = registers_get_data();

    if(in_edit_mode())
    {
        const enum NetworkPrefsTechnology tech =
            nwconfig_write_data.selected_interface->is_wired
            ? NWPREFSTECH_ETHERNET
            : NWPREFSTECH_WLAN;

        return connman_find_interface(network_prefs_get_mac_address_by_tech(tech)->address);
    }
    else
        return find_active_primary_interface(config, NULL);
}

/*!
 * Validate IPv4 address string.
 */
static bool is_valid_ip_address_string(const char *string, bool is_empty_ok)
{
    if(string[0] == '\0')
        return is_empty_ok;

    uint8_t dummy[sizeof(struct in_addr)];
    int result = inet_pton(AF_INET, string, dummy);

    if(result > 0)
        return true;

    if(result == 0)
        errno = 0;

    msg_error(errno, LOG_WARNING, "Failed parsing IPv4 address %s", string);

    return false;
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
        connman_get_primary_dns_string(iface_data, previous_primary,
                                       sizeof(previous_primary));
        connman_get_secondary_dns_string(iface_data, previous_secondary,
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
    bool ret = (iface_data != NULL)
        ? (connman_get_dhcp_mode(iface_data, CONNMAN_IP_VERSION_4,
                                 CONNMAN_READ_CONFIG_SOURCE_CURRENT) == CONNMAN_DHCP_ON)
        : false;
    connman_free_interface_data(iface_data);

    return ret;
}

static int handle_set_dhcp_mode(struct network_prefs *prefs)
{
    if(!IS_REQUESTED(REQ_DHCP_MODE_55))
        return 0;

    network_prefs_put_dhcp_mode(prefs, nwconfig_write_data.dhcpv4_mode, true);

    if(nwconfig_write_data.dhcpv4_mode)
        nwconfig_write_data.requested_changes &=
            ~(REQ_IP_ADDRESS_56 | REQ_NETMASK_57 | REQ_DEFAULT_GATEWAY_58 |
              REQ_DNS_SERVER1_62 | REQ_DNS_SERVER2_63);
    else if(!IS_REQUESTED(REQ_IP_ADDRESS_56 | REQ_NETMASK_57 | REQ_DEFAULT_GATEWAY_58))
    {
        msg_error(0, LOG_WARNING,
                  "Disabling IPv4 on interface %s because DHCPv4 was "
                  "disabled and static IPv4 configuration was not sent",
                  network_prefs_get_mac_address_by_prefs(prefs)->address);

        network_prefs_disable_ipv4(prefs);

        nwconfig_write_data.requested_changes &=
            ~(REQ_DNS_SERVER1_62 | REQ_DNS_SERVER2_63);
    }

    return 0;
}

static int handle_set_static_ipv4_config(struct network_prefs *prefs)
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
        network_prefs_put_ipv4_config(prefs, nwconfig_write_data.ipv4_address,
                                      nwconfig_write_data.ipv4_netmask,
                                      nwconfig_write_data.ipv4_gateway);
    else
    {
        msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                  "Disabling IPv4 on interface %s",
                  network_prefs_get_mac_address_by_prefs(prefs)->address);

        network_prefs_put_ipv4_config(prefs, "", "", "");
    }

    return 0;
}

static int handle_set_dns_servers(struct network_prefs *prefs)
{
    if(!IS_REQUESTED(REQ_DNS_SERVER1_62 | REQ_DNS_SERVER2_63))
        return 0;

    fill_in_missing_dns_server_config_requests();

    if(nwconfig_write_data.ipv4_dns_server1[0] != '\0')
        network_prefs_put_nameservers(prefs,
                                      nwconfig_write_data.ipv4_dns_server1,
                                      nwconfig_write_data.ipv4_dns_server2);

    else
    {
        msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                  "No nameservers on interface %s",
                  network_prefs_get_mac_address_by_prefs(prefs)->address);

        network_prefs_put_nameservers(prefs, "", "");
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

static bool is_known_security_mode_name(const char *name)
{
    static const char *const names[] =
    {
        "none",
        "psk",
        "ieee8021x",
        "wps",
        "wep",
    };

    for(size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
    {
        if(strcmp(name, names[i]) == 0)
            return true;
    }

    return false;
}

static int handle_set_wireless_config(struct network_prefs *prefs)
{
    if(!IS_REQUESTED(req_wireless_only_parameters))
        return 0;

    if(network_prefs_get_technology_by_prefs(prefs) != NWPREFSTECH_WLAN)
    {
        msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                  "Ignoring wireless parameters for active wired interface");
        return 0;
    }

    const char *network_name;
    const char *network_ssid;
    const char *passphrase;

    if(IS_REQUESTED(REQ_WLAN_SECURITY_MODE_92))
    {
        if(!is_known_security_mode_name(nwconfig_write_data.wlan_security_mode))
        {
            msg_error(EINVAL, LOG_ERR, "Invalid WLAN security mode \"%s\"",
                      nwconfig_write_data.wlan_security_mode);
            nwconfig_write_data.wlan_security_mode[0] = '\0';
        }

        if(strcmp(nwconfig_write_data.wlan_security_mode, "wep") == 0)
        {
            BUG("Support for insecure WLAN mode \"WEP\" not implemented yet");
            nwconfig_write_data.wlan_security_mode[0] = '\0';
        }
    }
    else
    {
        /* we need to know the security mode for some checks below, so we need
         * to retrieve it from ConnMan */
        struct ConnmanInterfaceData *iface_data = get_connman_iface_data();

        if(iface_data == NULL)
            nwconfig_write_data.wlan_security_mode[0] = '\0';
        else
        {
            connman_get_wlan_security_type_string(iface_data,
                                                  nwconfig_write_data.wlan_security_mode,
                                                  sizeof(nwconfig_write_data.wlan_security_mode));
            connman_free_interface_data(iface_data);
        }
    }

    if(nwconfig_write_data.wlan_security_mode[0] == '\0')
    {
        msg_error(EINVAL, LOG_ERR,
                  "Cannot set WLAN parameters, security mode missing");
        return -1;
    }

    static const char empty_string[] = "";

    char ssid_buffer[2 * (sizeof(nwconfig_write_data.wlan_ssid) - 1) + 1];

    if(IS_REQUESTED(REQ_WLAN_SSID_94))
    {
        network_name = empty_string;
        network_ssid = empty_string;

       if(nwconfig_write_data.wlan_ssid_length > 0)
       {
           if(is_wlan_ssid_simple_ascii(nwconfig_write_data.wlan_ssid,
                                        nwconfig_write_data.wlan_ssid_length))
               network_name = (const char *)nwconfig_write_data.wlan_ssid;
           else
           {
               binary_to_hexdump(ssid_buffer, nwconfig_write_data.wlan_ssid,
                                 nwconfig_write_data.wlan_ssid_length);
               network_ssid = ssid_buffer;
           }
       }
    }
    else
    {
        network_name = NULL;
        network_ssid = NULL;
    }

    if(IS_REQUESTED(REQ_WLAN_WPA_PASSPHRASE_102))
    {
        const size_t passphrase_length =
            (strcmp(nwconfig_write_data.wlan_security_mode, "none") == 0)
            ? 0
            : (nwconfig_write_data.wlan_wpa_passphrase_is_ascii
               ? strlen((const char *)nwconfig_write_data.wlan_wpa_passphrase)
               : (sizeof(nwconfig_write_data.wlan_wpa_passphrase) - 1));

        if(passphrase_length > 0)
            passphrase = (const char *)nwconfig_write_data.wlan_wpa_passphrase;
        else
            passphrase = "";
    }
    else
        passphrase = NULL;

    network_prefs_put_wlan_config(prefs, network_name, network_ssid,
                                  nwconfig_write_data.wlan_security_mode,
                                  passphrase);

    return 0;
}

static int apply_changes_to_prefs(struct network_prefs *prefs)
{
    log_assert(prefs != NULL);

    if(handle_set_dhcp_mode(prefs) < 0)
        return -1;

    if(handle_set_static_ipv4_config(prefs) < 0)
        return -1;

    if(handle_set_dns_servers(prefs) < 0)
        return -1;

    if(handle_set_wireless_config(prefs) < 0)
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

/*!
 * Write changes to file.
 *
 * \attention
 *     Must be called with the #ShutdownGuard from #nwstatus_data locked.
 */
static int modify_network_configuration(const struct register_network_interface_t *selected,
                                        char *previous_wlan_name_buffer,
                                        size_t previous_wlan_name_buffer_size)
{
    if(shutdown_guard_is_shutting_down_unlocked(nwstatus_data.shutdown_guard))
    {
        msg_info("Not writing network configuration during shutdown.");
        return -1;
    }

    struct network_prefs *ethernet_prefs;
    struct network_prefs *wlan_prefs;
    struct network_prefs_handle *cfg =
        network_prefs_open_rw(&ethernet_prefs, &wlan_prefs);

    if(cfg == NULL)
        return -1;

    struct network_prefs *selected_prefs =
        selected->is_wired ? ethernet_prefs : wlan_prefs;

    network_prefs_generate_service_name(selected->is_wired ? NULL : selected_prefs,
                                        previous_wlan_name_buffer,
                                        previous_wlan_name_buffer_size);

    if(selected_prefs == NULL)
        selected_prefs = network_prefs_add_prefs(cfg, selected->is_wired ? NWPREFSTECH_ETHERNET : NWPREFSTECH_WLAN);

    int ret = apply_changes_to_prefs(selected_prefs);

    if(ret == 0)
        ret = network_prefs_write_to_file(cfg);

    network_prefs_close(cfg);

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
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 53 handler %p %zu", data, length);

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

    const enum NetworkPrefsTechnology tech = selected->is_wired
        ? NWPREFSTECH_ETHERNET
        : NWPREFSTECH_WLAN;

    msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
              "Writing new network configuration for MAC address %s",
              network_prefs_get_mac_address_by_tech(tech)->address);

    shutdown_guard_lock(nwstatus_data.shutdown_guard);
    char current_wlan_service_name[NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE];
    int ret = modify_network_configuration(selected, current_wlan_service_name,
                                           sizeof(current_wlan_service_name));
    shutdown_guard_unlock(nwstatus_data.shutdown_guard);

    if(ret == 0)
        dbussignal_connman_manager_connect_to_service(tech,
                                                      current_wlan_service_name);

    return ret;
}

int dcpregs_write_54_selected_ip_profile(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 54 handler %p %zu", data, length);

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

static void fill_network_status_register_response(uint8_t response[static 2])
{
    struct register_configuration_t *config = registers_get_nonconst_data();

    config->active_interface = NULL;

    response[0] = 0x00;
    response[1] = 0x00;

    struct ConnmanInterfaceData *fallback_iface_data;
    struct ConnmanInterfaceData *iface_data =
        find_active_primary_interface(config, &fallback_iface_data);

    if(iface_data != NULL)
    {
        log_assert(fallback_iface_data == NULL);

        char result[2];

        connman_get_address_string(iface_data, CONNMAN_IP_VERSION_4,
                                   CONNMAN_READ_CONFIG_SOURCE_CURRENT,
                                   result, sizeof(result));

        if(result[0] != '\0')
            response[0] = (connman_get_dhcp_mode(iface_data, CONNMAN_IP_VERSION_4,
                                                 CONNMAN_READ_CONFIG_SOURCE_CURRENT) ==
                           CONNMAN_DHCP_ON) ? 0x02 : 0x01;
    }
    else if(fallback_iface_data != NULL)
    {
        iface_data = fallback_iface_data;
        fallback_iface_data = NULL;
    }

    if(iface_data != NULL)
    {
        const enum ConnmanConnectionType ctype = connman_get_connection_type(iface_data);

        switch(ctype)
        {
          case CONNMAN_CONNECTION_TYPE_UNKNOWN:
          case CONNMAN_CONNECTION_TYPE_ETHERNET:
            response[1] = 0x01;
            config->active_interface = &config->builtin_ethernet_interface;
            break;

          case CONNMAN_CONNECTION_TYPE_WLAN:
            response[1] = 0x02;
            config->active_interface = &config->builtin_wlan_interface;
            break;
        }
    }

    connman_free_interface_data(iface_data);
}

ssize_t dcpregs_read_50_network_status(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 50 handler %p %zu", response, length);

    if(data_length_is_unexpected(length, 2))
        return -1;

    fill_network_status_register_response(response);
    memcpy(nwstatus_data.previous_response, response, sizeof(nwstatus_data.previous_response));

    return length;
}

ssize_t dcpregs_read_51_mac_address(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 51 handler %p %zu", response, length);

    const struct register_network_interface_t *const iface =
        get_network_iface_data(registers_get_data());
    const struct network_prefs_mac_address *mac;

    if(data_length_is_unexpected(length, sizeof(mac->address)))
        return -1;

    if(length < sizeof(mac->address))
        return -1;

    const enum NetworkPrefsTechnology tech =
        iface->is_wired ? NWPREFSTECH_ETHERNET : NWPREFSTECH_WLAN;
    mac = network_prefs_get_mac_address_by_tech(tech);

    memcpy(response, mac->address, sizeof(mac->address));

    return sizeof(mac->address);
}

ssize_t dcpregs_read_55_dhcp_enabled(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 55 handler %p %zu", response, length);

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
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 55 handler %p %zu", data, length);

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
read_ip_parameter(uint32_t requested_mask,
                  const char edited_ipv4_parameter[static SIZE_OF_IPV4_ADDRESS_STRING],
                  bool (*connman_query_fn)(struct ConnmanInterfaceData *,
                                           char *, size_t),
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

static ssize_t
read_ipv4_parameter(uint32_t requested_mask,
                    const char edited_ipv4_parameter[static SIZE_OF_IPV4_ADDRESS_STRING],
                    bool (*connman_query_fn)(struct ConnmanInterfaceData *,
                                             enum ConnmanIPVersion,
                                             enum ConnmanReadConfigSource,
                                             char *, size_t),
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
            connman_query_fn(iface_data, CONNMAN_IP_VERSION_4,
                             CONNMAN_READ_CONFIG_SOURCE_CURRENT,
                             (char *)response, length);
        else
            response[0] = '\0';

        connman_free_interface_data(iface_data);
    }

    return strlen((char *)response) + 1;
}

ssize_t dcpregs_read_56_ipv4_address(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 56 handler %p %zu", response, length);

    return read_ipv4_parameter(REQ_IP_ADDRESS_56,
                               nwconfig_write_data.ipv4_address,
                               connman_get_address_string,
                               response, length);
}

ssize_t dcpregs_read_57_ipv4_netmask(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 57 handler %p %zu", response, length);

    return read_ipv4_parameter(REQ_NETMASK_57,
                               nwconfig_write_data.ipv4_netmask,
                               connman_get_netmask_string,
                               response, length);
}

ssize_t dcpregs_read_58_ipv4_gateway(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 58 handler %p %zu", response, length);

    return read_ipv4_parameter(REQ_DEFAULT_GATEWAY_58,
                               nwconfig_write_data.ipv4_gateway,
                               connman_get_gateway_string,
                               response, length);
}

ssize_t dcpregs_read_62_primary_dns(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 62 handler %p %zu", response, length);

    return read_ip_parameter(REQ_DNS_SERVER1_62,
                             nwconfig_write_data.ipv4_dns_server1,
                             connman_get_primary_dns_string,
                             response, length);
}

ssize_t dcpregs_read_63_secondary_dns(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 63 handler %p %zu", response, length);

    return read_ip_parameter(REQ_DNS_SERVER2_63,
                             nwconfig_write_data.ipv4_dns_server2,
                             connman_get_secondary_dns_string,
                             response, length);
}

static int copy_ipv4_address(char *const dest, const uint32_t requested_change,
                             const uint8_t *const data, size_t length,
                             bool is_empty_ok)
{
    length = dcpregs_trim_trailing_zero_padding(data, length);

    if(length == 0)
    {
        if(!is_empty_ok)
            return -1;
    }
    else if(length < MINIMUM_IPV4_ADDRESS_STRING_LENGTH ||
            length > SIZE_OF_IPV4_ADDRESS_STRING - 1)
        return -1;

    size_t i = 0;
    size_t j = 0;

    while(i < length)
    {
        while(i < length && data[i] == '0')
            ++i;

        if(i >= length || data[i] == '.')
            dest[j++] = '0';

        while(i < length && (dest[j++] = data[i++]) != '.')
            ;
    }

    dest[j] = '\0';

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
            failed = !connman_get_wlan_security_type_string(iface_data,
                                                            (char *)response,
                                                            length);
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
    nwconfig_write_data.wlan_ssid[length] = '\0';
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
    if(data_length_is_unexpectedly_small(length, sizeof(nwconfig_write_data.wlan_wpa_passphrase) - 1))
        return -1;

    if(!in_edit_mode())
    {
        msg_error(0, LOG_NOTICE,
                  "Passphrase cannot be read out while in non-edit mode");
        return -1;
    }

    ssize_t copied_bytes;

    if(IS_REQUESTED(REQ_WLAN_WPA_PASSPHRASE_102))
    {
        copied_bytes = (nwconfig_write_data.wlan_wpa_passphrase_is_ascii
                        ? ((nwconfig_write_data.wlan_wpa_passphrase[0] == '\0')
                           ? 0
                           : strlen((const char *)nwconfig_write_data.wlan_wpa_passphrase) - 1)
                        : (sizeof(nwconfig_write_data.wlan_wpa_passphrase) - 1));

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
    if(data_length_is_in_unexpected_range(length,
                                          0,
                                          sizeof(nwconfig_write_data.wlan_wpa_passphrase) - 1))
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

        nwconfig_write_data.wlan_wpa_passphrase[length] = '\0';

        static const char invalid_passphrase_fmt[] = "Invalid passphrase: %s";

        if(length == sizeof(nwconfig_write_data.wlan_wpa_passphrase) - 1)
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

void dcpregs_networkconfig_interfaces_changed(void)
{
    uint8_t response[sizeof(nwstatus_data.previous_response)];

    connman_wlan_power_on();
    fill_network_status_register_response(response);

    if(memcmp(nwstatus_data.previous_response, response, sizeof(response)) != 0)
        registers_get_data()->register_changed_notification_fn(50);
}

void dcpregs_networkconfig_prepare_for_shutdown(void)
{
    (void)shutdown_guard_down(nwstatus_data.shutdown_guard);
}
