/*
 * Copyright (C) 2015, 2016, 2017, 2018  T+A elektroakustik GmbH & Co. KG
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

#include <array>
#include <cstring>
#include <functional>
#include <algorithm>
#include <arpa/inet.h>

#include "dcpregs_networkconfig.h"
#include "dcpregs_networkconfig.hh"
#include "dcpregs_common.h"
#include "network_status_bits.h"
#include "registers_priv.h"
#include "connman_service_list.hh"
#include "network_device_list.hh"
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

enum class WPSMode
{
    INVALID,
    NONE,
    DIRECT,
    SCAN,
    ABORT,
};

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
struct WriteData
{
    /*!
     * Networking technology at the time the change request was commenced.
     */
    Connman::Technology selected_technology;

    /*!
     * Which configuration settings to change.
     *
     * \see \c REQ_* definitions (for instance, #REQ_DHCP_MODE_55)
     */
    uint32_t requested_changes;

    bool dhcpv4_mode;
    std::array<char, SIZE_OF_IPV4_ADDRESS_STRING> ipv4_address;
    std::array<char, SIZE_OF_IPV4_ADDRESS_STRING> ipv4_netmask;
    std::array<char, SIZE_OF_IPV4_ADDRESS_STRING> ipv4_gateway;
    std::array<char, SIZE_OF_IPV4_ADDRESS_STRING> ipv4_dns_server1;
    std::array<char, SIZE_OF_IPV4_ADDRESS_STRING> ipv4_dns_server2;

    std::array<char, SIZE_OF_WLAN_SECURITY_MODE> wlan_security_mode;

    size_t wlan_ssid_length;
    std::array<uint8_t, 32 + 1> wlan_ssid;

    bool wlan_wpa_passphrase_is_ascii;
    std::array<uint8_t, 64 + 1> wlan_wpa_passphrase;

    WriteData(const WriteData &) = delete;
    WriteData &operator=(const WriteData &) = delete;

    explicit WriteData():
        selected_technology(Connman::Technology::UNKNOWN_TECHNOLOGY),
        requested_changes(0),
        dhcpv4_mode(false),
        ipv4_address{0},
        ipv4_netmask{0},
        ipv4_gateway{0},
        ipv4_dns_server1{0},
        ipv4_dns_server2{0},
        wlan_security_mode{0},
        wlan_ssid_length(0),
        wlan_ssid{0},
        wlan_wpa_passphrase_is_ascii(false),
        wlan_wpa_passphrase{0}
    {}

    void reset(Connman::Technology tech)
    {
        selected_technology = tech;
        requested_changes = 0;
        dhcpv4_mode = false;
        ipv4_address[0] = '\0';
        ipv4_netmask[0] = '\0';
        ipv4_gateway[0] = '\0';
        ipv4_dns_server1[0] = '\0';
        ipv4_dns_server2[0] = '\0';
        wlan_security_mode[0] = '\0';
        wlan_ssid_length = 0;
        wlan_ssid.fill(0);
        wlan_wpa_passphrase_is_ascii = false;
        wlan_wpa_passphrase.fill(0);
    }
};

WriteData nwconfig_write_data;

/*!
 * Network status register data and other stuff.
 */
static struct
{
    struct ShutdownGuard *shutdown_guard;

    /*!
     * Appliance-specific networking technology to use as fallback.
     */
    Connman::Technology fallback_technology;

    /*!
     * The status last communicated to the slave device.
     *
     * Status changes are only sent to the slave if the information represented
     * by the status register actually changed.
     */
    std::array<uint8_t, 3> previous_response;
}
nwstatus_data;

void dcpregs_networkconfig_init(void)
{
    nwconfig_write_data.selected_technology = Connman::Technology::UNKNOWN_TECHNOLOGY;

    nwstatus_data.shutdown_guard = shutdown_guard_alloc("networkconfig");
    nwstatus_data.fallback_technology = Connman::Technology::UNKNOWN_TECHNOLOGY;
    nwstatus_data.previous_response[0] = UINT8_MAX;
    nwstatus_data.previous_response[1] = UINT8_MAX;
    nwstatus_data.previous_response[2] = UINT8_MAX;
}

void dcpregs_networkconfig_deinit(void)
{
    shutdown_guard_free(&nwstatus_data.shutdown_guard);
}

static NetworkPrefsTechnology map_network_technology(const Connman::Technology tech)
{
    switch(tech)
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
        break;

      case Connman::Technology::ETHERNET:
        return NWPREFSTECH_ETHERNET;

      case Connman::Technology::WLAN:
        return NWPREFSTECH_WLAN;
    }

    return NWPREFSTECH_UNKNOWN;
}

static Connman::Technology map_network_technology(const NetworkPrefsTechnology tech)
{
    switch(tech)
    {
      case NWPREFSTECH_UNKNOWN:
        break;

      case NWPREFSTECH_ETHERNET:
        return Connman::Technology::ETHERNET;

      case NWPREFSTECH_WLAN:
        return Connman::Technology::WLAN;
    }

    return Connman::Technology::UNKNOWN_TECHNOLOGY;
}

static bool in_edit_mode(void)
{
    return nwconfig_write_data.selected_technology != Connman::Technology::UNKNOWN_TECHNOLOGY;
}

static void update_service_selection(const Connman::ServiceBase *service,
                                     bool is_service_online,
                                     const Connman::Technology default_tech,
                                     const Connman::ServiceBase *&active_match,
                                     const Connman::ServiceBase *&active_mismatch,
                                     const Connman::ServiceBase *&inactive_match,
                                     const Connman::ServiceBase *&inactive_mismatch)
{
    log_assert(active_match == nullptr);

    if(is_service_online)
    {
        if(service->get_technology() == default_tech)
            active_match = service;
        else
            active_mismatch = service;
    }
    else
    {
        if(service->get_technology() == default_tech)
            inactive_match = service;
        else
            inactive_mismatch = service;
    }
}

static void update_fallback_service_selection(const Connman::ServiceBase *service,
                                              const Connman::Technology default_tech,
                                              const Connman::ServiceBase *&fallback_match,
                                              const Connman::ServiceBase *&fallback_mismatch)
{
    if(service->get_technology() == default_tech)
        fallback_match = service;
    else
        fallback_mismatch = service;
}

static const Connman::ServiceBase *
fixup_service_selection(const Connman::ServiceBase *active_match,
                        const Connman::ServiceBase *active_mismatch,
                        const Connman::ServiceBase *inactive_match,
                        const Connman::ServiceBase *inactive_mismatch,
                        const Connman::ServiceBase *fallback_match,
                        const Connman::ServiceBase *fallback_mismatch,
                        const Connman::ServiceBase **fallback)
{
    if(fallback != nullptr)
        *fallback = nullptr;

    if(active_match != nullptr)
        return active_match;

    if(active_mismatch != nullptr)
        return active_mismatch;

    if(fallback != nullptr)
    {
        if(inactive_match != nullptr)
            *fallback = inactive_match;
        else if(inactive_mismatch != nullptr)
            *fallback = inactive_mismatch;
        else if(fallback_match != nullptr)
            *fallback = fallback_match;
        else if(fallback_mismatch != nullptr)
            *fallback = fallback_mismatch;
    }

    return nullptr;
}

/*!
 * Find best ("most active") service on one of our interfaces, preferring the
 * given technology on tie.
 *
 * In case there is a single, active service on any matching NIC, that service
 * will be returned.
 *
 * In case both, the wired and the wireless, NICs are found and there are
 * active services on both of them, then the active service matching the
 * \p default_tech parameter is returned (making it a tiebreaker).
 *
 * In case any of the NICs is found, but none of them has an active service,
 * then (and only then) any non-idle service is returned in the \p fallback
 * parameter, where those matching the \p default_tech parameter are preferred.
 */
static const Connman::ServiceBase *find_current_service(const Connman::ServiceList &services,
                                                        const Connman::Technology default_tech,
                                                        const Connman::ServiceBase **fallback)
{
    log_assert(default_tech != Connman::Technology::UNKNOWN_TECHNOLOGY);

    const Connman::ServiceBase *active_service_match = nullptr;
    const Connman::ServiceBase *active_service_mismatch = nullptr;
    const Connman::ServiceBase *inactive_service_match = nullptr;
    const Connman::ServiceBase *inactive_service_mismatch = nullptr;
    const Connman::ServiceBase *fallback_service_match = nullptr;
    const Connman::ServiceBase *fallback_service_mismatch = nullptr;

    for(const auto &s : services)
    {
        if(!s.second->get_service_data().state_.is_known())
           continue;

        const auto &service(s.second);

        if(!service->is_ours())
            continue;

        bool is_online = false;

        switch(service->get_service_data().state_.get())
        {
          case Connman::ServiceState::NOT_AVAILABLE:
          case Connman::ServiceState::UNKNOWN_STATE:
            continue;

          case Connman::ServiceState::IDLE:
          case Connman::ServiceState::FAILURE:
          case Connman::ServiceState::DISCONNECT:
            update_fallback_service_selection(service.get(), default_tech,
                                              fallback_service_match,
                                              fallback_service_mismatch);
            continue;

          case Connman::ServiceState::ASSOCIATION:
          case Connman::ServiceState::CONFIGURATION:
            break;

          case Connman::ServiceState::READY:
          case Connman::ServiceState::ONLINE:
            is_online = true;
            break;
        }

        update_service_selection(service.get(), is_online, default_tech,
                                 active_service_match, active_service_mismatch,
                                 inactive_service_match, inactive_service_mismatch);

        if(active_service_match != nullptr)
            break;
    }

    return fixup_service_selection(active_service_match, active_service_mismatch,
                                   inactive_service_match, inactive_service_mismatch,
                                   fallback_service_match, fallback_service_mismatch,
                                   fallback);
}

static int rank_service_by_state(const Connman::ServiceBase &service)
{
    switch(service.get_service_data().state_.get())
    {
      case Connman::ServiceState::NOT_AVAILABLE:
      case Connman::ServiceState::UNKNOWN_STATE:
        break;

      case Connman::ServiceState::IDLE:
      case Connman::ServiceState::FAILURE:
      case Connman::ServiceState::DISCONNECT:
        return 0;

      case Connman::ServiceState::ASSOCIATION:
      case Connman::ServiceState::CONFIGURATION:
        return 1;

      case Connman::ServiceState::READY:
        return 2;

      case Connman::ServiceState::ONLINE:
        return 3;
    }

    return -1;
}

static const Connman::ServiceBase *
find_best_service_by_technology(const Connman::ServiceList &services,
                                const Connman::Technology tech)
{
    log_assert(tech != Connman::Technology::UNKNOWN_TECHNOLOGY);

    const Connman::ServiceBase *found = nullptr;
    int rank = -1;

    for(const auto &s : services)
    {
        if(!s.second->get_service_data().state_.is_known())
           continue;

        const auto &service(s.second);

        if(!service->is_ours())
            continue;

        if(service->get_technology() != tech)
            continue;

        const int temp = rank_service_by_state(*service);

        if(rank >= temp)
            continue;

        rank = temp;
        found = service.get();

        if(rank >= 3)
            break;
    }

    return found;
}

static Connman::Technology
determine_active_network_technology(const Connman::ServiceList &services,
                                    bool must_be_valid,
                                    const Connman::ServiceBase **service = nullptr)
{
    if(service != nullptr)
        *service = nullptr;

    Connman::Technology candidate = Connman::Technology::UNKNOWN_TECHNOLOGY;
    int candidate_rank = -2;

    for(const auto &it : services)
    {
        const auto &s(*it.second);

        if(s.get_service_data().device_ == nullptr)
        {
            BUG("Service \"%s\" has no device", it.first.c_str());
            continue;
        }

        if(!s.is_ours())
            continue;

        if(s.is_active())
        {
            if(service != nullptr)
                *service = &s;

            return s.get_technology();
        }

        const int temp = rank_service_by_state(s);

        if(candidate_rank >= temp)
            continue;

        candidate_rank = temp;
        candidate = s.get_technology();

        if(service != nullptr)
            *service = &s;
    }

    return (candidate != Connman::Technology::UNKNOWN_TECHNOLOGY
            ? candidate
            : (must_be_valid
               ? Connman::Technology::ETHERNET
               : Connman::Technology::UNKNOWN_TECHNOLOGY));
}

static const Connman::ServiceBase *get_connman_service_data(const Connman::ServiceList &services)
{
    if(in_edit_mode())
        return find_best_service_by_technology(services,
                                               nwconfig_write_data.selected_technology);
    else
        return find_current_service(services,
                                    determine_active_network_technology(services, true),
                                    nullptr);
}

/*!
 * Validate IPv4 address string.
 */
static bool is_valid_ip_address_string(const std::array<char, SIZE_OF_IPV4_ADDRESS_STRING> &string,
                                       bool is_empty_ok)
{
    if(string[0] == '\0')
        return is_empty_ok;

    uint8_t dummy[sizeof(struct in_addr)];
    int result = inet_pton(AF_INET, string.data(), dummy);

    if(result > 0)
        return true;

    if(result == 0)
        errno = 0;

    msg_error(errno, LOG_WARNING, "Failed parsing IPv4 address %s", string.data());

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
 * Short helper template for improving code readability.
 */
template <size_t N>
static size_t copy_to_array(const std::string &src, std::array<char, N> &dest)
{
    const size_t n(std::min(src.length(), N - 1));

    std::copy_n(src.begin(), n, dest.begin());
    dest[n] = '\0';

    return n + 1;
}

/*!
 * Short helper template for improving code readability.
 */
static size_t copy_to_array(const std::string &src, char *dest, size_t dest_size)
{
    const size_t n(std::min(src.length(), dest_size - 1));

    std::copy_n(src.begin(), n, dest);
    dest[n] = '\0';

    return n + 1;
}

/*!
 * Move secondary DNS to primary slot.
 */
static void shift_dns_servers(void)
{
    nwconfig_write_data.ipv4_dns_server1 = nwconfig_write_data.ipv4_dns_server2;
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
 * Because of the poor DCP design, this function is much more complicated than
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
static void fill_in_missing_dns_server_config_requests(const Connman::ServiceBase &service)
{
    log_assert(IS_REQUESTED(REQ_DNS_SERVER1_62 | REQ_DNS_SERVER2_63));

    if(ALL_REQUESTED(REQ_DNS_SERVER1_62 | REQ_DNS_SERVER2_63))
    {
        shift_dns_servers_if_necessary();
        return;
    }

    /* at this point we know that only one DNS server was sent to us, either a
     * "primary" one or a "secondary" */

    const bool have_dns_servers =
        (service.get_service_data().dns_servers_.is_known() &&
         !service.get_service_data().dns_servers_.get().empty());

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
        const auto &dns_servers(service.get_service_data().dns_servers_.get());

        if(IS_REQUESTED(REQ_DNS_SERVER1_62))
        {
            /* have new primary server, now copy over the previously defined,
             * secondary one (if any) */
            if(dns_servers.size() > 1)
                copy_to_array(dns_servers[1], nwconfig_write_data.ipv4_dns_server2);
            else
                nwconfig_write_data.ipv4_dns_server2[0] = '\0';

            shift_dns_servers_if_necessary();
        }
        else
        {
            /* have new secondary server, now copy over the previously defined,
             * primary one */
            copy_to_array(dns_servers[0], nwconfig_write_data.ipv4_dns_server1);
        }
    }
}

static uint8_t map_dhcp_method(const Connman::DHCPV4Method method)
{
    switch(method)
    {
      case Connman::DHCPV4Method::NOT_AVAILABLE:
      case Connman::DHCPV4Method::UNKNOWN_METHOD:
        break;

      case Connman::DHCPV4Method::OFF:
      case Connman::DHCPV4Method::MANUAL:
      case Connman::DHCPV4Method::FIXED:
        return NETWORK_STATUS_IPV4_STATIC_ADDRESS;

      case Connman::DHCPV4Method::ON:
        return NETWORK_STATUS_IPV4_DHCP;
    }

    return NETWORK_STATUS_IPV4_NOT_CONFIGURED;
}

static bool query_dhcp_mode(void)
{
    const auto locked_services(Connman::ServiceList::get_singleton_const());
    const auto &services(locked_services.first);
    const Connman::ServiceBase *service(get_connman_service_data(services));

    if(service == nullptr)
        return false;

    if(!service->get_service_data().ip_settings_v4_.is_known())
        return false;

    return map_dhcp_method(service->get_service_data().ip_settings_v4_.get().get_dhcp_method()) == NETWORK_STATUS_IPV4_DHCP;
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
        const auto locked_devices(Connman::NetworkDeviceList::get_singleton_const());
        const auto &devices(locked_devices.first);

        msg_error(0, LOG_WARNING,
                  "Disabling IPv4 on interface %s because DHCPv4 was "
                  "disabled and static IPv4 configuration was not sent",
                  devices.get_auto_select_mac_address(map_network_technology(network_prefs_get_technology_by_prefs(prefs))).get_string().c_str());

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
        network_prefs_put_ipv4_config(prefs, nwconfig_write_data.ipv4_address.data(),
                                      nwconfig_write_data.ipv4_netmask.data(),
                                      nwconfig_write_data.ipv4_gateway.data());
    else
    {
        const auto locked_devices(Connman::NetworkDeviceList::get_singleton_const());
        const auto &devices(locked_devices.first);

        msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                  "Disabling IPv4 on interface %s",
                  devices.get_auto_select_mac_address(map_network_technology(network_prefs_get_technology_by_prefs(prefs))).get_string().c_str());

        network_prefs_put_ipv4_config(prefs, "", "", "");
    }

    return 0;
}

static int handle_set_dns_servers(const Connman::ServiceBase &service,
                                  struct network_prefs *prefs)
{
    if(!IS_REQUESTED(REQ_DNS_SERVER1_62 | REQ_DNS_SERVER2_63))
        return 0;

    fill_in_missing_dns_server_config_requests(service);

    if(nwconfig_write_data.ipv4_dns_server1[0] != '\0')
        network_prefs_put_nameservers(prefs,
                                      nwconfig_write_data.ipv4_dns_server1.data(),
                                      nwconfig_write_data.ipv4_dns_server2.data());

    else
    {
        const auto locked_devices(Connman::NetworkDeviceList::get_singleton_const());
        const auto &devices(locked_devices.first);

        msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                  "No nameservers on interface %s",
                  devices.get_auto_select_mac_address(map_network_technology(network_prefs_get_technology_by_prefs(prefs))).get_string().c_str());

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

static uint8_t char_to_nibble(char ch)
{
    if(ch >= '0' && ch <= '9')
        return ch - '0';

    if(ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;

    if(ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;

    return UINT8_MAX;
}

static size_t binary_to_hexdump(char *dest, size_t dest_size,
                                const uint8_t *src, size_t src_size)
{
    size_t j = 0;

    for(size_t i = 0; i < src_size && j < dest_size; ++i)
    {
        const uint8_t byte = src[i];

        if(j >= dest_size)
            break;

        dest[j++] = nibble_to_char(byte >> 4);

        if(j >= dest_size)
            break;

        dest[j++] = nibble_to_char(byte & 0x0f);
    }

    if(j < dest_size)
        dest[j++] = '\0';
    else
        dest[dest_size - 1] = '\0';

    return j;
}

static size_t hexdump_to_binary(char *dest, size_t dest_size,
                                const std::string &src)
{
    size_t j = 0;

    for(size_t i = 0; i < src.size() && j < dest_size; i += 2)
    {
        if(j >= dest_size)
            break;

        dest[j] = char_to_nibble(src[i]) << 4;

        if(i + 1 >= src.size())
            break;

        dest[j++] |= char_to_nibble(src[i + 1]);
    }

    return j;
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

static bool is_known_security_mode_name(const std::array<char, SIZE_OF_WLAN_SECURITY_MODE> &name)
{
    static const std::array<const char *const, 6> names =
    {
        "none",
        "psk",
        "ieee8021x",
        "wps",
        "wps-abort",
        "wep",
    };

    for(size_t i = 0; i < names.size(); ++i)
    {
        if(strcmp(name.data(), names[i]) == 0)
            return true;
    }

    return false;
}

static WPSMode handle_set_wireless_config(const Connman::ServiceBase &service,
                                          struct network_prefs *prefs,
                                          char **out_wps_network_name,
                                          char **out_wps_network_ssid)
{
    if(!IS_REQUESTED(req_wireless_only_parameters))
        return WPSMode::NONE;

    switch(service.get_technology())
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
        BUG("Tried setting WLAN parameters for unknown technology");
        return WPSMode::NONE;

      case Connman::Technology::ETHERNET:
        msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                  "Ignoring wireless parameters for active wired interface");
        return WPSMode::NONE;

      case Connman::Technology::WLAN:
        break;
    }

    const char *network_name;
    const char *network_ssid;
    const char *passphrase;

    if(IS_REQUESTED(REQ_WLAN_SECURITY_MODE_92))
    {
        if(!is_known_security_mode_name(nwconfig_write_data.wlan_security_mode))
        {
            msg_error(EINVAL, LOG_ERR, "Invalid WLAN security mode \"%s\"",
                      nwconfig_write_data.wlan_security_mode.data());
            nwconfig_write_data.wlan_security_mode[0] = '\0';
        }

        if(strcmp(nwconfig_write_data.wlan_security_mode.data(), "wep") == 0)
        {
            BUG("Support for insecure WLAN mode \"WEP\" not implemented yet");
            nwconfig_write_data.wlan_security_mode[0] = '\0';
        }
    }
    else
    {
        const auto &tech_data(static_cast<const Connman::Service<Connman::Technology::WLAN> &>(service).get_tech_data());

        if(tech_data.security_.is_known())
            copy_to_array(tech_data.security_.get(), nwconfig_write_data.wlan_security_mode);
        else
            nwconfig_write_data.wlan_security_mode[0] = '\0';
    }

    if(nwconfig_write_data.wlan_security_mode[0] == '\0')
    {
        msg_error(EINVAL, LOG_ERR,
                  "Cannot set WLAN parameters, security mode missing");
        return WPSMode::INVALID;
    }

    static const char empty_string[] = "";

    char ssid_buffer[2 * (nwconfig_write_data.wlan_ssid.size() - 1) + 1];

    if(IS_REQUESTED(REQ_WLAN_SSID_94))
    {
        network_name = empty_string;
        network_ssid = empty_string;

        if(nwconfig_write_data.wlan_ssid_length > 0)
        {
            if(is_wlan_ssid_simple_ascii(nwconfig_write_data.wlan_ssid.data(),
                                         nwconfig_write_data.wlan_ssid_length))
                network_name = reinterpret_cast<const char *>(nwconfig_write_data.wlan_ssid.data());
            else
            {
                binary_to_hexdump(ssid_buffer, sizeof(ssid_buffer),
                                  nwconfig_write_data.wlan_ssid.data(),
                                  nwconfig_write_data.wlan_ssid_length);
                network_ssid = ssid_buffer;
            }
        }
    }
    else
    {
        network_name = nullptr;
        network_ssid = nullptr;
    }

    const WPSMode retval =
        (strcmp(nwconfig_write_data.wlan_security_mode.data(), "wps") == 0
         ? (network_name == nullptr
            ? WPSMode::SCAN
            : (network_name != empty_string || network_ssid != empty_string
               ? WPSMode::DIRECT
               : WPSMode::INVALID))
         : (strcmp(nwconfig_write_data.wlan_security_mode.data(), "wps-abort") == 0
            ? WPSMode::ABORT
            : WPSMode::NONE));

    if(IS_REQUESTED(REQ_WLAN_WPA_PASSPHRASE_102))
    {
        const size_t passphrase_length =
            (strcmp(nwconfig_write_data.wlan_security_mode.data(), "none") == 0)
            ? 0
            : (nwconfig_write_data.wlan_wpa_passphrase_is_ascii
               ? strlen(reinterpret_cast<const char *>(nwconfig_write_data.wlan_wpa_passphrase.data()))
               : (nwconfig_write_data.wlan_wpa_passphrase.size() - 1));

        if(passphrase_length > 0)
            passphrase = reinterpret_cast<const char *>(nwconfig_write_data.wlan_wpa_passphrase.data());
        else
            passphrase = "";
    }
    else
        passphrase = nullptr;

    network_prefs_put_wlan_config(prefs, network_name, network_ssid,
                                  nwconfig_write_data.wlan_security_mode.data(),
                                  passphrase);

    switch(retval)
    {
      case WPSMode::INVALID:
      case WPSMode::NONE:
      case WPSMode::SCAN:
      case WPSMode::ABORT:
        break;

      case WPSMode::DIRECT:
        if(network_name != nullptr && network_name[0] != '\0')
            *out_wps_network_name = strdup(network_name);

        if(network_ssid != nullptr && network_ssid[0] != '\0')
            *out_wps_network_ssid = strdup(network_ssid);

        break;
    }

    return retval;
}

static WPSMode apply_changes_to_prefs(const Connman::ServiceBase &service,
                                      struct network_prefs *prefs,
                                      char **out_wps_network_name,
                                      char **out_wps_network_ssid)
{
    log_assert(prefs != nullptr);

    if(handle_set_dhcp_mode(prefs) < 0)
        return WPSMode::INVALID;

    if(handle_set_static_ipv4_config(prefs) < 0)
        return WPSMode::INVALID;

    if(handle_set_dns_servers(service, prefs) < 0)
        return WPSMode::INVALID;

    const WPSMode mode = handle_set_wireless_config(service, prefs,
                                                    out_wps_network_name,
                                                    out_wps_network_ssid);

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
        return WPSMode::INVALID;
    }

    return mode;
}

/*!
 * Write changes to file.
 *
 * \attention
 *     Must be called with the #ShutdownGuard from #nwstatus_data locked.
 */
static WPSMode
modify_network_configuration(
        Connman::Technology prefs_tech,
        std::array<char, NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE> &previous_wlan_name_buffer,
        char **out_wps_network_name, char **out_wps_network_ssid)
{
    if(shutdown_guard_is_shutting_down_unlocked(nwstatus_data.shutdown_guard))
    {
        msg_info("Not writing network configuration during shutdown.");
        return WPSMode::INVALID;
    }

    if(prefs_tech == Connman::Technology::UNKNOWN_TECHNOLOGY)
        return WPSMode::INVALID;

    const auto locked_services(Connman::ServiceList::get_singleton_const());
    const auto &services(locked_services.first);
    const Connman::ServiceBase *service(get_connman_service_data(services));

    if(service == nullptr)
    {
        msg_error(0, LOG_ERR,
                  "Network service does not exist, cannot configure");
        return WPSMode::INVALID;
    }

    struct network_prefs *ethernet_prefs;
    struct network_prefs *wlan_prefs;
    struct network_prefs_handle *cfg =
        network_prefs_open_rw(&ethernet_prefs, &wlan_prefs);

    if(cfg == nullptr)
        return WPSMode::INVALID;

    struct network_prefs *selected_prefs =
        prefs_tech == Connman::Technology::ETHERNET ? ethernet_prefs : wlan_prefs;

    network_prefs_generate_service_name(prefs_tech == Connman::Technology::ETHERNET
                                        ? nullptr
                                        : selected_prefs,
                                        previous_wlan_name_buffer.data(),
                                        previous_wlan_name_buffer.size());

    if(selected_prefs == nullptr)
        selected_prefs = network_prefs_add_prefs(cfg, map_network_technology(prefs_tech));

    WPSMode wps_mode =
        apply_changes_to_prefs(*service, selected_prefs,
                               out_wps_network_name, out_wps_network_ssid);

    switch(wps_mode)
    {
      case WPSMode::NONE:
        if(network_prefs_write_to_file(cfg) < 0)
            wps_mode = WPSMode::INVALID;

        break;

      case WPSMode::INVALID:
      case WPSMode::DIRECT:
      case WPSMode::SCAN:
      case WPSMode::ABORT:
        break;
    }

    network_prefs_close(cfg);

    return wps_mode;
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

static bool is_ethernet_service_auto_configured(const Connman::ServiceBase &s)
{
    const Connman::ServiceData &sdata(s.get_service_data());

    if(sdata.dns_servers_.is_known() && !sdata.dns_servers_.get().empty())
        return false;

    if(!sdata.ip_settings_v4_.is_known())
        return false;

    const auto &settings(sdata.ip_settings_v4_.get());

    switch(settings.get_dhcp_method())
    {
      case Connman::DHCPV4Method::NOT_AVAILABLE:
      case Connman::DHCPV4Method::UNKNOWN_METHOD:
      case Connman::DHCPV4Method::OFF:
      case Connman::DHCPV4Method::MANUAL:
      case Connman::DHCPV4Method::FIXED:
        return false;

      case Connman::DHCPV4Method::ON:
        break;
    }

    if(settings.get_address().get_string().compare(0, 8, "168.254.") != 0)
        return false;

    if(settings.get_netmask().get_string().compare(0, 8, "255.255.") != 0)
        return false;

    if(!settings.get_gateway().empty())
        return false;

    return true;
}

/* switch to WLAN service in case WPS mode was requested while Ethernet is
 * selected, but the Ethernet service is either unconfigured or was configured
 * by IPv4LL */
static bool auto_switch_to_wlan_if_necessary()
{
    if(!IS_REQUESTED(REQ_WLAN_SECURITY_MODE_92))
        return false;

    switch(nwconfig_write_data.selected_technology)
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
      case Connman::Technology::WLAN:
        return false;

      case Connman::Technology::ETHERNET:
        /* so we have WLAN security mode for the Ethernet interface */
        break;
    }

    /* only switch for WPS */
    if(strcmp(nwconfig_write_data.wlan_security_mode.data(), "wps") != 0)
        return false;

    const auto locked_services(Connman::ServiceList::get_singleton_const());
    const auto &services(locked_services.first);

    const Connman::ServiceBase *wlan_service(
            find_best_service_by_technology(services, Connman::Technology::WLAN));

    /* don't switch if there is no alternative */
    if(wlan_service == nullptr)
        return false;

    const Connman::ServiceBase *ethernet_service(
            find_best_service_by_technology(services, Connman::Technology::ETHERNET));

    const bool result = ethernet_service != nullptr
        ? is_ethernet_service_auto_configured(*ethernet_service)
        : true;

    if(result)
    {
        if(ethernet_service != nullptr)
            msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                      "Configuring WLAN %s instead of Ethernet %s",
                      wlan_service->get_service_data().device_->mac_address_.get_string().c_str(),
                      ethernet_service->get_service_data().device_->mac_address_.get_string().c_str());
        else
            msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                      "Configuring WLAN %s instead of nonexistent Ethernet",
                      wlan_service->get_service_data().device_->mac_address_.get_string().c_str());

        nwconfig_write_data.selected_technology = Connman::Technology::WLAN;
    }

    return result;
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

    auto_switch_to_wlan_if_necessary();

    if(nwconfig_write_data.requested_changes == 0)
    {
        /* nothing to do */
        nwconfig_write_data.selected_technology = Connman::Technology::UNKNOWN_TECHNOLOGY;
        return 0;
    }

    {
    const auto locked_devices(Connman::NetworkDeviceList::get_singleton_const());
    const auto &devices(locked_devices.first);

    msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
              "Writing new network configuration for MAC address %s",
              devices.get_auto_select_mac_address(nwconfig_write_data.selected_technology).get_string().c_str());
    }

    shutdown_guard_lock(nwstatus_data.shutdown_guard);
    std::array<char, NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE> current_wlan_service_name;
    char *wps_network_name = nullptr;
    char *wps_network_ssid = nullptr;
    const WPSMode wps_mode =
        modify_network_configuration(nwconfig_write_data.selected_technology,
                                     current_wlan_service_name,
                                     &wps_network_name, &wps_network_ssid);
    shutdown_guard_unlock(nwstatus_data.shutdown_guard);

    log_assert((wps_mode == WPSMode::DIRECT &&
                (wps_network_name != nullptr || wps_network_ssid != nullptr)) ||
               (wps_mode != WPSMode::DIRECT &&
                (wps_network_name == nullptr && wps_network_ssid == nullptr)));

    const auto tech(nwconfig_write_data.selected_technology);

    nwconfig_write_data.selected_technology = Connman::Technology::UNKNOWN_TECHNOLOGY;

    switch(wps_mode)
    {
      case WPSMode::INVALID:
        dbussignal_connman_manager_cancel_wps();
        break;

      case WPSMode::NONE:
        dbussignal_connman_manager_connect_to_service(map_network_technology(tech),
                                                      current_wlan_service_name.data());
        return 0;

      case WPSMode::DIRECT:
        log_assert(tech == Connman::Technology::WLAN);
        dbussignal_connman_manager_connect_to_wps_service(wps_network_name,
                                                          wps_network_ssid,
                                                          current_wlan_service_name.data());
        free(wps_network_name);
        free(wps_network_ssid);
        return 0;

      case WPSMode::SCAN:
        log_assert(tech == Connman::Technology::WLAN);
        dbussignal_connman_manager_connect_to_wps_service(nullptr, nullptr,
                                                          current_wlan_service_name.data());
        return 0;

      case WPSMode::ABORT:
        dbussignal_connman_manager_cancel_wps();
        return 0;
    }

    return -1;
}

int dcpregs_write_54_selected_ip_profile(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 54 handler %p %zu", data, length);

    if(data_length_is_unexpected(length, 1))
        return -1;

    if(data[0] != 0)
        return -1;

    const auto locked_services(Connman::ServiceList::get_singleton_const());
    const auto &services(locked_services.first);

    auto tech = determine_active_network_technology(services, false);

    if(tech == Connman::Technology::UNKNOWN_TECHNOLOGY)
    {
        msg_info("Could not determine active network technology, "
                 "trying fallback");
        tech = nwstatus_data.fallback_technology;
    }

    nwconfig_write_data.reset(tech);

    switch(nwconfig_write_data.selected_technology)
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
        msg_error(0, LOG_ERR, "No active network technology, cannot modify configuration");
        break;

      case Connman::Technology::ETHERNET:
      case Connman::Technology::WLAN:
        msg_vinfo(MESSAGE_LEVEL_DEBUG, "Modify %s configuration",
                  nwconfig_write_data.selected_technology == Connman::Technology::ETHERNET
                  ? "Ethernet"
                  : "WLAN");
        return 0;
    }

    return -1;
}

static void fill_network_status_register_response(std::array<uint8_t, 3> &response)
{
    response[0] = NETWORK_STATUS_IPV4_NOT_CONFIGURED;
    response[1] = NETWORK_STATUS_DEVICE_NONE;
    response[2] = NETWORK_STATUS_CONNECTION_NONE;

    const auto locked_services(Connman::ServiceList::get_singleton_const());
    const auto &services(locked_services.first);
    const Connman::ServiceBase *fallback_service_data;
    const Connman::ServiceBase *service =
        find_current_service(services,
                             determine_active_network_technology(services, true),
                             &fallback_service_data);

    if(service == nullptr)
        service = fallback_service_data;
    else
        log_assert(fallback_service_data == nullptr);

    if(service == nullptr)
        return;

    if(service->get_service_data().ip_settings_v4_.is_known())
    {
        const auto &settings(service->get_service_data().ip_settings_v4_.get());

        if(settings.is_configuration_valid())
        {
            response[0] = map_dhcp_method(settings.get_dhcp_method());
            response[2] |= NETWORK_STATUS_CONNECTION_CONNECTED;
        }
    }

    bool is_wps;
    bool is_connecting = dbussignal_connman_manager_is_connecting(&is_wps);

    if(is_connecting)
        response[2] |= NETWORK_STATUS_CONNECTION_CONNECTING;

    if(is_wps)
        response[2] |= NETWORK_STATUS_CONNECTION_IS_WPS_MODE;

    switch(service->get_technology())
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
        break;

      case Connman::Technology::ETHERNET:
        response[1] = NETWORK_STATUS_DEVICE_ETHERNET;
        break;

      case Connman::Technology::WLAN:
        response[1] = NETWORK_STATUS_DEVICE_WLAN;
        break;
    }
}

ssize_t dcpregs_read_50_network_status(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 50 handler %p %zu", response, length);

    if(data_length_is_unexpected(length, nwstatus_data.previous_response.size()))
        return -1;

    fill_network_status_register_response(nwstatus_data.previous_response);
    std::copy(nwstatus_data.previous_response.begin(),
              nwstatus_data.previous_response.end(),
              response);

    return length;
}

static size_t copy_locally_administered_mac(uint8_t *response)
{
    const char local_address[] = "02:00:00:00:00:00";
    memcpy(response, local_address, sizeof(local_address));
    return sizeof(local_address);
}

ssize_t dcpregs_read_51_mac_address(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 51 handler %p %zu", response, length);

    if(data_length_is_unexpected(length, Connman::AddressTraits<Connman::AddressType::MAC>::ADDRESS_STRING_LENGTH + 1))
        return -1;

    if(length < Connman::AddressTraits<Connman::AddressType::MAC>::ADDRESS_STRING_LENGTH)
        return -1;

    const auto locked_services(Connman::ServiceList::get_singleton_const());
    const auto &services(locked_services.first);
    const Connman::ServiceBase *service;
    const auto tech(determine_active_network_technology(services, false, &service));

    if(tech == Connman::Technology::UNKNOWN_TECHNOLOGY)
        return copy_locally_administered_mac(response);

    if(service == nullptr || service->get_service_data().device_ == nullptr)
        return copy_locally_administered_mac(response);

    const auto mac(service->get_service_data().device_->mac_address_);

    if(mac.empty())
        return copy_locally_administered_mac(response);

    mac.get_string().copy(reinterpret_cast<char *>(response), length);
    response[mac.get_string().length()] = '\0';

    return mac.get_string().length() + 1;
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
read_out_parameter(const std::function<ssize_t(const Connman::ServiceBase &, char *, size_t)> &copy,
                   Connman::Technology required_technology,
                   uint8_t *response, size_t length)
{
    const auto locked_services(Connman::ServiceList::get_singleton_const());
    const auto &services(locked_services.first);
    const Connman::ServiceBase *service(get_connman_service_data(services));

    if(service != nullptr &&
       (service->get_technology() == required_technology ||
        required_technology == Connman::Technology::UNKNOWN_TECHNOLOGY))
    {
        return copy(*service, reinterpret_cast<char *>(response), length);
    }

    return -1;
}

template <typename T, size_t N>
static ssize_t
read_out_parameter(uint32_t requested_mask,
                   const std::array<T, N> &edited_ipv4_parameter,
                   bool expected_length_includes_zero_terminator,
                   const std::function<ssize_t(const Connman::ServiceBase &, char *, size_t)> &copy,
                   Connman::Technology required_technology,
                   uint8_t *response, size_t length,
                   size_t n_copy_max = N)
{
    const size_t length_decrease = expected_length_includes_zero_terminator ? 0 : 1;

    if(data_length_is_unexpectedly_small(length, N - length_decrease))
        return -1;

    log_assert(n_copy_max <= N);

    response[0] = '\0';

    ssize_t written;

    if(in_edit_mode() && IS_REQUESTED(requested_mask))
    {
        written = std::copy(edited_ipv4_parameter.begin(),
                            edited_ipv4_parameter.begin() + n_copy_max - length_decrease,
                            response) - response;

        if(expected_length_includes_zero_terminator && size_t(written) < length)
            written = strlen(reinterpret_cast<const char *>(response)) + 1;
    }
    else
        written = read_out_parameter(copy, required_technology, response, length);

    if(written < 0)
        return written;

    return (expected_length_includes_zero_terminator || size_t(written) <= length
            ? written
            : length);
}

ssize_t dcpregs_read_56_ipv4_address(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 56 handler %p %zu", response, length);

    return read_out_parameter(REQ_IP_ADDRESS_56,
                nwconfig_write_data.ipv4_address, true,
                [] (const Connman::ServiceBase &s, char *out, size_t len) -> ssize_t
                {
                    if(s.get_service_data().ip_settings_v4_.is_known())
                        return copy_to_array(s.get_service_data().ip_settings_v4_.get().get_address().get_string(),
                                             out, len);
                    else
                        return -1;
                },
                Connman::Technology::UNKNOWN_TECHNOLOGY,
                response, length);
}

ssize_t dcpregs_read_57_ipv4_netmask(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 57 handler %p %zu", response, length);

    return read_out_parameter(REQ_NETMASK_57,
                nwconfig_write_data.ipv4_netmask, true,
                [] (const Connman::ServiceBase &s, char *out, size_t len) -> ssize_t
                {
                    if(s.get_service_data().ip_settings_v4_.is_known())
                        return copy_to_array(s.get_service_data().ip_settings_v4_.get().get_netmask().get_string(),
                                             out, len);
                    else
                        return -1;
                },
                Connman::Technology::UNKNOWN_TECHNOLOGY,
                response, length);
}

ssize_t dcpregs_read_58_ipv4_gateway(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 58 handler %p %zu", response, length);

    return read_out_parameter(REQ_DEFAULT_GATEWAY_58,
                nwconfig_write_data.ipv4_gateway, true,
                [] (const Connman::ServiceBase &s, char *out, size_t len) -> ssize_t
                {
                    if(s.get_service_data().ip_settings_v4_.is_known())
                        return copy_to_array(s.get_service_data().ip_settings_v4_.get().get_gateway().get_string(),
                                             out, len);
                    else
                        return -1;
                },
                Connman::Technology::UNKNOWN_TECHNOLOGY,
                response, length);
}

ssize_t dcpregs_read_62_primary_dns(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 62 handler %p %zu", response, length);

    return read_out_parameter(REQ_DNS_SERVER1_62,
                nwconfig_write_data.ipv4_dns_server1, true,
                [] (const Connman::ServiceBase &s, char *out, size_t len) -> ssize_t
                {
                    if(!s.get_service_data().dns_servers_.is_known())
                        return -1;

                    const auto &servers(s.get_service_data().dns_servers_.get());

                    if(!servers.empty())
                        return copy_to_array(servers[0], out, len);
                    else
                        return -1;
                },
                Connman::Technology::UNKNOWN_TECHNOLOGY,
                response, length);
}

ssize_t dcpregs_read_63_secondary_dns(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 63 handler %p %zu", response, length);

    return read_out_parameter(REQ_DNS_SERVER2_63,
                nwconfig_write_data.ipv4_dns_server2, true,
                [] (const Connman::ServiceBase &s, char *out, size_t len) -> ssize_t
                {
                    if(!s.get_service_data().dns_servers_.is_known())
                        return -1;

                    const auto &servers(s.get_service_data().dns_servers_.get());

                    if(servers.size() >= 2)
                        return copy_to_array(servers[1], out, len);
                    else
                        return -1;

                },
                Connman::Technology::UNKNOWN_TECHNOLOGY,
                response, length);
}

static int copy_ipv4_address(std::array<char, SIZE_OF_IPV4_ADDRESS_STRING> &dest,
                             const uint32_t requested_change,
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

static const Connman::TechData<Connman::Technology::WLAN> *
get_wlan_tech_data(const Connman::ServiceBase &s)
{
    switch(s.get_technology())
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
      case Connman::Technology::ETHERNET:
        break;

      case Connman::Technology::WLAN:
        return &static_cast<const Connman::Service<Connman::Technology::WLAN> &>(s).get_tech_data();
    }

    return nullptr;
}

ssize_t dcpregs_read_92_wlan_security(uint8_t *response, size_t length)
{
    return read_out_parameter(REQ_WLAN_SECURITY_MODE_92,
                nwconfig_write_data.wlan_security_mode, false,
                [] (const Connman::ServiceBase &s, char *out, size_t len) -> ssize_t
                {
                    const auto *const d(get_wlan_tech_data(s));

                    if(d != nullptr && d->security_.is_known())
                        return copy_to_array(d->security_.get(), out, len);
                    else
                        return -1;
                },
                Connman::Technology::WLAN,
                response, length);
}

int dcpregs_write_92_wlan_security(const uint8_t *data, size_t length)
{
    if(data_length_is_in_unexpected_range(length,
                                          3, SIZE_OF_WLAN_SECURITY_MODE))
        return -1;

    if(!may_change_config())
        return -1;

    std::copy(data, data + length,
              nwconfig_write_data.wlan_security_mode.begin());
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
    std::array<char, 9> buffer;

    if(data_length_is_in_unexpected_range(length, 4, buffer.size() - 1))
        return -1;

    std::copy(data, data + length, buffer.begin());
    buffer[length] = '\0';

    if(strcmp(buffer.data(), "false") == 0)
    {
        msg_info("Ignoring IBSS infrastructure mode request (always using that mode)");
        return 0;
    }
    else if(strcmp(buffer.data(), "true") == 0)
        msg_error(EINVAL, LOG_NOTICE,
                  "Cannot change IBSS mode to ad-hoc, always using infrastructure mode");
    else
        msg_error(EINVAL, LOG_ERR, "Got invalid IBSS mode request");

    return -1;
}

ssize_t dcpregs_read_94_ssid(uint8_t *response, size_t length)
{
    ssize_t result =
        read_out_parameter(REQ_WLAN_SSID_94,
                           nwconfig_write_data.wlan_ssid, false,
                           [] (const Connman::ServiceBase &s, char *out, size_t len) -> ssize_t
                           {
                               const auto *const d(get_wlan_tech_data(s));

                               if(d != nullptr && d->network_name_.is_known())
                                   return copy_to_array(d->network_name_.get(), out, len);
                                else
                                   return -2;
                           },
                           Connman::Technology::WLAN,
                           response, length,
                           nwconfig_write_data.wlan_ssid_length + 1);

    if(result == -1 || result > 1)
        return result;

    if(result >= 0 && in_edit_mode() && IS_REQUESTED(REQ_WLAN_SSID_94))
        return result;

    /* binary SSID */
    result = read_out_parameter(
                [] (const Connman::ServiceBase &s, char *out, size_t len) -> ssize_t
                {
                    const auto *const d(get_wlan_tech_data(s));

                    if(d != nullptr && d->network_ssid_.is_known())
                        return hexdump_to_binary(out, len, d->network_ssid_.get());
                    else
                        return -2;
                },
                Connman::Technology::WLAN,
                response, length);

    return result >= 0 ? result : -1;
}

int dcpregs_write_94_ssid(const uint8_t *data, size_t length)
{
    if(data_length_is_in_unexpected_range(length, 1, 32))
        return -1;

    if(!may_change_config())
        return -1;

    std::copy(data, data + length, nwconfig_write_data.wlan_ssid.begin());
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
    std::array<char, 9> buffer;

    if(data_length_is_in_unexpected_range(length, 3, buffer.size() - 1))
        return -1;

    std::copy(data, data + length, buffer.begin());
    buffer[length] = '\0';

    if(strcmp(buffer.data(), "AES") == 0 || strcmp(buffer.data(), "TKIP") == 0)
    {
        msg_info("Ignoring setting WPA cipher (automatic, AES preferred)");
        return 0;
   }

    msg_error(EINVAL, LOG_ERR, "Got invalid WPA cipher");

    return -1;
}

ssize_t dcpregs_read_102_passphrase(uint8_t *response, size_t length)
{
    if(data_length_is_unexpectedly_small(length, nwconfig_write_data.wlan_wpa_passphrase.size() - 1))
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
                           : strlen(reinterpret_cast<const char *>(nwconfig_write_data.wlan_wpa_passphrase.data())) - 1)
                        : (nwconfig_write_data.wlan_wpa_passphrase.size() - 1));

        if(copied_bytes > 0)
            std::copy(nwconfig_write_data.wlan_wpa_passphrase.begin(),
                      nwconfig_write_data.wlan_wpa_passphrase.begin() + copied_bytes,
                      response);
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
                                          nwconfig_write_data.wlan_wpa_passphrase.size() - 1))
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

        if(length == nwconfig_write_data.wlan_wpa_passphrase.size() - 1)
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
    std::array<uint8_t, nwstatus_data.previous_response.size()> response;

    connman_wlan_power_on();
    fill_network_status_register_response(response);

    if(nwstatus_data.previous_response != response)
        registers_get_data()->register_changed_notification_fn(50);
}

void dcpregs_networkconfig_prepare_for_shutdown(void)
{
    (void)shutdown_guard_down(nwstatus_data.shutdown_guard);
}

void dcpregs_networkconfig_set_primary_technology(Connman::Technology tech)
{
    nwstatus_data.fallback_technology = tech;
}
