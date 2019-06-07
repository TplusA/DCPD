/*
 * Copyright (C) 2015--2019  T+A elektroakustik GmbH & Co. KG
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

#include "dcpregs_networkconfig.hh"
#include "network_status_bits.h"
#include "registers_priv.hh"
#include "connman_service_list.hh"
#include "network_device_list.hh"
#include "network_config_request.hh"
#include "accesspoint_manager.hh"
#include "connman_scan.hh"
#include "dbus_handlers_connman_manager.hh"
#include "string_trim.hh"
#include "shutdown_guard.h"

#include <arpa/inet.h>

#include <algorithm>
#include <functional>

class ConfigRequestEditState
{
  private:
    /*!
     * Networking technology at the time the change request was commenced.
     */
    Connman::Technology selected_technology_;

  public:
    ConfigRequestEditState(const ConfigRequestEditState &) = delete;
    ConfigRequestEditState &operator=(const ConfigRequestEditState &) = delete;

    explicit ConfigRequestEditState():
        selected_technology_(Connman::Technology::UNKNOWN_TECHNOLOGY)
    {}

    void enter_edit_mode(Connman::Technology tech)
    {
        if(tech != Connman::Technology::UNKNOWN_TECHNOLOGY)
            selected_technology_ = tech;
    };

    void cancel()
    {
        selected_technology_ = Connman::Technology::UNKNOWN_TECHNOLOGY;
    }

    bool is_in_edit_mode() const
    {
        return selected_technology_ != Connman::Technology::UNKNOWN_TECHNOLOGY;
    }

    void switch_technology(Connman::Technology tech)
    {
        if(is_in_edit_mode())
            selected_technology_ = tech;
    }

    Connman::Technology get_selected_technology() const
    {
        return selected_technology_;
    }
};

/*!
 * All network configuration changes are recorded in a #Network::ConfigRequest
 * object after the client has written a 0 to the \c SELECTED_IP_PROFILE
 * register (DCP register 54). This action puts the request object into edit
 * mode. Then, the SPI is expected to write to the various configuration
 * registers so that the object can be filled incrementally. All configuration
 * changes are committed when the client writes 0 into the \c ACTIVE_IP_PROFILE
 * register (DCP register 53). Writing a 0 to the \c SELECTED_IP_PROFILE
 * register deletes all requested changes, thus cancels the configuration
 * request.
 *
 * Note that it is necessary to collect all configuration changes in RAM before
 * writing them to file because updating each value immediately would cause
 * pointless file writes and trigger many failing reconfiguration attempts on
 * behalf of Connman.
 */
class NetworkConfigWriteData
{
  private:
    LoggedLock::Mutex commit_configuration_lock_;

    ConfigRequestEditState edit_state_;
    Network::ConfigRequest config_request_;

    /* handling the warts of the amateurish DC protocol... */
    Maybe<std::string> ipv4_dns_server1_;
    Maybe<std::string> ipv4_dns_server2_;

  public:
    NetworkConfigWriteData()
    {
        LoggedLock::configure(commit_configuration_lock_, "NetworkConfigWriteData",
                              MESSAGE_LEVEL_DEBUG);
    }

    void init()
    {
        edit_state_.cancel();
        config_request_.reset();
        ipv4_dns_server1_.set_unknown();
        ipv4_dns_server2_.set_unknown();
    }

    LoggedLock::UniqueLock<LoggedLock::Mutex> lock()
    {
        return LoggedLock::UniqueLock<LoggedLock::Mutex>(commit_configuration_lock_);
    }

    bool may_change_config() const
    {
        if(edit_state_.is_in_edit_mode())
            return true;

        msg_error(0, LOG_ERR,
                  "Network configuration may not be changed without prior "
                  "request for changing the configuration");

        return false;
    }

    bool have_requests() const
    {
        return ipv4_dns_server1_.is_known() || ipv4_dns_server2_.is_known() ||
               !config_request_.empty();
    }

    bool enter_edit_mode(Connman::Technology tech)
    {
        edit_state_.enter_edit_mode(tech);
        config_request_.reset();

        switch(edit_state_.get_selected_technology())
        {
          case Connman::Technology::UNKNOWN_TECHNOLOGY:
            msg_error(0, LOG_ERR, "No active network technology, cannot modify configuration");
            break;

          case Connman::Technology::ETHERNET:
          case Connman::Technology::WLAN:
            msg_vinfo(MESSAGE_LEVEL_DEBUG, "Modify %s configuration",
                      edit_state_.get_selected_technology() == Connman::Technology::ETHERNET
                      ? "Ethernet"
                      : "WLAN");
            config_request_.when_ = Network::ConfigRequest::ApplyWhen::NOW;
            return true;
        }

        return false;
    }

    Connman::Technology cancel_edit_mode()
    {
        const auto tech(edit_state_.get_selected_technology());
        edit_state_.cancel();
        return tech;
    }

    const ConfigRequestEditState &get_edit_state() const { return edit_state_; }
    const Network::ConfigRequest &get_configuration_request() const { return config_request_; }
    Network::ConfigRequest &get_configuration_request_rw() { return config_request_; }
    bool is_primary_dns_server_known() const { return ipv4_dns_server1_.is_known(); }
    bool is_secondary_dns_server_known() const { return ipv4_dns_server2_.is_known(); }
    const Maybe<std::string> &get_primary_dns_server() const { return ipv4_dns_server1_; }
    const Maybe<std::string> &get_secondary_dns_server() const { return ipv4_dns_server2_; }
    Maybe<std::string> &get_primary_dns_server_rw() { return ipv4_dns_server1_; }
    Maybe<std::string> &get_secondary_dns_server_rw() { return ipv4_dns_server2_; }

    void switch_technology(Connman::Technology tech) { edit_state_.switch_technology(tech); }

    /*!
     * Move secondary DNS to primary slot.
     */
    void shift_dns_servers()
    {
        ipv4_dns_server1_ = std::move(ipv4_dns_server2_);
    }

    /*!
     * Move secondary DNS to primary slot in case the primary slot is empty.
     */
    void shift_dns_servers_if_necessary()
    {
        if(!ipv4_dns_server1_.is_known() || ipv4_dns_server1_.get().empty())
            shift_dns_servers();
    }

    void set_primary_dns_server(const std::string *value)
    {
        set_dns(ipv4_dns_server1_, value);
    }

    void set_secondary_dns_server(const std::string *value)
    {
        set_dns(ipv4_dns_server2_, value);
    }

    void copy_defined_dns_servers(std::vector<std::string> &dest)
    {
        dest.clear();

        if(ipv4_dns_server1_.is_known())
            dest.push_back(ipv4_dns_server1_.get());

        if(ipv4_dns_server2_.is_known())
            dest.push_back(ipv4_dns_server2_.get());
    }

  private:
    static void set_dns(Maybe<std::string> &dest, const std::string *value)
    {
        if(value != nullptr)
            dest = *value;
        else
            dest.set_unknown();
    }
};

/*!
 * Network status register data and other stuff.
 */
class NetworkStatusData
{
  public:
    static constexpr size_t RESPONSE_SIZE = 3;

  private:
    struct ShutdownGuard *shutdown_guard_;

    /*!
     * Appliance-specific networking technology to use as fallback.
     */
    Connman::Technology fallback_technology_;

    /*!
     * The status last communicated to the slave device.
     *
     * Status changes are only sent to the slave if the information represented
     * by the status register actually changed.
     */
    std::array<uint8_t, RESPONSE_SIZE> previous_status_bytes_;

  public:
    NetworkStatusData():
        shutdown_guard_(shutdown_guard_alloc("networkconfig")),
        fallback_technology_(Connman::Technology::UNKNOWN_TECHNOLOGY),
        previous_status_bytes_{UINT8_MAX, UINT8_MAX, UINT8_MAX}
    {}

    ~NetworkStatusData()
    {
        shutdown_guard_free(&shutdown_guard_);
    }

    struct ShutdownGuard &shutdown_guard() { return *shutdown_guard_; }

    Connman::Technology fixup_active_technology(Connman::Technology tech) const
    {
        if(tech == Connman::Technology::UNKNOWN_TECHNOLOGY)
        {
            msg_info("Could not determine active network technology, "
                     "trying fallback");
            return fallback_technology_;
        }
        else
            return tech;
    }

    void set_fallback_technology(Connman::Technology tech)
    {
        fallback_technology_ = tech;
    }

    void store_network_status(const uint8_t *status_bytes, size_t length)
    {
        log_assert(length >= RESPONSE_SIZE);
        std::copy(status_bytes, status_bytes + RESPONSE_SIZE,
                  previous_status_bytes_.begin());
    }

    bool is_network_status_different(const std::array<uint8_t, NetworkStatusData::RESPONSE_SIZE> &status) const
    {
        return status != previous_status_bytes_;
    }
};

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

static const Connman::ServiceBase *get_connman_service_data(const ConfigRequestEditState &edit,
                                                            const Connman::ServiceList &services)
{
    if(edit.is_in_edit_mode())
        return find_best_service_by_technology(services,
                                               edit.get_selected_technology());
    else
        return find_current_service(services,
                                    determine_active_network_technology(services, true),
                                    nullptr);
}

/*!
 * Validate IPv4 address string.
 */
static bool is_valid_ip_address_string(const std::string &string,
                                       bool is_empty_ok)
{
    if(string[0] == '\0')
        return is_empty_ok;

    uint8_t dummy[sizeof(struct in_addr)];
    int result = inet_pton(AF_INET, string.c_str(), dummy);

    if(result > 0)
        return true;

    if(result == 0)
        errno = 0;

    msg_error(errno, LOG_WARNING, "Failed parsing IPv4 address %s", string.c_str());

    return false;
}

static int fill_in_missing_ipv4_config_requests(const Network::ConfigRequest &req)
{
    log_assert(req.ipv4_address_.is_known() || req.ipv4_netmask_.is_known() ||
               req.ipv4_gateway_.is_known());

    if(req.ipv4_address_.is_known() && req.ipv4_netmask_.is_known() &&
       req.ipv4_gateway_.is_known())
        return (is_valid_ip_address_string(req.ipv4_address_.get(), false) &&
                is_valid_ip_address_string(req.ipv4_netmask_.get(), false) &&
                is_valid_ip_address_string(req.ipv4_gateway_.get(), false))
            ? 0
            : -1;

    BUG("%s(): not implemented", __func__);

    return -1;
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
static void fill_in_missing_dns_server_config_requests(NetworkConfigWriteData &wd,
                                                       const Connman::ServiceBase &service)
{
    log_assert(wd.is_primary_dns_server_known() || wd.is_secondary_dns_server_known());

    if(wd.is_primary_dns_server_known() && wd.is_secondary_dns_server_known())
    {
        wd.shift_dns_servers_if_necessary();
        return;
    }

    /* at this point we know that only one DNS server was sent to us, either a
     * "primary" one or a "secondary" */

    const bool have_dns_servers =
        (service.get_service_data().active_.dns_servers_.is_known() &&
         !service.get_service_data().active_.dns_servers_.get().empty());

    if(!have_dns_servers)
    {
        /*
         * There are no previously defined DNS servers, and only one DNS server
         * was sent. If the sent DNS was meant to be the secondary one, we
         * silently make it the new primary one.
         */
        if(wd.is_secondary_dns_server_known())
            wd.shift_dns_servers();
    }
    else
    {
        const auto &dns_servers(service.get_service_data().active_.dns_servers_.get());

        if(wd.is_primary_dns_server_known())
        {
            /* have new primary server, now copy over the previously defined,
             * secondary one (if any) */
            wd.set_secondary_dns_server(dns_servers.size() > 1 ? &dns_servers[1] : nullptr);
            wd.shift_dns_servers_if_necessary();
        }
        else
        {
            /* have new secondary server, now copy over the previously defined,
             * primary one */
            wd.set_primary_dns_server(&dns_servers[0]);
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

static bool query_dhcp_mode(const ConfigRequestEditState &edit)
{
    LOGGED_LOCK_CONTEXT_HINT;
    const auto locked_services(Connman::ServiceList::get_singleton_const());
    const auto &services(locked_services.first);
    const Connman::ServiceBase *service(get_connman_service_data(edit, services));

    if(service == nullptr)
        return false;

    if(!service->get_service_data().active_.ipsettings_v4_.is_known())
        return false;

    return map_dhcp_method(service->get_service_data().active_.ipsettings_v4_.get().get_dhcp_method()) == NETWORK_STATUS_IPV4_DHCP;
}

static bool handle_set_dhcp_mode(Network::ConfigRequest &req,
                                 struct network_prefs *prefs)
{
    if(!req.dhcpv4_mode_.is_known())
        return true;

    const bool dhcp_mode = req.is_dhcpv4_mode();

    network_prefs_put_dhcp_mode(prefs, dhcp_mode, true);

    if(dhcp_mode)
    {
        req.ipv4_address_.set_unknown();
        req.ipv4_netmask_.set_unknown();
        req.ipv4_gateway_.set_unknown();
        req.dns_servers_.set_unknown();
    }
    else if(!req.ipv4_address_.is_known() && !req.ipv4_netmask_.is_known() &&
            !req.ipv4_gateway_.is_known())
    {
        LOGGED_LOCK_CONTEXT_HINT;
        const auto locked_devices(Connman::NetworkDeviceList::get_singleton_const());
        const auto &devices(locked_devices.first);

        msg_error(0, LOG_WARNING,
                  "Disabling IPv4 on interface %s because DHCPv4 was "
                  "disabled and static IPv4 configuration was not sent",
                  devices.get_auto_select_mac_address(map_network_technology(network_prefs_get_technology_by_prefs(prefs))).get_string().c_str());

        network_prefs_disable_ipv4(prefs);

        req.dns_servers_.set_unknown();
    }

    return true;
}

static bool handle_set_static_ipv4_config(const Network::ConfigRequest &req,
                                          struct network_prefs *prefs)
{
    if(!req.ipv4_address_.is_known() && !req.ipv4_netmask_.is_known() &&
       !req.ipv4_gateway_.is_known())
        return true;

    if(fill_in_missing_ipv4_config_requests(req) < 0)
    {
        msg_error(0, LOG_ERR,
                  "IPv4 data incomplete, cannot set interface configuration");
        return false;
    }

    if(!req.ipv4_address_.get().empty())
        network_prefs_put_ipv4_config(prefs,
                                      req.ipv4_address_.get().c_str(),
                                      req.ipv4_netmask_.get().c_str(),
                                      req.ipv4_gateway_.get().c_str());
    else
    {
        LOGGED_LOCK_CONTEXT_HINT;
        const auto locked_devices(Connman::NetworkDeviceList::get_singleton_const());
        const auto &devices(locked_devices.first);

        msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                  "Disabling IPv4 on interface %s",
                  devices.get_auto_select_mac_address(map_network_technology(network_prefs_get_technology_by_prefs(prefs))).get_string().c_str());

        network_prefs_put_ipv4_config(prefs, "", "", "");
    }

    return true;
}

static bool handle_set_dns_servers(const Network::ConfigRequest &req,
                                   struct network_prefs *prefs)
{
    if(!req.dns_servers_.is_known())
        return true;

    const auto &servers(req.dns_servers_.get());

    if(!servers.empty())
        network_prefs_put_nameservers(prefs,
                                      servers[0].c_str(),
                                      servers.size() > 1 ? servers[1].c_str() : "");
    else
    {
        LOGGED_LOCK_CONTEXT_HINT;
        const auto locked_devices(Connman::NetworkDeviceList::get_singleton_const());
        const auto &devices(locked_devices.first);

        msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                  "No nameservers on interface %s",
                  devices.get_auto_select_mac_address(map_network_technology(network_prefs_get_technology_by_prefs(prefs))).get_string().c_str());

        network_prefs_put_nameservers(prefs, "", "");
    }

    return true;
}

/*!
 * All the stuff that isn't in DCP yet...
 */
static bool handle_unhandled_settings(const Network::ConfigRequest &req)
{
    bool result = true;

    if(req.ipv6_address_.is_known() || req.ipv6_prefix_length_.is_known() ||
       req.ipv6_gateway_.is_known() || req.dhcpv6_mode_ != "off")
    {
        msg_error(0, LOG_ERR, "IPv6 configuration not supported yet");
        result = false;
    }

    if(req.time_servers_.is_known())
    {
        msg_error(0, LOG_ERR, "Time server configuration is not supported yet");
        result = false;
    }

    if(req.domains_.is_known())
    {
        msg_error(0, LOG_ERR, "Domain configuration is not supported yet");
        result = false;
    }

    if(req.proxy_method_.is_known() || req.proxy_pac_url_.is_known() ||
       req.proxy_servers_.is_known() || req.proxy_excluded_.is_known())
    {
        msg_error(0, LOG_ERR, "Proxy configuration is not supported yet");
        result = false;
    }

    return result;
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

static std::string binary_to_hexdump(const std::string &src)
{
    std::string dest;

    for(const auto &byte : src)
    {
        dest += nibble_to_char((byte >> 4) & 0x0f);
        dest += nibble_to_char(byte & 0x0f);
    }

    return dest;
}

static size_t hexdump_to_binary(char *dest, size_t dest_size,
                                const std::string &src)
{
    size_t j = 0;

    for(size_t i = 0; i < src.size() && j < dest_size; i += 2)
    {
        dest[j] = char_to_nibble(src[i]) << 4;

        if(i + 1 >= src.size())
            break;

        dest[j++] |= char_to_nibble(src[i + 1]);
    }

    return j;
}

static bool is_wlan_ssid_simple_ascii(const std::string &ssid)
{
    for(const char ch : ssid)
    {
        if(ch <= ' ')
            return false;

        if(ch > 0x7e)
            return false;
    }

    return true;
}

static bool is_known_security_mode_name(const std::string &name)
{
    static const std::array<const std::string, 6> names =
    {
        "none",
        "psk",
        "ieee8021x",
        "wps",
        "wps-abort",
        "wep",
    };

    return std::find(names.begin(), names.end(), name) != names.end();
}

static Network::WPSMode
handle_set_wireless_config(Network::ConfigRequest &req,
                           Connman::Technology target_tech,
                           const Maybe<std::string> *fallback_wlan_security_mode,
                           struct network_prefs *prefs,
                           std::unique_ptr<std::string> &out_wps_network_name,
                           std::unique_ptr<std::string> &out_wps_network_ssid,
                           bool &have_new_wlan_passphrase)
{
    if(!req.wlan_security_mode_.is_known() &&
       !req.wlan_ssid_ascii_.is_known() &&
       !req.wlan_ssid_hex_.is_known() &&
       !req.wlan_wpa_passphrase_ascii_.is_known() &&
       !req.wlan_wpa_passphrase_hex_.is_known())
        return Network::WPSMode::NONE;

    switch(target_tech)
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
        BUG("Tried setting WLAN parameters for unknown technology");
        return Network::WPSMode::NONE;

      case Connman::Technology::ETHERNET:
        msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                  "Ignoring wireless parameters for active wired interface");
        return Network::WPSMode::NONE;

      case Connman::Technology::WLAN:
        break;
    }

    if(req.wlan_security_mode_.is_known())
    {
        if(!is_known_security_mode_name(req.wlan_security_mode_.get()))
        {
            msg_error(EINVAL, LOG_ERR, "Invalid WLAN security mode \"%s\"",
                      req.wlan_security_mode_.get().c_str());
            req.wlan_security_mode_.set_unknown();
        }

        if(req.wlan_security_mode_ == "wep")
        {
            BUG("Support for insecure WLAN mode \"WEP\" not implemented");
            req.wlan_security_mode_.set_unknown();
        }
    }
    else if(fallback_wlan_security_mode != nullptr)
        req.wlan_security_mode_ = *fallback_wlan_security_mode;

    if(!req.wlan_security_mode_.is_known() ||
       req.wlan_security_mode_.get().empty())
    {
        msg_error(EINVAL, LOG_ERR,
                  "Cannot set WLAN parameters, security mode missing");
        return Network::WPSMode::INVALID;
    }

    if(req.wlan_ssid_hex_.is_known())
        req.wlan_ssid_ascii_.set_unknown();
    else if(req.wlan_ssid_ascii_.is_known())
    {
        if(!is_wlan_ssid_simple_ascii(req.wlan_ssid_ascii_.get()))
        {
            req.wlan_ssid_hex_ = binary_to_hexdump(req.wlan_ssid_ascii_.get());
            req.wlan_ssid_ascii_.set_unknown();
        }
    }

    const Network::WPSMode retval =
        (req.wlan_security_mode_ == "wps"
         ? (!req.wlan_ssid_hex_.is_known() && !req.wlan_ssid_ascii_.is_known()
            ? Network::WPSMode::SCAN
            : (req.wlan_ssid_hex_ != "" || req.wlan_ssid_ascii_ != ""
               ? Network::WPSMode::DIRECT
               : Network::WPSMode::INVALID))
         : (req.wlan_security_mode_ == "wps-abort"
            ? Network::WPSMode::ABORT
            : Network::WPSMode::NONE));

    const char *passphrase;

    if(req.wlan_wpa_passphrase_hex_.is_known() ||
       req.wlan_wpa_passphrase_ascii_.is_known())
    {
        const size_t passphrase_length =
            (req.wlan_security_mode_ == "none"
            ? 0
            : (req.wlan_wpa_passphrase_hex_.is_known()
               ? req.wlan_wpa_passphrase_hex_.get().length()
               : req.wlan_wpa_passphrase_ascii_.get().length()));

        if(passphrase_length > 0)
            passphrase = req.wlan_wpa_passphrase_hex_.is_known()
                ? req.wlan_wpa_passphrase_hex_.get().c_str()
                : req.wlan_wpa_passphrase_ascii_.get().c_str();
        else
            passphrase = "";
    }
    else
        passphrase = nullptr;

    network_prefs_put_wlan_config(
        prefs,
        req.wlan_ssid_ascii_.is_known() ? req.wlan_ssid_ascii_.get().c_str() : nullptr,
        req.wlan_ssid_hex_.is_known() ? req.wlan_ssid_hex_.get().c_str() : nullptr,
        req.wlan_security_mode_.get().c_str(), passphrase, &have_new_wlan_passphrase);

    switch(retval)
    {
      case Network::WPSMode::INVALID:
        msg_error(EINVAL, LOG_ERR, "WPS requested for empty SSID");
        break;

      case Network::WPSMode::NONE:
      case Network::WPSMode::SCAN:
      case Network::WPSMode::ABORT:
        break;

      case Network::WPSMode::DIRECT:
        if(req.wlan_ssid_ascii_ != "")
            out_wps_network_name = std::make_unique<std::string>(req.wlan_ssid_ascii_.get());

        if(req.wlan_ssid_hex_ != "")
            out_wps_network_ssid = std::make_unique<std::string>(req.wlan_ssid_hex_.get());

        break;
    }

    return retval;
}

static void move_dns_servers_to_config_request(NetworkConfigWriteData &wd,
                                               Network::ConfigRequest &req,
                                               const Connman::ServiceBase &service)
{
    if(!wd.is_primary_dns_server_known() && !wd.is_secondary_dns_server_known())
        return;

    fill_in_missing_dns_server_config_requests(wd, service);

    req.dns_servers_.set_known();
    wd.copy_defined_dns_servers(req.dns_servers_.get_rw());
}

static bool apply_changes_to_prefs(Network::ConfigRequest &req,
                                   struct network_prefs *prefs)
{
    log_assert(prefs != nullptr);

    return handle_set_dhcp_mode(req, prefs) &&
           handle_set_static_ipv4_config(req, prefs) &&
           handle_set_dns_servers(req, prefs) &&
           handle_unhandled_settings(req);
}

/*!
 * Write changes received from SPI slave to file.
 *
 * \attention
 *     Must be called with the #ShutdownGuard from #nwstatus_data locked.
 */
static Network::WPSMode
modify_network_configuration(
        const ConfigRequestEditState &edit, Network::ConfigRequest &req,
        const ShutdownGuard &sg,
        const std::function<void(Network::ConfigRequest &, const Connman::ServiceBase &)> &patch_request,
        std::array<char, NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE> &previous_wlan_name_buffer,
        std::unique_ptr<std::string> &out_wps_network_name,
        std::unique_ptr<std::string> &out_wps_network_ssid,
        bool &have_new_wlan_passphrase)
{
    if(shutdown_guard_is_shutting_down_unlocked(&sg))
    {
        msg_info("Not writing network configuration during shutdown.");
        return Network::WPSMode::INVALID;
    }

    if(!edit.is_in_edit_mode())
        return Network::WPSMode::INVALID;

    LOGGED_LOCK_CONTEXT_HINT;
    const auto locked_services(Connman::ServiceList::get_singleton_const());
    const auto &services(locked_services.first);
    const Connman::ServiceBase *service(get_connman_service_data(edit, services));

    if(service == nullptr)
    {
        msg_error(0, LOG_ERR,
                  "Network service does not exist, cannot configure");
        return Network::WPSMode::INVALID;
    }

    struct network_prefs *ethernet_prefs;
    struct network_prefs *wlan_prefs;
    struct network_prefs_handle *cfg =
        network_prefs_open_rw(&ethernet_prefs, &wlan_prefs);

    if(cfg == nullptr)
        return Network::WPSMode::INVALID;

    struct network_prefs *selected_prefs =
        edit.get_selected_technology() == Connman::Technology::ETHERNET ? ethernet_prefs : wlan_prefs;

    network_prefs_generate_service_name(edit.get_selected_technology() == Connman::Technology::ETHERNET
                                        ? nullptr
                                        : selected_prefs,
                                        previous_wlan_name_buffer.data(),
                                        previous_wlan_name_buffer.size(), true);

    if(selected_prefs == nullptr)
        selected_prefs = network_prefs_add_prefs(cfg, map_network_technology(edit.get_selected_technology()));

    if(patch_request != nullptr)
        patch_request(req, *service);

    auto wps_mode = apply_changes_to_prefs(req, selected_prefs)
        ? handle_set_wireless_config(
            req, service->get_technology(),
            service->get_technology() == Connman::Technology::WLAN
            ? &static_cast<const Connman::Service<Connman::Technology::WLAN> *>(service)->get_tech_data().security_
            : nullptr,
            selected_prefs, out_wps_network_name, out_wps_network_ssid,
            have_new_wlan_passphrase)
        : Network::WPSMode::INVALID;

    switch(wps_mode)
    {
      case Network::WPSMode::NONE:
        if(network_prefs_write_to_file(cfg) < 0)
            wps_mode = Network::WPSMode::INVALID;

        break;

      case Network::WPSMode::INVALID:
      case Network::WPSMode::DIRECT:
      case Network::WPSMode::SCAN:
      case Network::WPSMode::ABORT:
        break;
    }

    network_prefs_close(cfg);

    return wps_mode;
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

    if(sdata.active_.dns_servers_.is_known() &&
       !sdata.active_.dns_servers_.get().empty())
        return false;

    if(!sdata.active_.ipsettings_v4_.is_known())
        return false;

    const auto &settings(sdata.active_.ipsettings_v4_.get());

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

/* check if switching to WLAN service in case WPS mode was requested while
 * Ethernet is selected, but the Ethernet service is either unconfigured or was
 * configured by IPv4LL */
static bool should_auto_switch_to_wlan(Connman::Technology active_tech,
                                       Connman::Technology target_tech,
                                       const Network::ConfigRequest &req)
{
    switch(target_tech)
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
      case Connman::Technology::ETHERNET:
        return false;

      case Connman::Technology::WLAN:
        break;
    }

    switch(active_tech)
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
      case Connman::Technology::WLAN:
        return false;

      case Connman::Technology::ETHERNET:
        /* so we may want to go from Ethernet to WLAN */
        break;
    }

    /* only switch for WPS */
    if(req.wlan_security_mode_ != "wps")
        return false;

    LOGGED_LOCK_CONTEXT_HINT;
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
    }

    return result;
}

static bool process_config_request_from_spi_slave(
        NetworkConfigWriteData &cfg_wd, ShutdownGuard &shutdown_guard,
        const std::function<void(Network::ConfigRequest &, const Connman::ServiceBase &)> &patch_request)
{
    if(should_auto_switch_to_wlan(cfg_wd.get_edit_state().get_selected_technology(),
                                  cfg_wd.get_configuration_request().wlan_security_mode_.is_known()
                                  ? Connman::Technology::WLAN
                                  : Connman::Technology::UNKNOWN_TECHNOLOGY,
                                  cfg_wd.get_configuration_request()))
        cfg_wd.switch_technology(Connman::Technology::WLAN);

    {
    LOGGED_LOCK_CONTEXT_HINT;
    const auto locked_devices(Connman::NetworkDeviceList::get_singleton_const());
    const auto &devices(locked_devices.first);

    msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
              "Writing new network configuration for MAC address %s",
              devices.get_auto_select_mac_address(cfg_wd.get_edit_state().get_selected_technology()).get_string().c_str());
    }

    shutdown_guard_lock(&shutdown_guard);
    std::array<char, NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE> current_wlan_service_name;
    std::unique_ptr<std::string> wps_network_name;
    std::unique_ptr<std::string> wps_network_ssid;
    bool have_new_wlan_passphrase = false;
    const Network::WPSMode wps_mode = modify_network_configuration(
            cfg_wd.get_edit_state(),
            cfg_wd.get_configuration_request_rw(),
            shutdown_guard, patch_request,
            current_wlan_service_name, wps_network_name, wps_network_ssid,
            have_new_wlan_passphrase);
    shutdown_guard_unlock(&shutdown_guard);

    log_assert((wps_mode == Network::WPSMode::DIRECT &&
                (wps_network_name != nullptr || wps_network_ssid != nullptr)) ||
               (wps_mode != Network::WPSMode::DIRECT &&
                (wps_network_name == nullptr && wps_network_ssid == nullptr)));

    const Connman::Technology tech(cfg_wd.cancel_edit_mode());

    switch(wps_mode)
    {
      case Network::WPSMode::INVALID:
        Connman::cancel_wps();
        break;

      case Network::WPSMode::NONE:
        Connman::connect_to_service(map_network_technology(tech),
                                    current_wlan_service_name.data(),
                                    true, have_new_wlan_passphrase);
        return true;

      case Network::WPSMode::DIRECT:
        log_assert(tech == Connman::Technology::WLAN);
        Connman::connect_to_wps_service(
            wps_network_name != nullptr ? wps_network_name->c_str() : nullptr,
            wps_network_ssid != nullptr ? wps_network_ssid->c_str() : nullptr,
            current_wlan_service_name.data());
        return true;

      case Network::WPSMode::SCAN:
        log_assert(tech == Connman::Technology::WLAN);
        Connman::connect_to_wps_service(nullptr, nullptr,
                                        current_wlan_service_name.data());
        return true;

      case Network::WPSMode::ABORT:
        Connman::cancel_wps();
        return true;
    }

    return false;
}

/*!
 * Write changes received via D-Bus to file.
 *
 * \attention
 *     Must be called with the #ShutdownGuard from #nwstatus_data locked.
 */
static Network::WPSMode
modify_network_configuration_from_external_request(
        Network::ConfigRequest &req,
        Connman::Technology target_tech,
        const ShutdownGuard &sg,
        std::array<char, NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE> &previous_wlan_name_buffer,
        std::unique_ptr<std::string> &out_wps_network_name,
        std::unique_ptr<std::string> &out_wps_network_ssid,
        bool &have_new_wlan_passphrase)
{
    if(shutdown_guard_is_shutting_down_unlocked(&sg))
    {
        msg_info("Not writing network configuration during shutdown.");
        return Network::WPSMode::INVALID;
    }

    struct network_prefs *ethernet_prefs;
    struct network_prefs *wlan_prefs;
    struct network_prefs_handle *cfg =
        network_prefs_open_rw(&ethernet_prefs, &wlan_prefs);

    if(cfg == nullptr)
        return Network::WPSMode::INVALID;

    struct network_prefs *selected_prefs =
        target_tech == Connman::Technology::ETHERNET ? ethernet_prefs : wlan_prefs;

    network_prefs_generate_service_name(target_tech == Connman::Technology::ETHERNET
                                        ? nullptr
                                        : selected_prefs,
                                        previous_wlan_name_buffer.data(),
                                        previous_wlan_name_buffer.size(), true);

    if(selected_prefs == nullptr)
        selected_prefs = network_prefs_add_prefs(cfg, map_network_technology(target_tech));

    auto wps_mode = apply_changes_to_prefs(req, selected_prefs)
        ? handle_set_wireless_config(req, target_tech, nullptr,
                                     selected_prefs, out_wps_network_name,
                                     out_wps_network_ssid, have_new_wlan_passphrase)
        : Network::WPSMode::INVALID;

    switch(wps_mode)
    {
      case Network::WPSMode::NONE:
        if(network_prefs_write_to_file(cfg) < 0)
            wps_mode = Network::WPSMode::INVALID;

        break;

      case Network::WPSMode::INVALID:
      case Network::WPSMode::DIRECT:
      case Network::WPSMode::SCAN:
      case Network::WPSMode::ABORT:
        break;
    }

    network_prefs_close(cfg);

    return wps_mode;
}

static bool check_back_with_existing_devices(
        const Connman::Address<Connman::AddressType::MAC> &mac,
        bool &is_device_with_given_mac_present,
        Connman::Technology &target_tech)
{
    LOGGED_LOCK_CONTEXT_HINT;
    const auto locked_devices(Connman::NetworkDeviceList::get_singleton_const());
    const auto &devices(locked_devices.first);
    const auto device(devices[mac]);

    is_device_with_given_mac_present = device != nullptr && device->is_real_;

    switch(target_tech)
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
        if(device == nullptr)
        {
            msg_error(0, LOG_ERR,
                      "Cannot figure out technology of non-existent device "
                      "for network configuration request for MAC address %s",
                      mac.get_string().c_str());
            return false;
        }

        target_tech = device->technology_;
        return true;

      case Connman::Technology::ETHERNET:
      case Connman::Technology::WLAN:
        break;
    }

    if(device == nullptr)
        return true;

    if(target_tech == device->technology_)
        return true;

    msg_error(0, LOG_ERR,
              "Technology of device with MAC address %s differs from "
              "requested technology",
              mac.get_string().c_str());
    return false;
}

static bool connect_to_chosen_service(Network::WPSMode wps_mode,
                                      bool immediate_activation,
                                      Connman::Technology target_tech,
                                      const char *service_to_be_disabled,
                                      bool have_new_wlan_passphrase,
                                      const std::string *const wps_network_name,
                                      const std::string *const wps_network_ssid)
{
    switch(wps_mode)
    {
      case Network::WPSMode::INVALID:
        if(immediate_activation)
            Connman::cancel_wps();

        break;

      case Network::WPSMode::NONE:
        Connman::connect_to_service(map_network_technology(target_tech),
                                    service_to_be_disabled, immediate_activation,
                                    have_new_wlan_passphrase);
        return true;

      case Network::WPSMode::DIRECT:
        log_assert(target_tech == Connman::Technology::WLAN);

        if(immediate_activation)
            Connman::connect_to_wps_service(
                wps_network_name != nullptr ? wps_network_name->c_str() : nullptr,
                wps_network_ssid != nullptr ? wps_network_ssid->c_str() : nullptr,
                service_to_be_disabled);

        return true;

      case Network::WPSMode::SCAN:
        log_assert(target_tech == Connman::Technology::WLAN);

        if(immediate_activation)
            Connman::connect_to_wps_service(nullptr, nullptr, service_to_be_disabled);

        return true;

      case Network::WPSMode::ABORT:
        if(immediate_activation)
            Connman::cancel_wps();

        return true;
    }

    return false;
}

static bool process_external_config_request(
        Network::ConfigRequest &config_request,
        const Connman::Address<Connman::AddressType::MAC> &mac,
        Connman::Technology target_tech, Network::AccessPointManager &apman,
        ShutdownGuard &shutdown_guard)
{
    bool is_device_with_given_mac_present;

    if(!check_back_with_existing_devices(mac, is_device_with_given_mac_present,
                                         target_tech))
        return false;

    if(!is_device_with_given_mac_present)
    {
        msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                  "Writing network configuration for non-existent devices "
                  "not supported yet due to low-level protocol limitation");
        return false;
    }

    msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                "Writing new network configuration for MAC address %s (%s)",
                mac.get_string().c_str(),
                target_tech == Connman::Technology::WLAN ? "WLAN" : "Ethernet");

    shutdown_guard_lock(&shutdown_guard);
    std::array<char, NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE> current_wlan_service_name;
    std::unique_ptr<std::string> wps_network_name;
    std::unique_ptr<std::string> wps_network_ssid;
    bool have_new_wlan_passphrase = false;
    Network::WPSMode wps_mode = modify_network_configuration_from_external_request(
            config_request, target_tech, shutdown_guard,
            current_wlan_service_name, wps_network_name, wps_network_ssid,
            have_new_wlan_passphrase);
    shutdown_guard_unlock(&shutdown_guard);

    if(!is_device_with_given_mac_present)
    {
        switch(wps_mode)
        {
          case Network::WPSMode::INVALID:
            return false;

          case Network::WPSMode::NONE:
            break;

          case Network::WPSMode::DIRECT:
          case Network::WPSMode::SCAN:
            msg_info("Cannot start WPS on non-existent device");
            break;

          case Network::WPSMode::ABORT:
            msg_info("Cannot abort WPS on non-existent device");
            break;
        }

        return true;
    }

    bool immediate_activation = true;

    switch(config_request.when_.get())
    {
      case Network::ConfigRequest::ApplyWhen::NEVER:
        return true;

      case Network::ConfigRequest::ApplyWhen::ON_AUTO_CONNECT:
        immediate_activation = false;
        break;

      case Network::ConfigRequest::ApplyWhen::NOW:
        break;
    }

    /* work around problems with capturing by move and keeping the resulting
     * lambda movable */
    std::shared_ptr<std::string> wps_network_name_s = std::move(wps_network_name);
    std::shared_ptr<std::string> wps_network_ssid_s = std::move(wps_network_ssid);

    if(immediate_activation)
    {
        auto connect_later =
            [wps_mode,
             /* cppcheck-suppress shadowVar */ immediate_activation,
             target_tech, current_wlan_service_name,
             /* cppcheck-suppress shadowVar */ have_new_wlan_passphrase,
             /* cppcheck-suppress shadowVar */ wps_network_name_s,
             wps_network_ssid_s]
            (Network::AccessPoint::RequestResult result,
             Network::AccessPoint::Error error,
             Network::AccessPoint::Status status)
            {
                if(result == Network::AccessPoint::RequestResult::OK &&
                   status == Network::AccessPoint::Status::DISABLED)
                {
                    connect_to_chosen_service(wps_mode, immediate_activation, target_tech,
                                              current_wlan_service_name.data(),
                                              have_new_wlan_passphrase,
                                              wps_network_name_s.get(),
                                              wps_network_ssid_s.get());
                }
            };

        if(apman.deactivate(std::move(connect_later)))
            return true;
    }

    return connect_to_chosen_service(wps_mode, immediate_activation, target_tech,
                                     current_wlan_service_name.data(),
                                     have_new_wlan_passphrase,
                                     wps_network_name_s.get(),
                                     wps_network_ssid_s.get());
}

static NetworkConfigWriteData nwconfig_write_data;
static std::unique_ptr<NetworkStatusData> nwstatus_data;

void Regs::NetworkConfig::init()
{
    if(nwstatus_data != nullptr)
        return;

    nwconfig_write_data.init();
    nwstatus_data = std::make_unique<NetworkStatusData>();
}

void Regs::NetworkConfig::deinit()
{
    nwstatus_data = nullptr;
}

bool Regs::NetworkConfig::request_configuration_for_mac(
        Network::ConfigRequest &config_request,
        const Connman::Address<Connman::AddressType::MAC> &mac,
        Connman::Technology tech, Network::AccessPointManager &apman)
{
    if(config_request.empty())
    {
        /* nothing to do */
        return true;
    }

    LOGGED_LOCK_CONTEXT_HINT;
    const auto lock(nwconfig_write_data.lock());
    return process_external_config_request(config_request, mac, tech, apman,
                                           nwstatus_data->shutdown_guard());
}

int Regs::NetworkConfig::DCP::write_53_active_ip_profile(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 53 handler %p %zu", data, length);

    if(data_length_is_unexpected(length, 1))
        return -1;

    if(data[0] != 0)
        return -1;

    if(!nwconfig_write_data.may_change_config())
        return -1;

    if(!nwconfig_write_data.have_requests())
    {
        /* nothing to do */
        nwconfig_write_data.cancel_edit_mode();
        return 0;
    }

    if(!nwconfig_write_data.get_configuration_request().when_.is_known())
        BUG("Network configuration request application time point unknown");
    else if(nwconfig_write_data.get_configuration_request().when_ != Network::ConfigRequest::ApplyWhen::NOW)
        BUG("Unexpected network configuration request application time point");

    LOGGED_LOCK_CONTEXT_HINT;
    const auto lock(nwconfig_write_data.lock());
    return process_config_request_from_spi_slave(nwconfig_write_data,
                nwstatus_data->shutdown_guard(),
                [] (Network::ConfigRequest &req, const Connman::ServiceBase &service)
                {
                    move_dns_servers_to_config_request(nwconfig_write_data, req, service);
                }) ? 0 : -1;
}

int Regs::NetworkConfig::DCP::write_54_selected_ip_profile(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 54 handler %p %zu", data, length);

    if(data_length_is_unexpected(length, 1))
        return -1;

    if(data[0] != 0)
        return -1;

    LOGGED_LOCK_CONTEXT_HINT;
    const auto locked_services(Connman::ServiceList::get_singleton_const());
    const auto &services(locked_services.first);
    const auto tech =
        nwstatus_data->fixup_active_technology(determine_active_network_technology(services, false));

    return nwconfig_write_data.enter_edit_mode(tech) ? 0 : -1;
}

static void fill_network_status_register_response(uint8_t *response)
{
    const auto mode(Connman::get_networking_mode());

    switch(mode)
    {
      case Connman::Mode::REGULAR:
      case Connman::Mode::NONE:
        response[0] = NETWORK_STATUS_IPV4_NOT_CONFIGURED;
        response[1] = NETWORK_STATUS_DEVICE_NONE;
        response[2] = NETWORK_STATUS_CONNECTION_NONE;

        if(mode == Connman::Mode::NONE)
            return;

        break;

      case Connman::Mode::FAKE_CONNMAN:
        response[0] = NETWORK_STATUS_IPV4_DHCP;
        response[1] = NETWORK_STATUS_DEVICE_ETHERNET;
        response[2] = NETWORK_STATUS_CONNECTION_CONNECTED;
        return;
    }

    /* we must do this before locking the service list below */
    bool is_wps;
    bool is_connecting = Connman::is_connecting(&is_wps);

    LOGGED_LOCK_CONTEXT_HINT;
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

    if(service->get_service_data().active_.ipsettings_v4_.is_known())
    {
        const auto &settings(service->get_service_data().active_.ipsettings_v4_.get());

        if(settings.is_configuration_valid())
        {
            response[0] = map_dhcp_method(settings.get_dhcp_method());
            response[2] |= NETWORK_STATUS_CONNECTION_CONNECTED;
        }
    }

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

ssize_t Regs::NetworkConfig::DCP::read_50_network_status(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 50 handler %p %zu", response, length);

    if(data_length_is_unexpected(length, NetworkStatusData::RESPONSE_SIZE))
        return -1;

    fill_network_status_register_response(response);
    nwstatus_data->store_network_status(response, length);

    return length;
}

static size_t copy_locally_administered_mac(uint8_t *response)
{
    const char local_address[] = "02:00:00:00:00:00";
    memcpy(response, local_address, sizeof(local_address));
    return sizeof(local_address);
}

ssize_t Regs::NetworkConfig::DCP::read_51_mac_address(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 51 handler %p %zu", response, length);

    if(data_length_is_unexpected(length, Connman::AddressTraits<Connman::AddressType::MAC>::ADDRESS_STRING_LENGTH_MAX + 1))
        return -1;

    if(length < Connman::AddressTraits<Connman::AddressType::MAC>::ADDRESS_STRING_LENGTH_MAX)
        return -1;

    LOGGED_LOCK_CONTEXT_HINT;
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

ssize_t Regs::NetworkConfig::DCP::read_55_dhcp_enabled(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 55 handler %p %zu", response, length);

    if(data_length_is_unexpected(length, 1))
        return -1;

    if(nwconfig_write_data.get_edit_state().is_in_edit_mode() &&
       nwconfig_write_data.get_configuration_request().dhcpv4_mode_.is_known())
        response[0] = nwconfig_write_data.get_configuration_request().is_dhcpv4_mode();
    else
        response[0] = query_dhcp_mode(nwconfig_write_data.get_edit_state());

    return length;
}

int Regs::NetworkConfig::DCP::write_55_dhcp_enabled(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 55 handler %p %zu", data, length);

    if(data_length_is_unexpected(length, 1))
        return -1;

    if(!nwconfig_write_data.may_change_config())
        return -1;

    if(data[0] > 1)
    {
        msg_error(EINVAL, LOG_ERR,
                  "Received invalid DHCP configuration parameter 0x%02x",
                  data[0]);
        return -1;
    }

    msg_info("%sable DHCP", data[0] == 0 ? "Dis" : "En");

    auto &config_request(nwconfig_write_data.get_configuration_request_rw());

    if(data[0] == 0)
        config_request.dhcpv4_mode_ = "off";
    else
    {
        config_request.dhcpv4_mode_ = "dhcp";
        config_request.ipv4_address_ = "";
        config_request.ipv4_netmask_ = "";
        config_request.ipv4_gateway_ = "";
        config_request.dns_servers_.set_known();
        config_request.dns_servers_.get_rw().clear();
    }

    return 0;
}

static ssize_t
read_out_parameter(const ConfigRequestEditState &edit,
                   const std::function<ssize_t(const Connman::ServiceBase &, char *, size_t)> &copy,
                   Connman::Technology required_technology,
                   uint8_t *response, size_t max_response_length)
{
    LOGGED_LOCK_CONTEXT_HINT;
    const auto locked_services(Connman::ServiceList::get_singleton_const());
    const auto &services(locked_services.first);
    const Connman::ServiceBase *service(get_connman_service_data(edit, services));

    if(service != nullptr &&
       (service->get_technology() == required_technology ||
        required_technology == Connman::Technology::UNKNOWN_TECHNOLOGY))
    {
        return copy(*service, reinterpret_cast<char *>(response), max_response_length);
    }

    return -1;
}

static ssize_t
read_out_parameter(const ConfigRequestEditState &edit,
                   const Maybe<std::string> &edited_ipv4_parameter,
                   bool expected_length_includes_zero_terminator,
                   const std::function<ssize_t(const Connman::ServiceBase &, char *, size_t)> &copy,
                   Connman::Technology required_technology,
                   uint8_t *response, size_t max_response_length)
{
    const size_t length_decrease = expected_length_includes_zero_terminator ? 0 : 1;

    if(data_length_is_unexpectedly_small(max_response_length,
                                         edited_ipv4_parameter.get().length() + 1 - length_decrease))
        return -1;

    response[0] = '\0';

    ssize_t written;

    if(edit.is_in_edit_mode() && edited_ipv4_parameter.is_known())
        written = std::copy(edited_ipv4_parameter.get().begin(),
                            edited_ipv4_parameter.get().end() + 1 - length_decrease,
                            response) - response;
    else
        written = read_out_parameter(edit, copy, required_technology,
                                     response, max_response_length);

    if(written < 0)
        return written;

    return (expected_length_includes_zero_terminator || size_t(written) <= max_response_length
            ? written
            : max_response_length);
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

ssize_t Regs::NetworkConfig::DCP::read_56_ipv4_address(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 56 handler %p %zu", response, length);

    return read_out_parameter(nwconfig_write_data.get_edit_state(),
                nwconfig_write_data.get_configuration_request().ipv4_address_, true,
                [] (const Connman::ServiceBase &s, char *out, size_t len) -> ssize_t
                {
                    if(s.get_service_data().active_.ipsettings_v4_.is_known())
                        return copy_to_array(s.get_service_data().active_.ipsettings_v4_.get().get_address().get_string(),
                                             out, len);
                    else
                        return -1;
                },
                Connman::Technology::UNKNOWN_TECHNOLOGY,
                response, length);
}

ssize_t Regs::NetworkConfig::DCP::read_57_ipv4_netmask(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 57 handler %p %zu", response, length);

    return read_out_parameter(nwconfig_write_data.get_edit_state(),
                nwconfig_write_data.get_configuration_request().ipv4_netmask_, true,
                [] (const Connman::ServiceBase &s, char *out, size_t len) -> ssize_t
                {
                    if(s.get_service_data().active_.ipsettings_v4_.is_known())
                        return copy_to_array(s.get_service_data().active_.ipsettings_v4_.get().get_netmask().get_string(),
                                             out, len);
                    else
                        return -1;
                },
                Connman::Technology::UNKNOWN_TECHNOLOGY,
                response, length);
}

ssize_t Regs::NetworkConfig::DCP::read_58_ipv4_gateway(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 58 handler %p %zu", response, length);

    return read_out_parameter(nwconfig_write_data.get_edit_state(),
                nwconfig_write_data.get_configuration_request().ipv4_gateway_, true,
                [] (const Connman::ServiceBase &s, char *out, size_t len) -> ssize_t
                {
                    if(s.get_service_data().active_.ipsettings_v4_.is_known())
                        return copy_to_array(s.get_service_data().active_.ipsettings_v4_.get().get_gateway().get_string(),
                                             out, len);
                    else
                        return -1;
                },
                Connman::Technology::UNKNOWN_TECHNOLOGY,
                response, length);
}

ssize_t Regs::NetworkConfig::DCP::read_62_primary_dns(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 62 handler %p %zu", response, length);

    return read_out_parameter(nwconfig_write_data.get_edit_state(),
                nwconfig_write_data.get_primary_dns_server(), true,
                [] (const Connman::ServiceBase &s, char *out, size_t len) -> ssize_t
                {
                    if(!s.get_service_data().active_.dns_servers_.is_known())
                        return -1;

                    // cppcheck-suppress shadowVar
                    const auto &servers(s.get_service_data().active_.dns_servers_.get());

                    if(!servers.empty())
                        return copy_to_array(servers[0], out, len);
                    else
                        return -1;
                },
                Connman::Technology::UNKNOWN_TECHNOLOGY,
                response, length);
}

ssize_t Regs::NetworkConfig::DCP::read_63_secondary_dns(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 63 handler %p %zu", response, length);

    return read_out_parameter(nwconfig_write_data.get_edit_state(),
                nwconfig_write_data.get_secondary_dns_server(), true,
                [] (const Connman::ServiceBase &s, char *out, size_t len) -> ssize_t
                {
                    if(!s.get_service_data().active_.dns_servers_.is_known())
                        return -1;

                    // cppcheck-suppress shadowVar
                    const auto &servers(s.get_service_data().active_.dns_servers_.get());

                    if(servers.size() >= 2)
                        return copy_to_array(servers[1], out, len);
                    else
                        return -1;

                },
                Connman::Technology::UNKNOWN_TECHNOLOGY,
                response, length);
}

static int copy_ipv4_address(Maybe<std::string> &dest,
                             const uint8_t *const data, size_t length,
                             bool is_empty_ok)
{
    if(!Utils::trim_trailing_zero_padding(data, length) && !is_empty_ok)
        return -1;

    size_t i = 0;
    std::string addr;

    while(i < length)
    {
        while(i < length && data[i] == '0')
            ++i;

        if(i >= length || data[i] == '.')
            addr += '0';

        while(i < length)
        {
            const char ch = data[i++];
            addr += ch;
            if(ch == '.')
                break;
        }
    }

    if(!is_valid_ip_address_string(addr, is_empty_ok))
        return -1;

    dest = std::move(addr);

    return 0;
}

int Regs::NetworkConfig::DCP::write_56_ipv4_address(const uint8_t *data, size_t length)
{
    if(!nwconfig_write_data.may_change_config())
        return -1;

    return copy_ipv4_address(nwconfig_write_data.get_configuration_request_rw().ipv4_address_,
                             data, length, false);
}

int Regs::NetworkConfig::DCP::write_57_ipv4_netmask(const uint8_t *data, size_t length)
{
    if(!nwconfig_write_data.may_change_config())
        return -1;

    return copy_ipv4_address(nwconfig_write_data.get_configuration_request_rw().ipv4_netmask_,
                             data, length, false);
}

int Regs::NetworkConfig::DCP::write_58_ipv4_gateway(const uint8_t *data, size_t length)
{
    if(!nwconfig_write_data.may_change_config())
        return -1;

    return copy_ipv4_address(nwconfig_write_data.get_configuration_request_rw().ipv4_gateway_,
                             data, length, false);
}

int Regs::NetworkConfig::DCP::write_62_primary_dns(const uint8_t *data, size_t length)
{
    if(!nwconfig_write_data.may_change_config())
        return -1;

    return copy_ipv4_address(nwconfig_write_data.get_primary_dns_server_rw(),
                             data, length, true);
}

int Regs::NetworkConfig::DCP::write_63_secondary_dns(const uint8_t *data, size_t length)
{
    if(!nwconfig_write_data.may_change_config())
        return -1;

    return copy_ipv4_address(nwconfig_write_data.get_secondary_dns_server_rw(),
                             data, length, true);
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

ssize_t Regs::NetworkConfig::DCP::read_92_wlan_security(uint8_t *response, size_t length)
{
    return read_out_parameter(nwconfig_write_data.get_edit_state(),
                nwconfig_write_data.get_configuration_request().wlan_security_mode_, false,
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

int Regs::NetworkConfig::DCP::write_92_wlan_security(const uint8_t *data, size_t length)
{
    if(!nwconfig_write_data.may_change_config())
        return -1;

    auto &s(nwconfig_write_data.get_configuration_request_rw().wlan_security_mode_);

    s.set_known();
    s.get_rw().clear();
    std::copy(data, data + length, std::back_inserter(s.get_rw()));

    return 0;
}

ssize_t Regs::NetworkConfig::DCP::read_93_ibss(uint8_t *response, size_t length)
{
    if(data_length_is_unexpectedly_small(length, 8))
        return -1;

    strcpy((char *)response, "false");

    return 6;
}

int Regs::NetworkConfig::DCP::write_93_ibss(const uint8_t *data, size_t length)
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

ssize_t Regs::NetworkConfig::DCP::read_94_ssid(uint8_t *response, size_t length)
{
    ssize_t result =
        read_out_parameter(nwconfig_write_data.get_edit_state(),
                nwconfig_write_data.get_configuration_request().wlan_ssid_ascii_, false,
                [] (const Connman::ServiceBase &s, char *out, size_t len) -> ssize_t
                {
                    const auto *const d(get_wlan_tech_data(s));

                    if(d != nullptr && d->network_name_.is_known())
                        return copy_to_array(d->network_name_.get(), out, len);
                    else
                        return -2;
                },
                Connman::Technology::WLAN,
                response, length);

    if(result == -1 || result > 1)
        return result;

    if(result >= 0 &&
       nwconfig_write_data.get_edit_state().is_in_edit_mode() &&
       nwconfig_write_data.get_configuration_request().wlan_ssid_ascii_.is_known())
        return result;

    /* binary SSID */
    result = read_out_parameter(nwconfig_write_data.get_edit_state(),
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

int Regs::NetworkConfig::DCP::write_94_ssid(const uint8_t *data, size_t length)
{
    if(length == 0)
    {
        msg_error(EINVAL, LOG_ERR, "Empty SSID rejected");
        return -1;
    }

    if(!nwconfig_write_data.may_change_config())
        return -1;

    auto &s(nwconfig_write_data.get_configuration_request_rw().wlan_ssid_ascii_);

    s.set_known();
    s.get_rw().clear();
    std::copy(data, data + length, std::back_inserter(s.get_rw()));

    return 0;
}

ssize_t Regs::NetworkConfig::DCP::read_101_wpa_cipher(uint8_t *response, size_t length)
{
    if(data_length_is_unexpectedly_small(length, 8))
        return -1;

    strcpy((char *)response, "AES");

    return 4;
}

int Regs::NetworkConfig::DCP::write_101_wpa_cipher(const uint8_t *data, size_t length)
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

ssize_t Regs::NetworkConfig::DCP::read_102_passphrase(uint8_t *response, size_t length)
{
    if(!nwconfig_write_data.get_edit_state().is_in_edit_mode())
    {
        msg_error(0, LOG_NOTICE,
                  "Passphrase cannot be read out while in non-edit mode");
        return -1;
    }

    auto &sa(nwconfig_write_data.get_configuration_request().wlan_wpa_passphrase_ascii_);
    auto &sh(nwconfig_write_data.get_configuration_request().wlan_wpa_passphrase_hex_);
    auto &s(sa.is_known() ? sa : sh);

    if(!s.is_known())
    {
        msg_info("No passphrase set yet");
        return 0;
    }

    if(s.get().empty())
    {
        msg_info("Passphrase set, but empty");
        return 0;
    }

    if(data_length_is_unexpectedly_small(length, s.get().length()))
        return -1;

    std::copy(s.get().begin(), s.get().end(), response);

    return s.get().length();
}

int Regs::NetworkConfig::DCP::write_102_passphrase(const uint8_t *data, size_t length)
{
    if(!nwconfig_write_data.may_change_config())
        return -1;

    auto &config_request(nwconfig_write_data.get_configuration_request_rw());

    if(length == 0)
    {
        config_request.wlan_wpa_passphrase_ascii_ = "";
        config_request.wlan_wpa_passphrase_hex_.set_unknown();
        return 0;
    }

    bool passphrase_is_hex = true;
    bool passphrase_is_ascii = true;
    std::string pass;

    for(size_t i = 0; i < length; ++i)
    {
        uint8_t ch = data[i];
        pass += ch;

        if(ch < (uint8_t)' ' || ch > (uint8_t)'~')
            passphrase_is_ascii = false;
        else
        {
            ch = tolower(ch);

            if(!isdigit(ch) && !(ch >= 'a' && ch <= 'f'))
                passphrase_is_hex = false;
        }
    }

    if(!passphrase_is_ascii)
    {
        msg_error(EINVAL, LOG_ERR,
                  "Invalid passphrase: expected ASCII passphrase");
        return -1;
    }

    if(length == 64 && passphrase_is_hex)
    {
        config_request.wlan_wpa_passphrase_hex_ = pass;
        config_request.wlan_wpa_passphrase_ascii_.set_unknown();
    }
    else
    {
        config_request.wlan_wpa_passphrase_hex_.set_unknown();
        config_request.wlan_wpa_passphrase_ascii_ = pass;
    }

    return 0;
}

void Regs::NetworkConfig::interfaces_changed()
{
    std::array<uint8_t, NetworkStatusData::RESPONSE_SIZE> response;
    fill_network_status_register_response(response.data());

    if(nwstatus_data->is_network_status_different(response))
        Regs::get_data().register_changed_notification_fn(50);
}

void Regs::NetworkConfig::prepare_for_shutdown()
{
    (void)shutdown_guard_down(&nwstatus_data->shutdown_guard());
}

void Regs::NetworkConfig::set_primary_technology(Connman::Technology tech)
{
    nwstatus_data->set_fallback_technology(tech);
}
