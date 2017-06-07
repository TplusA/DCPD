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

#include <algorithm>
#include <cinttypes>

#include "dbus_handlers_connman_manager.h"
#include "dbus_handlers_connman_manager_glue.h"
#include "dbus_iface_deep.h"
#include "dcpregs_networkconfig.h"
#include "connman.h"
#include "connman_agent.h"
#include "connman_common.h"
#include "connman_service_list.hh"
#include "network_device_list.hh"
#include "networkprefs.h"
#include "messages.h"

class WLANConnectionState
{
  public:
    enum class State
    {
        IDLE,
        ABOUT_TO_CONNECT,
        ABOUT_TO_CONNECT_WPS,
        CONNECTING,
        CONNECTING_WPS,
        DONE,
        FAILED,
        ABORTED_WPS,
    };

  private:
    std::vector<std::string> service_names_;
    size_t next_wps_candidate_;
    State state_;

  public:
    WLANConnectionState(const WLANConnectionState &) = delete;
    WLANConnectionState &operator=(const WLANConnectionState &) = delete;

    explicit WLANConnectionState():
        next_wps_candidate_(0),
        state_(State::IDLE)
    {}

    void reset()
    {
        service_names_.clear();
        next_wps_candidate_ = 0;
        state_ = State::IDLE;
    }

    void abort_wps()
    {
        switch(state_)
        {
          case WLANConnectionState::State::IDLE:
          case WLANConnectionState::State::ABOUT_TO_CONNECT:
          case WLANConnectionState::State::CONNECTING:
          case WLANConnectionState::State::DONE:
          case WLANConnectionState::State::FAILED:
          case WLANConnectionState::State::ABORTED_WPS:
            break;

          case WLANConnectionState::State::ABOUT_TO_CONNECT_WPS:
          case WLANConnectionState::State::CONNECTING_WPS:
            next_wps_candidate_ = service_names_.size();
            state_ = State::ABORTED_WPS;
            break;
        }
    }

    void about_to_connect_to(const std::string &service_name)
    {
        log_assert(state_ == State::IDLE);
        log_assert(!service_name.empty());
        service_names_.push_back(service_name);
        state_ = State::ABOUT_TO_CONNECT;
    }

    void about_to_connect_to(std::vector<std::string> &&service_names)
    {
        log_assert(state_ == State::IDLE);
        log_assert(!service_names.empty());
        service_names_ = std::move(service_names);
        state_ = State::ABOUT_TO_CONNECT_WPS;
    }

    bool about_to_connect_next()
    {
        log_assert(state_ == State::CONNECTING_WPS ||
                   state_ == State::ABORTED_WPS);

        if(next_wps_candidate_ < service_names_.size() &&
           ++next_wps_candidate_ < service_names_.size())
        {
            state_ = State::ABOUT_TO_CONNECT_WPS;
        }

        return state_ == State::ABOUT_TO_CONNECT_WPS;
    }

    void start_connecting_direct()
    {
        log_assert(state_ == State::ABOUT_TO_CONNECT);
        state_ = State::CONNECTING;
    }

    void start_connecting_wps()
    {
        log_assert(state_ == State::ABOUT_TO_CONNECT_WPS);
        log_assert(next_wps_candidate_ < service_names_.size());
        state_ = State::CONNECTING_WPS;
    }

    void finished_successfully()
    {
        log_assert(state_ == State::CONNECTING ||
                   state_ == State::CONNECTING_WPS ||
                   state_ == State::ABORTED_WPS);
        state_ = State::DONE;
    }

    void finished_with_failure()
    {
        if(state_ == State::ABORTED_WPS)
            return;

        log_assert(state_ == State::CONNECTING ||
                   state_ == State::CONNECTING_WPS);
        state_ = State::FAILED;
    }

    void remove_pending_wps_service(const std::string &service_name)
    {
        log_assert(state_ == State::ABOUT_TO_CONNECT_WPS || state_ == State::CONNECTING_WPS);
        log_assert(!service_name.empty());

        if(next_wps_candidate_ >= service_names_.size())
            return;

        const auto it(std::find(service_names_.begin() + next_wps_candidate_,
                                service_names_.end(), service_name));

        if(it != service_names_.end())
            service_names_.erase(it);
    }

    State get_state() const { return state_; }

    bool is_wps_mode() const
    {
        return state_ == State::ABOUT_TO_CONNECT_WPS ||
               state_ == State::CONNECTING_WPS;
    }

    bool have_candidates() const
    {
        return next_wps_candidate_ < service_names_.size();
    }

    const std::string &get_service_name() const
    {
        log_assert(next_wps_candidate_ < service_names_.size());
        return service_names_[next_wps_candidate_];
    }
};

class DBusSignalManagerData
{
  public:
    GRecMutex lock;

    bool is_disabled;

    void (*schedule_connect_to_wlan)(void);
    void (*schedule_refresh_connman_services)(void);

    WLANConnectionState wlan_connection_state;

    DBusSignalManagerData(const DBusSignalManagerData &) = delete;
    DBusSignalManagerData &operator=(const DBusSignalManagerData &) = delete;

    explicit DBusSignalManagerData():
        is_disabled(false),
        schedule_connect_to_wlan(nullptr),
        schedule_refresh_connman_services(nullptr)
    {
        g_rec_mutex_init(&lock);
    }

    void init(void (*schedule_connect_to_wlan_fn)(),
              void (*schedule_refresh_connman_services_fn)(), bool is_enabled)
    {
        g_rec_mutex_init(&lock);
        is_disabled = !is_enabled;
        schedule_connect_to_wlan = schedule_connect_to_wlan_fn;
        schedule_refresh_connman_services = schedule_refresh_connman_services_fn;
        wlan_connection_state.reset();
        Connman::ServiceList::get_singleton_for_update().first.clear();
    }
};

static bool stop_wps(WLANConnectionState &state, bool emit_warning_if_idle)
{
    switch(state.get_state())
    {
      case WLANConnectionState::State::IDLE:
      case WLANConnectionState::State::ABOUT_TO_CONNECT:
      case WLANConnectionState::State::CONNECTING:
        if(emit_warning_if_idle)
            msg_info("Cannot stop WPS, not connecting");

        return false;

      case WLANConnectionState::State::DONE:
      case WLANConnectionState::State::FAILED:
      case WLANConnectionState::State::ABORTED_WPS:
        return true;

      case WLANConnectionState::State::ABOUT_TO_CONNECT_WPS:
      case WLANConnectionState::State::CONNECTING_WPS:
        break;
    }

    const std::string &service_name(state.get_service_name());

    msg_info("Stopping WPS connection with %s", service_name.c_str());

    connman_agent_set_wps_mode(false);
    connman_common_disconnect_service_by_object_path(service_name.c_str());
    state.abort_wps();

    return true;
}

static void service_connected(const char *service_name,
                              enum ConnmanCommonConnectServiceCallbackResult result,
                              void *user_data)
{
    auto *data = static_cast<DBusSignalManagerData *>(user_data);

    g_rec_mutex_lock(&data->lock);

    switch(result)
    {
      case CONNMAN_SERVICE_CONNECT_CONNECTED:
        msg_info("Connected to %s", service_name);
        data->wlan_connection_state.finished_successfully();
        break;

      case CONNMAN_SERVICE_CONNECT_FAILURE:
        msg_info("Failed connecting to %s", service_name);
        data->wlan_connection_state.finished_with_failure();
        break;

      case CONNMAN_SERVICE_CONNECT_DISCARDED:
        /* do not touch wlan_connection_state as it might be in use for another
         * WLAN connection attempt already */
        break;
    }

    g_rec_mutex_unlock(&data->lock);

    data->schedule_refresh_connman_services();
}

static void schedule_wlan_connect__unlocked(DBusSignalManagerData &data)
{
    log_assert(!data.wlan_connection_state.get_service_name().empty());

    connman_wlan_power_on();
    data.schedule_connect_to_wlan();

    msg_vinfo(MESSAGE_LEVEL_DEBUG,
              "***** Scheduled connect to WLAN *****");
}

static inline bool wps_bug_if(bool cond, const char *unknown)
{
    if(cond)
    {
        BUG("Connected via WPS, but %s unknown", unknown);
        return true;
    }
    else
        return false;
}

static void store_wlan_config(const Connman::ServiceBase *service)
{
    if(wps_bug_if(service == nullptr, "service"))
        return;

    const auto &s(static_cast<const Connman::Service<Connman::Technology::WLAN> &>(*service));
    const auto &t(s.get_tech_data());

    if(wps_bug_if(!t.security_.is_known(), "service security"))
        return;

    if(wps_bug_if(!t.network_name_.is_known() && !t.network_ssid_.is_known(), "service SSID"))
        return;

    struct network_prefs *dummy;
    struct network_prefs_handle *handle = network_prefs_open_rw(&dummy, &dummy);

    if(handle == nullptr)
        return;

    network_prefs_remove_prefs(handle, NWPREFSTECH_WLAN);

    struct network_prefs *wlan = network_prefs_add_prefs(handle, NWPREFSTECH_WLAN);

    if(wlan != nullptr)
    {
        network_prefs_put_wlan_config(wlan,
                                      t.network_name_.get().c_str(),
                                      t.network_ssid_.get().c_str(),
                                      t.security_.get().c_str(),
                                      nullptr);
        network_prefs_write_to_file(handle);
    }

    network_prefs_close(handle);
}

static void wps_connected(const char *service_name,
                          enum ConnmanCommonConnectServiceCallbackResult result,
                          void *user_data)
{
    auto &data(*static_cast<DBusSignalManagerData *>(user_data));
    bool leave_wps_mode = true;

    const auto locked_services(Connman::ServiceList::get_singleton_const());
    const auto &services(locked_services.first);

    g_rec_mutex_lock(&data.lock);

    switch(result)
    {
      case CONNMAN_SERVICE_CONNECT_CONNECTED:
        store_wlan_config(services[data.wlan_connection_state.get_service_name()]);
        data.wlan_connection_state.finished_successfully();
        break;

      case CONNMAN_SERVICE_CONNECT_FAILURE:
      case CONNMAN_SERVICE_CONNECT_DISCARDED:
        if(data.wlan_connection_state.about_to_connect_next())
        {
            leave_wps_mode = false;
            schedule_wlan_connect__unlocked(data);
        }
        else
            data.wlan_connection_state.finished_with_failure();

        break;
    }

    if(leave_wps_mode)
        connman_agent_set_wps_mode(false);

    g_rec_mutex_unlock(&data.lock);

    data.schedule_refresh_connman_services();
}

void dbussignal_connman_manager_connect_our_wlan(DBusSignalManagerData *data)
{
    g_rec_mutex_lock(&data->lock);

    switch(data->wlan_connection_state.get_state())
    {
      case WLANConnectionState::State::ABOUT_TO_CONNECT:
        data->wlan_connection_state.start_connecting_direct();

        if(!connman_common_connect_service_by_object_path(data->wlan_connection_state.get_service_name().c_str(),
                                                          service_connected,
                                                          data))
            service_connected(data->wlan_connection_state.get_service_name().c_str(),
                              CONNMAN_SERVICE_CONNECT_FAILURE, data);

        break;

      case WLANConnectionState::State::ABOUT_TO_CONNECT_WPS:
        data->wlan_connection_state.start_connecting_wps();

        if(!connman_common_connect_service_by_object_path(data->wlan_connection_state.get_service_name().c_str(),
                                                          wps_connected, data))
            wps_connected(data->wlan_connection_state.get_service_name().c_str(),
                              CONNMAN_SERVICE_CONNECT_FAILURE, data);

        break;

      case WLANConnectionState::State::IDLE:
      case WLANConnectionState::State::CONNECTING:
      case WLANConnectionState::State::CONNECTING_WPS:
      case WLANConnectionState::State::DONE:
      case WLANConnectionState::State::FAILED:
      case WLANConnectionState::State::ABORTED_WPS:
        BUG("Tried to connect to WLAN in state %d",
            static_cast<int>(data->wlan_connection_state.get_state()));
        break;
    }

    g_rec_mutex_unlock(&data->lock);
}

static bool ipv4_settings_are_different(const Maybe<Connman::IPSettings<Connman::AddressType::IPV4>> &maybe_settings,
                                        bool with_dhcp, const char *address,
                                        const char *nm, const char *gw,
                                        Connman::DHCPV4Method &system_dhcp_mode)
{
    if(!maybe_settings.is_known())
    {
        system_dhcp_mode = Connman::DHCPV4Method::UNKNOWN_METHOD;
        return false;
    }

    const auto &settings(maybe_settings.get());
    system_dhcp_mode = settings.get_dhcp_method();

    switch(system_dhcp_mode)
    {
      case Connman::DHCPV4Method::NOT_AVAILABLE:
      case Connman::DHCPV4Method::UNKNOWN_METHOD:
        break;

      case Connman::DHCPV4Method::ON:
      case Connman::DHCPV4Method::OFF:
        if((system_dhcp_mode == Connman::DHCPV4Method::ON && !with_dhcp) ||
           (system_dhcp_mode == Connman::DHCPV4Method::OFF && with_dhcp))
            return true;

        if(address != nullptr || nm != nullptr || gw != nullptr)
            return true;

        break;

      case Connman::DHCPV4Method::MANUAL:
        if(with_dhcp)
            return true;

        if(settings.get_address() != address ||
           settings.get_netmask() != nm ||
           settings.get_gateway() != gw)
            return true;

        break;

      case Connman::DHCPV4Method::FIXED:
        /* special case: cannot change the IPv4 parameters */
        break;
    }

    return false;
}

static bool nameservers_are_different(const Maybe<std::vector<std::string>> &dns_servers,
                                      const Connman::DHCPV4Method dhcp_method,
                                      const char *dns1, const char *dns2)
{
    if(!dns_servers.is_known())
        return false;

    const auto &servers(dns_servers.get());

    if(servers.size() > 0)
    {
        if((dns1 != nullptr && servers[0] != dns1) ||
           (dns1 == nullptr && dhcp_method != Connman::DHCPV4Method::ON && !servers[0].empty()))
            return true;
    }

    if(servers.size() > 1)
    {
        if((dns2 != nullptr && servers[1] != dns2) ||
           (dns2 == nullptr && dhcp_method != Connman::DHCPV4Method::ON && !servers[1].empty()))
            return true;
    }

    return false;
}

static void avoid_service(const Connman::Service<Connman::Technology::ETHERNET> *const service,
                          const std::string &service_name)
{

    log_assert(service != nullptr);
    log_assert(service->is_active());

    connman_common_disconnect_service_by_object_path(service_name.c_str());
}

static void avoid_service(const Connman::Service<Connman::Technology::WLAN> *const service,
                          const std::string &service_name)
{

    log_assert(service != nullptr);
    log_assert(service->is_active());

    connman_common_set_service_property(service_name.c_str(),
                                        "AutoConnect",
                                        g_variant_new_variant(g_variant_new_boolean(false)));
    connman_common_disconnect_service_by_object_path(service_name.c_str());
    connman_common_remove_service_by_object_path(service_name.c_str());
}

static bool avoid_service(const Connman::ServiceBase &service,
                          const std::string &service_name)
{
    switch(service.get_technology())
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
        break;

      case Connman::Technology::ETHERNET:
        avoid_service(dynamic_cast<const Connman::Service<Connman::Technology::ETHERNET> *>(&service),
                      service_name);
        return true;

      case Connman::Technology::WLAN:
        avoid_service(dynamic_cast<const Connman::Service<Connman::Technology::WLAN> *>(&service),
                      service_name);
        return true;
    }

    return false;
}

static bool configure_ipv4_settings(const Connman::ServiceBase &service,
                                    const std::string &service_name,
                                    const struct network_prefs *prefs)
{
    msg_vinfo(MESSAGE_LEVEL_DEBUG,
              "Configure IPv4 parameters for service %s",
              service_name.c_str());

    bool want_dhcp;
    const char *want_address;
    const char *want_netmask;
    const char *want_gateway;
    const char *want_dns1;
    const char *want_dns2;

    if(!network_prefs_get_ipv4_settings(prefs, &want_dhcp, &want_address,
                                        &want_netmask, &want_gateway,
                                        &want_dns1, &want_dns2))
    {
        avoid_service(service, service_name);
        return false;
    }

    Connman::DHCPV4Method system_dhcp_mode;
    const bool different_ipv4_config =
        ipv4_settings_are_different(service.get_service_data().ip_configuration_v4_,
                                    want_dhcp, want_address, want_netmask,
                                    want_gateway, system_dhcp_mode);
    const bool different_nameservers =
        different_ipv4_config
        ? false
        : nameservers_are_different(service.get_service_data().dns_servers_,
                                    system_dhcp_mode,
                                    want_dns1, want_dns2);

    if(!different_ipv4_config && !different_nameservers)
    {
        msg_vinfo(MESSAGE_LEVEL_DEBUG,
                  "Not configuring IPv4 parameters for %s: up to date",
                  service_name.c_str());
        return true;
    }

    GVariant *ipv4_config = NULL;
    GVariant *dns_config = NULL;

    if(different_ipv4_config)
    {
        GVariantBuilder builder;
        g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);

        if(want_dhcp)
            g_variant_builder_add(&builder, "{sv}", "Method", g_variant_new_string("dhcp"));
        else
        {
            g_variant_builder_add(&builder, "{sv}", "Method", g_variant_new_string("manual"));
            g_variant_builder_add(&builder, "{sv}", "Address", g_variant_new_string(want_address));
            g_variant_builder_add(&builder, "{sv}", "Netmask", g_variant_new_string(want_netmask));
            g_variant_builder_add(&builder, "{sv}", "Gateway", g_variant_new_string(want_gateway));
        }

        ipv4_config = g_variant_new_variant(g_variant_builder_end(&builder));
    }

    if(different_nameservers)
    {
        GVariantBuilder builder;
        g_variant_builder_init(&builder, G_VARIANT_TYPE_STRING_ARRAY);

        if(want_dns1 != NULL)
            g_variant_builder_add(&builder, "s", want_dns1);

        if(want_dns2 != NULL)
            g_variant_builder_add(&builder, "s", want_dns1);

        dns_config = g_variant_new_variant(g_variant_builder_end(&builder));
    }

    if(ipv4_config != NULL)
        connman_common_set_service_property(service_name.c_str(),
                                            "IPv4.Configuration", ipv4_config);

    if(dns_config != NULL)
        connman_common_set_service_property(service_name.c_str(),
                                            "Nameservers.Configuration",
                                            dns_config);

    return true;
}

/*!
 * Set network configuration for our WLAN.
 *
 * This function does not connect, it only informs ConnMan about configuration.
 * In case the configuratin is not available in our own configuration file, the
 * service is disconnnected and removed (if possible).
 *
 * \returns
 *     True in case WLAN connection should be established by the caller, false
 *     in case nothing needs to be done.
 */
static bool configure_our_wlan(const Connman::Service<Connman::Technology::WLAN> &service,
                               const std::string &service_name,
                               const struct network_prefs *prefs,
                               WLANConnectionState &wlan_connection_state,
                               bool make_it_favorite)
{
    switch(wlan_connection_state.get_state())
    {
      case WLANConnectionState::State::IDLE:
        break;

      case WLANConnectionState::State::DONE:
      case WLANConnectionState::State::FAILED:
      case WLANConnectionState::State::ABORTED_WPS:
        wlan_connection_state.reset();
        break;

      case WLANConnectionState::State::ABOUT_TO_CONNECT:
      case WLANConnectionState::State::ABOUT_TO_CONNECT_WPS:
      case WLANConnectionState::State::CONNECTING:
      case WLANConnectionState::State::CONNECTING_WPS:
        return false;
    }

    if(!configure_ipv4_settings(service, service_name, prefs))
        return false;

    const auto &service_data(service.get_service_data());

    msg_vinfo(MESSAGE_LEVEL_DEBUG,
              "Our WLAN is %sa favorite, auto-connect %s, "
              "make it favorite %d",
              service_data.is_favorite_.pick<const char *>("", "not ", "maybe "),
              service_data.is_auto_connect_.pick<const char *>("yes", "no", "maybe"),
              make_it_favorite);

    if(service_data.is_favorite_ == true)
    {
        if(service_data.is_auto_connect_ == false)
        {
            if(connman_common_set_service_property(service_name.c_str(),
                                                   "AutoConnect",
                                                   g_variant_new_variant(g_variant_new_boolean(true))) &&
               !service.is_active())
            {
                wlan_connection_state.about_to_connect_to(service_name);
                wlan_connection_state.start_connecting_direct();
            }
        }

        /* rely on auto-connect */
        return false;
    }

    if(service_data.is_favorite_ == false && make_it_favorite)
    {
        /* if this function returns true, then the caller will schedule a WLAN
         * connection attempt by calling #schedule_wlan_connect_if_necessary();
         * so we are returning true */
        return true;
    }

    return false;
}

static void dump_removed_services(enum MessageVerboseLevel level,
                                  const std::vector<std::string> &removed)
{
    if(!msg_is_verbose(level))
        return;

    for(const auto &name : removed)
        msg_info("Service removed: \"%s\"", name.c_str());
}

static bool dump_simple_value(const char *prefix,
                              const char *prop, GVariant *value)
{
    if(g_variant_is_of_type(value, G_VARIANT_TYPE_STRING))
        msg_info("%s %s = %s", prefix, prop, g_variant_get_string(value, NULL));
    else if(g_variant_is_of_type(value, G_VARIANT_TYPE_BOOLEAN))
        msg_info("%s %s = %s", prefix, prop, g_variant_get_boolean(value) ? "TRUE" : "FALSE");
    else if(g_variant_is_of_type(value, G_VARIANT_TYPE_BYTE))
        msg_info("%s %s = %" PRIu8, prefix, prop, g_variant_get_byte(value));
    else if(g_variant_is_of_type(value, G_VARIANT_TYPE_INT16))
        msg_info("%s %s = %" PRId16, prefix, prop, g_variant_get_int16(value));
    else if(g_variant_is_of_type(value, G_VARIANT_TYPE_UINT16))
        msg_info("%s %s = %" PRIu16, prefix, prop, g_variant_get_uint16(value));
    else if(g_variant_is_of_type(value, G_VARIANT_TYPE_INT32))
        msg_info("%s %s = %" PRId32, prefix, prop, g_variant_get_int32(value));
    else if(g_variant_is_of_type(value, G_VARIANT_TYPE_UINT32))
        msg_info("%s %s = %" PRIu32, prefix, prop, g_variant_get_uint32(value));
    else if(g_variant_is_of_type(value, G_VARIANT_TYPE_INT64))
        msg_info("%s %s = %" PRId64, prefix, prop, g_variant_get_int64(value));
    else if(g_variant_is_of_type(value, G_VARIANT_TYPE_UINT32))
        msg_info("%s %s = %" PRIu64, prefix, prop, g_variant_get_uint64(value));
    else if(g_variant_is_of_type(value, G_VARIANT_TYPE_DOUBLE))
        msg_info("%s %s = %f", prefix, prop, g_variant_get_double(value));
    else
        return false;

    return true;
}

static void dump_service_changes(enum MessageVerboseLevel level,
                                 const char *name, GVariantIter *props_iter)
{
    if(!msg_is_verbose(level))
        return;

    msg_info((g_variant_iter_n_children(props_iter) > 0)
             ? "Service changed: \"%s\""
             : "Service still available: \"%s\"", name);

    const char *prop = NULL;
    GVariant *value = NULL;
    GVariantIter *iter_copy = g_variant_iter_copy(props_iter);

    while(g_variant_iter_loop(iter_copy, "{&sv}", &prop, &value))
    {
        if(dump_simple_value("-", prop, value))
            continue;
        else if(g_variant_is_of_type(value, G_VARIANT_TYPE_STRING_ARRAY))
        {
            msg_info("- %s", prop);

            GVariantIter array_iter;
            g_variant_iter_init(&array_iter, value);

            const gchar *array_value = NULL;

            while(g_variant_iter_loop(&array_iter, "&s", &array_value))
                msg_info("`-- %s", array_value);
        }
        else if(g_variant_is_of_type(value, G_VARIANT_TYPE_VARDICT))
        {
            msg_info("- %s", prop);

            GVariantIter dict_iter;
            g_variant_iter_init(&dict_iter, value);

            const gchar *dict_key = NULL;
            GVariant *dict_value;

            while(g_variant_iter_loop(&dict_iter, "{&sv}", &dict_key, &dict_value))
            {
                if(dump_simple_value("--", dict_key, dict_value))
                    continue;
                else
                    msg_info("`-- %s (type %s)", dict_key, g_variant_get_type_string(dict_value));
            }
        }
        else
            msg_info("- %s (type %s)", prop, g_variant_get_type_string(value));
    }

    g_variant_iter_free(iter_copy);
}

template <Connman::AddressType IPType>
struct ParseIPSettingsTraits;

template <>
struct ParseIPSettingsTraits<Connman::AddressType::IPV4>
{
    using Settings = Connman::IPSettings<Connman::AddressType::IPV4>;

    static void set_dhcp_method(Settings &settings, const char *method)
    {
        settings.set_dhcp_method(Connman::parse_connman_dhcp_v4_method(method));
    }
};

template <>
struct ParseIPSettingsTraits<Connman::AddressType::IPV6>
{
    using Settings = Connman::IPSettings<Connman::AddressType::IPV6>;

    static void set_dhcp_method(Settings &settings, const char *method)
    {
        settings.set_dhcp_method(Connman::parse_connman_dhcp_v6_method(method));
    }
};

template <Connman::AddressType IPType, typename Traits = ParseIPSettingsTraits<IPType>>
static void parse_ip_settings(GVariant *values,
                              Maybe<Connman::IPSettings<IPType>> &ip_settings)
{
    GVariantIter iter;
    g_variant_iter_init(&iter, values);

    const char *iter_key;
    GVariant *iter_value;

    auto &settings(ip_settings.get_rw());

    while(g_variant_iter_loop(&iter, "{&sv}", &iter_key, &iter_value))
    {
        if(strcmp(iter_key, "Method") == 0)
            Traits::set_dhcp_method(settings, g_variant_get_string(iter_value, NULL));
        else if(strcmp(iter_key, "Address") == 0)
            settings.set_address(g_variant_get_string(iter_value, NULL));
        else if(strcmp(iter_key, "Netmask") == 0)
            settings.set_netmask(g_variant_get_string(iter_value, NULL));
        else if(strcmp(iter_key, "Gateway") == 0)
            settings.set_gateway(g_variant_get_string(iter_value, NULL));
        else if(strcmp(iter_key, "PrefixLength") == 0)
        {
            char temp[4];
            snprintf(temp, sizeof(temp), "%u", g_variant_get_byte(iter_value));
            settings.set_netmask(temp);
        }
    }

    ip_settings.set_known();
}

static bool parse_generic_service_data(const char *prop, GVariant *value,
                                       Connman::ServiceData &service_data,
                                       Connman::Technology &tech,
                                       Connman::Address<Connman::AddressType::MAC> &mac_address)
{
    if(strcmp(prop, "Type") == 0)
        tech = Connman::parse_connman_technology(g_variant_get_string(value, NULL));
    else if(strcmp(prop, "State") == 0)
        service_data.state_ =
            Connman::parse_connman_service_state(g_variant_get_string(value, NULL));
    else if(strcmp(prop, "Favorite") == 0)
        service_data.is_favorite_ = !!g_variant_get_boolean(value);
    else if(strcmp(prop, "AutoConnect") == 0)
        service_data.is_auto_connect_ = !!g_variant_get_boolean(value);
    else if(strcmp(prop, "Immutable") == 0)
        service_data.is_immutable_ = !!g_variant_get_boolean(value);
    else if(strcmp(prop, "Ethernet") == 0)
    {
        GVariantIter iter;
        g_variant_iter_init(&iter, value);

        const char *iter_key;
        GVariant *iter_value;

        while(g_variant_iter_loop(&iter, "{&sv}", &iter_key, &iter_value))
        {
            if(strcmp(iter_key, "Address") == 0 &&
               mac_address.set(g_variant_get_string(iter_value, NULL)))
            {
                g_variant_unref(iter_value);
                break;
            }
        }
    }
    else if(strcmp(prop, "Nameservers") == 0)
    {
        GVariantIter iter;
        g_variant_iter_init(&iter, value);

        const char *iter_string;

        auto &servers(service_data.dns_servers_.get_rw());

        while(g_variant_iter_loop(&iter, "&s", &iter_string))
            servers.push_back(iter_string);

        service_data.dns_servers_.set_known();
    }
    else if(strcmp(prop, "IPv4") == 0)
        parse_ip_settings(value, service_data.ip_settings_v4_);
    else if(strcmp(prop, "IPv4.Configuration") == 0)
        parse_ip_settings(value, service_data.ip_configuration_v4_);
    else if(strcmp(prop, "IPv6") == 0)
        parse_ip_settings(value, service_data.ip_settings_v6_);
    else if(strcmp(prop, "IPv6.Configuration") == 0)
        parse_ip_settings(value, service_data.ip_configuration_v6_);
    else
        return false;

    return true;
}

static bool parse_ethernet_data(const char *prop, GVariant *value,
                                Connman::Service<Connman::Technology::ETHERNET>::TechDataType &data)
{
    return false;
}

static bool parse_wlan_data(const char *prop, GVariant *value,
                            Connman::Service<Connman::Technology::WLAN>::TechDataType &data)
{
    if(strcmp(prop, "Name") == 0)
        data.network_name_ = g_variant_get_string(value, NULL);
    else if(strcmp(prop, "Security") == 0)
    {
        if(g_variant_n_children(value) > 0)
        {
            GVariant *str = g_variant_get_child_value(value, 0);
            data.security_ = g_variant_get_string(str, NULL);
            g_variant_unref(str);

            if(g_variant_n_children(value) == 1)
                data.is_wps_available_ = false;
            else
            {
                str = g_variant_get_child_value(value, 1);
                data.is_wps_available_ = strcmp(g_variant_get_string(str, NULL), "wps") == 0;
                g_variant_unref(str);
            }
        }
        else
        {
            data.security_ = "";
            data.is_wps_available_ = false;
        }
    }
    else if(strcmp(prop, "Strength") == 0)
        data.strength_ = g_variant_get_byte(value);
    else
        return false;

    return true;
}

static bool parse_service_data(GVariantIter *props_iter,
                               Connman::Technology &tech,
                               Connman::Address<Connman::AddressType::MAC> &mac_address,
                               Connman::ServiceData &service_data,
                               Connman::Service<Connman::Technology::ETHERNET>::TechDataType &ethernet_data,
                               Connman::Service<Connman::Technology::WLAN>::TechDataType &wlan_data)
{
    tech = Connman::Technology::UNKNOWN_TECHNOLOGY;

    bool parsed_any_property = false;
    const char *prop = NULL;
    GVariant *value = NULL;

    while(g_variant_iter_loop(props_iter, "{&sv}", &prop, &value))
    {
        if(parse_generic_service_data(prop, value, service_data, tech, mac_address) ||
           parse_ethernet_data(prop, value, ethernet_data) ||
           parse_wlan_data(prop, value, wlan_data))
        {
            parsed_any_property = true;
        }
    }

    return parsed_any_property;
}

/*!
 * Remove listed services from our list.
 */
static void update_service_list(Connman::ServiceList &known_services,
                                WLANConnectionState &wlan_connection_state,
                                const std::vector<std::string> &removed,
                                bool &have_lost_active_ethernet_device,
                                bool &have_lost_active_wlan_device)
{
    have_lost_active_ethernet_device = false;
    have_lost_active_wlan_device = false;

    if(removed.empty())
        return;

    dump_removed_services(MESSAGE_LEVEL_TRACE, removed);

    for(const auto &name : removed)
    {
        const Connman::ServiceBase *service(known_services[name]);

        if(service == nullptr)
            return;

        if(service->is_ours() && service->is_active())
        {
            switch(service->get_technology())
            {
              case Connman::Technology::UNKNOWN_TECHNOLOGY:
                BUG("Removed service \"%s\" of unknown technology", name.c_str());
                break;

              case Connman::Technology::ETHERNET:
                have_lost_active_ethernet_device = true;
                break;

              case Connman::Technology::WLAN:
                have_lost_active_wlan_device = true;
                break;
            }
        }

        switch(wlan_connection_state.get_state())
        {
          case WLANConnectionState::State::IDLE:
          case WLANConnectionState::State::CONNECTING:
          case WLANConnectionState::State::DONE:
          case WLANConnectionState::State::FAILED:
          case WLANConnectionState::State::ABORTED_WPS:
            break;

          case WLANConnectionState::State::ABOUT_TO_CONNECT:
            if(wlan_connection_state.get_service_name() == name)
                wlan_connection_state.reset();

            break;

          case WLANConnectionState::State::ABOUT_TO_CONNECT_WPS:
            if(wlan_connection_state.get_service_name() == name &&
               !wlan_connection_state.about_to_connect_next())
            {
                wlan_connection_state.reset();
            }
            else
                wlan_connection_state.remove_pending_wps_service(name);

            break;

          case WLANConnectionState::State::CONNECTING_WPS:
            wlan_connection_state.remove_pending_wps_service(name);
            break;
        }

        known_services.erase(name);
    };
}

static void update_service_list(GVariant *all_services,
                                Connman::ServiceList &known_services,
                                Connman::NetworkDeviceList &network_devices,
                                bool force_refresh_all)
{
    if(all_services == nullptr)
        return;

    /* go through all services */
    GVariantIter iter;
    g_variant_iter_init(&iter, all_services);

    const gchar *name;
    GVariantIter *props_iter;

    while(g_variant_iter_loop(&iter, "(&oa{sv})", &name, &props_iter))
    {
        if(name[0] == '\0')
            continue;

        dump_service_changes(MESSAGE_LEVEL_TRACE, name, props_iter);

        Connman::ServiceData service_data;
        Connman::Service<Connman::Technology::ETHERNET>::TechDataType ethernet_data;
        Connman::Service<Connman::Technology::WLAN>::TechDataType wlan_data;
        Connman::Technology tech;
        Connman::Address<Connman::AddressType::MAC> mac_address;

        if(!parse_service_data(props_iter, tech, mac_address,
                               service_data, ethernet_data, wlan_data))
        {
            BUG("Reported service \"%s\" contains no information", name);
            continue;
        }

        Connman::ServiceBase *service = known_services[name];

        auto dev = network_devices[mac_address];

        if(dev != nullptr)
            service_data.device_ = std::move(dev);
        else
            service_data.device_ = std::move(network_devices.insert(tech, std::move(mac_address)));

        switch(tech)
        {
          case Connman::Technology::UNKNOWN_TECHNOLOGY:
            break;

          case Connman::Technology::ETHERNET:
            if(service == nullptr)
                known_services.insert(name, std::move(service_data), std::move(ethernet_data));
            else
                static_cast<Connman::Service<Connman::Technology::ETHERNET> *>(service)->put_changes(
                        std::move(service_data), std::move(ethernet_data),
                        force_refresh_all);

            break;

          case Connman::Technology::WLAN:
            if(service == nullptr)
                known_services.insert(name, std::move(service_data), std::move(wlan_data));
            else
                static_cast<Connman::Service<Connman::Technology::WLAN> *>(service)->put_changes(
                        std::move(service_data), std::move(wlan_data),
                        force_refresh_all);

            break;
        }
    }
}

/*!
 * Disable use of IPv6 for given service.
 *
 * All we are ever doing about IPv6 is to disable it---sad. :(
 */
static bool disable_ipv6(Connman::ServiceBase &service,
                         const std::string &service_name)
{
    log_assert(service.is_active());

    const auto &data(service.get_service_data());

    if(!data.ip_configuration_v6_.is_known())
        return false;

    switch(data.ip_configuration_v6_.get().get_dhcp_method())
    {
      case Connman::DHCPV6Method::NOT_AVAILABLE:
      case Connman::DHCPV6Method::OFF:
      case Connman::DHCPV6Method::FIXED:
        return false;

      case Connman::DHCPV6Method::ON:
      case Connman::DHCPV6Method::MANUAL:
      case Connman::DHCPV6Method::SIX_TO_FOUR:
      case Connman::DHCPV6Method::UNKNOWN_METHOD:
        break;
    }

    msg_vinfo(MESSAGE_LEVEL_DEBUG,
              "Configure IPv6 parameters for service %s", service_name.c_str());

    GVariantBuilder builder;
    g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);

    g_variant_builder_add(&builder, "{sv}", "Method", g_variant_new_string("off"));

    GVariant *ipv6_config =
        g_variant_new_variant(g_variant_builder_end(&builder));

    if(ipv6_config == NULL)
        return false;

    g_variant_ref_sink(ipv6_config);
    const bool retval =
        connman_common_set_service_property(service_name.c_str(),
                                            "IPv6.Configuration", ipv6_config);
    g_variant_unref(ipv6_config);

    return retval;
}

static void ignore_services_if(Connman::ServiceList &services,
                               std::function<bool(const Connman::ServiceBase &service,
                                                  const std::string &name)> pred)
{
    for(auto &it : services)
    {
        const auto &s(it.second);

        log_assert(s != nullptr);

        if(s->needs_processing())
        {
            if(pred(*s, it.first))
                s->processed();
        }
    }
}

static void ignore_inactive_services_on_wrong_interfaces(Connman::ServiceList &known_services)
{
    ignore_services_if(known_services,
            [] (const Connman::ServiceBase &s, const std::string &name)
            {
                return !s.is_active() && !s.is_ours();
            });
}

static void ignore_wlan_services_on_our_interfaces(Connman::ServiceList &known_services)
{
    if(known_services.number_of_wlan_services() > 0)
        ignore_services_if(known_services,
                [] (const Connman::ServiceBase &s, const std::string &name)
                {
                    return s.is_ours() && s.get_technology() == Connman::Technology::WLAN;
                });
}

static void disconnect_active_services_if(Connman::ServiceList &services,
                                          std::function<bool(const Connman::ServiceBase &service,
                                                             const std::string &name)> pred)
{
    for(auto &it : services)
    {
        const auto &s(it.second);

        log_assert(s != nullptr);

        if(!s->is_active() || !pred(*s, it.first))
            continue;

        if(avoid_service(*s, it.first))
            s->processed();
    }
}

static void disconnect_active_services_on_wrong_interfaces(Connman::ServiceList &known_services)
{
    disconnect_active_services_if(known_services,
            [] (const Connman::ServiceBase &s, const std::string &name)
            {
                return !s.is_ours();
            });
}

static void
disconnect_nonmatching_active_services_on_our_interface(Connman::ServiceList &known_services,
                                                        const std::string &our_ethernet_name,
                                                        const std::string &our_wlan_name)
{
    if(our_ethernet_name.empty() && our_wlan_name.empty())
        return;

    disconnect_active_services_if(known_services,
            [&our_ethernet_name, &our_wlan_name]
            (const Connman::ServiceBase &s, const std::string &name)
            {
                if(!s.is_ours())
                    return false;

                switch(s.get_technology())
                {
                    case Connman::Technology::UNKNOWN_TECHNOLOGY:
                        break;

                    case Connman::Technology::ETHERNET:
                        return !our_ethernet_name.empty() && name != our_ethernet_name;

                    case Connman::Technology::WLAN:
                        return !our_wlan_name.empty() && name != our_wlan_name;
                }

                return false;
            });
}

static bool process_our_ethernet_service(Connman::ServiceBase &service,
                                         const std::string &name,
                                         const struct network_prefs *prefs)
{
    auto &s(static_cast<Connman::Service<Connman::Technology::ETHERNET> &>(service));

    bool consider_wlan_connection = true;

    if(s.needs_processing())
    {
        if(configure_ipv4_settings(s, name, prefs))
            consider_wlan_connection = false;

        if(s.is_active())
            disable_ipv6(s, name);
    }
    else if(s.is_active())
        consider_wlan_connection = false;

    s.processed();

    return consider_wlan_connection;
}

static bool process_our_wlan_service(Connman::ServiceBase &service,
                                     const std::string &name,
                                     bool consider_wlan_connection,
                                     bool have_lost_active_ethernet_device,
                                     WLANConnectionState &wlan_connection_state,
                                     const struct network_prefs *prefs)
{
    auto &s(static_cast<Connman::Service<Connman::Technology::WLAN> &>(service));

    bool want_to_switch_to_wlan = false;

    if(consider_wlan_connection)
    {
        if(s.needs_processing())
        {
            if(configure_our_wlan(s, name, prefs, wlan_connection_state, false))
                want_to_switch_to_wlan = true;

            if(s.is_active())
                disable_ipv6(s, name);
        }
        else if(have_lost_active_ethernet_device)
            want_to_switch_to_wlan = true;
    }

    s.processed();

    return want_to_switch_to_wlan;
}

#ifdef NDEBUG
static inline void bug_if_not_processed(const Connman::ServiceList &known_services) {}
#else /* !NDEBUG */
static void bug_if_not_processed(const Connman::ServiceList &known_services)
{
    bool found_bug = false;

    for(auto &it : known_services)
    {
        if(it.second->needs_processing())
        {
            BUG("Service \"%s\" not processed", it.first.c_str());
            found_bug = true;
        }
    }

    log_assert(!found_bug);
}
#endif /* NDEBUG */

static void survey_after_suspend(enum ConnmanSiteScanResult result)
{
    msg_vinfo(MESSAGE_LEVEL_DIAG,
              "Site survey result after suspend: %d", int(result));
}

/*!
 * Take care of ConnMan service changes.
 *
 * ConnMan is configured so to connect to Ethernet or WLAN automatically
 * whenever possible. We also prefer Ethernet and have ConnMan switch to
 * that technology as soon as it is available. In case ConnMan does not
 * know a WLAN passphrase, it will ask us via ConnMan agent API. Ideally,
 * this is how all connections are managed and there should be nothing to
 * do in here.
 *
 * There are, however, a few cases that we need to take care about. ConnMan
 * will cache WLAN credentials (in fact, all configuration data for a
 * service) in its own set of configuration files, and it will use them to
 * perform its automatic connection management. Now, if the user decides to
 * use a new or different WLAN, then ConnMan needs to be informed to use
 * it. This, unfortunately, only works if the network is currently visible
 * by ConnMan. While the user is configuring the network connection on the
 * device, the network is usually visible, but for instance due to bad
 * signal quality it may not, and configuration could fail. ConnMan will
 * then resort to the old WLAN it already knows about, leading to
 * confusion, at best. Similar things happen if the credentials entered by
 * the user are wrong, or when moving the device from one house to another,
 * or when configuring Ethernet while no cable is plugged in.
 *
 * The code below tries to sort it all out. It tries to stay connected to
 * the services explicitly configured by the user and to stay away from
 * others. For those services configured by the user, the code tries to
 * enforce use of user settings.
 *
 * Note that the problems described above occur only because our user
 * interface policy enforces a restriction to a single managed WLAN. A more
 * generalized approach that allows multiple configurations would actually
 * simplify things a lot, both for the software and for the end user.
 */
static bool do_process_pending_changes(Connman::ServiceList &known_services,
                                       bool have_lost_active_ethernet_device,
                                       bool have_lost_active_wlan_device,
                                       WLANConnectionState &wlan_connection_state,
                                       const struct network_prefs *ethernet_prefs,
                                       const struct network_prefs *wlan_prefs)
{
    if(have_lost_active_wlan_device)
        wlan_connection_state.reset();

    ignore_inactive_services_on_wrong_interfaces(known_services);
    disconnect_active_services_on_wrong_interfaces(known_services);

    char configured_ethernet_service_name[NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE];
    char configured_wlan_service_name[NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE];

    /* check what we have in the configuration file */
    const bool have_ethernet_service_prefs =
        network_prefs_generate_service_name(ethernet_prefs,
                                            configured_ethernet_service_name,
                                            sizeof(configured_ethernet_service_name)) > 0;
    const bool have_wlan_service_prefs =
        network_prefs_generate_service_name(wlan_prefs,
                                            configured_wlan_service_name,
                                            sizeof(configured_wlan_service_name)) > 0;

    /* up to two services known by Connman for which the user also has provided
     * configuration data */
    auto our_ethernet(have_ethernet_service_prefs
                      ? known_services.find(configured_ethernet_service_name)
                      : known_services.end());
    auto our_wlan(have_wlan_service_prefs
                  ? known_services.find(configured_wlan_service_name)
                  : known_services.end());

    if(wlan_connection_state.is_wps_mode())
    {
        if(our_ethernet != known_services.end())
        {
            /* cable was plugged, taking precedence over WLAN */
            stop_wps(wlan_connection_state, true);
        }

        /* do not interfere with Connman */
        our_wlan = known_services.end();
    }

    disconnect_nonmatching_active_services_on_our_interface(
            known_services,
            our_ethernet != known_services.end() ? our_ethernet->first : "",
            our_wlan != known_services.end() ? our_wlan->first : "");

    /* either all services have been disconnected above and the function has
     * returned already, or we end up here because there are exactly one or two
     * services left for further configuration */

    const bool consider_wlan_connection =
        our_ethernet != known_services.end()
        ? process_our_ethernet_service(*our_ethernet->second, our_ethernet->first,
                                       ethernet_prefs)
        : true;

    const bool want_to_switch_to_wlan =
        our_wlan != known_services.end()
        ? process_our_wlan_service(*our_wlan->second, our_wlan->first,
                                   consider_wlan_connection,
                                   have_lost_active_ethernet_device,
                                   wlan_connection_state, wlan_prefs)
        : false;

    ignore_wlan_services_on_our_interfaces(known_services);

    bug_if_not_processed(known_services);

    if(!want_to_switch_to_wlan)
    {
        bool revised_decision = false;

        if(consider_wlan_connection && have_wlan_service_prefs)
        {
            /* we didn't want to switch to WLAN in the first place, but we are
             * allowed to because there is no Ethernet connection; also, we
             * have a set of WLAN configuration data */
           if(known_services.number_of_wlan_services() == 0)
           {
               /* there are no known WLANs, maybe because the WLAN adapter
                * is in suspend mode */
               connman_start_wlan_site_survey(survey_after_suspend);
               return false;
           }

           /* switch to WLAN if there is a network matching our WLAN
            * configuration */
           revised_decision = our_wlan != known_services.end();
        }

        if(!revised_decision)
            return false;
    }

    /*
     * We have determined that we should switch over to WLAN. If the WLAN is
     * neither connected nor marked as auto-connect, then we need to connect to
     * it by hand.
     */

    log_assert(our_wlan != known_services.end());

    /* this is the least we should do so that ConnMan can find WLAN
     * networks, manual connect may or may not be necessary (see below) */
    connman_wlan_power_on();

    if(our_wlan->second->is_active() == true)
        return false;

    if(our_wlan->second->get_service_data().is_auto_connect_ == true)
        return false;

    switch(wlan_connection_state.get_state())
    {
      case WLANConnectionState::State::DONE:
      case WLANConnectionState::State::FAILED:
      case WLANConnectionState::State::ABORTED_WPS:
        msg_info("Minor glitch: WLAN connection state for \"%s\" is %d",
                 wlan_connection_state.have_candidates()
                 ? wlan_connection_state.get_service_name().c_str()
                 : "*NONE*",
                 static_cast<int>(wlan_connection_state.get_state()));
        wlan_connection_state.reset();

        /* fall-through */

      case WLANConnectionState::State::IDLE:
        wlan_connection_state.about_to_connect_to(our_wlan->first);

        /* Click. */
        return true;

      case WLANConnectionState::State::ABOUT_TO_CONNECT:
      case WLANConnectionState::State::ABOUT_TO_CONNECT_WPS:
      case WLANConnectionState::State::CONNECTING:
      case WLANConnectionState::State::CONNECTING_WPS:
        break;
    }

    return false;
}

static void schedule_wlan_connect_if_necessary(bool is_necessary,
                                               DBusSignalManagerData &data)
{
    g_rec_mutex_lock(&data.lock);

    if(is_necessary)
        schedule_wlan_connect__unlocked(data);

    g_rec_mutex_unlock(&data.lock);
}

static bool update_all_services(GVariant *all_services,
                                Connman::ServiceList &services,
                                Connman::NetworkDeviceList &devices,
                                bool force_refresh_all,
                                const char *context)
{
    if(all_services == nullptr)
    {
        BUG("Querying services from ConnMan failed (%s)", context);
        return false;
    }

    update_service_list(all_services, services, devices, force_refresh_all);

    return true;
}

static void process_pending_changes(DBusSignalManagerData &data,
                                    Connman::ServiceList &services,
                                    bool have_lost_active_ethernet_device,
                                    bool have_lost_active_wlan_device)
{
    const struct network_prefs *ethernet_prefs;
    const struct network_prefs *wlan_prefs;
    struct network_prefs_handle *handle =
        network_prefs_open_ro(&ethernet_prefs, &wlan_prefs);

    const bool need_to_schedule_wlan_connection =
        do_process_pending_changes(services,
                                   have_lost_active_ethernet_device,
                                   have_lost_active_wlan_device,
                                   data.wlan_connection_state,
                                   ethernet_prefs, wlan_prefs);

    if(handle != NULL)
        network_prefs_close(handle);

    dcpregs_networkconfig_interfaces_changed();

    schedule_wlan_connect_if_necessary(need_to_schedule_wlan_connection, data);
}

static const std::vector<std::string>
find_removed(const Connman::ServiceList &known_services, GVariant *all_services)
{
    std::vector<std::string> result;
    std::map<const std::string, bool> seen;

    GVariantIter iter;
    g_variant_iter_init(&iter, all_services);

    const gchar *name;
    GVariantIter *props_iter;

    while(g_variant_iter_loop(&iter, "(&oa{sv})", &name, &props_iter))
    {
        if(name[0] != '\0')
            seen[name] = true;
    }

    for(const auto &s : known_services)
    {
        if(seen.find(s.first) == seen.end())
            result.push_back(s.first);
    }

    return result;
}

static void refresh_services(DBusSignalManagerData &data, bool force_refresh_all,
                             const char *context)
{
    const auto locked_services(Connman::ServiceList::get_singleton_for_update());
    auto &services(locked_services.first);

    const auto locked_devices(Connman::NetworkDeviceList::get_singleton_for_update());
    auto &devices(locked_devices.first);

    GVariant *all_services =
        connman_common_query_services(dbus_get_connman_manager_iface());

    bool have_lost_active_ethernet_device = false;
    bool have_lost_active_wlan_device = false;

    if(all_services != nullptr)
    {
        const std::vector<std::string> removed(std::move(find_removed(services, all_services)));

        update_service_list(services, data.wlan_connection_state,
                            removed,
                            have_lost_active_ethernet_device,
                            have_lost_active_wlan_device);
    }

    if(update_all_services(all_services, services, devices, force_refresh_all,
                           context))
        g_variant_unref(all_services);

    process_pending_changes(data, services,
                            have_lost_active_ethernet_device,
                            have_lost_active_wlan_device);
}

void dbussignal_connman_manager(GDBusProxy *proxy, const gchar *sender_name,
                                const gchar *signal_name, GVariant *parameters,
                                gpointer user_data)
{
    auto *data = static_cast<DBusSignalManagerData *>(user_data);

    if(data != nullptr)
    {
        log_assert(!data->is_disabled);
        refresh_services(*data, false, signal_name);
    }
    else
        BUG("Got no data in %s()", __func__);
}

static bool is_ssid_rejected(const std::string &ssid, const char *wanted_network_name,
                             const char *wanted_network_ssid)
{
    log_assert(!ssid.empty());

    if(wanted_network_name == nullptr && wanted_network_ssid == nullptr)
        return false;

    if(wanted_network_name != nullptr && ssid == wanted_network_name)
        return false;

    if(wanted_network_ssid != nullptr && ssid == wanted_network_ssid)
        return false;

    return true;
}

static bool start_wps(DBusSignalManagerData &data,
                      const Connman::ServiceList &services,
                      const char *network_name, const char *network_ssid,
                      const char *service_to_be_disabled)
{
    switch(data.wlan_connection_state.get_state())
    {
      case WLANConnectionState::State::IDLE:
        break;

      case WLANConnectionState::State::DONE:
      case WLANConnectionState::State::FAILED:
      case WLANConnectionState::State::ABORTED_WPS:
        data.wlan_connection_state.reset();
        break;

      case WLANConnectionState::State::ABOUT_TO_CONNECT:
      case WLANConnectionState::State::ABOUT_TO_CONNECT_WPS:
      case WLANConnectionState::State::CONNECTING:
      case WLANConnectionState::State::CONNECTING_WPS:
        msg_info("Cannot connect via WPS, already connecting");
        return false;
    }

    if(services.number_of_wlan_services() == 0)
    {
        msg_info("No WLAN services available, cannot connect via WPS");
        return false;
    }

    std::vector<std::string> wps_candidates;

    for(const auto &it : services)
    {
        /* want WLAN */
        switch(it.second->get_technology())
        {
          case Connman::Technology::UNKNOWN_TECHNOLOGY:
          case Connman::Technology::ETHERNET:
            continue;

          case Connman::Technology::WLAN:
            break;
        }

        const auto &tech_data(static_cast<const Connman::Service<Connman::Technology::WLAN> &>(*it.second).get_tech_data());

        /* want non-hidden networks */
        if(!tech_data.network_name_.is_known() ||
           tech_data.network_name_.get().empty())
            continue;

        /* maybe want services which match a specific name */
        if(is_ssid_rejected(tech_data.network_name_.get(),
                            network_name, network_ssid))
        {
            msg_vinfo(MESSAGE_LEVEL_DIAG,
                      "Ignoring service with SSID \"%s\" for WPS",
                      tech_data.network_name_.get().c_str());
            continue;
        }

        /* want WPS */
        if(tech_data.is_wps_available_ == true)
            wps_candidates.push_back(it.first);
    }

    if(wps_candidates.empty())
    {
        msg_info("No WPS-enabled services found");
        connman_agent_set_wps_mode(false);
        return false;
    }

    /* sort by strength */
    std::sort(wps_candidates.begin(), wps_candidates.end(),
        [&services] (const std::string &a, const std::string &b) -> bool
        {
            const auto &td_a(static_cast<const Connman::Service<Connman::Technology::WLAN> *>(services[a])->get_tech_data());
            const auto &td_b(static_cast<const Connman::Service<Connman::Technology::WLAN> *>(services[b])->get_tech_data());

            return td_a.strength_.get() > td_b.strength_.get();
        });

    data.wlan_connection_state.about_to_connect_to(std::move(wps_candidates));

    if(service_to_be_disabled != NULL && service_to_be_disabled[0] != '\0')
    {
        auto service(services.find(service_to_be_disabled));

        if(service != services.end() && service->second->is_active())
            avoid_service(*service->second, service->first);
    }

    connman_agent_set_wps_mode(true);
    schedule_wlan_connect__unlocked(data);

    return true;
}

static DBusSignalManagerData global_dbussignal_connman_manager_data;

DBusSignalManagerData *
dbussignal_connman_manager_init(void (*schedule_connect_to_wlan_fn)(),
                                void (*schedule_refresh_connman_services_fn)(),
                                bool is_enabled)
{
    global_dbussignal_connman_manager_data.init(schedule_connect_to_wlan_fn,
                                                schedule_refresh_connman_services_fn,
                                                is_enabled);
    return &global_dbussignal_connman_manager_data;
}

void dbussignal_connman_manager_about_to_connect_signals(void)
{
    log_assert(!global_dbussignal_connman_manager_data.is_disabled);

    const auto locked_services(Connman::ServiceList::get_singleton_for_update());
    auto &services(locked_services.first);

    const auto locked_devices(Connman::NetworkDeviceList::get_singleton_for_update());
    auto &devices(locked_devices.first);

    GVariant *all_services =
        connman_common_query_services(dbus_get_connman_manager_iface());

    if(update_all_services(all_services, services, devices, true, "startup"))
        g_variant_unref(all_services);

    process_pending_changes(global_dbussignal_connman_manager_data,
                            services, false, false);
}

void dbussignal_connman_manager_connect_to_service(enum NetworkPrefsTechnology tech,
                                                   const char *service_to_be_disabled)
{
    if(global_dbussignal_connman_manager_data.is_disabled)
        return;

    if(tech == NWPREFSTECH_UNKNOWN)
        return;

    const struct network_prefs *ethernet_prefs;
    const struct network_prefs *wlan_prefs;
    struct network_prefs_handle *handle =
        network_prefs_open_ro(&ethernet_prefs, &wlan_prefs);

    if(handle == NULL)
        return;

    char service_name[NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE];
    bool need_to_schedule_wlan_connection = false;

    const auto locked_services(Connman::ServiceList::get_singleton_const());
    const auto &services(locked_services.first);

    g_rec_mutex_lock(&global_dbussignal_connman_manager_data.lock);

    switch(tech)
    {
      case NWPREFSTECH_UNKNOWN:
        break;

      case NWPREFSTECH_ETHERNET:
        if(network_prefs_generate_service_name(ethernet_prefs, service_name,
                                               sizeof(service_name)) > 0)
        {
            auto our_service(services.find(service_name));

            if(our_service != services.end())
                configure_ipv4_settings(*our_service->second, our_service->first,
                                        ethernet_prefs);
        }

        break;

      case NWPREFSTECH_WLAN:
        if(network_prefs_generate_service_name(wlan_prefs, service_name,
                                               sizeof(service_name)) > 0)
        {
            auto our_service(services.find(service_name));

            if(our_service != services.end())
            {
                if(configure_our_wlan(static_cast<const Connman::Service<Connman::Technology::WLAN> &>(*our_service->second),
                                      our_service->first, wlan_prefs,
                                      global_dbussignal_connman_manager_data.wlan_connection_state,
                                      true))
                {
                    global_dbussignal_connman_manager_data.wlan_connection_state.about_to_connect_to(our_service->first);
                    need_to_schedule_wlan_connection = true;
                }
            }
        }

        break;
    }

    network_prefs_close(handle);

    if(service_to_be_disabled != NULL && service_to_be_disabled[0] != '\0')
    {
        auto service(services.find(service_to_be_disabled));

        if(service != services.end() &&
           service->second->is_active())
            avoid_service(*service->second, service->first);
    }

    g_rec_mutex_unlock(&global_dbussignal_connman_manager_data.lock);

    schedule_wlan_connect_if_necessary(need_to_schedule_wlan_connection,
                                       global_dbussignal_connman_manager_data);
}

void dbussignal_connman_manager_connect_to_wps_service(const char *network_name,
                                                       const char *network_ssid,
                                                       const char *service_to_be_disabled)
{
    if(global_dbussignal_connman_manager_data.is_disabled)
        return;

    const auto locked_services(Connman::ServiceList::get_singleton_const());
    const auto &services(locked_services.first);

    g_rec_mutex_lock(&global_dbussignal_connman_manager_data.lock);
    start_wps(global_dbussignal_connman_manager_data, services,
              network_name, network_ssid, service_to_be_disabled);
    g_rec_mutex_unlock(&global_dbussignal_connman_manager_data.lock);
}

void dbussignal_connman_manager_cancel_wps()
{
    if(global_dbussignal_connman_manager_data.is_disabled)
        return;

    g_rec_mutex_lock(&global_dbussignal_connman_manager_data.lock);
    stop_wps(global_dbussignal_connman_manager_data.wlan_connection_state, false);
    g_rec_mutex_unlock(&global_dbussignal_connman_manager_data.lock);
}

static bool get_connecting_status(const Connman::ServiceList::Map::value_type &s,
                                  bool is_wps)
{
    if(!s.second->get_service_data().state_.is_known())
        return false;

    switch(s.second->get_service_data().state_.get())
    {
      case Connman::ServiceState::NOT_AVAILABLE:
      case Connman::ServiceState::UNKNOWN_STATE:
      case Connman::ServiceState::READY:
      case Connman::ServiceState::DISCONNECT:
      case Connman::ServiceState::ONLINE:
        break;

      case Connman::ServiceState::IDLE:
      case Connman::ServiceState::FAILURE:
        if(is_wps)
            return true;

        break;

      case Connman::ServiceState::ASSOCIATION:
      case Connman::ServiceState::CONFIGURATION:
        return true;
    }

    return false;
}

bool dbussignal_connman_manager_is_connecting(bool *is_wps)
{
    log_assert(!global_dbussignal_connman_manager_data.is_disabled);

    const auto locked_services(Connman::ServiceList::get_singleton_const());
    const auto &services(locked_services.first);

    auto &d(global_dbussignal_connman_manager_data);

    g_rec_mutex_lock(&d.lock);

    bool retval = false;
    *is_wps = false;

    switch(d.wlan_connection_state.get_state())
    {
      case WLANConnectionState::State::IDLE:
      case WLANConnectionState::State::DONE:
      case WLANConnectionState::State::FAILED:
        break;

      case WLANConnectionState::State::ABORTED_WPS:
        *is_wps = true;
        break;

      case WLANConnectionState::State::ABOUT_TO_CONNECT_WPS:
      case WLANConnectionState::State::CONNECTING_WPS:
        *is_wps = true;

        /* fall-through */

      case WLANConnectionState::State::ABOUT_TO_CONNECT:
      case WLANConnectionState::State::CONNECTING:
        retval = true;
        break;
    }

    if(!retval)
    {
        for(const auto &s : services)
        {
            if(get_connecting_status(s, false))
            {
                retval = true;
                break;
            }
        }
    }

    g_rec_mutex_unlock(&d.lock);

    return retval;
}

void dbussignal_connman_manager_refresh_services(bool force_refresh_all)
{
    if(!global_dbussignal_connman_manager_data.is_disabled)
        refresh_services(global_dbussignal_connman_manager_data,
                         force_refresh_all, __func__);
}
