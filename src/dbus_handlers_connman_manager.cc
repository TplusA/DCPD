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

#include <string>
#include <map>
#include <memory>
#include <algorithm>
#include <cstring>
#include <cinttypes>

#include "dbus_handlers_connman_manager.h"
#include "dbus_handlers_connman_manager_glue.h"
#include "dbus_iface_deep.h"
#include "dcpregs_networkconfig.h"
#include "connman.h"
#include "connman_common.h"
#include "connman_service.hh"
#include "messages.h"

class ServiceList
{
  public:
    using Map = std::map<std::string, std::unique_ptr<Connman::ServiceBase>>;

  private:
    Map services_;
    size_t number_of_ethernet_services_;
    size_t number_of_wlan_services_;

  public:
    ServiceList(const ServiceList &) = delete;
    ServiceList &operator=(const ServiceList &) = delete;

    explicit ServiceList():
        number_of_ethernet_services_(0),
        number_of_wlan_services_(0)
    {}

    void clear()
    {
        services_.clear();
        number_of_ethernet_services_ = 0;
        number_of_wlan_services_ = 0;
    }

    void erase(const std::string &name)
    {
        auto it(services_.find(name));

        if(it == services_.end())
            return;

        switch(it->second->get_technology())
        {
          case Connman::Technology::UNKNOWN_TECHNOLOGY:
            break;

          case Connman::Technology::ETHERNET:
            log_assert(number_of_ethernet_services_ > 0);
            --number_of_ethernet_services_;
            break;

          case Connman::Technology::WLAN:
            log_assert(number_of_wlan_services_ > 0);
            --number_of_wlan_services_;
            break;
        }

        services_.erase(name);
    }

    bool insert(const char *name, Connman::ServiceData &&service_data,
                Connman::Service<Connman::Technology::ETHERNET>::TechDataType &&ethernet_data,
                bool is_ours)
    {
        if(services_.find(name) != services_.end())
            return false;

        services_[name].reset(new Connman::Service<Connman::Technology::ETHERNET>(
                                        std::move(service_data),
                                        std::move(ethernet_data),
                                        is_ours));

        ++number_of_ethernet_services_;

        return true;
    }

    bool insert(const char *name, Connman::ServiceData &&service_data,
                Connman::Service<Connman::Technology::WLAN>::TechDataType &&wlan_data,
                bool is_ours)
    {
        if(services_.find(name) != services_.end())
            return false;

        services_[name].reset(new Connman::Service<Connman::Technology::WLAN>(
                                        std::move(service_data),
                                        std::move(wlan_data),
                                        is_ours));

        ++number_of_wlan_services_;

        return true;
    }

    size_t number_of_services() const
    {
        log_assert(services_.size() == number_of_ethernet_services_ + number_of_wlan_services_);
        return services_.size();
    }

    size_t number_of_ethernet_services() const { return number_of_ethernet_services_; }
    size_t number_of_wlan_services() const { return number_of_wlan_services_; }

    Connman::ServiceBase *operator[](const std::string &name)
    {
        auto it(services_.find(name));
        return it != services_.end() ? it->second.get() : nullptr;
    }

    const Connman::ServiceBase *operator[](const std::string &name) const
    {
        return const_cast<ServiceList *>(this)->operator[](name);
    }

    Map::const_iterator find(const std::string &name) const { return services_.find(name); }
    Map::const_iterator begin() const { return services_.begin(); }
    Map::const_iterator end() const { return services_.end(); }
    Map::iterator begin() { return services_.begin(); }
    Map::iterator end() { return services_.end(); }
};

class WLANConnectionState
{
  public:
    enum class State
    {
        IDLE,
        ABOUT_TO_CONNECT,
        CONNECTING,
        DONE,
        FAILED,
    };

  private:
    std::string service_name_;
    State state_;

  public:
    WLANConnectionState(const WLANConnectionState &) = delete;
    WLANConnectionState &operator=(const WLANConnectionState &) = delete;

    explicit WLANConnectionState():
        state_(State::IDLE)
    {}

    void reset()
    {
        service_name_.clear();
        state_ = State::IDLE;
    }

    void about_to_connect_to(const std::string &service_name)
    {
        log_assert(state_ == State::IDLE);
        log_assert(!service_name.empty());
        service_name_ = service_name;
        state_ = State::ABOUT_TO_CONNECT;
    }

    void start_connecting()
    {
        log_assert(state_ == State::ABOUT_TO_CONNECT);
        state_ = State::CONNECTING;
    }

    void finished_successfully()
    {
        log_assert(state_ == State::CONNECTING);
        state_ = State::DONE;
    }

    void finished_with_failure()
    {
        log_assert(state_ == State::CONNECTING);
        state_ = State::FAILED;
    }

    State get_state() const { return state_; }

    const std::string &get_service_name() const { return service_name_; }
};

class DBusSignalManagerData
{
  public:
    GMutex lock;

    void (*schedule_connect_to_wlan)(void);
    WLANConnectionState wlan_connection_state;

    ServiceList services;

    DBusSignalManagerData(const DBusSignalManagerData &) = delete;
    DBusSignalManagerData &operator=(const DBusSignalManagerData &) = delete;

    explicit DBusSignalManagerData():
        schedule_connect_to_wlan(nullptr)
    {
        g_mutex_init(&lock);
    }

    void init(void (*schedule_connect_to_wlan_fn)())
    {
        g_mutex_init(&lock);
        schedule_connect_to_wlan = schedule_connect_to_wlan_fn;
        wlan_connection_state.reset();
        services.clear();
    }
};

static void service_connected(const char *service_name,
                              enum ConnmanCommonConnectServiceCallbackResult result,
                              void *user_data)
{
    auto *data = static_cast<DBusSignalManagerData *>(user_data);

    g_mutex_lock(&data->lock);

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

    g_mutex_unlock(&data->lock);
}

void dbussignal_connman_manager_connect_our_wlan(DBusSignalManagerData *data)
{
    g_mutex_lock(&data->lock);

    switch(data->wlan_connection_state.get_state())
    {
      case WLANConnectionState::State::ABOUT_TO_CONNECT:
        data->wlan_connection_state.start_connecting();

        if(!connman_common_connect_service_by_object_path(data->wlan_connection_state.get_service_name().c_str(),
                                                          service_connected,
                                                          data))
            service_connected(data->wlan_connection_state.get_service_name().c_str(),
                              CONNMAN_SERVICE_CONNECT_FAILURE, data);

        break;

      case WLANConnectionState::State::IDLE:
      case WLANConnectionState::State::CONNECTING:
      case WLANConnectionState::State::DONE:
      case WLANConnectionState::State::FAILED:
        BUG("Tried to connect to WLAN in state %d",
            static_cast<int>(data->wlan_connection_state.get_state()));
        break;
    }

    g_mutex_unlock(&data->lock);
}

static void unknown_signal(const char *iface_name, const char *signal_name,
                           const char *sender_name)
{
    msg_error(ENOSYS, LOG_NOTICE, "Got unknown signal %s.%s from %s",
              iface_name, signal_name, sender_name);
}

static void check_parameter_assertions(GVariant *parameters,
                                       guint expected_number_of_parameters)
{
    /* we may use #log_assert() here because the GDBus code is supposed to do
     * any type checks before calling us---here, we just make sure we can
     * trust those type checks */
    log_assert(g_variant_type_is_tuple(g_variant_get_type(parameters)));
    log_assert(g_variant_n_children(parameters) == expected_number_of_parameters);
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

        if(settings.is_address_different(address) ||
           settings.is_netmask_different(nm) ||
           settings.is_gateway_different(gw))
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
        wlan_connection_state.reset();
        break;

      case WLANConnectionState::State::ABOUT_TO_CONNECT:
      case WLANConnectionState::State::CONNECTING:
        return false;
    }

    if(!configure_ipv4_settings(service, service_name, prefs))
        return false;

    const auto &service_data(service.get_service_data());

    msg_vinfo(MESSAGE_LEVEL_DEBUG,
              "Our WLAN is %sa favorite, auto-connect %s, "
              "make it auto-connect %d",
              service_data.is_favorite_.pick<const char *>("", "not ", "maybe "),
              service_data.is_auto_connect_.pick<const char *>("yes", "no", "maybe"),
              make_it_favorite);

    if(service_data.is_favorite_ == true)
    {
        if(service_data.is_auto_connect_ == false)
        {
            if(connman_common_set_service_property(service_name.c_str(),
                                                   "AutoConnect",
                                                   g_variant_new_variant(g_variant_new_boolean(true))))
            {
                wlan_connection_state.about_to_connect_to(service_name);
                wlan_connection_state.start_connecting();
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
                                  GVariant *removed)
{
    if(!msg_is_verbose(level))
        return;

    GVariantIter iter;
    g_variant_iter_init(&iter, removed);
    const gchar *name;

    while(g_variant_iter_loop(&iter, "&o", &name))
        msg_info("Service removed: \"%s\"", name);
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
                                       Connman::Technology &tech)
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
            if(strcmp(iter_key, "Address") == 0)
            {
                service_data.mac_address_.set(g_variant_get_string(iter_value, NULL));
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
        if(parse_generic_service_data(prop, value, service_data, tech) ||
           parse_ethernet_data(prop, value, ethernet_data) ||
           parse_wlan_data(prop, value, wlan_data))
        {
            parsed_any_property = true;
        }
    }

    return parsed_any_property;
}

static void get_changed_services_names(GVariant *changes,
                                       std::map<std::string, bool> &has_changed)
{
    GVariantIter iter;
    g_variant_iter_init(&iter, changes);

    GVariantIter *props_iter;
    const char *name;

    while(g_variant_iter_loop(&iter, "(&oa{sv})", &name, &props_iter))
    {
        if(name[0] != '\0' && g_variant_iter_n_children(props_iter) > 0)
            has_changed[name] = true;
    }

}

template <typename RemovedType>
struct UpdateServiceListTraits;

template <>
struct UpdateServiceListTraits<GVariant *>
{
    static inline bool is_empty(const GVariant *rm) { return rm == nullptr; }

    static inline void for_each(GVariant *rm,
                                const std::function<void(const char *)> &fn)
    {
        GVariantIter iter;
        const gchar *name;

        g_variant_iter_init(&iter, rm);

        while(g_variant_iter_loop(&iter, "&o", &name))
            fn(name);
    }
};

template <>
struct UpdateServiceListTraits<std::vector<std::string>>
{
    using RemovedType = std::vector<std::string>;

    static inline bool is_empty(const RemovedType &rm) { return rm.empty(); }

    static inline void for_each(const RemovedType &rm,
                                const std::function<void(const char *)> &fn)
    {
        for(const auto &name : rm)
            fn(name.c_str());
    }
};

/*!
 * Remove listed services from our list.
 */
template <typename RemovedType, typename Traits = UpdateServiceListTraits<RemovedType>>
static void update_service_list(ServiceList &known_services,
                                WLANConnectionState &wlan_connection_state,
                                const RemovedType &removed,
                                bool &have_lost_active_ethernet_device,
                                bool &have_lost_active_wlan_device)
{
    have_lost_active_ethernet_device = false;
    have_lost_active_wlan_device = false;

    if(Traits::is_empty(removed))
        return;

    dump_removed_services(MESSAGE_LEVEL_TRACE, removed);

    Traits::for_each(removed,
        [&known_services, &wlan_connection_state,
         &have_lost_active_ethernet_device, &have_lost_active_wlan_device]
        (const char *name)
        {
            const Connman::ServiceBase *service(known_services[name]);

            if(service == nullptr)
                return;

            if(service->is_ours() && service->is_active())
            {
                switch(service->get_technology())
                {
                case Connman::Technology::UNKNOWN_TECHNOLOGY:
                    BUG("Removed service \"%s\" of unknown technology", name);
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
                break;

              case WLANConnectionState::State::ABOUT_TO_CONNECT:
                if(wlan_connection_state.get_service_name() == name)
                    wlan_connection_state.reset();

                break;
            }

            known_services.erase(name);
        });
}

static void update_service_list(GVariant *all_services,
                                ServiceList &known_services,
                                const std::map<std::string, bool> *has_changed,
                                const struct network_prefs_mac_address &our_ethernet_mac,
                                const struct network_prefs_mac_address &our_wlan_mac)
{
    if(has_changed != nullptr && has_changed->empty())
        return;

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

        if(has_changed != nullptr && has_changed->find(name) == has_changed->end())
            continue;

        dump_service_changes(MESSAGE_LEVEL_TRACE, name, props_iter);

        Connman::ServiceData service_data;
        Connman::Service<Connman::Technology::ETHERNET>::TechDataType ethernet_data;
        Connman::Service<Connman::Technology::WLAN>::TechDataType wlan_data;
        Connman::Technology tech;

        if(!parse_service_data(props_iter, tech,
                               service_data, ethernet_data, wlan_data))
        {
            BUG("Reported service \"%s\" contains no information", name);
            continue;
        }

        Connman::ServiceBase *service = known_services[name];

        switch(tech)
        {
          case Connman::Technology::UNKNOWN_TECHNOLOGY:
            break;

          case Connman::Technology::ETHERNET:
            if(service == nullptr)
                known_services.insert(name,
                                      std::move(service_data), std::move(ethernet_data),
                                      our_ethernet_mac.is_real &&
                                      service_data.mac_address_ != our_ethernet_mac.address);
            else
                static_cast<Connman::Service<Connman::Technology::ETHERNET> *>(service)->put_changes(std::move(service_data), std::move(ethernet_data));

            break;

          case Connman::Technology::WLAN:
            if(service == nullptr)
                known_services.insert(name,
                                      std::move(service_data), std::move(wlan_data),
                                      our_wlan_mac.is_real &&
                                      service_data.mac_address_ != our_wlan_mac.address);
            else
                static_cast<Connman::Service<Connman::Technology::WLAN> *>(service)->put_changes(std::move(service_data), std::move(wlan_data));

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

static void ignore_services_if(ServiceList &services,
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

static void ignore_inactive_services_on_wrong_interfaces(ServiceList &known_services)
{
    ignore_services_if(known_services,
            [] (const Connman::ServiceBase &s, const std::string &name)
            {
                return !s.is_active() && !s.is_ours();
            });
}

static void ignore_wlan_services_on_our_interfaces(ServiceList &known_services)
{
    if(known_services.number_of_wlan_services() > 0)
        ignore_services_if(known_services,
                [] (const Connman::ServiceBase &s, const std::string &name)
                {
                    return s.is_ours() && s.get_technology() == Connman::Technology::WLAN;
                });
}

static void disconnect_active_services_if(ServiceList &services,
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

static void disconnect_active_services_on_wrong_interfaces(ServiceList &known_services)
{
    disconnect_active_services_if(known_services,
            [] (const Connman::ServiceBase &s, const std::string &name)
            {
                return !s.is_ours();
            });
}

static void disconnect_nonmatching_active_services_on_our_interface(ServiceList &known_services,
                                                                    const std::string &our_ethernet_name,
                                                                    const std::string &our_wlan_name)
{
    disconnect_active_services_if(known_services,
            [&our_ethernet_name, &our_wlan_name]
            (const Connman::ServiceBase &s, const std::string &name)
            {
                return s.is_ours() &&
                        name != our_ethernet_name && name != our_wlan_name;
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
static inline void bug_if_not_processed(const ServiceList &known_services) {}
#else /* !NDEBUG */
static void bug_if_not_processed(const ServiceList &known_services)
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
static bool do_process_pending_changes(ServiceList &known_services,
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
               /* there are no known WLANs, maybe because the the WLAN adapter
                * is in suspend mode */
               connman_wlan_power_on();
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
        BUG("WLAN connection state for \"%s\" is %d",
            wlan_connection_state.get_service_name().c_str(),
            static_cast<int>(wlan_connection_state.get_state()));
        wlan_connection_state.reset();

        /* fall-through */

      case WLANConnectionState::State::IDLE:
        wlan_connection_state.about_to_connect_to(our_wlan->first);

        /* Click. */
        return true;

      case WLANConnectionState::State::ABOUT_TO_CONNECT:
      case WLANConnectionState::State::CONNECTING:
        break;
    }

    return false;
}

static void schedule_wlan_connect_if_necessary(bool is_necessary,
                                               DBusSignalManagerData &data)
{
    g_mutex_lock(&data.lock);

    if(is_necessary)
    {
        log_assert(data.wlan_connection_state.get_state() == WLANConnectionState::State::ABOUT_TO_CONNECT);

        connman_wlan_power_on();
        data.schedule_connect_to_wlan();

        msg_vinfo(MESSAGE_LEVEL_DEBUG,
                  "***** Scheduled connect to WLAN *****");
    }

    g_mutex_unlock(&data.lock);
}

static bool update_all_services(GVariant *all_services, GVariant *changes,
                                DBusSignalManagerData &data,
                                const char *context)
{
    if(all_services == nullptr)
    {
        BUG("Querying services from ConnMan failed (%s)", context);
        return false;
    }

    const struct network_prefs_mac_address *preferred_ethernet_mac =
        network_prefs_get_mac_address_by_tech(NWPREFSTECH_ETHERNET);
    const struct network_prefs_mac_address *preferred_wlan_mac =
        network_prefs_get_mac_address_by_tech(NWPREFSTECH_WLAN);

    log_assert(preferred_ethernet_mac != nullptr);
    log_assert(preferred_wlan_mac != nullptr);

    if(changes != nullptr)
    {
        std::map<std::string, bool> has_changed;
        get_changed_services_names(changes, has_changed);
        update_service_list(all_services, data.services, &has_changed,
                            *preferred_ethernet_mac, *preferred_wlan_mac);
    }
    else
        update_service_list(all_services, data.services, nullptr,
                            *preferred_ethernet_mac, *preferred_wlan_mac);

    return true;
}

static void process_pending_changes(DBusSignalManagerData &data,
                                    bool have_lost_active_ethernet_device,
                                    bool have_lost_active_wlan_device)
{
    const struct network_prefs *ethernet_prefs;
    const struct network_prefs *wlan_prefs;
    struct network_prefs_handle *handle =
        network_prefs_open_ro(&ethernet_prefs, &wlan_prefs);

    const bool need_to_schedule_wlan_connection =
        do_process_pending_changes(data.services,
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
find_removed(const ServiceList &known_services, GVariant *all_services)
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

void dbussignal_connman_manager(GDBusProxy *proxy, const gchar *sender_name,
                                const gchar *signal_name, GVariant *parameters,
                                gpointer user_data)
{
    static const char iface_name[] = "net.connman.Manager";
    auto *data = static_cast<DBusSignalManagerData *>(user_data);

    if(strcmp(signal_name, "ServicesChanged") == 0)
    {
        msg_vinfo(MESSAGE_LEVEL_DIAG, "ConnMan services changed");
        check_parameter_assertions(parameters, 2);

        GVariant *changes = g_variant_get_child_value(parameters, 0);
        GVariant *removed = g_variant_get_child_value(parameters, 1);

        bool have_lost_active_ethernet_device;
        bool have_lost_active_wlan_device;
        update_service_list(data->services, data->wlan_connection_state,
                            removed,
                            have_lost_active_ethernet_device,
                            have_lost_active_wlan_device);

        /* stupid as it may seem, there are some important information (such as
         * the IP address...) missing in the changes reported by ConnMan, so we
         * ask ConnMan again to get at the full list of services; the service
         * names listed in the "has_changed" map below are used for filtering
         * only */
        GVariant *all_services =
            connman_common_query_services(dbus_get_connman_manager_iface());

        if(update_all_services(all_services, changes, *data,
                               "ServicesChanged"))
            g_variant_unref(all_services);

        g_variant_unref(changes);
        g_variant_unref(removed);

        process_pending_changes(*data,
                                have_lost_active_ethernet_device,
                                have_lost_active_wlan_device);
    }
    else if(strcmp(signal_name, "PropertyChanged") == 0)
    {
        check_parameter_assertions(parameters, 2);

        GVariant *all_services =
            connman_common_query_services(dbus_get_connman_manager_iface());

        bool have_lost_active_ethernet_device = false;
        bool have_lost_active_wlan_device = false;

        if(all_services != nullptr)
        {
            const std::vector<std::string> removed(
                    std::move(find_removed(data->services, all_services)));

            update_service_list(data->services, data->wlan_connection_state,
                                removed,
                                have_lost_active_ethernet_device,
                                have_lost_active_wlan_device);
        }

        if(update_all_services(all_services, nullptr, *data,
                               "PropertyChanged"))
            g_variant_unref(all_services);

        process_pending_changes(*data,
                                have_lost_active_ethernet_device,
                                have_lost_active_wlan_device);

        const char *param_name;
        GVariant *value;
        g_variant_get(parameters, "(&sv)", &param_name, &value);

        log_assert(param_name != NULL);

        if(strcmp(param_name, "State") == 0)
        {
            msg_vinfo(MESSAGE_LEVEL_DIAG, "ConnMan state changed -> %s",
                      g_variant_get_string(value, NULL));
            dcpregs_networkconfig_interfaces_changed();
        }
        else
            msg_vinfo(MESSAGE_LEVEL_DIAG,
                      "ConnMan property \"%s\" changed", param_name);

        g_variant_unref(value);
    }
    else if(strcmp(signal_name, "TechnologyAdded"))
    {
        BUG("ConnMan added technology, must be handled");

        /* TODO: Maybe switch to alternative technology, automatic switching to
         *       wifi is disabled in ConnMan */
    }
    else if(strcmp(signal_name, "TechnologyRemoved"))
    {
        BUG("ConnMan removed technology, must be handled");

        /* TODO: Maybe switch to alternative technology, automatic switching to
         *       wifi is disabled in ConnMan */
    }
    else
        unknown_signal(iface_name, signal_name, sender_name);
}

static DBusSignalManagerData global_dbussignal_connman_manager_data;

DBusSignalManagerData *
dbussignal_connman_manager_init(void (*schedule_connect_to_wlan_fn)())
{
    global_dbussignal_connman_manager_data.init(schedule_connect_to_wlan_fn);
    return &global_dbussignal_connman_manager_data;
}

void dbussignal_connman_manager_about_to_connect_signals(void)
{
    GVariant *all_services =
        connman_common_query_services(dbus_get_connman_manager_iface());

    if(update_all_services(all_services, nullptr,
                           global_dbussignal_connman_manager_data, "startup"))
        g_variant_unref(all_services);

    process_pending_changes(global_dbussignal_connman_manager_data,
                            false, false);
}

void dbussignal_connman_manager_connect_to_service(enum NetworkPrefsTechnology tech,
                                                   const char *service_to_be_disabled)
{
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

    g_mutex_lock(&global_dbussignal_connman_manager_data.lock);

    switch(tech)
    {
      case NWPREFSTECH_UNKNOWN:
        break;

      case NWPREFSTECH_ETHERNET:
        if(network_prefs_generate_service_name(ethernet_prefs, service_name,
                                               sizeof(service_name)) > 0)
        {
            auto our_service(global_dbussignal_connman_manager_data.services.find(service_name));

            if(our_service != global_dbussignal_connman_manager_data.services.end())
                configure_ipv4_settings(*our_service->second, our_service->first,
                                        ethernet_prefs);
        }

        break;

      case NWPREFSTECH_WLAN:
        if(network_prefs_generate_service_name(wlan_prefs, service_name,
                                               sizeof(service_name)) > 0)
        {
            auto our_service(global_dbussignal_connman_manager_data.services.find(service_name));

            if(our_service != global_dbussignal_connman_manager_data.services.end())
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

    g_mutex_unlock(&global_dbussignal_connman_manager_data.lock);

    network_prefs_close(handle);

    if(service_to_be_disabled != NULL && service_to_be_disabled[0] != '\0')
    {
        auto service(global_dbussignal_connman_manager_data.services.find(service_to_be_disabled));

        if(service != global_dbussignal_connman_manager_data.services.end() &&
           service->second->is_active())
            avoid_service(*service->second, service->first);
    }

    schedule_wlan_connect_if_necessary(need_to_schedule_wlan_connection,
                                       global_dbussignal_connman_manager_data);
}

void dbussignal_connman_manager_connect_to_wps_service(const char *network_name,
                                                       const char *network_ssid,
                                                       const char *service_to_be_disabled)
{
    if(network_name == NULL && network_ssid == NULL)
        BUG("Automatic connection to WPS service not implemented yet");
    else if(network_name != NULL)
        BUG("Connecting to WPS service by name (%s) not implemented yet ", network_name);
    else
        BUG("Connecting to WPS service by SSID (%s) not implemented yet ", network_ssid);
}
