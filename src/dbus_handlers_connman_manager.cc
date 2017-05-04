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
#include <cstring>
#include <cinttypes>

#include "dbus_handlers_connman_manager.h"
#include "dbus_handlers_connman_manager_glue.h"
#include "dcpregs_networkconfig.h"
#include "connman.h"
#include "connman_common.h"
#include "messages.h"

class Maybe
{
  private:
    bool is_state_known_;
    bool state_;

  public:
    Maybe(const Maybe &) = delete;
    Maybe(Maybe &&) = default;
    Maybe &operator=(const Maybe &) = delete;

    explicit Maybe():
        is_state_known_(false),
        state_(false)
    {}

    void set_unknown() { is_state_known_ = false; }

    bool operator=(bool state)
    {
        state_ = state;
        is_state_known_ = true;
        return state_;
    }

    bool operator==(bool b) const { return is_state_known_ ? state_ == b : false; }
    bool operator!=(bool b) const { return is_state_known_ ? state_ != b : false; }

    template <typename T>
    const T &pick(const T &if_yes, const T &if_no, const T &if_unknown) const
    {
        return is_state_known_
            ? (state_ ? if_yes : if_no)
            : if_unknown;
    }
};

class ServiceEntry
{
  public:
    Maybe is_favorite;
    Maybe is_auto_connect;
    Maybe is_connected;

    ServiceEntry(const ServiceEntry &) = delete;
    ServiceEntry(ServiceEntry &&) = default;
    ServiceEntry &operator=(const ServiceEntry &) = delete;

    explicit ServiceEntry() {}
};

using ServiceList = std::map<std::string, ServiceEntry>;

class WLANConnectionState
{
  public:
    bool is_connecting;
    Maybe has_failed;

    WLANConnectionState(const WLANConnectionState &) = delete;
    WLANConnectionState &operator=(const WLANConnectionState &) = delete;

    explicit WLANConnectionState():
        is_connecting(false)
    {}

    void init()
    {
        is_connecting = false;
        has_failed.set_unknown();
    }
};

class dbussignal_connman_manager_data
{
  public:
    GMutex lock;

    char wlan_service_name[512];
    void (*schedule_connect_to_wlan)(void);
    WLANConnectionState wlan_connection_state;

    ServiceList services;

    dbussignal_connman_manager_data(const dbussignal_connman_manager_data &) = delete;
    dbussignal_connman_manager_data &operator=(const dbussignal_connman_manager_data &) = delete;

    explicit dbussignal_connman_manager_data():
        schedule_connect_to_wlan(nullptr)
    {
        g_mutex_init(&lock);
        wlan_service_name[0] = '\0';
    }

    void init(void (*schedule_connect_to_wlan_fn)())
    {
        g_mutex_init(&lock);
        wlan_service_name[0] = '\0';
        schedule_connect_to_wlan = schedule_connect_to_wlan_fn;
        wlan_connection_state.init();
        services.clear();
    }
};

static ServiceList::iterator insert_service(ServiceList &services,
                                            const char *service_name)
{
    auto list_entry = services.find(service_name);

    if(list_entry != services.end())
        return list_entry;

    auto elem = services.emplace(service_name, std::move(ServiceEntry()));

    return elem.first;
}

static bool remove_service(ServiceList &services, const char *service_name)
{
    return services.erase(service_name) == 1;
}

static void service_connected(const char *service_name,
                              enum ConnmanCommonConnectServiceCallbackResult result,
                              void *user_data)
{
    auto *data = static_cast<dbussignal_connman_manager_data *>(user_data);

    g_mutex_lock(&data->lock);

    data->wlan_connection_state.is_connecting = false;

    switch(result)
    {
      case CONNMAN_SERVICE_CONNECT_CONNECTED:
        msg_info("Connected to %s", service_name);
        data->wlan_connection_state.has_failed = false;
        break;

      case CONNMAN_SERVICE_CONNECT_FAILURE:
        msg_info("Failed connecting to %s", service_name);
        data->wlan_connection_state.has_failed = true;
        break;

      case CONNMAN_SERVICE_CONNECT_DISCARDED:
        break;
    }

    g_mutex_unlock(&data->lock);
}

void dbussignal_connman_manager_connect_our_wlan(dbussignal_connman_manager_data *data)
{
    g_mutex_lock(&data->lock);

    data->wlan_connection_state.is_connecting = true;
    data->wlan_connection_state.has_failed.set_unknown();

    connman_common_connect_service_by_object_path(data->wlan_service_name,
                                                  service_connected, data);

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

static struct ConnmanInterfaceData *
get_iface_data_by_service_name(const std::string &service_name,
                               Maybe &is_favorite, Maybe &is_auto_connect,
                               Maybe &is_connected)
{
    struct ConnmanInterfaceData *data =
        connman_find_interface_by_object_path(service_name.c_str());

    if(data != NULL)
    {
        is_favorite = connman_get_favorite(data);
        is_auto_connect = connman_get_auto_connect_mode(data);

        switch(connman_get_state(data))
        {
          case CONNMAN_STATE_ASSOCIATION:
          case CONNMAN_STATE_CONFIGURATION:
          case CONNMAN_STATE_READY:
          case CONNMAN_STATE_ONLINE:
            is_connected = true;
            break;

          case CONNMAN_STATE_NOT_SPECIFIED:
          case CONNMAN_STATE_IDLE:
          case CONNMAN_STATE_FAILURE:
          case CONNMAN_STATE_DISCONNECT:
            is_connected = false;
            break;
        }
    }

    return data;
}

static bool ipv4_settings_are_different(struct ConnmanInterfaceData *iface_data,
                                        bool with_dhcp, const char *address,
                                        const char *nm, const char *gw,
                                        const char *dns1, const char *dns2,
                                        bool *different_ipv4_config,
                                        bool *different_nameservers)
{
    *different_ipv4_config = true;
    *different_nameservers = true;

    char buffer[64];

    const enum ConnmanDHCPMode system_dhcp_mode =
        connman_get_dhcp_mode(iface_data, CONNMAN_IP_VERSION_4,
                              CONNMAN_READ_CONFIG_SOURCE_ANY);

    switch(system_dhcp_mode)
    {
      case CONNMAN_DHCP_NOT_AVAILABLE:
      case CONNMAN_DHCP_UNKNOWN_METHOD:
        break;

      case CONNMAN_DHCP_ON:
      case CONNMAN_DHCP_OFF:
        if((system_dhcp_mode == CONNMAN_DHCP_ON && !with_dhcp) ||
           (system_dhcp_mode == CONNMAN_DHCP_OFF && with_dhcp))
            goto ipv4_check_done;

        if(address != NULL || nm != NULL || gw != NULL)
            goto ipv4_check_done;

        break;

      case CONNMAN_DHCP_AUTO:
        goto ipv4_check_done;

      case CONNMAN_DHCP_MANUAL:
        if(with_dhcp)
            goto ipv4_check_done;

        if(connman_get_address_string(iface_data, CONNMAN_IP_VERSION_4,
                                      CONNMAN_READ_CONFIG_SOURCE_ANY,
                                      buffer, sizeof(buffer)) &&
           strcmp(address, buffer) != 0)
            goto ipv4_check_done;

        if(connman_get_netmask_string(iface_data, CONNMAN_IP_VERSION_4,
                                      CONNMAN_READ_CONFIG_SOURCE_ANY,
                                      buffer, sizeof(buffer)) &&
           strcmp(nm, buffer) != 0)
            goto ipv4_check_done;

        if(connman_get_gateway_string(iface_data, CONNMAN_IP_VERSION_4,
                                      CONNMAN_READ_CONFIG_SOURCE_ANY,
                                      buffer, sizeof(buffer)) &&
           strcmp(gw, buffer) != 0)
            goto ipv4_check_done;

        break;

      case CONNMAN_DHCP_FIXED:
        /* special case: cannot change the IPv4 parameters */
        break;
    }

    *different_ipv4_config = false;

ipv4_check_done:
    if(connman_get_primary_dns_string(iface_data, buffer, sizeof(buffer)))
    {
        if((dns1 != NULL && strcmp(dns1, buffer) != 0) ||
           (dns1 == NULL && system_dhcp_mode != CONNMAN_DHCP_ON && buffer[0] != '\0'))
            goto dns_check_done;
    }

    if(connman_get_secondary_dns_string(iface_data, buffer, sizeof(buffer)))
    {
        if((dns2 != NULL && strcmp(dns2, buffer) != 0) ||
           (dns2 == NULL && system_dhcp_mode != CONNMAN_DHCP_ON && buffer[0] != '\0'))
            goto dns_check_done;
    }

    *different_nameservers = false;

dns_check_done:
    return *different_ipv4_config || *different_nameservers;
}

static void avoid_wlan_service(const char *service_name)
{
    connman_common_set_service_property(service_name,
                                        "AutoConnect",
                                        g_variant_new_variant(g_variant_new_boolean(false)));
    connman_common_disconnect_service_by_object_path(service_name);
    connman_common_remove_service_by_object_path(service_name);
}

static void avoid_service(const ServiceEntry &service_list_entry,
                          const std::string &service_name,
                          bool is_ethernet)
{
    if(service_list_entry.is_connected != true)
        return;

    if(is_ethernet)
        connman_common_disconnect_service_by_object_path(service_name.c_str());
    else
        avoid_wlan_service(service_name.c_str());
}

static bool avoid_service_if_no_preferences(const ServiceEntry &service_list_entry,
                                            const std::string &service_name,
                                            const struct network_prefs *prefs,
                                            bool is_ethernet)
{
    if(prefs != NULL)
        return false;

    avoid_service(service_list_entry, service_name, is_ethernet);

    BUG("Cannot configure ConnMan service \"%s\": no preferences",
        service_name.c_str());

    return true;
}

static void configure_our_ipv6_network_common(struct ConnmanInterfaceData *iface_data,
                                              const std::string &service_name)
{
    msg_vinfo(MESSAGE_LEVEL_DEBUG,
              "Configure IPv6 parameters for service %s", service_name.c_str());

    const enum ConnmanDHCPMode system_dhcp_mode =
        connman_get_dhcp_mode(iface_data, CONNMAN_IP_VERSION_6,
                              CONNMAN_READ_CONFIG_SOURCE_ANY);

    switch(system_dhcp_mode)
    {
      case CONNMAN_DHCP_OFF:
        msg_vinfo(MESSAGE_LEVEL_DEBUG,
                  "Not configuring IPv6 parameters for %s: up to date",
                  service_name.c_str());
        return;

      case CONNMAN_DHCP_NOT_AVAILABLE:
      case CONNMAN_DHCP_UNKNOWN_METHOD:
      case CONNMAN_DHCP_ON:
      case CONNMAN_DHCP_AUTO:
      case CONNMAN_DHCP_MANUAL:
      case CONNMAN_DHCP_FIXED:
        break;
    }

    /* All we are doing about IPv6 is to disable it---sad. :( */
    msg_vinfo(MESSAGE_LEVEL_DEBUG,
              "Disable IPv6 for service %s", service_name.c_str());

    GVariantBuilder builder;
    g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);

    g_variant_builder_add(&builder, "{sv}", "Method", g_variant_new_string("off"));

    GVariant *ipv6_config =
        g_variant_new_variant(g_variant_builder_end(&builder));

    if(ipv6_config != NULL)
        connman_common_set_service_property(service_name.c_str(),
                                            "IPv6.Configuration", ipv6_config);
}

static bool configure_our_ipv4_network_common(struct ConnmanInterfaceData *iface_data,
                                              const ServiceEntry &service_list_entry,
                                              const std::string &service_name,
                                              const struct network_prefs *prefs,
                                              bool is_ethernet)
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
        avoid_service(service_list_entry, service_name, is_ethernet);
        return false;
    }

    bool different_ipv4_config;
    bool different_nameservers;

    if(!ipv4_settings_are_different(iface_data, want_dhcp,
                                    want_address, want_netmask, want_gateway,
                                    want_dns1, want_dns2,
                                    &different_ipv4_config,
                                    &different_nameservers))
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
 * Set network configuration for our LAN.
 *
 * This function does not connect, it only informs ConnMan about configuration.
 * In case the configuratin is not available in our own configuration file, the
 * service is disconnnected and removed (if possible).
 *
 * \returns
 *     True in case the LAN has been configured, false in case it hasn't.
 */
static bool configure_our_lan(const struct network_prefs *prefs,
                              ServiceEntry &service_list_entry,
                              const std::string &service_name)
{
    if(avoid_service_if_no_preferences(service_list_entry, service_name, prefs, true))
        return false;

    Maybe dummy;
    struct ConnmanInterfaceData *iface_data =
        get_iface_data_by_service_name(service_name,
                                       service_list_entry.is_favorite,
                                       dummy,
                                       service_list_entry.is_connected);

    if(iface_data == NULL)
        return false;

    configure_our_ipv6_network_common(iface_data, service_name);

    const bool ret =
        configure_our_ipv4_network_common(iface_data, service_list_entry,
                                          service_name, prefs, true);

    connman_free_interface_data(iface_data);

    return ret;
}

static bool is_wlan_connecting_or_has_failed(const WLANConnectionState &wlan_conn_state)
{
    return wlan_conn_state.is_connecting ||
           wlan_conn_state.has_failed == true;
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
static bool configure_our_wlan(const struct network_prefs *prefs,
                               ServiceEntry &service_list_entry,
                               const std::string &service_name,
                               WLANConnectionState &wlan_conn_state,
                               const char *ethernet_service_name,
                               bool have_just_lost_ethernet_device,
                               bool make_it_favorite)
{
    if(avoid_service_if_no_preferences(service_list_entry, service_name, prefs, false))
        return false;

    if(is_wlan_connecting_or_has_failed(wlan_conn_state))
        return false;

    struct ConnmanInterfaceData *iface_data =
        get_iface_data_by_service_name(service_name,
                                       service_list_entry.is_favorite,
                                       service_list_entry.is_auto_connect,
                                       service_list_entry.is_connected);

    if(iface_data == NULL)
        return false;

    configure_our_ipv6_network_common(iface_data, service_name);

    const bool ret =
        configure_our_ipv4_network_common(iface_data, service_list_entry,
                                          service_name, prefs, false);

    connman_free_interface_data(iface_data);
    iface_data = NULL;

    if(!ret)
        return false;

    msg_vinfo(MESSAGE_LEVEL_DEBUG,
              "Our WLAN is %sa favorite, auto-connect %s, "
              "make it auto-connect %d",
              service_list_entry.is_favorite.pick<const char *>("", "not", "maybe"),
              service_list_entry.is_auto_connect.pick<const char *>("yes", "no", "maybe"),
              make_it_favorite);

    if(service_list_entry.is_favorite == true)
    {
        if(service_list_entry.is_auto_connect == false)
        {
            if(connman_common_set_service_property(service_name.c_str(),
                                                   "AutoConnect",
                                                   g_variant_new_variant(g_variant_new_boolean(true))))
                wlan_conn_state.is_connecting = true;
        }

        /* rely on auto-connect */
        return false;
    }

    if(service_list_entry.is_favorite == false && make_it_favorite)
    {
        /* if this function returns true, then the caller will schedule a WLAN
         * connection attempt by calling #schedule_wlan_connect_if_necessary();
         * so we are returning true */
        return true;
    }

    /* fall back to Ethernet if possible */

    if(ethernet_service_name[0] == '\0')
        return have_just_lost_ethernet_device;

    struct ConnmanInterfaceData *data =
        connman_find_interface_by_object_path(ethernet_service_name);

    if(data == NULL)
        return have_just_lost_ethernet_device;

    switch(connman_get_state(data))
    {
      case CONNMAN_STATE_ASSOCIATION:
      case CONNMAN_STATE_CONFIGURATION:
      case CONNMAN_STATE_READY:
      case CONNMAN_STATE_ONLINE:
        break;

      case CONNMAN_STATE_NOT_SPECIFIED:
      case CONNMAN_STATE_IDLE:
      case CONNMAN_STATE_FAILURE:
      case CONNMAN_STATE_DISCONNECT:
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

static bool react_to_service_changes(ServiceList &known_services_list,
                                     GVariant *changes, GVariant *removed,
                                     char *wlan_service_name,
                                     WLANConnectionState &wlan_conn_state,
                                     const struct network_prefs *ethernet_prefs,
                                     const struct network_prefs *wlan_prefs)
{
    if(changes == NULL && removed == NULL)
    {
        /* ignore unlikely, but possible funny data from ConnMan */
        return false;
    }

    char ethernet_service_name[NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE];

    const bool have_ethernet_service_name =
        network_prefs_generate_service_name(ethernet_prefs, ethernet_service_name,
                                            sizeof(ethernet_service_name)) > 0;
    network_prefs_generate_service_name(wlan_prefs, wlan_service_name,
                                        NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE);

    /* ConnMan is configured so to connect to Ethernet or WLAN automatically
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
     * So what we are doing in the code below is (1) remove any successfully
     * connected WLAN service that does not match the one configured by the
     * user; (2) tell ConnMan to connect to the WLAN the user has configured;
     * and (3) configure any changed service with our set of stored preferences
     * in case they are different.
     *
     * Note that the problems described above occur only because our user
     * interface policy enforces a restriction to a single managed WLAN. A more
     * generalized approach that allows multiple configurations would actually
     * simplify things a lot, both for the software and for the end user. */

    bool have_just_lost_ethernet_device = false;

    dump_removed_services(MESSAGE_LEVEL_TRACE, removed);

    GVariantIter iter;
    g_variant_iter_init(&iter, removed);
    const gchar *name;

    while(g_variant_iter_loop(&iter, "&o", &name))
    {
        remove_service(known_services_list, name);

        if(have_ethernet_service_name &&
           strcmp(name, ethernet_service_name) == 0)
            have_just_lost_ethernet_device = true;
        else if(strcmp(name, wlan_service_name) == 0)
        {
            wlan_conn_state.is_connecting = false;
            wlan_conn_state.has_failed.set_unknown();
        }
    }

    g_variant_iter_init(&iter, changes);

    GVariantIter *props_iter;
    bool want_to_switch_to_wlan = false;
    std::string our_ethernet_service_name;
    std::string our_wlan_service_name;

    while(g_variant_iter_loop(&iter, "(&oa{sv})", &name, &props_iter))
    {
        if(name[0] == '\0')
            continue;

        dump_service_changes(MESSAGE_LEVEL_TRACE, name, props_iter);

        const auto service_list_entry_iter(insert_service(known_services_list, name));
        const std::string &service_name(service_list_entry_iter->first);
        ServiceEntry &service_list_entry(service_list_entry_iter->second);
        const char *prop = NULL;
        GVariant *value = NULL;

        while(g_variant_iter_loop(props_iter, "{&sv}", &prop, &value))
        {
            if(strcmp(prop, "State") == 0)
                service_list_entry.is_connected =
                    (strcmp(g_variant_get_string(value, NULL), "ready") == 0);
            else if(strcmp(prop, "Favorite") == 0)
                service_list_entry.is_favorite = !!g_variant_get_boolean(value);
        }

        if(service_name == wlan_service_name)
        {
            /* our WLAN service has changed, perhaps, so we may have to
             * configure it and we have to connect to it in case there is no
             * Ethernet connection */
            if(configure_our_wlan(wlan_prefs, service_list_entry, service_name,
                                  wlan_conn_state, ethernet_service_name,
                                  have_just_lost_ethernet_device, false))
                want_to_switch_to_wlan = true;

            our_wlan_service_name = service_name;

            continue;
        }

        if(service_name == ethernet_service_name)
        {
            /* our LAN service may need some care */
            configure_our_lan(ethernet_prefs, service_list_entry, service_name);
            our_ethernet_service_name = service_name;

            continue;
        }

        /* some service not managed by us */
        if(service_list_entry.is_favorite == false)
        {
            /* we know each other already, and it's not a favorite */
            continue;
        }

        /* new or favorite or both, or state unknown: smash it */
        switch(network_prefs_get_technology_by_service_name(service_name.c_str()))
        {
          case NWPREFSTECH_UNKNOWN:
            msg_error(0, LOG_INFO,
                      "ConnMan service %s changed, but cannot handle technology",
                      service_name.c_str());
            break;

          case NWPREFSTECH_ETHERNET:
            avoid_service(service_list_entry, service_name, true);
            break;

          case NWPREFSTECH_WLAN:
            avoid_service(service_list_entry, service_name, false);
            break;
        }
    }

    if(have_just_lost_ethernet_device && wlan_service_name[0] != '\0')
        want_to_switch_to_wlan = true;

    if(our_ethernet_service_name.empty() && our_wlan_service_name.empty())
    {
        /* there is no Ethernet interface (cable not plugged in), but there is
         * a WLAN matching the configuration set by the user */
        want_to_switch_to_wlan = true;
    }

    if(want_to_switch_to_wlan)
    {
        /* this is the least we should do so that ConnMan can find WLAN
         * networks, manual connect may or may not be necessary (see below) */
        connman_wlan_power_on();
    }
    else
        return false;

    /*
     * We have determined that we should switch over to WLAN. If the WLAN is
     * neither connected nor marked as auto-connect, then we need to connect to
     * it by hand.
     */

    if(our_wlan_service_name.empty())
        return false;

    const auto our_wlan_service(known_services_list.find(our_wlan_service_name));

    if(our_wlan_service->second.is_connected == true)
        return false;

    if(our_wlan_service->second.is_auto_connect == true)
        return false;

    if(is_wlan_connecting_or_has_failed(wlan_conn_state))
        return false;

    /* Click. */
    return true;
}

static void schedule_wlan_connect_if_necessary(bool is_necessary,
                                               dbussignal_connman_manager_data *data,
                                               const char *service_name)
{
    g_mutex_lock(&data->lock);

    if(is_necessary)
    {
        connman_wlan_power_on();

        log_assert(service_name[0] != '\0');

        strncpy(data->wlan_service_name, service_name,
                sizeof(data->wlan_service_name));
        data->wlan_service_name[sizeof(data->wlan_service_name) - 1] = '\0';
        data->schedule_connect_to_wlan();

        msg_vinfo(MESSAGE_LEVEL_DEBUG,
                  "***** Scheduled connect to WLAN *****");
    }
    else
        data->wlan_service_name[0] = '\0';

    g_mutex_unlock(&data->lock);
}

void dbussignal_connman_manager(GDBusProxy *proxy, const gchar *sender_name,
                                const gchar *signal_name, GVariant *parameters,
                                gpointer user_data)
{
    static const char iface_name[] = "net.connman.Manager";
    auto *data = static_cast<dbussignal_connman_manager_data *>(user_data);

    if(strcmp(signal_name, "ServicesChanged") == 0)
    {
        msg_vinfo(MESSAGE_LEVEL_DIAG, "ConnMan services changed");
        check_parameter_assertions(parameters, 2);

        const struct network_prefs *ethernet_prefs;
        const struct network_prefs *wlan_prefs;
        struct network_prefs_handle *handle =
            network_prefs_open_ro(&ethernet_prefs, &wlan_prefs);

        char wlan_service_name_buffer[NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE];
        G_STATIC_ASSERT(sizeof(wlan_service_name_buffer) == sizeof(data->wlan_service_name));

        bool need_to_schedule_wlan_connection = false;

        if(handle != NULL)
        {
            GVariant *changes = g_variant_get_child_value(parameters, 0);
            GVariant *removed = g_variant_get_child_value(parameters, 1);

            need_to_schedule_wlan_connection =
                react_to_service_changes(data->services, changes, removed,
                                         wlan_service_name_buffer,
                                         data->wlan_connection_state,
                                         ethernet_prefs, wlan_prefs);

            g_variant_unref(changes);
            g_variant_unref(removed);

            network_prefs_close(handle);
        }

        dcpregs_networkconfig_interfaces_changed();

        schedule_wlan_connect_if_necessary(need_to_schedule_wlan_connection,
                                           data, wlan_service_name_buffer);
    }
    else if(strcmp(signal_name, "PropertyChanged") == 0)
    {
        check_parameter_assertions(parameters, 2);

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

static dbussignal_connman_manager_data global_dbussignal_connman_manager_data;

dbussignal_connman_manager_data *
dbussignal_connman_manager_init(void (*schedule_connect_to_wlan_fn)())
{
    global_dbussignal_connman_manager_data.init(schedule_connect_to_wlan_fn);
    return &global_dbussignal_connman_manager_data;
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

    char ethernet_service_name[NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE];
    char wlan_service_name[NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE];

    network_prefs_generate_service_name(ethernet_prefs,
                                        ethernet_service_name,
                                        sizeof(ethernet_service_name));

    g_mutex_lock(&global_dbussignal_connman_manager_data.lock);

    bool need_to_schedule_wlan_connection = false;

    switch(tech)
    {
      case NWPREFSTECH_UNKNOWN:
        break;

      case NWPREFSTECH_ETHERNET:
        wlan_service_name[0] = '\0';

        if(ethernet_service_name[0] != '\0')
        {
            const auto iter(insert_service(global_dbussignal_connman_manager_data.services,
                                           ethernet_service_name));
            configure_our_lan(ethernet_prefs, iter->second, iter->first);
        }

        break;

      case NWPREFSTECH_WLAN:
        if(network_prefs_generate_service_name(wlan_prefs,
                                               wlan_service_name,
                                               sizeof(wlan_service_name)))
        {
            const auto iter(insert_service(global_dbussignal_connman_manager_data.services,
                                           wlan_service_name));

            global_dbussignal_connman_manager_data.wlan_connection_state.is_connecting = false;
            global_dbussignal_connman_manager_data.wlan_connection_state.has_failed.set_unknown();

            if(configure_our_wlan(wlan_prefs, iter->second, iter->first,
                                  global_dbussignal_connman_manager_data.wlan_connection_state,
                                  ethernet_service_name, false, true))
                need_to_schedule_wlan_connection = true;
        }

        break;
    }

    g_mutex_unlock(&global_dbussignal_connman_manager_data.lock);

    network_prefs_close(handle);

    if(service_to_be_disabled != NULL && service_to_be_disabled[0] != '\0')
        avoid_wlan_service(service_to_be_disabled);

    schedule_wlan_connect_if_necessary(need_to_schedule_wlan_connection,
                                       &global_dbussignal_connman_manager_data,
                                       wlan_service_name);
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
