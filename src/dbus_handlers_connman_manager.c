/*
 * Copyright (C) 2016  T+A elektroakustik GmbH & Co. KG
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
#include <stdlib.h>
#include <errno.h>

#include "dbus_handlers_connman_manager.h"
#include "dbus_handlers_connman_manager_glue.h"
#include "dcpregs_networkconfig.h"
#include "connman.h"
#include "connman_common.h"
#include "messages.h"

struct Maybe
{
    bool is_state_known;
    bool state;
};

static inline void init_maybe(struct Maybe *maybe)
{
    maybe->state = false;
    maybe->is_state_known = false;
}

static inline void set_maybe_value(struct Maybe *maybe, bool state)
{
    maybe->state = state;
    maybe->is_state_known = true;
}

static inline bool maybe_true(const struct Maybe *maybe)
{
    return maybe->is_state_known ? maybe->state : false;
}

static inline bool maybe_false(const struct Maybe *maybe)
{
    return maybe->is_state_known ? !maybe->state : false;
}

struct ServiceList
{
    struct ServiceList *next;

    char *service_name;

    struct Maybe is_favorite;
    struct Maybe is_auto_connect;
    struct Maybe is_connected;
};

struct dbussignal_connman_manager_data
{
    GMutex lock;
    char wlan_service_name[512];
    void (*schedule_connect_to_wlan)(void);

    struct ServiceList *services;
};

static struct ServiceList *lookup_service_rw(struct ServiceList *head,
                                             const char *service_name,
                                             struct ServiceList **prev)
{
    struct ServiceList *p = NULL;

    for(struct ServiceList *s = head; s != NULL; s = s->next)
    {
        if(strcmp(s->service_name, service_name) == 0)
        {
            if(prev != NULL)
                *prev = p;

            return s;
        }

        p = s;
    }

    if(prev != NULL)
        *prev = p;

    return NULL;
}

static bool insert_service(struct ServiceList **head, const char *service_name,
                           struct ServiceList **list_entry)
{
    struct ServiceList *last = NULL;
    struct ServiceList *service = (*head != NULL)
        ? lookup_service_rw(*head, service_name, &last)
        : NULL;

    if(list_entry != NULL)
        *list_entry = service;

    if(service != NULL)
        return false;

    service = malloc(sizeof(*service));

    if(service == NULL)
    {
        msg_out_of_memory("service list entry");
        return false;
    }

    service->next = NULL;
    service->service_name = strdup(service_name);
    init_maybe(&service->is_favorite);
    init_maybe(&service->is_auto_connect);
    init_maybe(&service->is_connected);

    if(service->service_name == NULL)
    {
        msg_out_of_memory("service name copy");
        free(service);
        return false;
    }

    if(last != NULL)
    {
        log_assert(last->next == NULL);
        last->next = service;
    }
    else
    {
        log_assert(*head == NULL);
        *head = service;
    }

    if(list_entry != NULL)
        *list_entry = service;

    return true;
}

static bool remove_service(struct ServiceList **head, const char *service_name)
{
    struct ServiceList *prev;
    struct ServiceList *service = (*head != NULL)
        ? lookup_service_rw(*head, service_name, &prev)
        : NULL;

    if(service == NULL)
        return false;

    if(prev != NULL)
    {
        log_assert(prev->next == service);
        prev->next = service->next;
    }
    else
    {
        log_assert(service == *head);
        *head = service->next;
    }

    free(service->service_name);
    service->service_name = NULL;
    service->next = NULL;
    free(service);

    return true;
}

static void service_connected(const char *service_name,
                              enum ConnmanCommonConnectServiceCallbackResult result,
                              void *user_data)
{
    switch(result)
    {
      case CONNMAN_SERVICE_CONNECT_CONNECTED:
        msg_info("Connected to %s", service_name);
        break;

      case CONNMAN_SERVICE_CONNECT_FAILURE:
        msg_info("Failed connecting to %s", service_name);
        break;

      case CONNMAN_SERVICE_CONNECT_DISCARDED:
        break;
    }
}

void dbussignal_connman_manager_connect_our_wlan(struct dbussignal_connman_manager_data *data)
{
    g_mutex_lock(&data->lock);
    connman_common_connect_service_by_object_path(data->wlan_service_name,
                                                  service_connected, NULL);
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
get_iface_data_by_service_name(const char *service_name,
                               struct Maybe *is_favorite,
                               struct Maybe *is_auto_connect,
                               struct Maybe *is_connected)
{
    struct ConnmanInterfaceData *data =
        connman_find_interface_by_object_path(service_name);

    if(data != NULL)
    {
        set_maybe_value(is_favorite, connman_get_favorite(data));
        set_maybe_value(is_auto_connect, connman_get_auto_connect_mode(data));

        switch(connman_get_state(data))
        {
          case CONNMAN_STATE_ASSOCIATION:
          case CONNMAN_STATE_CONFIGURATION:
          case CONNMAN_STATE_READY:
          case CONNMAN_STATE_ONLINE:
            set_maybe_value(is_connected, true);
            break;

          case CONNMAN_STATE_NOT_SPECIFIED:
          case CONNMAN_STATE_IDLE:
          case CONNMAN_STATE_FAILURE:
          case CONNMAN_STATE_DISCONNECT:
            set_maybe_value(is_connected, false);
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

static void avoid_service(const struct ServiceList *service_list_entry,
                          bool is_ethernet)
{
    if(!maybe_true(&service_list_entry->is_connected))
        return;

    if(is_ethernet)
        connman_common_disconnect_service_by_object_path(service_list_entry->service_name);
    else
        avoid_wlan_service(service_list_entry->service_name);
}

static bool avoid_service_if_no_preferences(const struct ServiceList *service_list_entry,
                                            const struct network_prefs *prefs,
                                            bool is_ethernet)
{
    if(prefs != NULL)
        return false;

    avoid_service(service_list_entry, is_ethernet);

    BUG("Cannot configure ConnMan service \"%s\": no preferences",
        service_list_entry->service_name);

    return true;
}

static void configure_our_ipv6_network_common(struct ConnmanInterfaceData *iface_data,
                                              const char *service_name)
{
    msg_vinfo(MESSAGE_LEVEL_DEBUG,
              "Configure IPv6 parameters for service %s", service_name);

    const enum ConnmanDHCPMode system_dhcp_mode =
        connman_get_dhcp_mode(iface_data, CONNMAN_IP_VERSION_6,
                              CONNMAN_READ_CONFIG_SOURCE_ANY);

    switch(system_dhcp_mode)
    {
      case CONNMAN_DHCP_OFF:
        msg_vinfo(MESSAGE_LEVEL_DEBUG,
                  "Not configuring IPv6 parameters for %s: up to date",
                  service_name);
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
              "Disable IPv6 for service %s", service_name);

    GVariantBuilder builder;
    g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);

    g_variant_builder_add(&builder, "{sv}", "Method", g_variant_new_string("off"));

    GVariant *ipv6_config =
        g_variant_new_variant(g_variant_builder_end(&builder));

    if(ipv6_config != NULL)
        connman_common_set_service_property(service_name,
                                            "IPv6.Configuration", ipv6_config);
}

static bool configure_our_ipv4_network_common(struct ConnmanInterfaceData *iface_data,
                                              const struct ServiceList *service_list_entry,
                                              const struct network_prefs *prefs,
                                              bool is_ethernet)
{
    msg_vinfo(MESSAGE_LEVEL_DEBUG,
              "Configure IPv4 parameters for service %s",
              service_list_entry->service_name);

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
        avoid_service(service_list_entry, is_ethernet);
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
                  service_list_entry->service_name);
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
        connman_common_set_service_property(service_list_entry->service_name,
                                            "IPv4.Configuration", ipv4_config);

    if(dns_config != NULL)
        connman_common_set_service_property(service_list_entry->service_name,
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
                              struct ServiceList *service_list_entry)
{
    if(avoid_service_if_no_preferences(service_list_entry, prefs, true))
        return false;

    struct Maybe dummy;

    struct ConnmanInterfaceData *iface_data =
        get_iface_data_by_service_name(service_list_entry->service_name,
                                       &service_list_entry->is_favorite,
                                       &dummy,
                                       &service_list_entry->is_connected);

    if(iface_data == NULL)
        return false;

    configure_our_ipv6_network_common(iface_data, service_list_entry->service_name);

    const bool ret =
        configure_our_ipv4_network_common(iface_data, service_list_entry,
                                          prefs, true);

    connman_free_interface_data(iface_data);

    return ret;
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
                               struct ServiceList *service_list_entry,
                               const char *ethernet_service_name,
                               bool have_just_lost_ethernet_device,
                               bool make_it_favorite)
{
    if(avoid_service_if_no_preferences(service_list_entry, prefs, false))
        return false;

    struct ConnmanInterfaceData *iface_data =
        get_iface_data_by_service_name(service_list_entry->service_name,
                                       &service_list_entry->is_favorite,
                                       &service_list_entry->is_auto_connect,
                                       &service_list_entry->is_connected);

    if(iface_data == NULL)
        return false;

    configure_our_ipv6_network_common(iface_data, service_list_entry->service_name);

    const bool ret =
        configure_our_ipv4_network_common(iface_data, service_list_entry,
                                          prefs, false);

    connman_free_interface_data(iface_data);
    iface_data = NULL;

    if(!ret)
        return false;

    msg_vinfo(MESSAGE_LEVEL_DEBUG,
              "Our WLAN is %sa favorite, auto-connect %s, "
              "make it auto-connect %d",
              service_list_entry->is_favorite.is_state_known
              ? (service_list_entry->is_favorite.state ? "" : "not ")
              : "maybe ",
              service_list_entry->is_auto_connect.is_state_known
              ? (service_list_entry->is_auto_connect.state ? "yes" : "no")
              : "maybe",
              make_it_favorite);

    if(maybe_true(&service_list_entry->is_favorite))
    {
        if(maybe_false(&service_list_entry->is_auto_connect))
            connman_common_set_service_property(service_list_entry->service_name,
                                                "AutoConnect",
                                                g_variant_new_variant(g_variant_new_boolean(true)));

        /* rely on auto-connect */
        return false;
    }

    if(maybe_false(&service_list_entry->is_favorite) && make_it_favorite)
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

static bool react_to_service_changes(struct ServiceList **known_services_list,
                                     GVariant *changes, GVariant *removed,
                                     char *ethernet_service_name,
                                     char *wlan_service_name,
                                     const struct network_prefs *ethernet_prefs,
                                     const struct network_prefs *wlan_prefs)
{
    if(changes == NULL && removed == NULL)
    {
        /* ignore unlikely, but possible funny data from ConnMan */
        return false;
    }

    const bool have_ethernet_service_name =
        network_prefs_generate_service_name(ethernet_prefs, ethernet_service_name,
                                            NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE) > 0;
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

    GVariantIter iter;
    g_variant_iter_init(&iter, removed);
    const gchar *name;

    while(g_variant_iter_loop(&iter, "&o", &name))
    {
        msg_vinfo(MESSAGE_LEVEL_TRACE, "Service removed: \"%s\"", name);

        remove_service(known_services_list, name);

        if(have_ethernet_service_name &&
           strcmp(name, ethernet_service_name) == 0)
            have_just_lost_ethernet_device = true;
    }

    g_variant_iter_init(&iter, changes);

    GVariantIter *props_iter;
    bool want_to_switch_to_wlan = false;
    const struct ServiceList *our_ethernet_service = NULL;
    const struct ServiceList *our_wlan_service = NULL;

    while(g_variant_iter_loop(&iter, "(&oa{sv})", &name, &props_iter))
    {
        if(name[0] == '\0')
            continue;

        msg_vinfo(MESSAGE_LEVEL_TRACE,
                  (g_variant_iter_n_children(props_iter) > 0)
                  ? "Service changed: \"%s\""
                  : "Service still available: \"%s\"", name);

        struct ServiceList *service_list_entry;
        insert_service(known_services_list, name, &service_list_entry);

        if(msg_is_verbose(MESSAGE_LEVEL_TRACE))
        {
            const char *prop = NULL;
            GVariant *value = NULL;
            GVariantIter *iter_copy = g_variant_iter_copy(props_iter);

            while(g_variant_iter_loop(iter_copy, "{&sv}", &prop, &value))
            {
                if(g_variant_is_of_type(value, G_VARIANT_TYPE_STRING))
                    msg_info("- %s = %s", prop, g_variant_get_string(value, NULL));
                else if(g_variant_is_of_type(value, G_VARIANT_TYPE_BOOLEAN))
                    msg_info("- %s = %s", prop, g_variant_get_boolean(value) ? "TRUE" : "FALSE");
                else if(g_variant_is_of_type(value, G_VARIANT_TYPE_BYTE))
                    msg_info("- %s = %u", prop, g_variant_get_byte(value));
                else if(g_variant_is_of_type(value, G_VARIANT_TYPE_INT16))
                    msg_info("- %s = %d", prop, g_variant_get_int16(value));
                else if(g_variant_is_of_type(value, G_VARIANT_TYPE_UINT16))
                    msg_info("- %s = %u", prop, g_variant_get_uint16(value));
                else if(g_variant_is_of_type(value, G_VARIANT_TYPE_INT32))
                    msg_info("- %s = %d", prop, g_variant_get_int32(value));
                else if(g_variant_is_of_type(value, G_VARIANT_TYPE_UINT32))
                    msg_info("- %s = %u", prop, g_variant_get_uint32(value));
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
                        if(g_variant_is_of_type(dict_value, G_VARIANT_TYPE_STRING))
                            msg_info("`-- %s = %s", dict_key, g_variant_get_string(dict_value, NULL));
                        else
                            msg_info("`-- %s (type %s)", dict_key, g_variant_get_type_string(dict_value));
                    }
                }
                else
                    msg_info("- %s (type %s)", prop, g_variant_get_type_string(value));
            }

            g_variant_iter_free(iter_copy);
        }

        const char *prop = NULL;
        GVariant *value = NULL;

        while(g_variant_iter_loop(props_iter, "{&sv}", &prop, &value))
        {
            if(strcmp(prop, "State") == 0)
                set_maybe_value(&service_list_entry->is_connected,
                                strcmp(g_variant_get_string(value, NULL), "ready") == 0);
            else if(strcmp(prop, "Favorite") == 0)
                set_maybe_value(&service_list_entry->is_favorite,
                                !!g_variant_get_boolean(value));
        }

        if(strcmp(service_list_entry->service_name, wlan_service_name) == 0)
        {
            /* our WLAN service has changed, perhaps, so we may have to
             * configure it and we have to connect to it in case there is no
             * Ethernet connection */
            if(configure_our_wlan(wlan_prefs, service_list_entry,
                                  ethernet_service_name,
                                  have_just_lost_ethernet_device, false))
                want_to_switch_to_wlan = true;

            our_wlan_service = service_list_entry;

            continue;
        }

        if(strcmp(service_list_entry->service_name, ethernet_service_name) == 0)
        {
            /* our LAN service may need some care */
            configure_our_lan(ethernet_prefs, service_list_entry);

            our_ethernet_service = service_list_entry;

            continue;
        }

        /* some service not managed by us */
        if(maybe_false(&service_list_entry->is_favorite))
        {
            /* we know each other already, and it's not a favorite */
            continue;
        }

        /* new or favorite or both, or state unknown: smash it */
        switch(network_prefs_get_technology_by_service_name(service_list_entry->service_name))
        {
          case NWPREFSTECH_UNKNOWN:
            msg_error(0, LOG_INFO,
                      "ConnMan service %s changed, but cannot handle technology",
                      service_list_entry->service_name);
            break;

          case NWPREFSTECH_ETHERNET:
            avoid_service(service_list_entry, true);
            break;

          case NWPREFSTECH_WLAN:
            avoid_service(service_list_entry, false);
            break;
        }
    }

    if(have_just_lost_ethernet_device && wlan_service_name[0] != '\0')
        want_to_switch_to_wlan = true;

    if(our_ethernet_service == NULL && our_wlan_service != NULL)
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

    if(our_wlan_service == NULL)
        return false;

    if(maybe_true(&our_wlan_service->is_connected))
        return false;

    if(maybe_true(&our_wlan_service->is_auto_connect))
        return false;

    /* Click. */
    return true;
}

static void schedule_wlan_connect_if_necessary(bool is_necessary,
                                               struct dbussignal_connman_manager_data *data,
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
    struct dbussignal_connman_manager_data *const data = user_data;

    if(strcmp(signal_name, "ServicesChanged") == 0)
    {
        msg_vinfo(MESSAGE_LEVEL_DIAG, "ConnMan services changed");
        check_parameter_assertions(parameters, 2);

        const struct network_prefs *ethernet_prefs;
        const struct network_prefs *wlan_prefs;
        struct network_prefs_handle *handle =
            network_prefs_open_ro(&ethernet_prefs, &wlan_prefs);

        char ethernet_service_name_buffer[NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE];
        char wlan_service_name_buffer[NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE];
        G_STATIC_ASSERT(sizeof(wlan_service_name_buffer) == sizeof(data->wlan_service_name));

        bool need_to_schedule_wlan_connection = false;

        if(handle != NULL)
        {
            GVariant *changes = g_variant_get_child_value(parameters, 0);
            GVariant *removed = g_variant_get_child_value(parameters, 1);

            need_to_schedule_wlan_connection =
                react_to_service_changes(&data->services, changes, removed,
                                         ethernet_service_name_buffer,
                                         wlan_service_name_buffer,
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

        GVariant *name = g_variant_get_child_value(parameters, 0);
        log_assert(name != NULL);

        if(strcmp(g_variant_get_string(name, NULL), "State") == 0)
        {
            msg_vinfo(MESSAGE_LEVEL_DIAG, "ConnMan state changed");
            dcpregs_networkconfig_interfaces_changed();
        }
        else
            msg_vinfo(MESSAGE_LEVEL_DIAG,
                      "ConnMan property \"%s\" changed",
                      g_variant_get_string(name, NULL));

        g_variant_unref(name);
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

static struct dbussignal_connman_manager_data global_dbussignal_connman_manager_data;

struct dbussignal_connman_manager_data *
dbussignal_connman_manager_init(void (*schedule_connect_to_wlan_fn)(void))
{
    memset(&global_dbussignal_connman_manager_data, 0,
           sizeof(global_dbussignal_connman_manager_data));
    g_mutex_init(&global_dbussignal_connman_manager_data.lock);
    global_dbussignal_connman_manager_data.schedule_connect_to_wlan =
        schedule_connect_to_wlan_fn;

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

    bool need_to_schedule_wlan_connection  = false;

    switch(tech)
    {
      case NWPREFSTECH_UNKNOWN:
        break;

      case NWPREFSTECH_ETHERNET:
        wlan_service_name[0] = '\0';

        if(ethernet_service_name[0] != '\0')
        {
            struct ServiceList *service_list_entry;

            insert_service(&global_dbussignal_connman_manager_data.services,
                           ethernet_service_name,
                           &service_list_entry);
            configure_our_lan(ethernet_prefs, service_list_entry);
        }

        break;

      case NWPREFSTECH_WLAN:
        if(network_prefs_generate_service_name(wlan_prefs,
                                               wlan_service_name,
                                               sizeof(wlan_service_name)))
        {
            struct ServiceList *service_list_entry;

            insert_service(&global_dbussignal_connman_manager_data.services,
                           wlan_service_name,
                           &service_list_entry);
            if(configure_our_wlan(wlan_prefs, service_list_entry,
                                  ethernet_service_name, false, true))
                need_to_schedule_wlan_connection = true;
        }

        break;
    }

    network_prefs_close(handle);

    if(service_to_be_disabled != NULL && service_to_be_disabled[0] != '\0')
        avoid_wlan_service(service_to_be_disabled);

    schedule_wlan_connect_if_necessary(need_to_schedule_wlan_connection,
                                       &global_dbussignal_connman_manager_data,
                                       wlan_service_name);
}
