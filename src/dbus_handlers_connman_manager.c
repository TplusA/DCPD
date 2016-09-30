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
#include <errno.h>

#include "dbus_handlers_connman_manager.h"
#include "dbus_handlers_connman_manager_data.h"
#include "dbus_handlers_connman_manager_util.h"
#include "dcpregs_networkconfig.h"
#include "connman.h"
#include "connman_common.h"
#include "messages.h"

void dbussignal_connman_manager_connect_our_wlan(struct dbussignal_connman_manager_data *data)
{
    g_mutex_lock(&data->lock);

    if(data->wlan_service_name[0] != '\0')
        connman_common_connect_service_by_object_path(data->wlan_service_name);

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

static bool ipv4_settings_are_different(const char *service_name,
                                        bool with_dhcp, const char *address,
                                        const char *nm, const char *gw,
                                        const char *dns1, const char *dns2,
                                        bool *different_ipv4_config,
                                        bool *different_nameservers,
                                        bool *is_favorite,
                                        bool *is_auto_connect)
{
    *different_ipv4_config = true;
    *different_nameservers = true;
    *is_favorite = false;
    *is_auto_connect = false;

    struct ConnmanInterfaceData *data =
        connman_find_interface_by_object_path(service_name);

    if(data == NULL)
        return true;

    *is_favorite = connman_get_favorite(data);
    *is_auto_connect = connman_get_auto_connect_mode(data);

    char buffer[64];

    enum ConnmanDHCPMode system_dhcp_mode = connman_get_dhcp_mode(data, false);

    switch(system_dhcp_mode)
    {
      case CONNMAN_DHCP_NOT_SPECIFIED:
        goto ipv4_check_done;

      case CONNMAN_DHCP_ON:
      case CONNMAN_DHCP_OFF:
        if((system_dhcp_mode == CONNMAN_DHCP_ON && !with_dhcp) ||
           (system_dhcp_mode == CONNMAN_DHCP_OFF && with_dhcp))
            goto ipv4_check_done;

        if(address != NULL || nm != NULL || gw != NULL)
            goto ipv4_check_done;

        break;

      case CONNMAN_DHCP_MANUAL:
        if(with_dhcp)
            goto ipv4_check_done;

        connman_get_ipv4_address_string(data, buffer, sizeof(buffer));
        if(strcmp(address, buffer) != 0)
            goto ipv4_check_done;

        connman_get_ipv4_netmask_string(data, buffer, sizeof(buffer));
        if(strcmp(nm, buffer) != 0)
            goto ipv4_check_done;

        connman_get_ipv4_gateway_string(data, buffer, sizeof(buffer));
        if(strcmp(gw, buffer) != 0)
            goto ipv4_check_done;

        break;

      case CONNMAN_DHCP_FIXED:
        /* special case: cannot change the IPv4 parameters */
        break;
    }

    *different_ipv4_config = false;

ipv4_check_done:
    connman_get_ipv4_primary_dns_string(data, buffer, sizeof(buffer));
    if((dns1 != NULL && strcmp(dns1, buffer) != 0) ||
       (dns1 == NULL && buffer[0] != '\0'))
        goto dns_check_done;

    connman_get_ipv4_secondary_dns_string(data, buffer, sizeof(buffer));
    if((dns2 != NULL && strcmp(dns2, buffer) != 0) ||
       (dns2 == NULL && buffer[0] != '\0'))
        goto dns_check_done;

    *different_nameservers = false;

dns_check_done:
    connman_free_interface_data(data);

    return *different_ipv4_config || *different_nameservers;
}

static bool configure_our_ipv4_network_common(const char *service_name,
                                              const struct network_prefs *prefs,
                                              bool is_ethernet,
                                              bool *is_favorite,
                                              bool *is_auto_connect)
{
    *is_favorite = false;
    *is_auto_connect = false;

    if(prefs == NULL)
    {
        if(is_ethernet)
            connman_common_disconnect_service_by_object_path(service_name);
        else
            connman_common_remove_service_by_object_path(service_name);

        BUG("Cannot configure ConnMan service \"%s\": no preferences",
            service_name);

        return false;
    }

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
        if(is_ethernet)
            connman_common_disconnect_service_by_object_path(service_name);
        else
            connman_common_remove_service_by_object_path(service_name);

        return false;
    }

    bool different_ipv4_config;
    bool different_nameservers;

    if(!ipv4_settings_are_different(service_name, want_dhcp,
                                    want_address, want_netmask, want_gateway,
                                    want_dns1, want_dns2,
                                    &different_ipv4_config,
                                    &different_nameservers,
                                    is_favorite, is_auto_connect))
        return true;

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
        connman_common_set_service_property(service_name,
                                            "IPv4.Configuration", ipv4_config);

    if(dns_config != NULL)
        connman_common_set_service_property(service_name,
                                            "Nameservers.Configuration",
                                            dns_config);

    return true;
}

static inline void configure_our_lan(const char *service_name,
                                     const struct network_prefs *prefs)
{
    bool dummy1, dummy2;

    configure_our_ipv4_network_common(service_name, prefs, true,
                                      &dummy1, &dummy2);
}

static bool configure_our_wlan(const char *service_name,
                               const struct network_prefs *prefs,
                               const char *ethernet_service_name,
                               bool have_just_lost_ethernet_device)
{
    bool is_favorite;
    bool is_auto_connect;

    if(!configure_our_ipv4_network_common(service_name, prefs, false,
                                          &is_favorite, &is_auto_connect))
        return false;

    if(is_favorite)
    {
        if(!is_auto_connect)
            connman_common_set_service_property(service_name,
                                                "AutoConnect",
                                                g_variant_new_variant(g_variant_new_boolean(true)));

        return false;
    }

    /* try connecting to our WLAN for the first time if there is no Ethernet
     * device or the Ethernet device is not up and running */

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

static bool react_to_service_changes(GVariant *changes, GVariant *removed,
                                     char *wlan_service_name,
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

    GVariantIter iter;

    if(have_ethernet_service_name)
    {
        g_variant_iter_init(&iter, removed);

        const gchar *name;

        while(g_variant_iter_loop(&iter, "&o", &name))
        {
            if(strcmp(name, ethernet_service_name) == 0)
                have_just_lost_ethernet_device = true;
        }
    }

    g_variant_iter_init(&iter, changes);

    const gchar *name;
    GVariantIter *props_iter;
    bool need_to_schedule_wlan_connection = false;

    while(g_variant_iter_loop(&iter, "(&oa{sv})", &name, &props_iter))
    {
        if(name[0] == '\0')
            continue;

        if(strcmp(name, wlan_service_name) == 0)
        {
            /* our WLAN service has changed, perhaps, so we may have to
             * configure it and we have to connect to it in case there is no
             * Ethernet connection */
            if(configure_our_wlan(name, wlan_prefs, ethernet_service_name,
                                  have_just_lost_ethernet_device))
                need_to_schedule_wlan_connection = true;

            continue;
        }

        if(g_variant_iter_n_children(props_iter) == 0)
        {
            /* service is still there and has not changed, so there should be
             * nothing to do for us */
            continue;
        }

        if(strcmp(name, ethernet_service_name) == 0)
        {
            configure_our_lan(name, ethernet_prefs);
            continue;
        }

        /* some service not managed by us has changed */
        switch(network_prefs_get_technology_by_service_name(name))
        {
          case NWPREFSTECH_UNKNOWN:
            msg_error(0, LOG_INFO,
                      "ConnMan service %s changed, but cannot handle technology",
                      name);
            break;

          case NWPREFSTECH_ETHERNET:
            connman_common_disconnect_service_by_object_path(name);
            break;

          case NWPREFSTECH_WLAN:
            connman_common_remove_service_by_object_path(name);
            break;
        }
    }

    if(have_just_lost_ethernet_device && wlan_service_name[0] != '\0')
        need_to_schedule_wlan_connection = true;

    return need_to_schedule_wlan_connection;
}

static void schedule_wlan_connect_if_necessary(bool is_necessary,
                                               struct dbussignal_connman_manager_data *data,
                                               const char *service_name)
{
    g_mutex_lock(&data->lock);

    if(is_necessary)
    {
        log_assert(service_name[0] != '\0');

        strncpy(data->wlan_service_name, service_name,
                sizeof(data->wlan_service_name));
        data->wlan_service_name[sizeof(data->wlan_service_name) - 1] = '\0';
        data->schedule_connect_to_wlan();
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
                react_to_service_changes(changes, removed,
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
            dcpregs_networkconfig_interfaces_changed();

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

static struct dbussignal_connman_manager_data *global_dbussignal_connman_manager_data;

void dbussignal_connman_manager_init(struct dbussignal_connman_manager_data *data,
                                     void (*schedule_connect_to_wlan_fn)(void))
{
    memset(data, 0, sizeof(*data));
    g_mutex_init(&data->lock);
    data->schedule_connect_to_wlan = schedule_connect_to_wlan_fn;
    global_dbussignal_connman_manager_data = data;
}

void dbussignal_connman_manager_connect_to_service(enum NetworkPrefsTechnology tech)
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
            configure_our_lan(ethernet_service_name, ethernet_prefs);

        break;

      case NWPREFSTECH_WLAN:
        if(network_prefs_generate_service_name(wlan_prefs,
                                               wlan_service_name,
                                               sizeof(wlan_service_name)))
        {
            if(configure_our_wlan(wlan_service_name, wlan_prefs,
                                  ethernet_service_name, false))
                need_to_schedule_wlan_connection = true;
        }

        break;
    }

    network_prefs_close(handle);

    schedule_wlan_connect_if_necessary(need_to_schedule_wlan_connection,
                                       global_dbussignal_connman_manager_data,
                                       wlan_service_name);
}
