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

#include <glib.h>
#include <string.h>
#include <strings.h>

#include "connman.h"
#include "dbus_iface_deep.h"
#include "messages.h"

static int handle_dbus_error(GError **error)
{
    if(*error == NULL)
        return 0;

    msg_error(0, LOG_EMERG, "%s", (*error)->message);
    g_error_free(*error);
    *error = NULL;

    return -1;
}

static GVariant *query_services(void)
{
    GVariant *result = NULL;
    tdbusconnmanManager *iface = dbus_get_connman_manager_iface();

    if(iface != NULL)
    {
        GError *error = NULL;
        tdbus_connman_manager_call_get_services_sync(iface,
                                                     &result, NULL, &error);
        (void)handle_dbus_error(&error);
    }

    return result;
}

static void init_dict_from_temp_gvariant(GVariant *temp, GVariantDict *dict)
{
    log_assert(temp != NULL);
    g_variant_dict_init(dict, temp);
    g_variant_unref(temp);
}

static void init_subdict(GVariant *tuple,
                         GVariantDict *subdict, const char *subdict_name)
{
    GVariantDict dict;
    init_dict_from_temp_gvariant(g_variant_get_child_value(tuple, 1), &dict);
    init_dict_from_temp_gvariant(g_variant_dict_lookup_value(&dict, subdict_name,
                                                             G_VARIANT_TYPE_VARDICT),
                                 subdict);
    g_variant_dict_clear(&dict);
}

static int determine_service_rank(GVariant *state_variant)
{
    log_assert(state_variant != NULL);

    const char *state = g_variant_get_string(state_variant, NULL);
    int rank = ((strcmp(state, "online") == 0)
                ? 2
                : ((strcmp(state, "ready") == 0)
                   ? 1
                   : 0));

    g_variant_unref(state_variant);

    return rank;
}

static bool match_mac_address(const char *mac_address, const char *needle,
                              GVariant **found, GVariant *tuple)
{
    if(*found != NULL || strcasecmp(mac_address, needle) != 0)
        return false;

    *found = tuple;
    g_variant_ref(tuple);

    return true;
}

struct ConnmanInterfaceData *connman_find_interface(const char *mac_address)
{
    GVariant *services = query_services();
    if(services == NULL)
        return NULL;

    GVariant *found = NULL;
    int best_rank = -1;
    const size_t count = g_variant_n_children(services);

    for(size_t i = 0; i < count; ++i)
    {
        GVariant *tuple = g_variant_get_child_value(services, i);
        log_assert(tuple != NULL);

        GVariantDict dict;
        init_dict_from_temp_gvariant(g_variant_get_child_value(tuple, 1), &dict);

        int rank =
            determine_service_rank(g_variant_dict_lookup_value(&dict, "State",
                                                               G_VARIANT_TYPE_STRING));

        if(rank > best_rank)
        {
            GVariantDict ethernet_dict;
            init_dict_from_temp_gvariant(g_variant_dict_lookup_value(&dict, "Ethernet",
                                                                     G_VARIANT_TYPE_VARDICT),
                                         &ethernet_dict);

            GVariant *mac_address_variant =
                g_variant_dict_lookup_value(&ethernet_dict, "Address", G_VARIANT_TYPE_STRING);
            log_assert(mac_address_variant != NULL);

            const char *service_mac_address =
                g_variant_get_string(mac_address_variant, NULL);

            if(strcasecmp(service_mac_address, mac_address) == 0)
            {
                found = tuple;
                g_variant_ref(tuple);
            }

            g_variant_unref(mac_address_variant);
            g_variant_dict_clear(&ethernet_dict);
        }

        g_variant_dict_clear(&dict);
        g_variant_unref(tuple);
    }

    g_variant_unref(services);

    return (struct ConnmanInterfaceData *)found;
}

struct match_mac_address_data
{
    GVariant *active_default;
    GVariant *active_wired;
    GVariant *active_wireless;
    int wired_rank;
    int wireless_rank;
};

static void match_mac_addresses(GVariantDict *dict,
                                const char *default_mac_address,
                                const char *wired_mac_address,
                                const char *wireless_mac_address,
                                GVariant *tuple, int rank,
                                struct match_mac_address_data *data)
{
    GVariantDict ethernet_dict;
    init_dict_from_temp_gvariant(g_variant_dict_lookup_value(dict, "Ethernet",
                                                             G_VARIANT_TYPE_VARDICT),
                                 &ethernet_dict);

    GVariant *mac_address_variant =
        g_variant_dict_lookup_value(&ethernet_dict, "Address", G_VARIANT_TYPE_STRING);
    log_assert(mac_address_variant != NULL);

    const char *mac_address = g_variant_get_string(mac_address_variant, NULL);

    (void)match_mac_address(mac_address, default_mac_address,
                            &data->active_default, tuple);

    if(match_mac_address(mac_address, wired_mac_address,
                         &data->active_wired, tuple))
        data->wired_rank = rank;

    if(match_mac_address(mac_address, wireless_mac_address,
                         &data->active_wireless, tuple))
        data->wireless_rank = rank;

    g_variant_unref(mac_address_variant);
    g_variant_dict_clear(&ethernet_dict);
}

struct ConnmanInterfaceData *
connman_find_active_primary_interface(const char *default_mac_address,
                                      const char *wired_mac_address,
                                      const char *wireless_mac_address)
{
    GVariant *services = query_services();
    if(services == NULL)
        return NULL;

    struct match_mac_address_data match = { 0 };
    const size_t count = g_variant_n_children(services);

    for(size_t i = 0; i < count; ++i)
    {
        GVariant *tuple = g_variant_get_child_value(services, i);
        log_assert(tuple != NULL);

        GVariantDict dict;
        init_dict_from_temp_gvariant(g_variant_get_child_value(tuple, 1), &dict);

        int rank =
            determine_service_rank(g_variant_dict_lookup_value(&dict, "State",
                                                               G_VARIANT_TYPE_STRING));

        if(rank > 0)
            match_mac_addresses(&dict, default_mac_address, wired_mac_address,
                                wireless_mac_address, tuple, rank, &match);

        g_variant_dict_clear(&dict);
        g_variant_unref(tuple);
    }

    g_variant_unref(services);

    GVariant *found = NULL;

    if(match.active_wired == NULL && match.active_wireless == NULL)
        found = match.active_default;
    else if(match.active_wired != NULL)
    {
        if(match.active_wireless == NULL)
            found = match.active_wired;
        else
            found = ((match.wired_rank == match.wireless_rank)
                     ? match.active_default
                     : ((match.wired_rank > match.wireless_rank)
                        ? match.active_wired
                        : match.active_wireless));
    }

    if(found != NULL)
        g_variant_ref(found);

    if(match.active_default != NULL)
        g_variant_unref(match.active_default);

    if(match.active_wired != NULL)
        g_variant_unref(match.active_wired);

    if(match.active_wireless != NULL)
        g_variant_unref(match.active_wireless);

    return (struct ConnmanInterfaceData *)found;
}

bool connman_get_dhcp_mode(struct ConnmanInterfaceData *iface_data)
{
    log_assert(iface_data != NULL);

    GVariantDict dict;
    init_subdict((GVariant *)iface_data, &dict, "IPv4.Configuration");

    GVariant *method_variant =
        g_variant_dict_lookup_value(&dict, "Method", G_VARIANT_TYPE_STRING);
    log_assert(method_variant != NULL);

    const char *method = g_variant_get_string(method_variant, NULL);
    bool retval = (strcmp(method, "dhcp") == 0);

    g_variant_unref(method_variant);
    g_variant_dict_clear(&dict);

    return retval;
}

enum ConnmanConnectionType connman_get_connection_type(struct ConnmanInterfaceData *iface_data)
{
    log_assert(iface_data != NULL);

    GVariant *dict = g_variant_get_child_value((GVariant *)iface_data, 1);
    GVariant *type_variant =
        dict != NULL
        ? g_variant_lookup_value(dict, "Type", G_VARIANT_TYPE_STRING)
        : NULL;

    if(type_variant == NULL)
    {
        msg_error(0, LOG_NOTICE, "No connection type set for network interface");

        if(dict != NULL)
            g_variant_unref(dict);

        return CONNMAN_CONNECTION_TYPE_UNKNOWN;
    }

    const char *connection_type = g_variant_get_string(type_variant, NULL);

    enum ConnmanConnectionType retval;

    if(strcmp(connection_type, "ethernet") == 0)
        retval = CONNMAN_CONNECTION_TYPE_ETHERNET;
    else if(strcmp(connection_type, "wifi") == 0)
        retval = CONNMAN_CONNECTION_TYPE_WLAN;
    else
    {
        msg_error(0, LOG_NOTICE, "Unsupported connection type \"%s\"", connection_type);
        retval = CONNMAN_CONNECTION_TYPE_UNKNOWN;
    }

    g_variant_unref(type_variant);
    g_variant_unref(dict);

    return retval;
}

static void get_ipv4_parameter_string(struct ConnmanInterfaceData *iface_data,
                                      const char *parameter_name,
                                      char *dest, size_t dest_size)
{
    log_assert(iface_data != NULL);
    log_assert(parameter_name != NULL);
    log_assert(dest != NULL);
    log_assert(dest_size > 0);

    GVariantDict dict;
    init_subdict((GVariant *)iface_data, &dict, "IPv4");

    GVariant *ipv4_parameter_variant =
        g_variant_dict_lookup_value(&dict, parameter_name, G_VARIANT_TYPE_STRING);

    if(ipv4_parameter_variant != NULL)
    {
        const char *ipv4_parameter = g_variant_get_string(ipv4_parameter_variant, NULL);

        strncpy(dest, ipv4_parameter, dest_size);
        dest[dest_size - 1] = '\0';

        g_variant_unref(ipv4_parameter_variant);
    }
    else
        dest[0] = '\0';

    g_variant_dict_clear(&dict);
}

void connman_get_ipv4_address_string(struct ConnmanInterfaceData *iface_data,
                                     char *dest, size_t dest_size)
{
    get_ipv4_parameter_string(iface_data, "Address", dest, dest_size);
}

void connman_get_ipv4_netmask_string(struct ConnmanInterfaceData *iface_data,
                                     char *dest, size_t dest_size)
{
    get_ipv4_parameter_string(iface_data, "Netmask", dest, dest_size);
}

void connman_get_ipv4_gateway_string(struct ConnmanInterfaceData *iface_data,
                                     char *dest, size_t dest_size)
{
    get_ipv4_parameter_string(iface_data, "Gateway", dest, dest_size);
}

static void get_nameserver_string(struct ConnmanInterfaceData *iface_data,
                                  size_t idx, char *dest, size_t dest_size)
{
    log_assert(iface_data != NULL);
    log_assert(dest != NULL);
    log_assert(dest_size > 0);

    dest[0] = '\0';

    GVariantDict dict;
    init_dict_from_temp_gvariant(g_variant_get_child_value((GVariant *)iface_data, 1),
                                 &dict);

    GVariant *dns_array = g_variant_dict_lookup_value(&dict, "Nameservers",
                                                      G_VARIANT_TYPE_ARRAY);

    if(dns_array != NULL)
    {
        if(idx < g_variant_n_children(dns_array))
        {
            GVariant *dns_string = g_variant_get_child_value(dns_array, idx);
            const char *string = g_variant_get_string(dns_string, NULL);

            strncpy(dest, string, dest_size);
            dest[dest_size - 1] = '\0';

            g_variant_unref(dns_string);
        }

        g_variant_unref(dns_array);
    }

    g_variant_dict_clear(&dict);
}

void connman_get_ipv4_primary_dns_string(struct ConnmanInterfaceData *iface_data,
                                         char *dest, size_t dest_size)
{
    get_nameserver_string(iface_data, 0, dest, dest_size);
}

void connman_get_ipv4_secondary_dns_string(struct ConnmanInterfaceData *iface_data,
                                           char *dest, size_t dest_size)
{
    get_nameserver_string(iface_data, 1, dest, dest_size);
}

bool connman_get_wlan_security_type_string(struct ConnmanInterfaceData *iface_data,
                                           char *dest, size_t dest_size)
{
    log_assert(iface_data != NULL);
    log_assert(dest != NULL);
    log_assert(dest_size > 0);

    dest[0] = '\0';

    bool retval = false;
    GVariantDict dict;
    init_dict_from_temp_gvariant(g_variant_get_child_value((GVariant *)iface_data, 1),
                                 &dict);

    GVariant *security_array =
        g_variant_dict_lookup_value(&dict, "Security", G_VARIANT_TYPE_ARRAY);

    if(security_array != NULL)
    {
        if(g_variant_n_children(security_array) > 0)
        {
            GVariant *security_string = g_variant_get_child_value(security_array, 0);
            const char *string = g_variant_get_string(security_string, NULL);

            strncpy(dest, string, dest_size);
            dest[dest_size - 1] = '\0';

            retval = true;

            g_variant_unref(security_string);
        }

        g_variant_unref(security_array);
    }

    g_variant_dict_clear(&dict);

    return retval;
}

/*!
 * \todo Need to check what happens in case a binary SSID is used.
 */
size_t connman_get_wlan_ssid(struct ConnmanInterfaceData *iface_data,
                             uint8_t *dest, size_t dest_size)
{
    log_assert(iface_data != NULL);
    log_assert(dest != NULL);

    size_t retval = 0;
    GVariantDict dict;
    init_dict_from_temp_gvariant(g_variant_get_child_value((GVariant *)iface_data, 1),
                                 &dict);

    GVariant *ssid_string =
        g_variant_dict_lookup_value(&dict, "Name", G_VARIANT_TYPE_STRING);

    if(ssid_string != NULL)
    {
        const char *string = g_variant_get_string(ssid_string, NULL);

        strncpy((char *)dest, string, dest_size);
        dest[dest_size - 1] = '\0';

        retval = strlen((const char *)dest);

        g_variant_unref(ssid_string);
    }

    g_variant_dict_clear(&dict);

    return retval;
}

void connman_free_interface_data(struct ConnmanInterfaceData *iface_data)
{
    if(iface_data != NULL)
        g_variant_unref((GVariant *)iface_data);
}
