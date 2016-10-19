/*
 * Copyright (C) 2015, 2016  T+A elektroakustik GmbH & Co. KG
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

#include "connman.h"
#include "connman_common.h"
#include "dbus_iface_deep.h"
#include "dbus_common.h"
#include "messages.h"

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

static bool match_mac_address(const char *needle, const char *mac_address,
                              int rank, GVariant **found, GVariant **fallback,
                              GVariant *tuple)
{
    if(*found != NULL || strcasecmp(mac_address, needle) != 0)
        return false;

    if(rank > 0)
    {
        *found = tuple;
        g_variant_ref(tuple);
    }
    else if(fallback != NULL && *fallback == NULL)
    {
        *fallback = tuple;
        g_variant_ref(tuple);
    }

    return *found != NULL;
}

struct ConnmanInterfaceData *connman_find_interface(const char *mac_address)
{
    GVariant *services = connman_common_query_services(dbus_get_connman_manager_iface());
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
        connman_common_init_dict_from_temp_gvariant(
            g_variant_get_child_value(tuple, 1), &dict);

        int rank =
            determine_service_rank(g_variant_dict_lookup_value(&dict, "State",
                                                               G_VARIANT_TYPE_STRING));

        if(rank > best_rank)
        {
            GVariantDict ethernet_dict;
            connman_common_init_dict_from_temp_gvariant(
                g_variant_dict_lookup_value(&dict, "Ethernet", G_VARIANT_TYPE_VARDICT),
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

struct ConnmanInterfaceData *connman_find_interface_by_object_path(const char *path)
{
    GVariant *services = connman_common_query_services(dbus_get_connman_manager_iface());
    if(services == NULL)
        return NULL;

    GVariant *found = NULL;
    const size_t count = g_variant_n_children(services);

    for(size_t i = 0; i < count && found == NULL; ++i)
    {
        GVariant *tuple = g_variant_get_child_value(services, i);
        GVariant *path_variant = g_variant_get_child_value(tuple, 0);

        if(strcmp(g_variant_get_string(path_variant, NULL), path) == 0)
            found = tuple;
        else
            g_variant_unref(tuple);

        g_variant_unref(path_variant);
    }

    g_variant_unref(services);

    return (struct ConnmanInterfaceData *)found;
}

struct match_mac_address_data
{
    GVariant *active_default;
    GVariant *active_wired;
    GVariant *active_wireless;
    GVariant *fallback_iface;
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
    connman_common_init_dict_from_temp_gvariant(
        g_variant_dict_lookup_value(dict, "Ethernet", G_VARIANT_TYPE_VARDICT),
        &ethernet_dict);

    GVariant *mac_address_variant =
        g_variant_dict_lookup_value(&ethernet_dict, "Address", G_VARIANT_TYPE_STRING);
    log_assert(mac_address_variant != NULL);

    const char *mac_address = g_variant_get_string(mac_address_variant, NULL);

    (void)match_mac_address(mac_address, default_mac_address,
                            rank, &data->active_default, NULL, tuple);

    if(match_mac_address(mac_address, wired_mac_address,
                         rank, &data->active_wired,
                         &data->fallback_iface, tuple))
        data->wired_rank = rank;

    if(match_mac_address(mac_address, wireless_mac_address,
                         rank, &data->active_wireless,
                         &data->fallback_iface, tuple))
        data->wireless_rank = rank;

    g_variant_unref(mac_address_variant);
    g_variant_dict_clear(&ethernet_dict);
}

static GVariant *
extract_result_from_match_data(const struct match_mac_address_data *const match)
{
    if(match->active_wired != NULL && match->active_wireless != NULL)
        return ((match->wired_rank == match->wireless_rank)
                ? match->active_default
                : ((match->wired_rank > match->wireless_rank)
                   ? match->active_wired
                   : match->active_wireless));
    else if(match->active_wired != NULL)
        return match->active_wired;
    else if(match->active_wireless != NULL)
        return match->active_wireless;
    else
        return match->active_default;
}

struct ConnmanInterfaceData *
connman_find_active_primary_interface(const char *default_mac_address,
                                      const char *wired_mac_address,
                                      const char *wireless_mac_address,
                                      struct ConnmanInterfaceData **fallback)
{
    if(fallback != NULL)
        *fallback = NULL;

    GVariant *services = connman_common_query_services(dbus_get_connman_manager_iface());
    if(services == NULL)
        return NULL;

    struct match_mac_address_data match = { 0 };
    const size_t count = g_variant_n_children(services);

    for(size_t i = 0; i < count; ++i)
    {
        GVariant *tuple = g_variant_get_child_value(services, i);
        log_assert(tuple != NULL);

        GVariantDict dict;
        connman_common_init_dict_from_temp_gvariant(
            g_variant_get_child_value(tuple, 1), &dict);

        int rank =
            determine_service_rank(g_variant_dict_lookup_value(&dict, "State",
                                                               G_VARIANT_TYPE_STRING));

        match_mac_addresses(&dict, default_mac_address, wired_mac_address,
                            wireless_mac_address, tuple, rank, &match);

        g_variant_dict_clear(&dict);
        g_variant_unref(tuple);
    }

    g_variant_unref(services);

    GVariant *const found = extract_result_from_match_data(&match);

    if(found != NULL)
        g_variant_ref(found);

    if(match.fallback_iface != NULL)
    {
        if(found == NULL && fallback != NULL)
            *fallback = (struct ConnmanInterfaceData *)match.fallback_iface;
        else
            g_variant_unref(match.fallback_iface);
    }

    if(match.active_default != NULL)
        g_variant_unref(match.active_default);

    if(match.active_wired != NULL)
        g_variant_unref(match.active_wired);

    if(match.active_wireless != NULL)
        g_variant_unref(match.active_wireless);

    return (struct ConnmanInterfaceData *)found;
}

static bool get_bool_value(struct ConnmanInterfaceData *iface_data,
                           const char *key)
{
    log_assert(iface_data != NULL);

    GVariant *dict = g_variant_get_child_value((GVariant *)iface_data, 1);
    GVariant *bool_variant =
        dict != NULL
        ? g_variant_lookup_value(dict, key, G_VARIANT_TYPE_BOOLEAN)
        : NULL;

    if(bool_variant == NULL)
    {
        msg_error(0, LOG_NOTICE,
                  "Property \"%s\" not defined for network interface", key);

        if(dict != NULL)
            g_variant_unref(dict);

        return false;
    }

    const bool bool_value = g_variant_get_boolean(bool_variant);

    g_variant_unref(bool_variant);
    g_variant_unref(dict);

    return bool_value;
}

bool connman_get_favorite(struct ConnmanInterfaceData *iface_data)
{
    return get_bool_value(iface_data, "Favorite");
}

bool connman_get_auto_connect_mode(struct ConnmanInterfaceData *iface_data)
{
    return get_bool_value(iface_data, "AutoConnect");
}

static const char *
ipver_and_src_to_section_name(const enum ConnmanIPVersion ipver,
                              const enum ConnmanReadConfigSource src)
{
    static const char *const section_names_current[] = { "IPv4", "IPv6", };
    static const char *const section_names_requested[] =
    {
        "IPv4.Configuration",
        "IPv6.Configuration",
    };

    switch(src)
    {
      case CONNMAN_READ_CONFIG_SOURCE_CURRENT:
        return section_names_current[ipver];

      case CONNMAN_READ_CONFIG_SOURCE_REQUESTED:
        return section_names_requested[ipver];

      case CONNMAN_READ_CONFIG_SOURCE_ANY:
        BUG("Cannot determine section name from source \"any\"");
        break;
    }

    return NULL;
}

static enum ConnmanDHCPMode get_dhcp_mode(struct ConnmanInterfaceData *iface_data,
                                          enum ConnmanIPVersion ipver,
                                          enum ConnmanReadConfigSource src)
{
    GVariantDict dict;
    connman_common_init_subdict((GVariant *)iface_data, &dict,
                                ipver_and_src_to_section_name(ipver, src));

    GVariant *method_variant =
        g_variant_dict_lookup_value(&dict, "Method", G_VARIANT_TYPE_STRING);

    if(method_variant == NULL)
    {
        g_variant_dict_clear(&dict);
        return CONNMAN_DHCP_NOT_AVAILABLE;
    }

    const char *method = g_variant_get_string(method_variant, NULL);

    enum ConnmanDHCPMode retval;

    if(strcmp(method, "dhcp") == 0)
        retval = CONNMAN_DHCP_ON;
    else if(strcmp(method, "off") == 0)
        retval = CONNMAN_DHCP_OFF;
    else if(strcmp(method, "manual") == 0)
        retval = CONNMAN_DHCP_MANUAL;
    else if(strcmp(method, "fixed") == 0)
        retval = CONNMAN_DHCP_FIXED;
    else
    {
        msg_error(0, LOG_WARNING,
                  "IP configuration method \"%s\" unknown", method);
        retval = CONNMAN_DHCP_UNKNOWN_METHOD;
    }

    g_variant_unref(method_variant);
    g_variant_dict_clear(&dict);

    return retval;
}

enum ConnmanDHCPMode connman_get_dhcp_mode(struct ConnmanInterfaceData *iface_data,
                                           enum ConnmanIPVersion ipver,
                                           enum ConnmanReadConfigSource src)
{
    log_assert(iface_data != NULL);

    enum ConnmanDHCPMode mode = CONNMAN_DHCP_NOT_AVAILABLE;

    switch(src)
    {
      case CONNMAN_READ_CONFIG_SOURCE_CURRENT:
      case CONNMAN_READ_CONFIG_SOURCE_REQUESTED:
        mode = get_dhcp_mode(iface_data, ipver, src);
        break;

      case CONNMAN_READ_CONFIG_SOURCE_ANY:
        mode = get_dhcp_mode(iface_data, ipver, CONNMAN_READ_CONFIG_SOURCE_CURRENT);

        if(mode == CONNMAN_DHCP_NOT_AVAILABLE)
            mode = get_dhcp_mode(iface_data, ipver, CONNMAN_READ_CONFIG_SOURCE_REQUESTED);

        break;
    }

    if(mode == CONNMAN_DHCP_NOT_AVAILABLE)
    {
        switch(src)
        {
          case CONNMAN_READ_CONFIG_SOURCE_CURRENT:
            msg_vinfo(MESSAGE_LEVEL_DIAG,
                      "IP method not provided in current configuration");
            break;

          case CONNMAN_READ_CONFIG_SOURCE_REQUESTED:
            msg_vinfo(MESSAGE_LEVEL_DIAG,
                      "IP method not provided in requested configuration");
            break;

          case CONNMAN_READ_CONFIG_SOURCE_ANY:
            msg_vinfo(MESSAGE_LEVEL_DIAG,
                      "IP configuration method not provided at all");
            break;
        }
    }

    return mode;
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

enum ConnmanServiceState connman_get_state(struct ConnmanInterfaceData *iface_data)
{
    log_assert(iface_data != NULL);

    GVariant *dict = g_variant_get_child_value((GVariant *)iface_data, 1);
    GVariant *state_variant =
        dict != NULL
        ? g_variant_lookup_value(dict, "State", G_VARIANT_TYPE_STRING)
        : NULL;

    if(state_variant == NULL)
    {
        msg_error(0, LOG_NOTICE, "No connection state for network interface");

        if(dict != NULL)
            g_variant_unref(dict);

        return CONNMAN_STATE_NOT_SPECIFIED;
    }

    const char *state = g_variant_get_string(state_variant, NULL);

    enum ConnmanServiceState retval;

    if(strcmp(state, "idle") == 0)
        retval = CONNMAN_STATE_IDLE;
    else if(strcmp(state, "failure") == 0)
        retval = CONNMAN_STATE_FAILURE;
    else if(strcmp(state, "association") == 0)
        retval = CONNMAN_STATE_ASSOCIATION;
    else if(strcmp(state, "configuration") == 0)
        retval = CONNMAN_STATE_CONFIGURATION;
    else if(strcmp(state, "ready") == 0)
        retval = CONNMAN_STATE_READY;
    else if(strcmp(state, "disconnect") == 0)
        retval = CONNMAN_STATE_DISCONNECT;
    else if(strcmp(state, "online") == 0)
        retval = CONNMAN_STATE_ONLINE;
    else
    {
        msg_error(0, LOG_NOTICE, "Unsupported connection state \"%s\"", state);
        retval = CONNMAN_STATE_NOT_SPECIFIED;
    }

    g_variant_unref(state_variant);
    g_variant_unref(dict);

    return retval;
}

static bool get_parameter_string_from_source(struct ConnmanInterfaceData *iface_data,
                                             enum ConnmanIPVersion ipver,
                                             enum ConnmanReadConfigSource src,
                                             const char *parameter_name,
                                             char *dest, size_t dest_size)
{
    GVariantDict dict;
    connman_common_init_subdict((GVariant *)iface_data, &dict,
                                ipver_and_src_to_section_name(ipver, src));

    GVariant *ip_parameter_variant =
        g_variant_dict_lookup_value(&dict, parameter_name, G_VARIANT_TYPE_STRING);

    if(ip_parameter_variant != NULL)
    {
        const char *ip_parameter = g_variant_get_string(ip_parameter_variant, NULL);

        strncpy(dest, ip_parameter, dest_size);
        dest[dest_size - 1] = '\0';

        g_variant_unref(ip_parameter_variant);
    }
    else
        dest[0] = '\0';

    g_variant_dict_clear(&dict);

    return ip_parameter_variant != NULL;
}

static bool get_parameter_string(struct ConnmanInterfaceData *iface_data,
                                 enum ConnmanIPVersion ipver,
                                 enum ConnmanReadConfigSource src,
                                 const char *parameter_name,
                                 char *dest, size_t dest_size)
{
    log_assert(iface_data != NULL);
    log_assert(parameter_name != NULL);
    log_assert(dest != NULL);
    log_assert(dest_size > 0);

    bool succeeded = false;

    switch(src)
    {
      case CONNMAN_READ_CONFIG_SOURCE_CURRENT:
      case CONNMAN_READ_CONFIG_SOURCE_REQUESTED:
        succeeded =
            get_parameter_string_from_source(iface_data, ipver, src,
                                             parameter_name,
                                             dest, dest_size);
        break;

      case CONNMAN_READ_CONFIG_SOURCE_ANY:
        succeeded =
            get_parameter_string_from_source(iface_data, ipver,
                                             CONNMAN_READ_CONFIG_SOURCE_CURRENT,
                                             parameter_name,
                                             dest, dest_size);

        if(!succeeded)
            succeeded =
                get_parameter_string_from_source(iface_data, ipver,
                                                 CONNMAN_READ_CONFIG_SOURCE_REQUESTED,
                                                 parameter_name,
                                                 dest, dest_size);

        break;
    }

    if(!succeeded)
    {
        switch(src)
        {
          case CONNMAN_READ_CONFIG_SOURCE_CURRENT:
            msg_vinfo(MESSAGE_LEVEL_DIAG,
                      "IP parameter \"%s\" not provided in current configuration",
                      parameter_name);
            break;

          case CONNMAN_READ_CONFIG_SOURCE_REQUESTED:
            msg_vinfo(MESSAGE_LEVEL_DIAG,
                      "IP parameter \"%s\" not provided in requested configuration",
                      parameter_name);
            break;

          case CONNMAN_READ_CONFIG_SOURCE_ANY:
            msg_vinfo(MESSAGE_LEVEL_DIAG,
                      "IP parameter \"%s\" not provided at all",
                      parameter_name);
            break;
        }
    }

    return succeeded;
}

bool connman_get_address_string(struct ConnmanInterfaceData *iface_data,
                                enum ConnmanIPVersion ipver,
                                enum ConnmanReadConfigSource src,
                                char *dest, size_t dest_size)
{
    return get_parameter_string(iface_data, ipver, src, "Address",
                                dest, dest_size);
}

bool connman_get_netmask_string(struct ConnmanInterfaceData *iface_data,
                                enum ConnmanIPVersion ipver,
                                enum ConnmanReadConfigSource src,
                                char *dest, size_t dest_size)
{
    return get_parameter_string(iface_data, ipver, src, "Netmask",
                                dest, dest_size);
}

bool connman_get_gateway_string(struct ConnmanInterfaceData *iface_data,
                                enum ConnmanIPVersion ipver,
                                enum ConnmanReadConfigSource src,
                                char *dest, size_t dest_size)
{
    return get_parameter_string(iface_data, ipver, src, "Gateway",
                                dest, dest_size);
}

static bool get_nameserver_string(struct ConnmanInterfaceData *iface_data,
                                  size_t idx, char *dest, size_t dest_size)
{
    log_assert(iface_data != NULL);
    log_assert(dest != NULL);
    log_assert(dest_size > 0);

    dest[0] = '\0';

    GVariantDict dict;
    connman_common_init_dict_from_temp_gvariant(
        g_variant_get_child_value((GVariant *)iface_data, 1), &dict);

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

    return dns_array != NULL;
}

bool connman_get_primary_dns_string(struct ConnmanInterfaceData *iface_data,
                                    char *dest, size_t dest_size)
{
    return get_nameserver_string(iface_data, 0, dest, dest_size);
}

bool connman_get_secondary_dns_string(struct ConnmanInterfaceData *iface_data,
                                      char *dest, size_t dest_size)
{
    return get_nameserver_string(iface_data, 1, dest, dest_size);
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
    connman_common_init_dict_from_temp_gvariant(
        g_variant_get_child_value((GVariant *)iface_data, 1), &dict);

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
    connman_common_init_dict_from_temp_gvariant(
        g_variant_get_child_value((GVariant *)iface_data, 1), &dict);

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
