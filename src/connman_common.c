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

#include "connman_common.h"
#include "dbus_common.h"
#include "dbus_iface_deep.h"
#include "messages.h"

GVariant *connman_common_query_services(tdbusconnmanManager *iface)
{
    if(iface == NULL)
        return NULL;

    GVariant *result = NULL;
    GError *error = NULL;
    tdbus_connman_manager_call_get_services_sync(iface, &result, NULL, &error);
    (void)dbus_common_handle_dbus_error(&error);

    return result;
}

void connman_common_set_service_property(const char *object_path,
                                         const char *property_name,
                                         GVariant *value)
{
    tdbusconnmanService *proxy =
        dbus_get_connman_service_proxy_for_object_path(object_path);

    if(proxy == NULL)
        return;

    GError *error = NULL;
    tdbus_connman_service_call_set_property_sync(proxy, property_name, value,
                                                 NULL, &error);
    (void)dbus_common_handle_dbus_error(&error);

    g_object_unref(proxy);
}

void connman_common_connect_service_by_object_path(const char *object_path)
{
    tdbusconnmanService *proxy =
        dbus_get_connman_service_proxy_for_object_path(object_path);

    if(proxy == NULL)
        return;

    GError *error = NULL;
    tdbus_connman_service_call_connect_sync(proxy, NULL, &error);
    (void)dbus_common_handle_dbus_error(&error);

    g_object_unref(proxy);
}

void connman_common_disconnect_service_by_object_path(const char *object_path)
{
    tdbusconnmanService *proxy =
        dbus_get_connman_service_proxy_for_object_path(object_path);

    if(proxy == NULL)
        return;

    GError *error = NULL;
    tdbus_connman_service_call_disconnect_sync(proxy, NULL, &error);
    (void)dbus_common_handle_dbus_error(&error);

    g_object_unref(proxy);
}

void connman_common_remove_service_by_object_path(const char *object_path)
{
    tdbusconnmanService *proxy =
        dbus_get_connman_service_proxy_for_object_path(object_path);

    if(proxy == NULL)
        return;

    GError *error = NULL;
    tdbus_connman_service_call_remove_sync(proxy, NULL, &error);
    (void)dbus_common_handle_dbus_error(&error);

    g_object_unref(proxy);
}

void connman_common_init_dict_from_temp_gvariant(GVariant *temp,
                                                 GVariantDict *dict)
{
    log_assert(temp != NULL);
    g_variant_dict_init(dict, temp);
    g_variant_unref(temp);
}

void connman_common_init_subdict(GVariant *tuple, GVariantDict *subdict,
                                 const char *subdict_name)
{
    GVariantDict dict;
    connman_common_init_dict_from_temp_gvariant(g_variant_get_child_value(tuple, 1),
                                                &dict);
    connman_common_init_dict_from_temp_gvariant(g_variant_dict_lookup_value(&dict, subdict_name,
                                                                            G_VARIANT_TYPE_VARDICT),
                                                subdict);
    g_variant_dict_clear(&dict);
}
