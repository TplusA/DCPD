/*
 * Copyright (C) 2015, 2017, 2018, 2019  T+A elektroakustik GmbH & Co. KG
 *
 * This file is part of DCPD.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
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
    (void)dbus_common_handle_dbus_error(&error, "Query ConnMan services");

    return result;
}

bool connman_common_set_service_property(const char *object_path,
                                         const char *property_name,
                                         GVariant *value)
{
    tdbusconnmanService *proxy =
        dbus_new_connman_service_proxy_for_object_path(object_path, -1);

    if(proxy == NULL)
        return false;

    msg_vinfo(MESSAGE_LEVEL_DEBUG,
              "Set ConnMan property %s on %s", property_name, object_path);

    tdbus_connman_service_call_set_property(proxy, property_name, value,
                                            NULL, NULL, NULL);

    g_object_unref(proxy);

    return true;
}

void connman_common_disconnect_service_by_object_path(const char *object_path)
{
    tdbusconnmanService *proxy =
        dbus_new_connman_service_proxy_for_object_path(object_path, -1);

    if(proxy == NULL)
        return;

    msg_vinfo(MESSAGE_LEVEL_DEBUG,
              "Disconnect ConnMan service %s", object_path);

    GError *error = NULL;
    tdbus_connman_service_call_disconnect_sync(proxy, NULL, &error);
    (void)dbus_common_handle_dbus_error(&error, "Disconnect ConnMan service");

    g_object_unref(proxy);
}

void connman_common_remove_service_by_object_path(const char *object_path)
{
    tdbusconnmanService *proxy =
        dbus_new_connman_service_proxy_for_object_path(object_path, -1);

    if(proxy == NULL)
        return;

    msg_vinfo(MESSAGE_LEVEL_DEBUG, "Remove ConnMan service %s", object_path);

    GError *error = NULL;
    tdbus_connman_service_call_remove_sync(proxy, NULL, &error);
    (void)dbus_common_handle_dbus_error(&error, "Remove ConnMan service");

    msg_vinfo(MESSAGE_LEVEL_DEBUG, "Removed ConnMan service");

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
