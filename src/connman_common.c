/*
 * Copyright (C) 2015, 2017  T+A elektroakustik GmbH & Co. KG
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

#include <stdio.h>

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
        dbus_get_connman_service_proxy_for_object_path(object_path, -1);

    if(proxy == NULL)
        return false;

    msg_vinfo(MESSAGE_LEVEL_DEBUG,
              "Set ConnMan property %s on %s", property_name, object_path);

    tdbus_connman_service_call_set_property(proxy, property_name, value,
                                            NULL, NULL, NULL);

    g_object_unref(proxy);

    return true;
}

struct ConnectToServiceDoneFn
{
    ConnmanCommonConnectServiceCallback fn;
    void *user_data;
};

struct ConnectToServiceData
{
    GRecMutex lock;

    tdbusconnmanService *proxy;
    struct ConnectToServiceDoneFn connect_done_fn;

    char queued_service_name[512];
    struct ConnectToServiceDoneFn queued_connect_done_fn;
};

/*!
 * Store service name for chaining of connection requests.
 */
static void queue_service_connect_request(struct ConnectToServiceData *data,
                                          const char *object_path,
                                          ConnmanCommonConnectServiceCallback done_fn,
                                          void *user_data)
{
    if(object_path[0] != '\0')
    {
        snprintf(data->queued_service_name, sizeof(data->queued_service_name),
                 "%s", object_path);
        data->queued_connect_done_fn.fn = done_fn;
        data->queued_connect_done_fn.user_data = user_data;
    }
    else
    {
        data->queued_service_name[0] = '\0';
        data->queued_connect_done_fn.fn = NULL;
    }
}

static bool prepare_service_connect_request(struct ConnectToServiceData *data,
                                            const char *object_path,
                                            ConnmanCommonConnectServiceCallback fn,
                                            void *user_data)
{
    if(object_path != NULL)
        log_assert(data->queued_service_name[0] == '\0');
    else
    {
        object_path = data->queued_service_name;
        log_assert(object_path[0] != '\0');
    }

    data->connect_done_fn.fn = fn;
    data->connect_done_fn.user_data = user_data;

    if(object_path[0] == '\0')
        fn(object_path, CONNMAN_SERVICE_CONNECT_FAILURE, user_data);
    else
    {
        static const int wlan_connect_timeout_seconds = 60;

        data->proxy =
            dbus_get_connman_service_proxy_for_object_path(object_path,
                                                           wlan_connect_timeout_seconds);

        if(data->proxy != NULL)
            return true;

        fn(object_path, CONNMAN_SERVICE_CONNECT_FAILURE, user_data);
    }

    return false;
}

static bool connect_to_service_if_needed(bool need_start_connect,
                                         struct ConnectToServiceData *data);

static void connect_to_service_done(GObject *source_object, GAsyncResult *res,
                                    gpointer user_data)
{
    struct ConnectToServiceData *const data = user_data;

    g_rec_mutex_lock(&data->lock);

    log_assert(TDBUS_CONNMAN_SERVICE(source_object) == data->proxy);

    GError *error = NULL;
    (void)tdbus_connman_service_call_connect_finish(data->proxy, res, &error);

    const bool success = (dbus_common_handle_dbus_error(&error, "Connect ConnMan service") == 0);

    if(data->queued_service_name[0] == '\0')
        data->connect_done_fn.fn(g_dbus_proxy_get_object_path(G_DBUS_PROXY(data->proxy)),
                                 success ? CONNMAN_SERVICE_CONNECT_CONNECTED : CONNMAN_SERVICE_CONNECT_FAILURE,
                                 data->connect_done_fn.user_data);
    else
        data->connect_done_fn.fn(g_dbus_proxy_get_object_path(G_DBUS_PROXY(data->proxy)),
                                 CONNMAN_SERVICE_CONNECT_DISCARDED,
                                 data->connect_done_fn.user_data);

    g_object_unref(data->proxy);
    data->proxy = NULL;
    data->connect_done_fn.fn = NULL;

    bool need_start_connect = false;

    if(data->queued_service_name[0] != '\0')
    {
        /* chain next request */
        need_start_connect =
            prepare_service_connect_request(data, NULL,
                                            data->queued_connect_done_fn.fn,
                                            data->queued_connect_done_fn.user_data);
        data->queued_service_name[0] = '\0';
        data->queued_connect_done_fn.fn = NULL;
    }

    g_rec_mutex_unlock(&data->lock);

    connect_to_service_if_needed(need_start_connect, data);
}

static bool connect_to_service_if_needed(bool need_start_connect,
                                         struct ConnectToServiceData *data)
{
    if(!need_start_connect)
        return false;

    /* so we have just created our proxy object, no async callbacks to be
     * expected---we may freely access the #ConnectToServiceData object passed
     * in \p data and start the asynchronous D-Bus call */

    msg_vinfo(MESSAGE_LEVEL_DEBUG, "Connecting to ConnMan service %s",
             g_dbus_proxy_get_object_path(G_DBUS_PROXY(data->proxy)));

    tdbus_connman_service_call_connect(data->proxy, NULL,
                                       connect_to_service_done, data);

    return true;
}

static struct ConnectToServiceData connect_to_service_data;

bool connman_common_connect_service_by_object_path(const char *object_path,
                                                   ConnmanCommonConnectServiceCallback done_fn,
                                                   void *user_data)
{
    log_assert(object_path != NULL);
    log_assert(done_fn != NULL);

    g_rec_mutex_lock(&connect_to_service_data.lock);

    bool need_start_connect = false;

    if(connect_to_service_data.proxy != NULL)
        queue_service_connect_request(&connect_to_service_data, object_path,
                                      done_fn, user_data);
    else
    {
        need_start_connect =
            prepare_service_connect_request(&connect_to_service_data, object_path,
                                            done_fn, user_data);
    }

    g_rec_mutex_unlock(&connect_to_service_data.lock);

    return connect_to_service_if_needed(need_start_connect,
                                        &connect_to_service_data);
}

void connman_common_disconnect_service_by_object_path(const char *object_path)
{
    tdbusconnmanService *proxy =
        dbus_get_connman_service_proxy_for_object_path(object_path, -1);

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
        dbus_get_connman_service_proxy_for_object_path(object_path, -1);

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
