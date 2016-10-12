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
        data->proxy =
            dbus_get_connman_service_proxy_for_object_path(object_path);

        if(data->proxy != NULL)
            return true;

        fn(object_path, CONNMAN_SERVICE_CONNECT_FAILURE, user_data);
    }

    return false;
}

static void connect_to_service_if_needed(bool need_start_connect,
                                         struct ConnectToServiceData *data);

static void connect_to_service_done(GObject *source_object, GAsyncResult *res,
                                    gpointer user_data)
{
    struct ConnectToServiceData *const data = user_data;

    g_rec_mutex_lock(&data->lock);

    log_assert(TDBUS_CONNMAN_SERVICE(source_object) == data->proxy);

    GError *error = NULL;
    (void)tdbus_connman_service_call_connect_finish(data->proxy, res, &error);

    const bool success = (dbus_common_handle_dbus_error(&error) == 0);

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

static void connect_to_service_if_needed(bool need_start_connect,
                                         struct ConnectToServiceData *data)
{
    if(!need_start_connect)
        return;

    /* so we have just created our proxy object, no async callbacks to be
     * expected---we may freely access the #ConnectToServiceData object passed
     * in \p data and start the asynchronous D-Bus call */

    tdbus_connman_service_call_connect(data->proxy, NULL,
                                       connect_to_service_done, data);
}

static struct ConnectToServiceData connect_to_service_data;

void connman_common_connect_service_by_object_path(const char *object_path,
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

    connect_to_service_if_needed(need_start_connect, &connect_to_service_data);
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
