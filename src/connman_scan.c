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
#include "dbus_common.h"
#include "dbus_iface_deep.h"
#include "messages.h"

struct wifi_scan_data
{
    GMutex lock;

    tdbusconnmanTechnology *proxy;
    int remaining_tries;

    ConnmanSurveyDoneFn callbacks[2];
    size_t number_of_callbacks;
};

static bool enable_wifi_if_necessary(tdbusconnmanTechnology *proxy, bool is_powered)
{
    if(is_powered)
        return false;

    GError *error = NULL;
    GVariant *bool_variant = g_variant_new("v", g_variant_new("b", true));
    tdbus_connman_technology_call_set_property_sync(proxy,
                                                    "Powered", bool_variant,
                                                    NULL, &error);
    (void)dbus_common_handle_dbus_error(&error);

    return true;
}

/*!
 * Call and clear all registered callbacks for WLAN survey completion.
 *
 * Must be called while holding #wifi_scan_data::lock.
 */
static void call_all_callbacks(struct wifi_scan_data *data,
                               enum ConnmanSiteScanResult result)
{
    for(size_t i = 0; i < data->number_of_callbacks; ++i)
        (data->callbacks[i])(result);

    data->number_of_callbacks = 0;
}

static gboolean do_initiate_scan(gpointer user_data);

/*!
 * D-Bus callback for WLAN survey completion.
 *
 * This function is called from GLib's D-Bus code, context basically unknown.
 */
static void wifi_scan_done(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
    struct wifi_scan_data *const data = user_data;

    g_mutex_lock(&data->lock);

    log_assert(TDBUS_CONNMAN_TECHNOLOGY(source_object) == data->proxy);

    GError *error = NULL;
    (void)tdbus_connman_technology_call_scan_finish(data->proxy, res, &error);

    const bool success = (dbus_common_handle_dbus_error(&error) == 0);

    if(success || --data->remaining_tries <= 0)
    {
        data->remaining_tries = 0;
        call_all_callbacks(data,
                           success ? CONNMAN_SITE_SCAN_OK : CONNMAN_SITE_SCAN_CONNMAN_ERROR);
        g_object_unref(data->proxy);
        data->proxy = NULL;
    }
    else
    {
        static const guint retry_interval_ms = 100;

        msg_info("WLAN scan failed, trying again in %u ms (%d tr%s left)",
                 retry_interval_ms, data->remaining_tries,
                 data->remaining_tries != 1 ? "ies" : "y");
        g_timeout_add(retry_interval_ms, do_initiate_scan, user_data);
    }

    g_mutex_unlock(&data->lock);
}

/*!
 * Start WLAN survey, asynchronously.
 *
 * Must be called while holding #wifi_scan_data::lock.
 */
static gboolean do_initiate_scan(gpointer user_data)
{
    struct wifi_scan_data *const data = user_data;

    tdbus_connman_technology_call_scan(data->proxy, NULL,
                                       wifi_scan_done, user_data);
    return G_SOURCE_REMOVE;
}

/*!
 * WLAN survey already in progress, take a free ride.
 *
 * Must be called while holding #wifi_scan_data::lock.
 */
static void free_ride(struct wifi_scan_data *data,
                      ConnmanSurveyDoneFn callback)
{
    size_t i;

    for(i = 0; i < data->number_of_callbacks; ++i)
    {
        if(data->callbacks[i] == callback)
            break;
    }

    if(i == data->number_of_callbacks)
    {
        /* not registered yet */
        if(data->number_of_callbacks < sizeof(data->callbacks) / sizeof(data->callbacks[0]))
            data->callbacks[data->number_of_callbacks++] = callback;
        else
        {
            BUG("Too many WLAN site survey callbacks registered");
            callback(CONNMAN_SITE_SCAN_OUT_OF_MEMORY);
        }
    }
}

/*!
 * Initiate WLAN scan or take a free ride on ongoing scan.
 *
 * Must be called while holding #wifi_scan_data::lock.
 */
static void scan_wifi(struct wifi_scan_data *data,
                      const char *object_path, bool is_powered,
                      ConnmanSurveyDoneFn callback)
{
    log_assert(callback != NULL);

    if(data->proxy != NULL)
    {
        free_ride(data, callback);
        return;
    }

    data->proxy =
        dbus_get_connman_technology_proxy_for_object_path(object_path);

    if(data->proxy == NULL)
    {
        callback(CONNMAN_SITE_SCAN_DBUS_ERROR);
        return;
    }

    if(enable_wifi_if_necessary(data->proxy, is_powered))
        data->remaining_tries = 10;
    else
        data->remaining_tries = 1;

    data->callbacks[0] = callback;
    data->number_of_callbacks = 1;

    do_initiate_scan(data);
}

static GVariant *find_technology_by_name(tdbusconnmanManager *iface,
                                         const char *name, GVariantDict *dict)
{
    if(iface == NULL)
        return NULL;

    GVariant *technologies = NULL;
    GError *error = NULL;
    tdbus_connman_manager_call_get_technologies_sync(iface, &technologies,
                                                     NULL, &error);
    (void)dbus_common_handle_dbus_error(&error);

    if(technologies == NULL)
    {
        msg_error(0, LOG_CRIT, "Failed getting technologies from Connman");
        return NULL;
    }

    const size_t count = g_variant_n_children(technologies);
    GVariant *tuple = NULL;

    for(size_t i = 0; i < count; ++i)
    {
        tuple = g_variant_get_child_value(technologies, i);
        log_assert(tuple != NULL);

        connman_common_init_dict_from_temp_gvariant(
            g_variant_get_child_value(tuple, 1), dict);

        GVariant *tech_type_variant =
            g_variant_dict_lookup_value(dict, "Type", G_VARIANT_TYPE_STRING);
        log_assert(tech_type_variant != NULL);

        const char *tech_type_string =
            g_variant_get_string(tech_type_variant, NULL);

        if(strcmp(tech_type_string, name) != 0)
        {
            g_variant_dict_clear(dict);
            g_variant_unref(tuple);
            tuple = NULL;
        }
        else
            i = count;

        g_variant_unref(tech_type_variant);
    }

    g_variant_unref(technologies);

    return tuple;
}

static bool check_if_powered(GVariantDict *dict)
{
    GVariant *tech_powered_variant =
        g_variant_dict_lookup_value(dict, "Powered", G_VARIANT_TYPE_BOOLEAN);
    bool is_powered;

    if(tech_powered_variant == NULL)
    {
        msg_error(0, LOG_ERR, "Failed to get power state for WLAN");
        is_powered = false;
    }
    else
        is_powered = g_variant_get_boolean(tech_powered_variant);

    g_variant_unref(tech_powered_variant);

    return is_powered;
}

static bool site_survey_or_just_power_on(ConnmanSurveyDoneFn site_survey_callback)
{
    tdbusconnmanManager *iface = dbus_get_connman_manager_iface();

    GVariantDict dict;
    GVariant *entry = find_technology_by_name(iface, "wifi", &dict);

    if(entry == NULL)
    {
        msg_error(0, LOG_NOTICE, "No WLAN adapter connected");

        if(site_survey_callback != NULL)
            site_survey_callback(CONNMAN_SITE_SCAN_NO_HARDWARE);

        return false;
    }

    const bool is_powered = check_if_powered(&dict);

    GVariant *tech_path_variant = g_variant_get_child_value(entry, 0);
    log_assert(tech_path_variant != NULL);

    const char *object_path = g_variant_get_string(tech_path_variant, NULL);

    if(site_survey_callback != NULL)
    {
        static struct wifi_scan_data scan_data;

        g_mutex_lock(&scan_data.lock);
        scan_wifi(&scan_data, object_path, is_powered, site_survey_callback);
        g_mutex_unlock(&scan_data.lock);
    }
    else
    {
        tdbusconnmanTechnology *const proxy =
            dbus_get_connman_technology_proxy_for_object_path(object_path);

        if(proxy != NULL)
        {
            (void)enable_wifi_if_necessary(proxy, is_powered);
            g_object_unref(proxy);
        }
    }

    g_variant_unref(tech_path_variant);
    g_variant_unref(entry);
    g_variant_dict_clear(&dict);

    return true;
}

void connman_wlan_power_on(void)
{
    (void)site_survey_or_just_power_on(NULL);
}

bool connman_start_wlan_site_survey(ConnmanSurveyDoneFn callback)
{
    log_assert(callback != NULL);
    return site_survey_or_just_power_on(callback);
}
