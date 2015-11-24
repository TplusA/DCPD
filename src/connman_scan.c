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

#include <string.h>

#include "connman.h"
#include "connman_common.h"
#include "dbus_common.h"
#include "dbus_iface_deep.h"
#include "messages.h"

struct wifi_scan_data
{
    tdbusconnmanTechnology *proxy;
    int remaining_tries;
    ConnmanSurveyDoneFn callback;
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

static gboolean do_initiate_scan(gpointer user_data);

static void wifi_scan_done(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
    struct wifi_scan_data *const data = user_data;

    log_assert(TDBUS_CONNMAN_TECHNOLOGY(source_object) == data->proxy);

    GError *error = NULL;
    (void)tdbus_connman_technology_call_scan_finish(data->proxy, res, &error);

    const bool success = (dbus_common_handle_dbus_error(&error) == 0);

    if(success || --data->remaining_tries <= 0)
    {
        data->remaining_tries = 0;
        data->callback(success ? CONNMAN_SITE_SCAN_OK : CONNMAN_SITE_SCAN_CONNMAN_ERROR);
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
}

static gboolean do_initiate_scan(gpointer user_data)
{
    struct wifi_scan_data *const data = user_data;

    tdbus_connman_technology_call_scan(data->proxy, NULL,
                                       wifi_scan_done, user_data);
    return G_SOURCE_REMOVE;
}

static void scan_wifi(struct wifi_scan_data *data,
                      const char *object_path, bool is_powered,
                      ConnmanSurveyDoneFn callback)
{
    if(data->proxy != NULL)
    {
        BUG("Attempted to ask Connman to scan WLAN, but is already in progress");
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

    data->callback = callback;

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

bool connman_start_wlan_site_survey(ConnmanSurveyDoneFn callback)
{
    tdbusconnmanManager *iface = dbus_get_connman_manager_iface();

    GVariantDict dict;
    GVariant *entry = find_technology_by_name(iface, "wifi", &dict);

    if(entry == NULL)
    {
        msg_error(0, LOG_NOTICE, "No WLAN adapter connected");
        callback(CONNMAN_SITE_SCAN_NO_HARDWARE);
        return false;
    }

    const bool is_powered = check_if_powered(&dict);

    GVariant *tech_path_variant = g_variant_get_child_value(entry, 0);
    log_assert(tech_path_variant != NULL);

    static struct wifi_scan_data scan_data;
    scan_wifi(&scan_data, g_variant_get_string(tech_path_variant, NULL),
              is_powered, callback);

    g_variant_unref(tech_path_variant);
    g_variant_unref(entry);
    g_variant_dict_clear(&dict);

    return true;
}