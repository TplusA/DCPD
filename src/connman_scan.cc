/*
 * Copyright (C) 2015, 2016, 2017, 2018  T+A elektroakustik GmbH & Co. KG
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

#include "connman_scan.hh"
#include "connman_common.h"
#include "dbus_common.h"
#include "dbus_iface_deep.h"
#include "gvariantwrapper.hh"
#include "messages.h"

#include <vector>
#include <mutex>
#include <algorithm>

static bool enable_wifi_if_necessary(tdbusconnmanTechnology *proxy, bool is_powered)
{
    if(is_powered)
        return false;

    GVariant *bool_variant = g_variant_new("v", g_variant_new("b", true));
    tdbus_connman_technology_call_set_property(proxy, "Powered", bool_variant,
                                               nullptr, nullptr, nullptr);

    return true;
}

class WifiScanner
{
  private:
    std::mutex lock_;
    std::vector<Connman::SiteSurveyDoneFn> callbacks_;
    tdbusconnmanTechnology *proxy_;
    int remaining_tries_;

  public:
    WifiScanner(const WifiScanner &) = delete;
    WifiScanner(WifiScanner &&) = default;
    WifiScanner &operator=(const WifiScanner &) = delete;
    WifiScanner &operator=(WifiScanner &&) = default;

    explicit WifiScanner():
        proxy_(nullptr),
        remaining_tries_(0)
    {}

    /*!
     * Initiate WLAN scan or take a free ride with ongoing scan.
     */
    void scan(const char *object_path, bool is_powered,
              Connman::SiteSurveyDoneFn &&callback)
    {
        log_assert(object_path != nullptr);
        log_assert(callback != nullptr);

        std::lock_guard<std::mutex> lock(lock_);

        if(proxy_ != nullptr)
        {
            free_ride(std::move(callback));
            return;
        }

        proxy_ = dbus_new_connman_technology_proxy_for_object_path(object_path, nullptr, nullptr);

        if(proxy_ == nullptr)
        {
            callback(Connman::SiteSurveyResult::DBUS_ERROR);
            return;
        }

        if(enable_wifi_if_necessary(proxy_, is_powered))
            remaining_tries_ = 10;
        else
            remaining_tries_ = 1;

        callbacks_.emplace_back(std::move(callback));

        do_initiate_scan();
    }

  private:
    /*!
     * WLAN survey already in progress, take a free ride.
     */
    void free_ride(Connman::SiteSurveyDoneFn &&callback)
    {
        if(std::find(callbacks_.begin(), callbacks_.end(), callback) != callbacks_.end())
            return;

        if(callbacks_.size() < 10)
            callbacks_.emplace_back(std::move(callback));
        else
        {
            BUG("Too many WLAN site survey callbacks registered");
            callback(Connman::SiteSurveyResult::OUT_OF_MEMORY);
        }
    }

    /*!
     * D-Bus callback for WLAN survey completion.
     *
     * This function is called from GLib's D-Bus code, context basically
     * unknown.
     */
    static void done_callback(GObject *source_object, GAsyncResult *res, gpointer user_data)
    {
        auto *const scanner = static_cast<WifiScanner *>(user_data);
        std::lock_guard<std::mutex> lock(scanner->lock_);
        scanner->done(source_object, res);
    }

    /*!
     * Finalize WLAN survey.
     *
     * All callbacks are called informing about the survey completion, and the
     * object is reset to idle state so that more WLAN survey requests can be
     * handled.
     *
     * In case of survey failure, the operation may be automatically restarted.
     */
    void done(GObject *source_object, GAsyncResult *res)
    {
        GError *error = nullptr;
        (void)tdbus_connman_technology_call_scan_finish(TDBUS_CONNMAN_TECHNOLOGY(source_object),
                                                        res, &error);

        const bool success = (dbus_common_handle_dbus_error(&error, "WLAN survey done") == 0);

        if(success || --remaining_tries_ <= 0)
        {
            remaining_tries_ = 0;

            for(const auto &fn : callbacks_)
                fn(success ? Connman::SiteSurveyResult::OK : Connman::SiteSurveyResult::CONNMAN_ERROR);

            callbacks_.clear();

            if(proxy_ != nullptr)
            {
                g_object_unref(proxy_);
                proxy_ = nullptr;
            }
        }
        else
        {
            static constexpr guint retry_interval_ms = 100;

            msg_info("WLAN scan failed, trying again in %u ms (%d tr%s left)",
                     retry_interval_ms, remaining_tries_,
                     remaining_tries_ != 1 ? "ies" : "y");
            g_timeout_add(retry_interval_ms, timed_scan, this);
        }
    }

    /*!
     * GLib callback for starting WLAN survey.
     *
     * This function is called from GLib's main loop.
     */
    static gboolean timed_scan(gpointer user_data)
    {
        auto *const scanner = static_cast<WifiScanner *>(user_data);
        std::lock_guard<std::mutex> lock(scanner->lock_);
        scanner->do_initiate_scan();
        return G_SOURCE_REMOVE;
    }

    /*!
     * Ask Connman to start WLAN survey now.
     *
     * This function does not block. Upon completion, the function
     * #WifiScanner::done_callback() is called.
     */
    void do_initiate_scan()
    {
        tdbus_connman_technology_call_scan(proxy_, nullptr,
                                           WifiScanner::done_callback, this);
    }
};

static GVariantWrapper find_technology_by_name(tdbusconnmanManager *iface,
                                               const std::string &name,
                                               GVariantDict *dict)
{
    if(iface == nullptr)
        return GVariantWrapper();

    GVariant *temp = nullptr;
    GError *error = nullptr;
    tdbus_connman_manager_call_get_technologies_sync(iface, &temp,
                                                     nullptr, &error);
    (void)dbus_common_handle_dbus_error(&error, "Find network technology");
    GVariantWrapper technologies(temp);

    if(technologies == nullptr)
    {
        msg_error(0, LOG_CRIT, "Failed getting technologies from Connman");
        return GVariantWrapper();
    }

    const size_t count = g_variant_n_children(GVariantWrapper::get(technologies));

    for(size_t i = 0; i < count; ++i)
    {
        GVariantWrapper tuple(g_variant_get_child_value(GVariantWrapper::get(technologies), i),
                              GVariantWrapper::Transfer::JUST_MOVE);
        log_assert(tuple != nullptr);

        connman_common_init_dict_from_temp_gvariant(
            g_variant_get_child_value(GVariantWrapper::get(tuple), 1), dict);

        GVariantWrapper tech_type_variant(g_variant_dict_lookup_value(dict, "Type",
                                                                      G_VARIANT_TYPE_STRING),
                                          GVariantWrapper::Transfer::JUST_MOVE);
        log_assert(tech_type_variant != nullptr);

        const char *tech_type_string =
            g_variant_get_string(GVariantWrapper::get(tech_type_variant), nullptr);

        if(tech_type_string == name)
            return tuple;

        g_variant_dict_clear(dict);
    }

    return GVariantWrapper();
}

static bool check_if_powered(GVariantDict *dict)
{
    GVariantWrapper tech_powered_variant(g_variant_dict_lookup_value(dict, "Powered",
                                                                     G_VARIANT_TYPE_BOOLEAN),
                                         GVariantWrapper::Transfer::JUST_MOVE);

    if(tech_powered_variant != nullptr)
        return g_variant_get_boolean(GVariantWrapper::get(tech_powered_variant));
    else
    {
        msg_error(0, LOG_ERR, "Failed to get power state for WLAN");
        return false;
    }
}

static bool site_survey_or_just_power_on(Connman::SiteSurveyDoneFn &&site_survey_callback)
{
    tdbusconnmanManager *iface = dbus_get_connman_manager_iface();

    GVariantDict dict;
    GVariantWrapper entry(find_technology_by_name(iface, "wifi", &dict));

    if(entry == nullptr)
    {
        msg_error(0, LOG_NOTICE, "No WLAN adapter connected");

        if(site_survey_callback != nullptr)
            site_survey_callback(Connman::SiteSurveyResult::NO_HARDWARE);

        return false;
    }

    const bool is_powered = check_if_powered(&dict);

    GVariantWrapper tech_path_variant(g_variant_get_child_value(GVariantWrapper::get(entry), 0),
                                      GVariantWrapper::Transfer::JUST_MOVE);
    log_assert(tech_path_variant != nullptr);

    const char *object_path = g_variant_get_string(GVariantWrapper::get(tech_path_variant), nullptr);

    if(site_survey_callback != nullptr)
    {
        /* scan requested */
        static WifiScanner scanner;
        scanner.scan(object_path, is_powered, std::move(site_survey_callback));
    }
    else
    {
        /* power on requested */
        tdbusconnmanTechnology *const proxy =
            dbus_new_connman_technology_proxy_for_object_path(object_path, nullptr, nullptr);

        if(proxy != nullptr)
        {
            (void)enable_wifi_if_necessary(proxy, is_powered);
            g_object_unref(proxy);
        }
    }

    g_variant_dict_clear(&dict);

    return true;
}

void Connman::wlan_power_on()
{
    (void)site_survey_or_just_power_on(nullptr);
}

bool Connman::start_wlan_site_survey(Connman::SiteSurveyDoneFn callback)
{
    log_assert(callback != nullptr);
    return site_survey_or_just_power_on(std::move(callback));
}
