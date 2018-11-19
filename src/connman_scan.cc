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
#include "connman_technology_registry.hh"
#include "connman_dbus.h"
#include "dbus_common.h"
#include "messages.h"

#include <algorithm>

static bool enable_wifi_if_necessary(bool is_powered)
{
    if(is_powered)
        return false;

    const auto &locked_reg(Connman::TechnologyRegistry::get_singleton_for_update());
    auto &reg(locked_reg.first);
    reg.wifi().set<Connman::TechnologyPropertiesWIFI::Property::POWERED>(true);
    return true;
}

class WifiScanner
{
  private:
    std::mutex lock_;
    std::vector<Connman::SiteSurveyDoneFn> callbacks_;
    bool is_active_;
    int remaining_tries_;

  public:
    WifiScanner(const WifiScanner &) = delete;
    WifiScanner(WifiScanner &&) = default;
    WifiScanner &operator=(const WifiScanner &) = delete;
    WifiScanner &operator=(WifiScanner &&) = default;

    explicit WifiScanner():
        is_active_(false),
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

        if(is_active_)
        {
            free_ride(std::move(callback));
            return;
        }

        callbacks_.emplace_back(std::move(callback));

        try
        {
            is_active_ = true;

            if(enable_wifi_if_necessary(is_powered))
                remaining_tries_ = 10;
            else
                remaining_tries_ = 1;

            do_initiate_scan();
        }
        catch(...)
        {
            notify_and_finish(Connman::SiteSurveyResult::DBUS_ERROR);
            return;
        }
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
     * Ask Connman to start WLAN survey now.
     *
     * This function does not block. Upon completion, the function
     * #WifiScanner::done_callback() is called.
     */
    void do_initiate_scan()
    {
        const auto &locked_reg(Connman::TechnologyRegistry::get_singleton_for_update());
        auto &reg(locked_reg.first);
        tdbusconnmanTechnology *const proxy = reg.wifi().get_dbus_proxy();

        tdbus_connman_technology_call_scan(proxy, nullptr,
                                           WifiScanner::done_callback, this);
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
            notify_and_finish(success
                              ? Connman::SiteSurveyResult::OK
                              : Connman::SiteSurveyResult::CONNMAN_ERROR);
        else
        {
            static constexpr guint retry_interval_ms = 100;

            msg_info("WLAN scan failed, trying again in %u ms (%d tr%s left)",
                     retry_interval_ms, remaining_tries_,
                     remaining_tries_ != 1 ? "ies" : "y");
            g_timeout_add(retry_interval_ms, timed_scan, this);
        }
    }

    void notify_and_finish(Connman::SiteSurveyResult result)
    {
        for(const auto &fn : callbacks_)
            fn(result);

        remaining_tries_ = 0;
        is_active_ = false;
        callbacks_.clear();
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

        try
        {
            scanner->do_initiate_scan();
        }
        catch(...)
        {
            scanner->notify_and_finish(Connman::SiteSurveyResult::DBUS_ERROR);
        }

        return G_SOURCE_REMOVE;
    }
};

static bool site_survey_or_just_power_on(Connman::SiteSurveyDoneFn &&site_survey_callback)
{
    const char *object_path = nullptr;
    bool is_powered = false;

    {
        const auto &locked_reg(Connman::TechnologyRegistry::get_singleton_for_update());
        auto &reg(locked_reg.first);

        try
        {
            tdbusconnmanTechnology *proxy = reg.wifi().get_dbus_proxy();
            object_path = g_dbus_proxy_get_object_path(G_DBUS_PROXY(proxy));
            is_powered = reg.wifi().get<Connman::TechnologyPropertiesWIFI::Property::POWERED>();
        }
        catch(const Connman::TechnologyRegistryUnavailableError &e)
        {
            /* don't have anything WLAN for some reason: don't emit any error
             * messages to avoid flooding the log */
            return false;
        }
        catch(const Connman::TechnologyRegistryError &e)
        {
            msg_error(0, LOG_ERR, "Failed to get WLAN properties: %s", e.what());
            return false;
        }
    }

    if(site_survey_callback != nullptr)
    {
        /* scan requested */
        static WifiScanner scanner;
        scanner.scan(object_path, is_powered, std::move(site_survey_callback));
    }
    else
    {
        /* power on requested */
        enable_wifi_if_necessary(is_powered);
    }

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
