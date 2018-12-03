/*
 * Copyright (C) 2015, 2016, 2018  T+A elektroakustik GmbH & Co. KG
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

#include "dcpregs_wlansurvey.hh"
#include "registers_priv.hh"
#include "connman_scan.hh"
#include "connman_iter.h"
#include "messages.h"

#include <sstream>
#include <cstring>
#include <mutex>

static struct
{
    /* must be a recursive mutex because sometimes the survey-done callback is
     * called from our own context while we are holding the lock, sometimes
     * its called from another context */
    std::recursive_mutex lock;

    bool survey_in_progress;
    Connman::SiteSurveyResult last_result;
    Connman::WLANTools *wlan;
}
nwwlan_survey_data;

enum WifiServiceType
{
    WIFI_SERVICE_TYPE_NONE,
    WIFI_SERVICE_TYPE_WLAN_WITH_SSID,
    WIFI_SERVICE_TYPE_HIDDEN,
};

void Regs::WLANSurvey::init(Connman::WLANTools *wlan)
{
    nwwlan_survey_data.survey_in_progress = false;
    nwwlan_survey_data.last_result = Connman::SiteSurveyResult::OK;
    nwwlan_survey_data.wlan = wlan;
}

void Regs::WLANSurvey::deinit() {}

static void survey_done(Connman::SiteSurveyResult result)
{
    {
    std::lock_guard<std::recursive_mutex> lock(nwwlan_survey_data.lock);

    if(!nwwlan_survey_data.survey_in_progress)
        BUG("Got WLAN survey done notification, but didn't start any");

    msg_info("WLAN site survey done, %s (%d)",
             (result == Connman::SiteSurveyResult::OK) ? "succeeded" : "failed",
             int(result));

    nwwlan_survey_data.survey_in_progress = false;
    nwwlan_survey_data.last_result = result;
    }

    Regs::get_data().register_changed_notification_fn(105);
}

/*!
 * \todo This function is copied in various places. Must be refactored.
 */
static bool data_length_is_unexpected(size_t length, size_t expected)
{
    if(length == expected)
        return false;

    msg_error(EINVAL, LOG_ERR,
              "Unexpected data length %zu (expected %zu)", length, expected);

    return true;
}

int Regs::WLANSurvey::DCP::write_104_start_wlan_site_survey(const uint8_t *data, size_t length)
{
    if(data_length_is_unexpected(length, 0))
        return -1;

    std::lock_guard<std::recursive_mutex> lock(nwwlan_survey_data.lock);

    if(nwwlan_survey_data.wlan == nullptr)
    {
        msg_error(0, LOG_NOTICE,
                  "WLAN not available, site survey not started");
        return 0;
    }

    if(nwwlan_survey_data.survey_in_progress)
    {
        msg_error(0, LOG_NOTICE,
                  "WLAN site survey already in progress---please hold the line");
        return 0;
    }

    nwwlan_survey_data.survey_in_progress = true;

    if(nwwlan_survey_data.wlan->start_site_survey(survey_done))
        msg_info("WLAN site survey started");

    return 0;
}

static size_t limit_number_of_services(size_t n)
{
    static const size_t MAX_NUMBER_OF_SERVICES = 10;

    if(n > MAX_NUMBER_OF_SERVICES)
    {
        msg_info("Found %zu WLAN services, limiting to %zu entries",
                 n, MAX_NUMBER_OF_SERVICES);
        n = MAX_NUMBER_OF_SERVICES;
    }

    return n;
}

static bool
fill_buffer_with_security_entries(std::ostream &os,
                                  struct ConnmanServiceSecurityIterator *const iter,
                                  const size_t sec_count)
{
    if(iter == NULL)
        return false;

    os << "<security_list count=\"" << sec_count << "\">";

    for(size_t i = 0; i < sec_count; ++i)
    {
        log_assert(iter != NULL);

        os << "<security index=\"" << i << "\">"
           << connman_security_iterator_get_security(iter) << "</security>";

        connman_security_iterator_next(iter);
    }

    os << "</security_list>";

    return true;
}

static inline enum WifiServiceType is_wifi_service(struct ConnmanServiceIterator *const iter)
{
    if(strcmp(connman_service_iterator_get_technology_type(iter), "wifi") != 0)
        return WIFI_SERVICE_TYPE_NONE;

    return (connman_service_iterator_get_ssid(iter) != NULL
            ? WIFI_SERVICE_TYPE_WLAN_WITH_SSID
            : WIFI_SERVICE_TYPE_HIDDEN);
}

static size_t count_number_of_wifi_services(struct ConnmanServiceIterator *const iter)
{
    if(iter == NULL)
        return  0;

    size_t count = 0;

    do
    {
        switch(is_wifi_service(iter))
        {
          case WIFI_SERVICE_TYPE_NONE:
            break;

          case WIFI_SERVICE_TYPE_WLAN_WITH_SSID:
            ++count;
            break;

          case WIFI_SERVICE_TYPE_HIDDEN:
            break;
        }
    }
    while(connman_service_iterator_next(iter));

    connman_service_iterator_rewind(iter);

    return limit_number_of_services(count);
}

static bool fill_buffer_with_single_service(std::ostream &os,
                                            struct ConnmanServiceIterator *const iter,
                                            const size_t idx)
{
    os << "<bss index=\"" << idx << "\">"
       << "<ssid>" << connman_service_iterator_get_ssid(iter) << "</ssid>"
       << "<quality>" << connman_service_iterator_get_strength(iter) << "</quality>";

    size_t number_of_sec;
    struct ConnmanServiceSecurityIterator *const security =
        connman_service_iterator_get_security_iterator(iter,
                                                       &number_of_sec);

    const bool retval = fill_buffer_with_security_entries(os, security, number_of_sec);

    if(retval)
        os << "</bss>";

    connman_security_iterator_free(security);

    return retval;
}

static bool fill_buffer_with_services(std::vector<uint8_t> &buffer)
{
    bool retval = true;
    struct ConnmanServiceIterator *const service = connman_service_iterator_get();
    const size_t number_of_wifi_services = count_number_of_wifi_services(service);

    buffer.clear();

    if(number_of_wifi_services == 0)
    {
        static const std::string empty("<bss_list count=\"0\"/>");
        connman_service_iterator_free(service);
        std::copy(empty.begin(), empty.end(), std::back_inserter(buffer));
        return retval;
    }

    size_t idx = 0;
    std::ostringstream os;
    os << "<bss_list count=\"" << number_of_wifi_services << "\">";

    do
    {
        log_assert(service != NULL);

        switch(is_wifi_service(service))
        {
          case WIFI_SERVICE_TYPE_NONE:
            break;

          case WIFI_SERVICE_TYPE_WLAN_WITH_SSID:
            retval = fill_buffer_with_single_service(os, service, idx++);
            if(!retval)
            {
                connman_service_iterator_free(service);
                return retval;
            }

            break;

          case WIFI_SERVICE_TYPE_HIDDEN:
            break;
        }
    }
    while(connman_service_iterator_next(service));

    connman_service_iterator_free(service);

    os << "</bss_list>";

    const auto &str(os.str());
    std::copy(str.begin(), str.end(), std::back_inserter(buffer));

    return retval;
}

static const char *survey_result_to_string(Connman::SiteSurveyResult result)
{
    const auto idx = size_t(result);

    if(idx >= 0 && idx <= size_t(Connman::SiteSurveyResult::LAST_RESULT))
    {
        static const char *strings[size_t(Connman::SiteSurveyResult::LAST_RESULT) + 1] =
        {
            "ok",
            "network",
            "internal",
            "oom",
            "hardware",
        };

        return strings[idx];
    }
    else
        return "bug";
}

bool Regs::WLANSurvey::DCP::read_105_wlan_site_survey_results(std::vector<uint8_t> &buffer)
{
    log_assert(buffer.empty());

    std::lock_guard<std::recursive_mutex> lock(nwwlan_survey_data.lock);

    switch(nwwlan_survey_data.last_result)
    {
      case Connman::SiteSurveyResult::OK:
        if(fill_buffer_with_services(buffer))
            break;

        nwwlan_survey_data.last_result = Connman::SiteSurveyResult::OUT_OF_MEMORY;

        /* fall-through */

      case Connman::SiteSurveyResult::CONNMAN_ERROR:
      case Connman::SiteSurveyResult::DBUS_ERROR:
      case Connman::SiteSurveyResult::OUT_OF_MEMORY:
      case Connman::SiteSurveyResult::NO_HARDWARE:
        {
            std::ostringstream os;
            os << "<bss_list count=\"-1\" error=\""
               << survey_result_to_string(nwwlan_survey_data.last_result) << "\"/>";
            const auto &str(os.str());
            buffer.clear();
            std::copy(str.begin(), str.end(), std::back_inserter(buffer));
            buffer.push_back('\0');
        }

        break;
    }

    return true;
}
