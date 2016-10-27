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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

/* for mutex */
#include <glib.h>

#include "dcpregs_wlansurvey.h"
#include "registers_priv.h"
#include "connman.h"
#include "dynamic_buffer_util.h"
#include "messages.h"

static struct
{
    /* must be a recursive mutex because sometimes the survey-done callback is
     * called from our own context while we are holding the lock, sometimes
     * its called from another context */
    GRecMutex lock;

    bool survey_in_progress;
    enum ConnmanSiteScanResult last_result;
}
nwwlan_survey_data;

enum WifiServiceType
{
    WIFI_SERVICE_TYPE_NONE,
    WIFI_SERVICE_TYPE_WLAN_WITH_SSID,
    WIFI_SERVICE_TYPE_HIDDEN,
};

void dcpregs_wlansurvey_init(void)
{
    memset(&nwwlan_survey_data, 0, sizeof(nwwlan_survey_data));
    g_rec_mutex_init(&nwwlan_survey_data.lock);
}

void dcpregs_wlansurvey_deinit(void)
{
    g_rec_mutex_clear(&nwwlan_survey_data.lock);
}

static void survey_done(enum ConnmanSiteScanResult result)
{
    g_rec_mutex_lock(&nwwlan_survey_data.lock);

    if(!nwwlan_survey_data.survey_in_progress)
        BUG("Got WLAN survey done notification, but didn't start any");

    msg_info("WLAN site survey done, %s (%d)",
             (result == CONNMAN_SITE_SCAN_OK) ? "succeeded" : "failed",
             result);

    nwwlan_survey_data.survey_in_progress = false;
    nwwlan_survey_data.last_result = result;

    g_rec_mutex_unlock(&nwwlan_survey_data.lock);

    registers_get_data()->register_changed_notification_fn(105);
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

int dcpregs_write_104_start_wlan_site_survey(const uint8_t *data, size_t length)
{
    if(data_length_is_unexpected(length, 0))
        return -1;

    g_rec_mutex_lock(&nwwlan_survey_data.lock);

    if(nwwlan_survey_data.survey_in_progress)
        msg_error(0, LOG_NOTICE,
                  "WLAN site survey already in progress---please hold the line");
    else
    {
        nwwlan_survey_data.survey_in_progress = true;

        if(connman_start_wlan_site_survey(survey_done))
            msg_info("WLAN site survey started");
    }

    g_rec_mutex_unlock(&nwwlan_survey_data.lock);

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

#define TRY_EMIT(BUF, FAILCODE, ...) \
    do \
    { \
        if(retval && !dynamic_buffer_printf((BUF), __VA_ARGS__)) \
        { \
            retval = false; \
            FAILCODE \
        } \
    }\
    while(0)

static bool
fill_buffer_with_security_entries(struct dynamic_buffer *const buffer,
                                  struct ConnmanServiceSecurityIterator *const iter,
                                  const size_t sec_count)
{
    if(iter == NULL)
        return false;

    bool retval = true;

    TRY_EMIT(buffer, return false;,
             "<security_list count=\"%zu\">", sec_count);

    for(size_t i = 0; i < sec_count; ++i)
    {
        log_assert(iter != NULL);

        TRY_EMIT(buffer, break;,
                 "<security index=\"%zu\">%s</security>",
                 i, connman_security_iterator_get_security(iter));

        connman_security_iterator_next(iter);
    }

    TRY_EMIT(buffer, /* nothing */;, "</security_list>");

    return retval;
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

static bool fill_buffer_with_single_service(struct dynamic_buffer *const buffer,
                                            struct ConnmanServiceIterator *const iter,
                                            const size_t idx)
{
    bool retval = true;

    TRY_EMIT(buffer, return false;,
             "<bss index=\"%zu\">", idx);
    TRY_EMIT(buffer, return false;,
             "<ssid>%s</ssid>", connman_service_iterator_get_ssid(iter));
    TRY_EMIT(buffer, return false;,
             "<quality>%d</quality>", connman_service_iterator_get_strength(iter));

    size_t number_of_sec;
    struct ConnmanServiceSecurityIterator *const security =
        connman_service_iterator_get_security_iterator(iter,
                                                       &number_of_sec);

    retval = fill_buffer_with_security_entries(buffer,
                                               security, number_of_sec);
    if(retval)
        TRY_EMIT(buffer, /* nothing */;, "</bss>");

    connman_security_iterator_free(security);

    return retval;
}

static bool fill_buffer_with_services(struct dynamic_buffer *const buffer)
{
    bool retval = true;

    dynamic_buffer_clear(buffer);

    struct ConnmanServiceIterator *const service = connman_service_iterator_get();
    const size_t number_of_wifi_services = count_number_of_wifi_services(service);

    if(number_of_wifi_services == 0)
    {
        connman_service_iterator_free(service);
        TRY_EMIT(buffer, /* nothing */, "<bss_list count=\"0\"/>");
        return retval;
    }

    TRY_EMIT(buffer, goto exit_free_service_iter;,
             "<bss_list count=\"%zu\">", number_of_wifi_services);

    size_t idx = 0;

    do
    {
        log_assert(service != NULL);

        switch(is_wifi_service(service))
        {
          case WIFI_SERVICE_TYPE_NONE:
            break;

          case WIFI_SERVICE_TYPE_WLAN_WITH_SSID:
            retval = fill_buffer_with_single_service(buffer, service, idx++);
            if(!retval)
                goto exit_free_service_iter;

            break;

          case WIFI_SERVICE_TYPE_HIDDEN:
            break;
        }
    }
    while(connman_service_iterator_next(service));

    TRY_EMIT(buffer, /* nothing */, "</bss_list>");

exit_free_service_iter:
    connman_service_iterator_free(service);

    return retval;
}

static const char *survey_result_to_string(enum ConnmanSiteScanResult result)
{
    if(result >= 0 && result <= CONNMAN_SITE_SCAN_RESULT_LAST)
    {
        static const char *strings[CONNMAN_SITE_SCAN_RESULT_LAST + 1] =
        {
            "ok",
            "network",
            "internal",
            "oom",
            "hardware",
        };

        return strings[result];
    }
    else
        return "bug";
}

bool dcpregs_read_105_wlan_site_survey_results(struct dynamic_buffer *buffer)
{
    log_assert(dynamic_buffer_is_empty(buffer));

    g_rec_mutex_lock(&nwwlan_survey_data.lock);

    bool retval = false;

    switch(nwwlan_survey_data.last_result)
    {
      case CONNMAN_SITE_SCAN_OK:
        if(fill_buffer_with_services(buffer))
        {
            retval = true;
            break;
        }

        dynamic_buffer_clear(buffer);
        nwwlan_survey_data.last_result = CONNMAN_SITE_SCAN_OUT_OF_MEMORY;

        /* fall-through */

      case CONNMAN_SITE_SCAN_CONNMAN_ERROR:
      case CONNMAN_SITE_SCAN_DBUS_ERROR:
      case CONNMAN_SITE_SCAN_OUT_OF_MEMORY:
      case CONNMAN_SITE_SCAN_NO_HARDWARE:
        retval = true;

        TRY_EMIT(buffer, /* nothing */,
                 "<bss_list count=\"-1\" error=\"%s\"/>",
                 survey_result_to_string(nwwlan_survey_data.last_result));

        if(buffer->pos > 0)
            retval = true;

        break;
    }

    g_rec_mutex_unlock(&nwwlan_survey_data.lock);

    return retval;
}
