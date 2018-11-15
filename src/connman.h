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

#ifndef CONNMAN_H
#define CONNMAN_H

#include <stdbool.h>
#include <unistd.h>

/*!
 * WLAN site survey result.
 *
 * \attention
 *     This enumeration must match the array in #survey_result_to_string().
 */
enum ConnmanSiteScanResult
{
    CONNMAN_SITE_SCAN_OK,
    CONNMAN_SITE_SCAN_CONNMAN_ERROR,
    CONNMAN_SITE_SCAN_DBUS_ERROR,
    CONNMAN_SITE_SCAN_OUT_OF_MEMORY,
    CONNMAN_SITE_SCAN_NO_HARDWARE,

    CONNMAN_SITE_SCAN_RESULT_LAST = CONNMAN_SITE_SCAN_NO_HARDWARE,
};

typedef void (*ConnmanSurveyDoneFn)(enum ConnmanSiteScanResult result);

#ifdef __cplusplus
extern "C" {
#endif

void connman_wlan_power_on(void);

/*!
 * Start WLAN site survey, call callback when done.
 *
 * The callback function may be called directly by this function, or it may be
 * called within D-Bus context. Thus, the callback should be implemented in a
 * thread-safe way.
 */
bool connman_start_wlan_site_survey(ConnmanSurveyDoneFn callback);

#ifdef __cplusplus
}
#endif

#endif /* !CONNMAN_H */
