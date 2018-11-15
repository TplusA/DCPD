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

#ifndef CONNMAN_SCAN_HH
#define CONNMAN_SCAN_HH

namespace Connman
{

/*!
 * WLAN site survey result.
 *
 * \attention
 *     This enumeration must match the array in #survey_result_to_string().
 */
enum class SiteSurveyResult
{
    OK,
    CONNMAN_ERROR,
    DBUS_ERROR,
    OUT_OF_MEMORY,
    NO_HARDWARE,

    LAST_RESULT = NO_HARDWARE,
};

using SiteSurveyDoneFn = void (*)(SiteSurveyResult result);

void wlan_power_on();

/*!
 * Start WLAN site survey, call callback when done.
 *
 * The callback function may be called directly by this function, or it may be
 * called within D-Bus context. Thus, the callback should be implemented in a
 * thread-safe way.
 */
bool start_wlan_site_survey(SiteSurveyDoneFn callback);

}

#endif /* !CONNMAN_SCAN_HH */
