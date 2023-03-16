/*
 * Copyright (C) 2015--2019, 2023  T+A elektroakustik GmbH & Co. KG
 *
 * This file is part of DCPD.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 */

#ifndef CONNMAN_SCAN_HH
#define CONNMAN_SCAN_HH

namespace Connman
{

class TechnologyRegistry;

/*!
 * WLAN site survey result.
 */
enum class SiteSurveyResult
{
    OK,
    CONNMAN_ERROR,
    DBUS_ERROR,
    OUT_OF_MEMORY,
    NO_HARDWARE,

    LAST_VALUE = NO_HARDWARE,
};

using SiteSurveyDoneFn = void (*)(SiteSurveyResult result);

class WLANTools
{
  private:
    TechnologyRegistry &tech_reg_;

  public:
    WLANTools(const WLANTools &) = delete;
    WLANTools(WLANTools &&) = default;
    WLANTools &operator=(const WLANTools &) = delete;
    WLANTools &operator=(WLANTools &&) = default;

    explicit WLANTools(Connman::TechnologyRegistry &reg):
        tech_reg_(reg)
    {}

    bool power_on();

    /*!
     * Start WLAN site survey, call callback when done.
     *
     * The callback function may be called directly by this function, or it may
     * be called within D-Bus context. Thus, the callback should be implemented
     * in a thread-safe way.
     */
    bool start_site_survey(SiteSurveyDoneFn callback);
};

}

#endif /* !CONNMAN_SCAN_HH */
