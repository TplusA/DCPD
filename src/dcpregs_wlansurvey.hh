/*
 * Copyright (C) 2015, 2018  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCPREGS_WLANSURVEY_HH
#define DCPREGS_WLANSURVEY_HH

#include "dynamic_buffer.h"

namespace Connman { class WLANTools; }

/*!
 * \addtogroup registers
 */
/*!@{*/

namespace Regs
{

namespace WLANSurvey
{
void init(Connman::WLANTools *wlan);
void deinit();

namespace DCP
{
int write_104_start_wlan_site_survey(const uint8_t *data, size_t length);
bool read_105_wlan_site_survey_results(struct dynamic_buffer *buffer);
}

}

}

/*!@}*/

#endif /* !DCPREGS_WLANSURVEY_HH */
