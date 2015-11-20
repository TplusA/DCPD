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

#ifndef DCPREGS_WLANSURVEY_H
#define DCPREGS_WLANSURVEY_H

#include <inttypes.h>

/*!
 * \addtogroup registers
 */
/*!@{*/

#ifdef __cplusplus
extern "C" {
#endif

void dcpregs_wlansurvey_init(void);
void dcpregs_wlansurvey_deinit(void);

int dcpregs_write_104_start_wlan_site_survey(const uint8_t *data, size_t length);
ssize_t dcpregs_read_105_wlan_site_survey_results(uint8_t *response, size_t length);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !DCPREGS_WLANSURVEY_H */
