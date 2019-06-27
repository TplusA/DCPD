/*
 * Copyright (C) 2017, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef CONNMAN_AGENT_H
#define CONNMAN_AGENT_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool connman_agent_set_wps_mode(bool is_wps_mode);

#ifdef __cplusplus
}
#endif

#endif /* !CONNMAN_AGENT_H */
