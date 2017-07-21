/*
 * Copyright (C) 2017  T+A elektroakustik GmbH & Co. KG
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

#ifndef CONFIGURATION_DCPD_H
#define CONFIGURATION_DCPD_H

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

bool configuration_set_key(const char *origin, const char *key, GVariant *value);
GVariant *configuration_get_key(const char *key);

#ifdef __cplusplus
}
#endif

#endif /* !CONFIGURATION_DCPD_H */
