/*
 * Copyright (C) 2015, 2017, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef CONNMAN_COMMON_H
#define CONNMAN_COMMON_H

#include "connman_dbus.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

GVariant *connman_common_query_services(tdbusconnmanManager *iface);
bool connman_common_set_service_property(const char *object_path,
                                         const char *property_name,
                                         GVariant *value);
void connman_common_disconnect_service_by_object_path(const char *object_path);
void connman_common_remove_service_by_object_path(const char *object_path);
void connman_common_init_dict_from_temp_gvariant(GVariant *temp,
                                                 GVariantDict *dict);
void connman_common_init_subdict(GVariant *tuple, GVariantDict *subdict,
                                 const char *subdict_name);

#ifdef __cplusplus
}
#endif

#endif /* !CONNMAN_COMMON_H */
