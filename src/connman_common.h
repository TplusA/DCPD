/*
 * Copyright (C) 2015, 2017  T+A elektroakustik GmbH & Co. KG
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

#ifndef CONNMAN_COMMON_H
#define CONNMAN_COMMON_H

#include <stdbool.h>

#include "connman_dbus.h"

enum ConnmanCommonConnectServiceCallbackResult
{
    CONNMAN_SERVICE_CONNECT_CONNECTED,
    CONNMAN_SERVICE_CONNECT_FAILURE,
    CONNMAN_SERVICE_CONNECT_DISCARDED,
};

typedef void (*ConnmanCommonConnectServiceCallback)(const char *service_name,
                                                    enum ConnmanCommonConnectServiceCallbackResult result,
                                                    void *user_data);

#ifdef __cplusplus
extern "C" {
#endif

GVariant *connman_common_query_services(tdbusconnmanManager *iface);
bool connman_common_set_service_property(const char *object_path,
                                         const char *property_name,
                                         GVariant *value);
bool connman_common_connect_service_by_object_path(const char *object_path,
                                                   ConnmanCommonConnectServiceCallback done_fn,
                                                   void *user_data);
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
