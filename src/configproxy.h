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

#ifndef CONFIGPROXY_H
#define CONFIGPROXY_H

#include <stdbool.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Opaque structure for variant types.
 *
 * This is just another name for GVariant from GLib. It is used to avoid
 * pulling in GLib headers.
 */
struct ConfigProxyVariant;

void configproxy_init(void);
void configproxy_deinit(void);

bool configproxy_register_configuration_owner(const char *id,
                                              const char *dbus_dest,
                                              const char *dbus_path);
bool configproxy_register_local_configuration_owner(const char *id, char **keys);

typedef bool (*PatchUint32Fn)(uint32_t *value);

bool configproxy_set_uint32(const char *origin, const char *key, uint32_t value);
bool configproxy_set_uint32_from_string(const char *origin, const char *key,
                                        const char *string, size_t len,
                                        PatchUint32Fn patcher);
bool configproxy_set_string(const char *origin, const char *key, const char *value);
bool configproxy_set_value(const char *origin, const char *key, struct ConfigProxyVariant *value);

struct ConfigProxyVariant *configproxy_get_value(const char *key);
ssize_t configproxy_get_value_as_string(const char *key,
                                        char *buffer, size_t buffer_size,
                                        PatchUint32Fn patcher);

#ifdef __cplusplus
}
#endif

#endif /* !CONFIGPROXY_H */
