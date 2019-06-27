/*
 * Copyright (C) 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef CONNMAN_ITER_H
#define CONNMAN_ITER_H

#include <stdbool.h>
#include <unistd.h>

struct ConnmanServiceIterator;
struct ConnmanServiceSecurityIterator;

#ifdef __cplusplus
extern "C" {
#endif

struct ConnmanServiceIterator *connman_service_iterator_get(void);
void connman_service_iterator_rewind(struct ConnmanServiceIterator *iter);
bool connman_service_iterator_next(struct ConnmanServiceIterator *iter);
void connman_service_iterator_free(struct ConnmanServiceIterator *iter);
const char *connman_service_iterator_get_service_name(struct ConnmanServiceIterator *iter);
const char *connman_service_iterator_get_technology_type(struct ConnmanServiceIterator *iter);
const char *connman_service_iterator_get_ssid(struct ConnmanServiceIterator *iter);
int connman_service_iterator_get_strength(struct ConnmanServiceIterator *iter);
struct ConnmanServiceSecurityIterator *
connman_service_iterator_get_security_iterator(struct ConnmanServiceIterator *iter,
                                               size_t *count);
bool connman_security_iterator_next(struct ConnmanServiceSecurityIterator *iter);
void connman_security_iterator_free(struct ConnmanServiceSecurityIterator *iter);
const char *connman_security_iterator_get_security(struct ConnmanServiceSecurityIterator *iter);

#ifdef __cplusplus
}
#endif

#endif /* !CONNMAN_ITER_H */
