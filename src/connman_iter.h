/*
 * Copyright (C) 2018  T+A elektroakustik GmbH & Co. KG
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
