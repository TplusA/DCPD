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

#ifndef SHUTDOWN_GUARD_H
#define SHUTDOWN_GUARD_H

#include <stdbool.h>

struct ShutdownGuard;

#ifdef __cplusplus
extern "C" {
#endif

struct ShutdownGuard *shutdown_guard_alloc(const char *name);
void shutdown_guard_free(struct ShutdownGuard **sdg);
void shutdown_guard_lock(struct ShutdownGuard *sdg);
void shutdown_guard_unlock(struct ShutdownGuard *sdg);
bool shutdown_guard_down(struct ShutdownGuard *sdg);

/*!
 * Check if the system is shutting down.
 *
 * \attention
 *     Function may only be called with a locked \p sdg.
 */
bool shutdown_guard_is_shutting_down_unlocked(struct ShutdownGuard *sdg);

#ifdef __cplusplus
}
#endif

#endif /* !SHUTDOWN_GUARD_H */
