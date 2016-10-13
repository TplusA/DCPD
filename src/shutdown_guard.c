/*
 * Copyright (C) 2015, 2016  T+A elektroakustik GmbH & Co. KG
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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>

#include <glib.h>

#include "shutdown_guard.h"
#include "messages.h"

struct ShutdownGuard
{
    GMutex lock;
    bool is_shutting_down;
    const char *name;
};

struct ShutdownGuard *shutdown_guard_alloc(const char *name)
{
    struct ShutdownGuard *sdg = malloc(sizeof(struct ShutdownGuard));

    if(sdg == NULL)
    {
        msg_out_of_memory("shutdown guard");
        return NULL;
    }

    g_mutex_init(&sdg->lock);
    sdg->is_shutting_down = false;
    sdg->name = name;

    msg_vinfo(MESSAGE_LEVEL_DIAG, "Allocated shutdown guard \"%s\"", sdg->name);

    return sdg;
}

void shutdown_guard_free(struct ShutdownGuard **sdg)
{
    log_assert(sdg != NULL);

    if(*sdg == NULL)
    {
        BUG("Passed NULL to %s()", __func__);
        return;
    }

    if(!g_mutex_trylock(&(*sdg)->lock))
    {
        msg_error(0, LOG_CRIT,
                  "BUG: Tried to free locked shutdown guard \"%s\"",
                  (*sdg)->name);
        return;
    }
    else
        g_mutex_unlock(&(*sdg)->lock);

    g_mutex_clear(&(*sdg)->lock);

    free(*sdg);
    *sdg = NULL;
}

void shutdown_guard_lock(struct ShutdownGuard *sdg)
{
    log_assert(sdg != NULL);
    g_mutex_lock(&sdg->lock);
}

void shutdown_guard_unlock(struct ShutdownGuard *sdg)
{
    log_assert(sdg != NULL);
    g_mutex_unlock(&sdg->lock);
}

bool shutdown_guard_down(struct ShutdownGuard *sdg)
{
    log_assert(sdg != NULL);

    msg_vinfo(MESSAGE_LEVEL_DIAG, "Shutdown guard \"%s\" down", sdg->name);

    g_mutex_lock(&sdg->lock);
    const bool ret = !sdg->is_shutting_down;
    sdg->is_shutting_down = true;
    g_mutex_unlock(&sdg->lock);

    return ret;
}

bool shutdown_guard_is_shutting_down_unlocked(struct ShutdownGuard *sdg)
{
    log_assert(sdg != NULL);
    return sdg->is_shutting_down;
}
