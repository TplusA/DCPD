/*
 * Copyright (C) 2015, 2016, 2018, 2019, 2022  T+A elektroakustik GmbH & Co. KG
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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "shutdown_guard.h"
#include "messages.h"

#include <stdlib.h>

#include <glib.h>

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
    msg_log_assert(sdg != NULL);

    if(*sdg == NULL)
    {
        MSG_BUG("Passed NULL to %s()", __func__);
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
    msg_log_assert(sdg != NULL);
    g_mutex_lock(&sdg->lock);
}

void shutdown_guard_unlock(struct ShutdownGuard *sdg)
{
    msg_log_assert(sdg != NULL);
    g_mutex_unlock(&sdg->lock);
}

bool shutdown_guard_down(struct ShutdownGuard *sdg)
{
    msg_log_assert(sdg != NULL);

    msg_vinfo(MESSAGE_LEVEL_DIAG, "Shutdown guard \"%s\" down", sdg->name);

    g_mutex_lock(&sdg->lock);
    const bool ret = !sdg->is_shutting_down;
    sdg->is_shutting_down = true;
    g_mutex_unlock(&sdg->lock);

    return ret;
}

bool shutdown_guard_is_shutting_down_unlocked(const struct ShutdownGuard *sdg)
{
    msg_log_assert(sdg != NULL);
    return sdg->is_shutting_down;
}
