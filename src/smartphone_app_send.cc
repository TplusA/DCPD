/*
 * Copyright (C) 2016, 2018  T+A elektroakustik GmbH & Co. KG
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

#include "smartphone_app_send.hh"

#define SEND_FN_TEMPLATE(VAR, ...) \
    do \
    { \
        struct ApplinkOutputCommand *const cmd = applink_output_command_alloc_from_pool(); \
        if(cmd == NULL) \
            break; \
        \
        const ssize_t len = \
            applink_make_answer_for_name(cmd->buffer, sizeof(cmd->buffer), \
                                         VAR, __VA_ARGS__); \
        \
        if(len <= 0) \
            break; \
        \
        cmd->buffer_used = len; \
        \
        g_mutex_lock(&conn->out_queue.lock) ;\
        applink_output_command_append_to_queue(&conn->out_queue.queue, cmd) ; \
        conn->out_queue.notification_fn(); \
        g_mutex_unlock(&conn->out_queue.lock) ;\
    } \
    while(0)

void appconn_send_airable_service_logged_in(struct smartphone_app_connection_data *conn,
                                            const char *service_id,
                                            const char *username)
{
    SEND_FN_TEMPLATE("SERVICE_LOGGED_IN", service_id, username);
}

void appconn_send_airable_service_logged_out(struct smartphone_app_connection_data *conn,
                                             const char *service_id,
                                             const char *logout_url)
{
    SEND_FN_TEMPLATE("SERVICE_LOGGED_OUT", service_id, logout_url);
}
