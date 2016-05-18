/*
 * Copyright (C) 2016  T+A elektroakustik GmbH & Co. KG
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

#ifndef SMARTPHONE_APP_SEND_H
#define SMARTPHONE_APP_SEND_H

#include "smartphone_app.h"

#ifdef __cplusplus
extern "C" {
#endif

void appconn_send_airable_service_logged_in(struct smartphone_app_connection_data *conn,
                                            const char *service_id,
                                            const char *username);
void appconn_send_airable_service_logged_out(struct smartphone_app_connection_data *conn,
                                             const char *service_id,
                                             const char *logout_url);

#ifdef __cplusplus
}
#endif

#endif /* !SMARTPHONE_APP_SEND_H */
