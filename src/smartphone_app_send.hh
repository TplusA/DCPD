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

#ifndef SMARTPHONE_APP_SEND_HH
#define SMARTPHONE_APP_SEND_HH

#include "smartphone_app.hh"

#ifdef __cplusplus
extern "C" {
#endif

namespace Applink
{

void send_airable_service_logged_in(AppConnections &conn,
                                    const char *service_id, const char *username);
void send_airable_service_logged_out(AppConnections &conn,
                                     const char *service_id, const char *logout_url);

}

#ifdef __cplusplus
}
#endif

#endif /* !SMARTPHONE_APP_SEND_HH */
