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

#include <sstream>

template <typename ... Args>
static void send_command(Applink::AppConnections &conn,
                         const char *variable_name,
                         std::vector<const char *> &&params)
{
    std::ostringstream os;
    Applink::make_answer_for_name(os, variable_name, std::move(params));
    conn.send_to_all_peers(std::move(os.str()));
}

void Applink::send_airable_service_logged_in(Applink::AppConnections &conn,
                                             const char *service_id,
                                             const char *username)
{
    send_command(conn, "SERVICE_LOGGED_IN", { service_id, username });
}

void Applink::send_airable_service_logged_out(Applink::AppConnections &conn,
                                              const char *service_id,
                                              const char *logout_url)
{
    send_command(conn, "SERVICE_LOGGED_OUT", { service_id, logout_url });
}
