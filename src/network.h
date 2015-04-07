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

#ifndef NETWORK_H
#define NETWORK_H

#include <stdbool.h>

struct network_socket_pair
{
    int server_fd;
    int peer_fd;
};

#ifdef __cplusplus
extern "C" {
#endif

int network_create_socket(void);
int network_accept_peer_connection(int server_fd);
bool network_have_data(int peer_fd);
void network_close(int *fd);

#ifdef __cplusplus
}
#endif

#endif /* !NETWORK_H */
