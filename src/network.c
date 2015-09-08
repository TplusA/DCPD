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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "network.h"
#include "messages.h"

int network_create_socket(uint16_t port, int backlog)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if(fd < 0)
    {
        msg_error(errno, LOG_CRIT, "Failed creating socket");
        return -1;
    }

    struct sockaddr_in addr =
    {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr =
        {
            .s_addr = INADDR_ANY,
        },
    };

    if(bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        msg_error(errno, LOG_CRIT,
                  "Failed binding socket to address %u", addr.sin_port);
        network_close(&fd);
        return -1;
    }

    if(listen(fd, backlog) < 0)
    {
        msg_error(errno, LOG_CRIT, "Failed to listen on socket fd %d", fd);
        network_close(&fd);
        return -1;
    }

    return fd;
}

int network_accept_peer_connection(int server_fd)
{
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int peer_fd = accept(server_fd, (struct sockaddr *)&addr, &addrlen);

    if(peer_fd < 0)
    {
        msg_error(errno, LOG_ERR,
                  "Failed to accept peer connection on fd %d", server_fd);
        return -1;
    }

    char addr_string[INET_ADDRSTRLEN];

    if(inet_ntop(AF_INET, &addr.sin_addr,
                 addr_string, sizeof(addr_string)) == NULL)
    {
        msg_error(errno, LOG_ERR, "Failed to determine peer IP address");
        network_close(&peer_fd);
        return -1;
    }

    msg_info("Accepted connection from %s", addr_string);

    return peer_fd;
}

bool network_have_data(int peer_fd)
{
    uint8_t dummy;
    ssize_t result = recv(peer_fd, &dummy, sizeof(dummy), MSG_PEEK);

    if(result < 0)
        msg_error(errno, LOG_ERR,
                  "Failed to peek network receive buffer on fd %d", peer_fd);

    return result > 0;
}

void network_close(int *fd)
{
    os_file_close(*fd);
    *fd = -1;
}
