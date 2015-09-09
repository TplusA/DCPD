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

#include <string.h>
#include <errno.h>
#include <sys/socket.h>

#include "dcpregs_tcptunnel.h"
#include "registers_priv.h"
#include "network.h"
#include "network_dispatcher.h"
#include "messages.h"

struct tcp_client;

struct tcp_client_link
{
    uint8_t id;
    struct tcp_client *peer;
};

struct tcp_tunnel
{
    uint16_t port;
    int server_fd;

    uint8_t next_peer_id;
    struct tcp_client_link peer_links[4];
};

struct tcp_client
{
    struct tcp_tunnel *tunnel;
    uint8_t idx;
    int fd;
};

static struct
{
    struct tcp_client *peer_with_data;
}
register_status;

static inline uint8_t get_peer_id(const struct tcp_client *peer)
{
    return peer->tunnel->peer_links[peer->idx].id;
}

static bool queue_read_from_peer_event(struct tcp_client *peer)
{
    if(register_status.peer_with_data != NULL)
    {
        /* read function has not yet processed the previous peer request */
        return false;
    }

    register_status.peer_with_data = peer;
    registers_get_data()->register_changed_notification_fn(120);

    return true;
}

static int handle_peer_data(int fd, void *user_data)
{
    struct tcp_client *peer = user_data;

    if(queue_read_from_peer_event(peer))
        msg_info("Queued push-to-slave for data from peer %u on port %u",
                 get_peer_id(peer), peer->tunnel->port);

    return 0;
}

static void handle_peer_died(int fd, void *user_data)
{
    struct tcp_client *peer = user_data;

    if(queue_read_from_peer_event(peer))
        msg_info("Peer %u on port %u died, closing connection",
                 get_peer_id(peer), peer->tunnel->port);
}

static inline uint8_t increment_peer_id(uint8_t id)
{
    if(++id == 0)
        id = 1;

    return id;
}

static uint8_t find_client_link_index_by_id(const struct tcp_tunnel *tunnel,
                                            uint8_t id)
{
    for(size_t i = 0;
        i < sizeof(tunnel->peer_links) / sizeof(tunnel->peer_links[0]);
        ++i)
    {
        if(tunnel->peer_links[i].id == id)
            return (uint8_t)i;
    }

    return UINT8_MAX;
}

static struct tcp_client *allocate_peer(struct tcp_tunnel *tunnel)
{
    log_assert(tunnel != NULL);

    const uint8_t free_id_slot = find_client_link_index_by_id(tunnel, 0);

    if(free_id_slot == UINT8_MAX)
    {
        msg_error(0, LOG_NOTICE,
                  "Too many client connections, rejecting new connection");
        return NULL;
    }

    while(find_client_link_index_by_id(tunnel,
                                       tunnel->next_peer_id) != UINT8_MAX)
        tunnel->next_peer_id = increment_peer_id(tunnel->next_peer_id);

    struct tcp_client *peer = malloc(sizeof(*peer));

    if(peer == NULL)
    {
        msg_out_of_memory("peer connection data");
        return NULL;
    }

    peer->tunnel = tunnel;
    peer->idx = free_id_slot;
    peer->fd = -1;

    log_assert(tunnel->peer_links[peer->idx].peer == NULL);

    tunnel->peer_links[peer->idx].id = tunnel->next_peer_id;
    tunnel->peer_links[peer->idx].peer = peer;
    tunnel->next_peer_id = increment_peer_id(tunnel->next_peer_id);

    return peer;
}

static void close_and_free_peer(struct tcp_client *peer, bool simple_close)
{
    log_assert(peer != NULL);
    log_assert(peer->tunnel != NULL);
    log_assert(peer->fd >= 0);

    if(simple_close)
        network_close(&peer->fd);
    else
    {
        nwdispatch_unregister_and_close(peer->fd);
        peer->fd = -1;
    }

    peer->tunnel->peer_links[peer->idx].id = 0;
    peer->tunnel->peer_links[peer->idx].peer = NULL;
    peer->tunnel = NULL;

    free(peer);
}

static const struct nwdispatch_iface dispatch_peer_connection =
{
    .handle_incoming_data = handle_peer_data,
    .connection_died = handle_peer_died,
};

static int handle_new_peer(int fd, void *user_data)
{
    struct tcp_tunnel *tunnel = user_data;

    log_assert(fd == tunnel->server_fd);

    msg_info("Connection attempt on port %u", tunnel->port);

    int peer_fd = network_accept_peer_connection(tunnel->server_fd);
    if(peer_fd < 0)
        return -1;

    struct tcp_client *peer = allocate_peer(tunnel);

    if(peer == NULL)
    {
        network_close(&peer_fd);
        return -1;
    }

    peer->fd = peer_fd;

    if(nwdispatch_register(peer_fd, &dispatch_peer_connection, peer) < 0)
    {
        close_and_free_peer(peer, true);
        return -1;
    }

    msg_info("Accepted connection on tunnel on port %u, fd %d",
             tunnel->port, peer->fd);

    return 0;
}

static void handle_server_died(int fd, void *user_data)
{
    struct tcp_tunnel *tunnel = user_data;

    BUG("Server connection on port %u died, but this event is not handled yet",
        tunnel->port);
}

static const struct nwdispatch_iface dispatch_server_connection =
{
    .handle_incoming_data = handle_new_peer,
    .connection_died = handle_server_died,
};

static struct tcp_tunnel all_tunnels[NWDISPATCH_MAX_CONNECTIONS - 1];

static struct tcp_tunnel *find_tunnel(uint16_t port)
{
    log_assert(port != 0);

    for(size_t i = 0; i < sizeof(all_tunnels) / sizeof(all_tunnels[0]); ++i)
    {
        if(all_tunnels[i].port == port)
            return &all_tunnels[i];
    }

    return NULL;
}

static struct tcp_tunnel *allocate_tunnel(uint16_t port)
{
    log_assert(port != 0);

    for(size_t i = 0; i < sizeof(all_tunnels) / sizeof(all_tunnels[0]); ++i)
    {
        if(all_tunnels[i].port == 0)
        {
            struct tcp_tunnel *tunnel = &all_tunnels[i];

            tunnel->port = port;
            tunnel->server_fd = -1;
            tunnel->next_peer_id = 1;
            memset(tunnel->peer_links, 0, sizeof(tunnel->peer_links));

            return tunnel;
        }
    }

    return NULL;
}

static int tunnel_error(const char *what, uint16_t port, const char *why)
{
    msg_error(EINVAL, LOG_ERR,
              "%s TCP tunnel on port %u failed: %s", what, port, why);
    return -1;
}

static void do_close_and_free_tunnel(struct tcp_tunnel *tunnel,
                                     bool simple_close)
{
    log_assert(tunnel->port > 0);
    log_assert(tunnel->server_fd >= 0);

    for(size_t i = 0;
        i < sizeof(tunnel->peer_links) / sizeof(tunnel->peer_links[0]);
        ++i)
    {
        if(tunnel->peer_links[i].id != 0)
        {
            log_assert(tunnel->peer_links[i].peer != NULL);
            close_and_free_peer(tunnel->peer_links[i].peer, false);
        }

        log_assert(tunnel->peer_links[i].id == 0);
        log_assert(tunnel->peer_links[i].peer == NULL);
    }

    if(simple_close)
        network_close(&tunnel->server_fd);
    else
    {
        nwdispatch_unregister_and_close(tunnel->server_fd);
        tunnel->server_fd = -1;
    }

    tunnel->port = 0;
}

static int close_tunnel(uint16_t port)
{
    struct tcp_tunnel *tunnel = find_tunnel(port);

    if(tunnel == NULL)
        return tunnel_error("Close", port, "no active tunnel");

    do_close_and_free_tunnel(tunnel, false);

    msg_info("Closed TCP tunnel on port %u", port);

    return 0;
}

static int open_tunnel(uint16_t port)
{
    static const char what_error[] = "Open";

    if(find_tunnel(port) != NULL)
        return tunnel_error(what_error, port, "already open");

    struct tcp_tunnel *tunnel = allocate_tunnel(port);
    if(tunnel == NULL)
        return tunnel_error(what_error, port,
                            "maximum number of tunnels exceeded");

    tunnel->server_fd = network_create_socket(tunnel->port, SOMAXCONN);
    if(tunnel->server_fd < 0)
    {
        tunnel->port = 0;
        return tunnel_error(what_error, port, "socket error");
    }

    if(nwdispatch_register(tunnel->server_fd,
                           &dispatch_server_connection, tunnel) < 0)
    {
        do_close_and_free_tunnel(tunnel, true);
        return tunnel_error(what_error, port, "internal error");
    }

    msg_info("Opened TCP tunnel on port %u, fd %d", port, tunnel->server_fd);

    return 0;
}

int dcpregs_write_119_tcp_tunnel_control(const uint8_t *data, size_t length)
{
    msg_info("write 119 handler %p %zu", data, length);

    if(length < 2 || length > 3)
    {
        msg_error(EINVAL, LOG_ERR, "Unexpected command length");
        return -1;
    }

    const uint16_t requested_port = data[0] | (data[1] << 8);

    if(requested_port == 0)
        return tunnel_error("Configure", 0, "port 0 is invalid");

    uint8_t requested_state;

    if(length == 2)
        requested_state = 0;
    else
        requested_state = data[2];

    if(requested_state > 1)
    {
        msg_error(EINVAL, LOG_ERR,
                  "Invalid TCP tunnel state requested, must be 0 or 1");
        return -1;
    }

    if(requested_state == 1)
        return open_tunnel(requested_port);
    else
        return close_tunnel(requested_port);
}

ssize_t dcpregs_read_120_tcp_tunnel_read(uint8_t *response, size_t length)
{
    msg_info("read 120 handler %p %zu", response, length);

    if(length < 4)
    {
        msg_error(EINVAL, LOG_ERR,
                  "Read buffer too small, cannot read anything from peer");
        return -1;
    }

    if(register_status.peer_with_data == NULL)
    {
        msg_info("No active peer, cannot read data");
        response[0] = response[1] = response[2] = 0;
        register_status.peer_with_data = NULL;
        return 3;
    }

    const uint16_t port = register_status.peer_with_data->tunnel->port;

    response[0] = port & 0xff;
    response[1] = port >> 8;
    response[2] = get_peer_id(register_status.peer_with_data);

    ssize_t len;

    if(network_have_data(register_status.peer_with_data->fd))
    {
        while(1)
        {
            len = os_read(register_status.peer_with_data->fd,
                          response + 3, length - 3);
            if(len >= 0 || errno != EINTR)
                break;
        }

        if(len < 0)
        {
            msg_error(errno, LOG_ERR,
                      "Reading data from peer failed, closing connection");
            close_and_free_peer(register_status.peer_with_data, false);
            register_status.peer_with_data = NULL;
            return -1;
        }

        msg_info("Read %zd bytes of up to %zu bytes from network peer %u on port %u",
                 len, length - 3,
                 get_peer_id(register_status.peer_with_data), port);
    }
    else
        len = 0;

    if(len == 0)
    {
        msg_info("Peer %u on port %u has no more data, closing connection",
                 get_peer_id(register_status.peer_with_data), port);
        close_and_free_peer(register_status.peer_with_data, false);
    }

    register_status.peer_with_data = NULL;

    return len + 3;
}

int dcpregs_write_121_tcp_tunnel_write(const uint8_t *data, size_t length)
{
    static const char what_error[] = "Write to";

    msg_info("write 121 handler %p %zu", data, length);

    if(length < 4)
    {
        msg_error(EINVAL, LOG_ERR,
                  "Write buffer too small, cannot send anything to peer");
        return -1;
    }

    const uint16_t requested_port = data[0] | (data[1] << 8);

    if(requested_port == 0)
        return tunnel_error(what_error, 0, "port 0 is invalid");

    const uint8_t requested_peer_id = data[2];

    if(requested_peer_id == 0)
        return tunnel_error(what_error, requested_port,
                            "peer ID 0 is invalid");

    const struct tcp_tunnel *tunnel = find_tunnel(requested_port);
    if(tunnel == NULL)
        return tunnel_error(what_error, requested_port, "no active tunnel");

    const uint8_t peer_id_slot =
        find_client_link_index_by_id(tunnel, requested_peer_id);
    if(peer_id_slot == UINT8_MAX)
        return tunnel_error(what_error, requested_port, "no such peer");

    /* skip command header parsed above */
    data += 3;
    length -= 3;

    if(os_write_from_buffer(data, length,
                            tunnel->peer_links[peer_id_slot].peer->fd) < 0)
    {
        msg_error(errno, LOG_ERR,
                  "Sending data to peer failed, closing connection");
        close_and_free_peer(tunnel->peer_links[peer_id_slot].peer, false);
        return -1;
    }

    msg_info("Sent %zu bytes to network peer %u on port %u",
             length, requested_peer_id, requested_port);

    return 0;
}
