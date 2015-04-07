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
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>

#include "named_pipe.h"
#include "network.h"
#include "messages.h"
#include "transactions.h"
#include "dynamic_buffer.h"
#include "drcp.h"
#include "dbus_iface.h"
#include "registers.h"
#include "os.h"

/* generic events */
#define WAITEVENT_POLL_ERROR                            (1U << 0)
#define WAITEVENT_POLL_TIMEOUT                          (1U << 1)

/* FIFO events */
#define WAITEVENT_CAN_READ_DCP                          (1U << 2)
#define WAITEVENT_CAN_READ_DRCP                         (1U << 3)
#define WAITEVENT_DCP_CONNECTION_DIED                   (1U << 4)
#define WAITEVENT_DRCP_CONNECTION_DIED                  (1U << 5)

/* socket events */
#define WAITEVENT_CAN_READ_FROM_SERVER_SOCKET           (1U << 6)
#define WAITEVENT_CAN_READ_DCP_FROM_PEER_SOCKET         (1U << 7)
#define WAITEVENT_DCP_CONNECTION_PEER_SOCKET_DIED       (1U << 8)

/*!
 * Global state of the DCP machinery.
 */
struct state
{
    /*!
     * The transaction that is currently going on between dcpspi and dcpd.
     *
     * If this pointer is NULL, then there is no transaction going on, meaning
     * that the DCP is in idle state.
     */
    struct transaction *active_transaction;

    /*!
     * A queue of transactions initiated by the master.
     */
    struct transaction *master_transaction_queue;

    /*!
     * Dynamically growing buffer for holding XML data from drcpd.
     *
     * This buffer is filled while receiving XML data from drcpd. As soon as
     * drcpd is finished, one or more transactions are constructed and queued
     * in the #state::master_transaction_queue queue.
     */
    struct dynamic_buffer drcp_buffer;

    /*!
     * Pointer to an immortal SPI slave transaction object.
     *
     * This is allocated on startup and never freed. We just want to make sure
     * that there is always space for the single slave transaction that may be
     * active at a time.
     */
    struct transaction *preallocated_spi_slave_transaction;

    /*!
     * Pointer to an immortal network slave transaction object.
     */
    struct transaction *preallocated_inet_slave_transaction;
};

ssize_t (*os_read)(int fd, void *dest, size_t count) = read;
ssize_t (*os_write)(int fd, const void *buf, size_t count) = write;

/*!
 * Global flag that gets cleared in the SIGTERM signal handler.
 *
 * For clean shutdown.
 */
static volatile bool keep_running = true;

static void schedule_transaction(struct state *state, struct transaction *t)
{
    log_assert(state->active_transaction == NULL);

    if(t != NULL)
        state->active_transaction = t;
}

static void try_dequeue_next_transaction(struct state *state)
{
    if(state->active_transaction != NULL)
        return;

    if(state->master_transaction_queue != NULL)
        schedule_transaction(state,
                             transaction_queue_remove(&state->master_transaction_queue));
}

static unsigned int
schedule_slave_transaction_or_defer(struct state *state, struct transaction *t,
                                    unsigned int retcode_if_scheduled)
{
    if(state->active_transaction != NULL)
        return 0;

    transaction_reset_for_slave(t);

    /* bypass queue because slave requests always have priority */
    schedule_transaction(state, t);

    return retcode_if_scheduled;
}

static unsigned int handle_dcp_fifo_in_events(int fd, short revents,
                                              struct state *state)
{
    unsigned int result = 0;

    if(revents & POLLIN)
        result |=
            schedule_slave_transaction_or_defer(state,
                                                state->preallocated_spi_slave_transaction,
                                                WAITEVENT_CAN_READ_DCP);

    if(revents & POLLHUP)
    {
        msg_error(EPIPE, LOG_ERR, "DCP daemon died, need to reopen");
        result |= WAITEVENT_DCP_CONNECTION_DIED;
    }

    if(revents & ~(POLLIN | POLLHUP))
        msg_error(EINVAL, LOG_WARNING,
                  "Unexpected poll() events on DCP fifo %d: %04x",
                  fd, revents);

    return result;
}

static unsigned int handle_dcp_fifo_out_events(int fd, short revents)
{
    unsigned int result = 0;

    if(revents & POLLIN)
        result |= WAITEVENT_CAN_READ_DRCP;

    if(revents & POLLHUP)
    {
        msg_error(EPIPE, LOG_ERR, "DRCP daemon died, need to reopen");
        result |= WAITEVENT_DRCP_CONNECTION_DIED;
    }

    if(revents & ~(POLLIN | POLLHUP))
        msg_error(EINVAL, LOG_WARNING,
                  "Unexpected poll() events on DRCP fifo_fd %d: %04x",
                  fd, revents);

    return result;
}

static unsigned int handle_network_server_events(int fd, short revents)
{
    unsigned int result = 0;

    if(revents & POLLIN)
        result |= WAITEVENT_CAN_READ_FROM_SERVER_SOCKET;

    if(revents & ~POLLIN)
        msg_error(EINVAL, LOG_WARNING,
                  "Unexpected poll() events on DCP server socket fd %d: %04x",
                  fd, revents);

    return result;
}

static unsigned int handle_network_peer_events(int fd, short revents,
                                               struct state *state)
{
    unsigned int result = 0;

    if((revents & POLLIN) && network_have_data(fd))
        result |=
            schedule_slave_transaction_or_defer(state,
                                                state->preallocated_inet_slave_transaction,
                                                WAITEVENT_CAN_READ_DCP_FROM_PEER_SOCKET);

    if(revents & POLLHUP)
    {
        msg_error(EPIPE, LOG_INFO, "DCP peer connection died, need to close");
        result |= WAITEVENT_DCP_CONNECTION_PEER_SOCKET_DIED;
    }

    if(revents & ~(POLLIN | POLLHUP))
        msg_error(EINVAL, LOG_WARNING,
                  "Unexpected poll() events on DCP peer socket fd %d: %04x",
                  fd, revents);

    return result;
}

static unsigned int wait_for_events(struct state *state,
                                    const int drcp_fifo_in_fd,
                                    const int dcpspi_fifo_in_fd,
                                    const int server_socket_fd,
                                    const int peer_socket_fd,
                                    bool do_block)
{
    struct pollfd fds[] =
    {
        {
            .fd = dcpspi_fifo_in_fd,
            .events = POLLIN,
        },
        {
            .fd = drcp_fifo_in_fd,
            .events = POLLIN,
        },
        {
            .fd = server_socket_fd,
            .events = POLLIN,
        },
        {
            .fd = peer_socket_fd,
            .events = POLLIN,
        },
    };

    int ret = poll(fds, sizeof(fds) / sizeof(fds[0]), do_block ? -1 : 0);

    if(ret <= 0)
    {
        if(ret == 0)
            return WAITEVENT_POLL_TIMEOUT;

        if(errno != EINTR)
            msg_error(errno, LOG_CRIT, "poll() failed");

        return WAITEVENT_POLL_ERROR;
    }

    unsigned int return_value = 0;

    return_value |= handle_dcp_fifo_in_events(dcpspi_fifo_in_fd,   fds[0].revents, state);
    return_value |= handle_dcp_fifo_out_events(drcp_fifo_in_fd,    fds[1].revents);
    return_value |= handle_network_server_events(server_socket_fd, fds[2].revents);
    return_value |= handle_network_peer_events(peer_socket_fd,     fds[3].revents, state);

    return return_value;
}

static bool try_preallocate_buffer(struct dynamic_buffer *buffer,
                                   const struct fifo_pair *fds)
{
    if(dynamic_buffer_is_allocated(buffer))
        return true;

    static size_t prealloc_size;
    if(prealloc_size == 0)
        prealloc_size = getpagesize();

    if(!dynamic_buffer_resize(buffer, prealloc_size))
        return false;

    size_t expected_size;
    size_t xml_data_offset;

    buffer->size = 16;
    if(!drcp_read_size_from_fd(buffer, fds->in_fd, &expected_size, &xml_data_offset))
    {
        dynamic_buffer_free(buffer);
        return false;
    }
    buffer->size = prealloc_size;

    log_assert(buffer->pos >= xml_data_offset);

    if(expected_size > buffer->size)
    {
        if(!dynamic_buffer_resize(buffer, expected_size))
        {
            dynamic_buffer_free(buffer);
            return false;
        }
    }
    else
    {
        /*
         * This is kind of a hack, but a safe one. The size field now contains
         * the expected number of bytes to read from the pipe, and if there is
         * any error, the buffer will be freed regardless of the size field.
         * Even in case the size is 0, the buffer will be freed because free()
         * is going to be called for a non-NULL pointer.
         */
        buffer->size = expected_size;
    }

    buffer->pos -= xml_data_offset;
    memmove(buffer->data, buffer->data + xml_data_offset, buffer->pos);

    return true;
}

struct files
{
    struct fifo_pair drcp_fifo;
    struct fifo_pair dcpspi_fifo;

    const char *drcp_fifo_in_name;
    const char *drcp_fifo_out_name;
    const char *dcpspi_fifo_in_name;
    const char *dcpspi_fifo_out_name;
};

static bool process_drcp_input(struct state *state,
                               enum transaction_channel channel)
{
    const struct dynamic_buffer *buffer = &state->drcp_buffer;

    if(dynamic_buffer_is_empty(buffer))
    {
        msg_error(EINVAL, LOG_NOTICE, "Received empty DRCP buffer");
        return false;
    }

    struct transaction *head =
        transaction_fragments_from_data(buffer->data, buffer->pos, 71, channel);
    if(head == NULL)
        return false;

    transaction_queue_add(&state->master_transaction_queue, head);

    return true;
}

static bool try_reopen(int *fd, const char *devname, const char *errorname)
{
    if(fifo_reopen(fd, devname, false))
        return true;

    msg_error(EPIPE, LOG_EMERG,
              "Failed reopening %s connection, unable to recover. "
              "Terminating", errorname);

    return false;
}

static void terminate_active_transaction(struct state *state,
                                         int *network_peer_fd)
{
    switch(transaction_get_channel(state->active_transaction))
    {
      case TRANSACTION_CHANNEL_SPI:
        break;

      case TRANSACTION_CHANNEL_INET:
        network_close(network_peer_fd);
        break;
    }

    if(!transaction_is_pinned(state->active_transaction))
        transaction_free(&state->active_transaction);

    state->active_transaction = NULL;
}

static bool handle_reopen_connections(unsigned int wait_result,
                                      struct files *files,
                                      struct network_socket_pair *network,
                                      struct state *state)
{
    if((wait_result & (WAITEVENT_DRCP_CONNECTION_DIED |
                       WAITEVENT_DCP_CONNECTION_DIED)) == 0)
        return true;

    if(state->active_transaction != NULL)
        terminate_active_transaction(state, &network->peer_fd);

    if((wait_result & WAITEVENT_DRCP_CONNECTION_DIED) != 0 &&
       !try_reopen(&files->drcp_fifo.in_fd, files->drcp_fifo_in_name,
                   "DRCP"))
        return false;

    if((wait_result & WAITEVENT_DCP_CONNECTION_DIED) != 0 &&
       !try_reopen(&files->dcpspi_fifo.in_fd, files->dcpspi_fifo_in_name,
                   "DCPSPI"))
        return false;

    return true;
}

static void handle_network_connection(unsigned int wait_result,
                                      struct network_socket_pair *sockets,
                                      struct state *state)
{
    if((wait_result & (WAITEVENT_CAN_READ_FROM_SERVER_SOCKET |
                       WAITEVENT_CAN_READ_DCP_FROM_PEER_SOCKET |
                       WAITEVENT_DCP_CONNECTION_PEER_SOCKET_DIED)) == 0)
        return;

    if((wait_result & WAITEVENT_CAN_READ_FROM_SERVER_SOCKET) != 0)
    {
        int peer_fd = network_accept_peer_connection(sockets->server_fd);

        if(peer_fd >= 0)
        {
            if(sockets->peer_fd >= 0)
            {
                network_close(&peer_fd);
                msg_info("Rejected peer connection, only single connection supported");
            }
            else
            {
                sockets->peer_fd = peer_fd;
                msg_info("Accepted peer connection, fd %d", sockets->peer_fd);
            }
        }
    }

    if((wait_result & WAITEVENT_CAN_READ_DCP_FROM_PEER_SOCKET) != 0)
    {
        log_assert(sockets->peer_fd >= 0);
        msg_info("DCP over TCP/IP");
    }

    if((wait_result & WAITEVENT_DCP_CONNECTION_PEER_SOCKET_DIED) != 0)
    {
        if(sockets->peer_fd >= 0)
        {
            msg_info("Peer disconnected");
            network_close(&sockets->peer_fd);
        }
    }
}

/*!
 * Process DCP.
 */
static void main_loop(struct files *files)
{
    static struct state state;

    state.preallocated_spi_slave_transaction =
        transaction_alloc(true, TRANSACTION_CHANNEL_SPI, true);
    state.preallocated_inet_slave_transaction =
        transaction_alloc(true, TRANSACTION_CHANNEL_INET, true);
    dynamic_buffer_init(&state.drcp_buffer);

    static struct network_socket_pair network_sockets;

    network_sockets.server_fd = network_create_socket();
    network_sockets.peer_fd = -1;

    /* send device status register (17) */
    transaction_push_register_to_slave(&state.master_transaction_queue,
                                       17, TRANSACTION_CHANNEL_SPI);
    try_dequeue_next_transaction(&state);

    msg_info("Ready for accepting traffic");

    while(keep_running)
    {
        const unsigned int wait_result =
            wait_for_events(&state,
                            files->drcp_fifo.in_fd, files->dcpspi_fifo.in_fd,
                            network_sockets.server_fd, network_sockets.peer_fd,
                            transaction_is_input_required(state.active_transaction));

        if((wait_result & WAITEVENT_POLL_ERROR) != 0)
            continue;

        if((wait_result & WAITEVENT_CAN_READ_DRCP) != 0)
        {
            if(try_preallocate_buffer(&state.drcp_buffer, &files->drcp_fifo) &&
               drcp_fill_buffer(&state.drcp_buffer, files->drcp_fifo.in_fd))
            {
                if(state.drcp_buffer.pos >= state.drcp_buffer.size)
                {
                    drcp_finish_request(process_drcp_input(&state,
                                                           TRANSACTION_CHANNEL_SPI),
                                        files->drcp_fifo.out_fd);
                    dynamic_buffer_free(&state.drcp_buffer);
                }
            }
            else
            {
                dynamic_buffer_free(&state.drcp_buffer);
                drcp_finish_request(false, files->drcp_fifo.out_fd);
            }
        }

        if(!handle_reopen_connections(wait_result, files, &network_sockets, &state))
        {
            keep_running = false;
            continue;
        }

        handle_network_connection(wait_result, &network_sockets, &state);

        try_dequeue_next_transaction(&state);

        if(state.active_transaction == NULL)
            continue;

        int in_fd = -1;
        int out_fd = -1;

        switch(transaction_get_channel(state.active_transaction))
        {
          case TRANSACTION_CHANNEL_SPI:
            in_fd = files->dcpspi_fifo.in_fd;
            out_fd = files->dcpspi_fifo.out_fd;
            break;

          case TRANSACTION_CHANNEL_INET:
            in_fd = network_sockets.peer_fd;
            out_fd = network_sockets.peer_fd;
            break;
        }

        switch(transaction_process(state.active_transaction, in_fd, out_fd))
        {
          case TRANSACTION_IN_PROGRESS:
            break;

          case TRANSACTION_FINISHED:
          case TRANSACTION_ERROR:
            terminate_active_transaction(&state, &network_sockets.peer_fd);
            try_dequeue_next_transaction(&state);
            break;
        }
    }

    transaction_free(&state.preallocated_spi_slave_transaction);
    transaction_free(&state.preallocated_inet_slave_transaction);

    network_close(&network_sockets.server_fd);
    network_close(&network_sockets.peer_fd);
}

struct parameters
{
    bool run_in_foreground;
    bool connect_to_session_dbus;
    const char *primary_network_interface_name;
    const char *primary_network_interface_mac_address;
};

/*!
 * Open devices, daemonize.
 */
static int setup(const struct parameters *parameters, struct files *files)
{
    msg_enable_syslog(!parameters->run_in_foreground);

    if(!parameters->run_in_foreground)
        openlog("dcpd", LOG_PID, LOG_DAEMON);

    if(!parameters->run_in_foreground)
    {
        if(daemon(0, 0) < 0)
        {
            msg_error(errno, LOG_EMERG, "Failed to run as daemon");
            goto error_daemon;
        }
    }

    msg_info("Attempting to open named pipes");

    files->dcpspi_fifo.in_fd =
        fifo_open(files->dcpspi_fifo_in_name, false);
    if(files->dcpspi_fifo.in_fd < 0)
        goto error_dcpspi_fifo_in;

    files->drcp_fifo.in_fd =
        fifo_create_and_open(files->drcp_fifo_in_name, false);
    if(files->drcp_fifo.in_fd < 0)
        goto error_drcp_fifo_in;

    files->drcp_fifo.out_fd =
        fifo_create_and_open(files->drcp_fifo_out_name, true);
    if(files->drcp_fifo.out_fd < 0)
        goto error_drcp_fifo_out;

    files->dcpspi_fifo.out_fd =
        fifo_open(files->dcpspi_fifo_out_name, true);
    if(files->dcpspi_fifo.out_fd < 0)
        goto error_dcpspi_fifo_out;

    return 0;

error_daemon:
    fifo_close(&files->dcpspi_fifo.out_fd);

error_dcpspi_fifo_out:
    fifo_close_and_delete(&files->drcp_fifo.out_fd, files->drcp_fifo_out_name);

error_drcp_fifo_out:
    fifo_close_and_delete(&files->drcp_fifo.in_fd, files->drcp_fifo_in_name);

error_drcp_fifo_in:
    fifo_close(&files->dcpspi_fifo.in_fd);

error_dcpspi_fifo_in:
    return -1;
}

static void shutdown(struct files *files)
{
    fifo_close_and_delete(&files->drcp_fifo.in_fd, files->drcp_fifo_in_name);
    fifo_close_and_delete(&files->drcp_fifo.out_fd, files->drcp_fifo_out_name);
    fifo_close(&files->dcpspi_fifo.in_fd);
    fifo_close(&files->dcpspi_fifo.out_fd);
}

static void usage(const char *program_name)
{
    printf("Usage: %s [options]\n"
           "\n"
           "Options:\n"
           "  --help         Show this help.\n"
           "  --fg           Run in foreground, don't run as daemon.\n"
           "  --iface        Name of the primary network interface (mandatory)\n"
           "  --mac          MAC address of the primary network interface (mandatory)\n"
           "  --ispi  name   Name of the named pipe the DCPSPI daemon writes to.\n"
           "  --ospi  name   Name of the named pipe the DCPSPI daemon reads from.\n"
           "  --idrcp name   Name of the named pipe the DRCP daemon writes to.\n"
           "  --odrcp name   Name of the named pipe the DRCP daemon reads from.\n"
           "  --session-dbus Connect to session D-Bus.\n"
           "  --system-dbus  Connect to system D-Bus.\n",
           program_name);
}

static int process_command_line(int argc, char *argv[],
                                struct parameters *parameters,
                                struct files *files)
{
    parameters->run_in_foreground = false;
    parameters->connect_to_session_dbus = true;

    files->dcpspi_fifo_in_name = "/tmp/spi_to_dcp";
    files->dcpspi_fifo_out_name = "/tmp/dcp_to_spi";
    files->drcp_fifo_in_name = "/tmp/drcpd_to_dcpd";
    files->drcp_fifo_out_name = "/tmp/dcpd_to_drcpd";

#define CHECK_ARGUMENT() \
    do \
    { \
        if(i + 1 >= argc) \
        { \
            fprintf(stderr, "Option %s requires an argument.\n", argv[i]); \
            return -1; \
        } \
        ++i; \
    } \
    while(0)

    for(int i = 1; i < argc; ++i)
    {
        if(strcmp(argv[i], "--help") == 0)
            return 1;
        else if(strcmp(argv[i], "--fg") == 0)
            parameters->run_in_foreground = true;
        else if(strcmp(argv[i], "--ispi") == 0)
        {
            CHECK_ARGUMENT();
            files->dcpspi_fifo_in_name = argv[i];
        }
        else if(strcmp(argv[i], "--ospi") == 0)
        {
            CHECK_ARGUMENT();
            files->dcpspi_fifo_out_name = argv[i];
        }
        else if(strcmp(argv[i], "--idrcp") == 0)
        {
            CHECK_ARGUMENT();
            files->drcp_fifo_in_name = argv[i];
        }
        else if(strcmp(argv[i], "--odrcp") == 0)
        {
            CHECK_ARGUMENT();
            files->drcp_fifo_out_name = argv[i];
        }
        else if(strcmp(argv[i], "--session-dbus") == 0)
            parameters->connect_to_session_dbus = true;
        else if(strcmp(argv[i], "--system-dbus") == 0)
            parameters->connect_to_session_dbus = false;
        else if(strcmp(argv[i], "--iface") == 0)
        {
            CHECK_ARGUMENT();
            parameters->primary_network_interface_name = argv[i];
        }
        else if(strcmp(argv[i], "--mac") == 0)
        {
            CHECK_ARGUMENT();
            parameters->primary_network_interface_mac_address = argv[i];
        }
        else
        {
            fprintf(stderr, "Unknown option \"%s\". Please try --help.\n", argv[i]);
            return -1;
        }
    }

#undef CHECK_ARGUMENT

    if(parameters->primary_network_interface_name == NULL ||
       parameters->primary_network_interface_mac_address == NULL)
    {
        fprintf(stderr, "Missing options. Please try --help.\n");
        return -1;
    }

    return 0;
}

static void signal_handler(int signum, siginfo_t *info, void *ucontext)
{
    keep_running = false;
}

int main(int argc, char *argv[])
{
    static struct parameters parameters;
    static struct files files;

    int ret = process_command_line(argc, argv, &parameters, &files);

    if(ret == -1)
        return EXIT_FAILURE;
    else if(ret == 1)
    {
        usage(argv[0]);
        return EXIT_SUCCESS;
    }

    if(setup(&parameters, &files) < 0)
        return EXIT_FAILURE;

    register_init(parameters.primary_network_interface_mac_address);

    if(dbus_setup(parameters.connect_to_session_dbus) < 0)
    {
        shutdown(&files);
        return EXIT_FAILURE;
    }

    static struct sigaction action =
    {
        .sa_sigaction = signal_handler,
        .sa_flags = SA_SIGINFO | SA_RESETHAND,
    };

    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    transaction_init_allocator();

    main_loop(&files);

    msg_info("Shutting down");

    shutdown(&files);
    dbus_shutdown();

    return EXIT_SUCCESS;
}