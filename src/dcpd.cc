/*
 * Copyright (C) 2015, 2016, 2017  T+A elektroakustik GmbH & Co. KG
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

#include <cstdio>
#include <cstring>
#include <csignal>
#include <cerrno>

#include "named_pipe.h"
#include "dcp_over_tcp.h"
#include "smartphone_app.h"
#include "network_dispatcher.h"
#include "messages.h"
#include "messages_glib.h"
#include "transactions.h"
#include "dynamic_buffer.h"
#include "dynamic_buffer_util.h"
#include "drcp.h"
#include "dbus_iface.h"
#include "dbus_handlers_connman_manager_glue.h"
#include "registers.h"
#include "dcpregs_appliance.h"
#include "dcpregs_status.h"
#include "dcpregs_filetransfer.h"
#include "dcpregs_filetransfer.hh"
#include "dcpregs_filetransfer_priv.h"
#include "dcpregs_playstream.hh"
#include "connman.h"
#include "networkprefs.h"
#include "configproxy.h"
#include "configuration_dcpd.hh"
#include "os.h"
#include "versioninfo.h"

/* generic events */
#define WAITEVENT_POLL_ERROR                            (1U << 0)
#define WAITEVENT_POLL_TIMEOUT                          (1U << 1)

/* FIFO events */
#define WAITEVENT_CAN_READ_DCP                          (1U << 2)
#define WAITEVENT_CAN_READ_DRCP                         (1U << 3)
#define WAITEVENT_DCP_CONNECTION_DIED                   (1U << 4)
#define WAITEVENT_DRCP_CONNECTION_DIED                  (1U << 5)

/* socket events on DCP over TCP/IP connection */
#define WAITEVENT_CAN_READ_FROM_SERVER_SOCKET           (1U << 6)
#define WAITEVENT_CAN_READ_DCP_FROM_PEER_SOCKET         (1U << 7)
#define WAITEVENT_DCP_CONNECTION_PEER_SOCKET_DIED       (1U << 8)

/* socket events on smartphone app TCP/IP connection */
#define WAITEVENT_CAN_READ_FROM_SMARTPHONE_SOCKET       (1U << 9)
#define WAITEVENT_CAN_READ_XLINK_FROM_PEER_SOCKET       (1U << 10)
#define WAITEVENT_SMARTPHONE_PEER_SOCKET_DIED           (1U << 11)

/* internal events */
#define WAITEVENT_REGISTER_CHANGED                      (1U << 12)
#define WAITEVENT_SMARTPHONE_QUEUE_HAS_COMMANDS         (1U << 13)
#define WAITEVENT_CONNECT_TO_WLAN_REQUESTED             (1U << 14)
#define WAITEVENT_REFRESH_CONNMAN_SERVICES_REQUESTED    (1U << 15)

enum PrimitiveQueueCommand
{
    PRIMITIVE_QUEUECMD_PROCESS_APP_QUEUE,
    PRIMITIVE_QUEUECMD_CONNECT_TO_MANAGED_WLAN,
    PRIMITIVE_QUEUECMD_REFRESH_CONNMAN_SERVICES,
};

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
int (*os_poll)(struct pollfd *fds, nfds_t nfds, int timeout) = poll;

/*!
 * Global flag that gets cleared in the SIGTERM signal handler.
 *
 * For clean shutdown.
 */
static volatile bool keep_running = true;

/*!
 * Global write end of pipe to self for communicating back register changes
 * from others contexts.
 *
 * The read end is passed as parameter to #main_loop().
 */
static int register_changed_write_fd;

/*!
 * Global write end of pipe to self for communicating back requests to do
 * something in main context.
 *
 * This is a simple queue of one-byte commands that tells the main loop to do
 * something, most notably processing the smartphone app command queue.
 *
 * The read end is passed as parameter to #main_loop().
 */
static int primitive_command_queue_write_fd;

static void show_version_info(void)
{
    printf("%s\n"
           "Revision %s%s\n"
           "         %s+%d, %s\n",
           PACKAGE_STRING,
           VCS_FULL_HASH, VCS_WC_MODIFIED ? " (tainted)" : "",
           VCS_TAG, VCS_TICK, VCS_DATE);
}

static void log_version_info(void)
{
    msg_vinfo(MESSAGE_LEVEL_IMPORTANT, "Rev %s%s, %s+%d, %s",
              VCS_FULL_HASH, VCS_WC_MODIFIED ? " (tainted)" : "",
              VCS_TAG, VCS_TICK, VCS_DATE);
}

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

static unsigned int try_schedule_slave_transaction(struct state *state,
                                                   struct transaction *t,
                                                   unsigned int retcode)
{
    if(state->active_transaction != NULL)
        return retcode;

    transaction_reset_for_slave(t);

    /* bypass queue because slave requests always have priority */
    schedule_transaction(state, t);

    return retcode;
}

static unsigned int handle_dcp_fifo_in_events(int fd, short revents,
                                              struct state *state)
{
    unsigned int result = 0;

    if(revents & POLLIN)
        result |= try_schedule_slave_transaction(state,
                                                 state->preallocated_spi_slave_transaction,
                                                 WAITEVENT_CAN_READ_DCP);

    if(revents & POLLHUP)
    {
        msg_error(EPIPE, LOG_ERR, "DCPSPI daemon died, need to reopen");
        result |= WAITEVENT_DCP_CONNECTION_DIED;
    }

    if(revents & ~(POLLIN | POLLHUP))
        msg_error(EINVAL, LOG_WARNING,
                  "Unexpected poll() events on DCPSPI fifo %d: %04x",
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

static unsigned int handle_register_events(int fd, short revents)
{
    unsigned int result = 0;

    if(revents & POLLIN)
        result |= WAITEVENT_REGISTER_CHANGED;

    if(revents & ~POLLIN)
        msg_error(EINVAL, LOG_WARNING,
                  "Unexpected poll() events on internal socket fd %d: %04x",
                  fd, revents);

    return result;
}

static unsigned int handle_dcp_server_events(int fd, short revents)
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

static unsigned int handle_dcp_peer_events(int fd, short revents,
                                           struct state *state)
{
    unsigned int result = 0;

    if((revents & POLLIN) && network_have_data(fd))
        result |= try_schedule_slave_transaction(state,
                                                 state->preallocated_inet_slave_transaction,
                                                 WAITEVENT_CAN_READ_DCP_FROM_PEER_SOCKET);

    if(revents & (POLLHUP | POLLERR))
    {
        msg_error(EPIPE, LOG_INFO, "DCP peer connection died, need to close");
        result |= WAITEVENT_DCP_CONNECTION_PEER_SOCKET_DIED;
    }

    if(revents & ~(POLLIN | POLLHUP | POLLERR))
        msg_error(EINVAL, LOG_WARNING,
                  "Unexpected poll() events on DCP peer socket fd %d: %04x",
                  fd, revents);

    return result;
}

static unsigned int handle_app_server_events(int fd, short revents)
{
    unsigned int result = 0;

    if(revents & POLLIN)
        result |= WAITEVENT_CAN_READ_FROM_SMARTPHONE_SOCKET;

    if(revents & ~POLLIN)
        msg_error(EINVAL, LOG_WARNING,
                  "Unexpected poll() events on smartphone app server socket fd %d: %04x",
                  fd, revents);

    return result;
}

static unsigned int handle_app_peer_events(int fd, short revents)
{
    unsigned int result = 0;

    if(revents & POLLIN)
    {
        if(network_have_data(fd))
            result |= WAITEVENT_CAN_READ_XLINK_FROM_PEER_SOCKET;
        else
        {
            msg_error(EPIPE, LOG_INFO, "Smartphone app peer connection closed");
            result |= WAITEVENT_SMARTPHONE_PEER_SOCKET_DIED;
        }
    }

    if(revents & (POLLHUP | POLLERR))
    {
        msg_error(EPIPE, LOG_INFO, "Smartphone app peer connection died, need to close");
        result |= WAITEVENT_SMARTPHONE_PEER_SOCKET_DIED;
    }

    if(revents & ~(POLLIN | POLLHUP | POLLERR))
        msg_error(EINVAL, LOG_WARNING,
                  "Unexpected poll() events on smartphone app peer socket fd %d: %04x",
                  fd, revents);

    return result;
}

static unsigned int handle_primqueue_events(int fd, short revents)
{
    unsigned int result = 0;

    if(revents & POLLIN)
    {
        while(true)
        {
            errno = 0;

            uint8_t commands[16];
            const ssize_t number_of_commands =
                os_read(fd, commands, sizeof(commands));

            if(number_of_commands < 0)
            {
                if(errno == EINTR)
                    continue;
                else
                {
                    msg_error(errno, LOG_ERR,
                              "Error while reading from primitive queue");
                    break;
                }
            }

            for(ssize_t i = 0; i < number_of_commands; ++i)
            {
                const enum PrimitiveQueueCommand cmd =
                    static_cast<const enum PrimitiveQueueCommand>(commands[i]);

                switch(cmd)
                {
                  case PRIMITIVE_QUEUECMD_PROCESS_APP_QUEUE:
                    result |= WAITEVENT_SMARTPHONE_QUEUE_HAS_COMMANDS;
                    break;

                  case PRIMITIVE_QUEUECMD_CONNECT_TO_MANAGED_WLAN:
                    result |= WAITEVENT_CONNECT_TO_WLAN_REQUESTED;
                    break;

                  case PRIMITIVE_QUEUECMD_REFRESH_CONNMAN_SERVICES:
                    result |= WAITEVENT_REFRESH_CONNMAN_SERVICES_REQUESTED;;
                    break;
                }
            }

            break;
        }
    }

    if(revents & ~POLLIN)
        msg_error(EINVAL, LOG_WARNING,
                  "Unexpected poll() events on internal socket fd %d: %04x",
                  fd, revents);

    return result;
}

static unsigned int wait_for_events(struct state *state,
                                    const int drcp_fifo_in_fd,
                                    const int dcpspi_fifo_in_fd,
                                    const int dcp_server_socket_fd,
                                    const int dcp_peer_socket_fd,
                                    const int app_server_socket_fd,
                                    const int app_peer_socket_fd,
                                    const int primitive_queue_fd,
                                    const int register_changed_fd,
                                    bool do_block)
{
    /*
     * Local define for array layout below.
     */
#define FIRST_NWDISPATCH_INDEX  8U

    /*
     * File descriptor breakdown:
     * - 1 fd for the incoming named pipe from dcpspi
     * - 1 fd for the incoming named pipe from drcpd
     * - 1 fd for the incoming internal pipe from ourselves used for
     *   communicating register changes from the DCP register code
     * - 2 fds for the DCP over TCP control interface, not registered with the
     *   network dispatcher
     * - the remaining #NWDISPATCH_MAX_CONNECTIONS fds are for server and
     *   client connections to the TCP tunnel (registers 119, 120, 121), all
     *   registered with the network dispatcher
     */
    struct pollfd fds[FIRST_NWDISPATCH_INDEX + NWDISPATCH_MAX_CONNECTIONS] =
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
            .fd = dcp_server_socket_fd,
            .events = POLLIN,
        },
        {
            .fd = dcp_peer_socket_fd,
            .events = POLLIN,
        },
        {
            .fd = app_server_socket_fd,
            .events = POLLIN,
        },
        {
            .fd = app_peer_socket_fd,
            .events = POLLIN,
        },
        {
            .fd = primitive_queue_fd,
            .events = POLLIN,
        },
        {
            .fd = register_changed_fd,
            .events = POLLIN,
        },
    };

    (void)nwdispatch_scatter_fds(&fds[FIRST_NWDISPATCH_INDEX],
                                 NWDISPATCH_MAX_CONNECTIONS, POLLIN);

    int ret = os_poll(fds, sizeof(fds) / sizeof(fds[0]), do_block ? -1 : 0);

    if(ret <= 0)
    {
        if(ret == 0)
            return WAITEVENT_POLL_TIMEOUT;

        if(errno != EINTR)
            msg_error(errno, LOG_CRIT, "poll() failed");

        return WAITEVENT_POLL_ERROR;
    }

    (void)nwdispatch_handle_events(&fds[FIRST_NWDISPATCH_INDEX],
                                   NWDISPATCH_MAX_CONNECTIONS);

    unsigned int return_value = 0;

    return_value |= handle_dcp_fifo_in_events(dcpspi_fifo_in_fd,   fds[0].revents, state);
    return_value |= handle_dcp_fifo_out_events(drcp_fifo_in_fd,    fds[1].revents);
    return_value |= handle_dcp_server_events(dcp_server_socket_fd, fds[2].revents);
    return_value |= handle_dcp_peer_events(dcp_peer_socket_fd,     fds[3].revents, state);
    return_value |= handle_app_server_events(app_server_socket_fd, fds[4].revents);
    return_value |= handle_app_peer_events(app_peer_socket_fd,     fds[5].revents);
    return_value |= handle_primqueue_events(primitive_queue_fd,    fds[6].revents);
    return_value |= handle_register_events(register_changed_fd,    fds[7].revents);

    return return_value;

#undef FIRST_NWDISPATCH_INDEX
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
                                         struct dcp_over_tcp_data *dot)
{
    switch(transaction_get_channel(state->active_transaction))
    {
      case TRANSACTION_CHANNEL_SPI:
        break;

      case TRANSACTION_CHANNEL_INET:
        dot_close_peer(dot);
        break;
    }

    if(!transaction_is_pinned(state->active_transaction))
        transaction_free(&state->active_transaction);

    state->active_transaction = NULL;
}

static bool handle_reopen_connections(unsigned int wait_result,
                                      struct files *files,
                                      struct dcp_over_tcp_data *dot,
                                      struct state *state)
{
    if((wait_result & (WAITEVENT_DRCP_CONNECTION_DIED |
                       WAITEVENT_DCP_CONNECTION_DIED)) == 0)
        return true;

    if(state->active_transaction != NULL)
        terminate_active_transaction(state, dot);

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

static void handle_register_change(unsigned int wait_result, int fd,
                                   struct state *state)
{
    if((wait_result & WAITEVENT_REGISTER_CHANGED) == 0)
        return;

    ssize_t ret;
    uint8_t reg_number;

    while((ret = os_read(fd, &reg_number, sizeof(reg_number))) < 0 && errno == EINTR)
        ;

    if(ret < 0)
        msg_error(errno, LOG_ERR, "Failed dequeuing register number");
    else if(ret != sizeof(reg_number))
        msg_error(0, LOG_ERR,
                  "Read %zd bytes instead of 1 while trying to dequeue register number",
                  ret);
    else
        transaction_push_register_to_slave(&state->master_transaction_queue,
                                           reg_number, TRANSACTION_CHANNEL_SPI);
}

static void handle_connman_manager_events(unsigned int wait_result,
                                          struct DBusSignalManagerData *data)
{
    if((wait_result & WAITEVENT_REFRESH_CONNMAN_SERVICES_REQUESTED) != 0)
        dbussignal_connman_manager_refresh_services();

    if((wait_result & WAITEVENT_CONNECT_TO_WLAN_REQUESTED) != 0)
        dbussignal_connman_manager_connect_our_wlan(data);
}

static struct
{
    bool is_filter_active;
    uint32_t regs[8];
}
push_register_filter;

static void push_register_filter_set(uint8_t reg_number)
{
    const uint32_t mask = 1U << (reg_number & 0x1f);

    push_register_filter.is_filter_active = true;
    push_register_filter.regs[reg_number >> 5] |= mask;
}

static inline bool push_register_filter_is_filtered(uint8_t reg_number)
{
    if(!push_register_filter.is_filter_active)
        return false;

    const uint32_t mask = 1U << (reg_number & 0x1f);

    return (push_register_filter.regs[reg_number >> 5] & mask) != 0;
}

/*!
 * Callback from network status register implementation.
 *
 * In case some register has changed, push it to the slave device.
 */
static void push_register_to_slave(uint8_t reg_number)
{
    if(push_register_filter_is_filtered(reg_number))
        return;

    ssize_t ret;

    while((ret = os_write(register_changed_write_fd, &reg_number, sizeof(reg_number))) < 0 && errno == EINTR)
        ;

    if(ret < 0)
        msg_error(errno, LOG_ERR, "Failed queuing change of register %u", reg_number);
    else if(ret != sizeof(reg_number))
        msg_error(0, LOG_ERR,
                  "Wrote %zd bytes instead of 1 while trying to queue change of register %u",
                  ret, reg_number);
}

static void primitive_queue_send(const enum PrimitiveQueueCommand cmd, const char *what)
{
    const uint8_t cmd_as_byte = (const uint8_t)cmd;
    ssize_t ret;

    while((ret = os_write(primitive_command_queue_write_fd,
                          &cmd_as_byte, sizeof(cmd_as_byte))) < 0 &&
          errno == EINTR)
        ;

    if(ret < 0)
        msg_error(errno, LOG_ERR, "Failed queuing command for %s", what);
    else if(ret != sizeof(cmd_as_byte))
        msg_error(0, LOG_ERR,
                  "Wrote %zd bytes instead of 1 while queuing command for %s",
                  ret, what);
}

static void process_smartphone_outgoing_queue(void)
{
    primitive_queue_send(PRIMITIVE_QUEUECMD_PROCESS_APP_QUEUE,
                         "processing smartphone queue");
}

static void try_connect_to_managed_wlan(void)
{
    primitive_queue_send(PRIMITIVE_QUEUECMD_CONNECT_TO_MANAGED_WLAN,
                         "connecting to WLAN");
}

static void deferred_connman_refresh(void)
{
    primitive_queue_send(PRIMITIVE_QUEUECMD_REFRESH_CONNMAN_SERVICES,
                         "refreshing ConnMan service list");
}

/*!
 * Hold back active transaction, make another transaction the active one.
 *
 * This function moves the active transaction to the front of our pending
 * queue. Then, the passed transaction is made the active one.
 */
static void replace_active_transaction(struct state *const state,
                                       struct transaction *new_active)
{
    transaction_queue_add(&state->master_transaction_queue,
                          state->active_transaction);
    state->master_transaction_queue = state->active_transaction;

    state->active_transaction = new_active;
}

/*!
 * Possibly replace active transaction by some other transaction.
 */
static void handle_transaction_exception(struct state *const state,
                                         const struct transaction_exception *const e)
{
    log_assert(state->active_transaction != NULL);

    struct transaction *t = NULL;
    enum transaction_process_status result = TRANSACTION_EXCEPTION;

    switch(e->exception_code)
    {
      case TRANSACTION_EXCEPTION_COLLISION:
        /* colliding slave transaction must be processed next because there
         * might be more data in the pipe buffer that belongs to the
         * transaction */
        log_assert(e->d.collision.t != NULL);
        log_assert(e->d.collision.t != state->active_transaction);

        replace_active_transaction(state, e->d.collision.t);

        break;

      case TRANSACTION_EXCEPTION_OUT_OF_ORDER_ACK:
        t = transaction_queue_find_by_serial(state->master_transaction_queue,
                                             e->d.ack.serial);

        if(t == NULL)
        {
            BUG("Packet serial 0x%04x unknown, dropping out-of-order ACK",
                e->d.ack.serial);
            break;
        }

        result = transaction_process_out_of_order_ack(t, &e->d.ack);

        break;

      case TRANSACTION_EXCEPTION_OUT_OF_ORDER_NACK:
        t = transaction_queue_find_by_serial(state->master_transaction_queue,
                                             e->d.nack.serial);

        if(t == NULL)
        {
            BUG("Packet serial 0x%04x unknown, dropping out-of-order NACK",
                e->d.nack.serial);
            break;
        }

        result = transaction_process_out_of_order_nack(t, &e->d.nack);

        break;
    }

    switch(result)
    {
      case TRANSACTION_IN_PROGRESS:
        break;

      case TRANSACTION_PUSH_BACK:
      case TRANSACTION_FINISHED:
      case TRANSACTION_ERROR:
        BUG("Unimplemented outcome of transaction exception handling");
        break;

      case TRANSACTION_EXCEPTION:
        break;
    }
}

/*!
 * Process DCP.
 */
static void main_loop(struct files *files,
                      struct dcp_over_tcp_data *dot,
                      struct smartphone_app_connection_data *appconn,
                      struct DBusSignalManagerData *connman,
                      int primitive_queue_fd, int register_changed_fd)
{
    static struct state state;

    state.preallocated_spi_slave_transaction =
        transaction_alloc(TRANSACTION_ALLOC_SLAVE_BY_SLAVE,
                          TRANSACTION_CHANNEL_SPI, true);
    state.preallocated_inet_slave_transaction =
        transaction_alloc(TRANSACTION_ALLOC_SLAVE_BY_SLAVE,
                          TRANSACTION_CHANNEL_INET, true);
    dynamic_buffer_init(&state.drcp_buffer);

    dcpregs_status_set_ready();

    msg_info("Ready for accepting traffic");

    while(keep_running)
    {
        const unsigned int wait_result =
            wait_for_events(&state,
                            files->drcp_fifo.in_fd, files->dcpspi_fifo.in_fd,
                            dot->server_fd, dot->peer_fd,
                            appconn->server_fd, appconn->peer_fd,
                            primitive_queue_fd, register_changed_fd,
                            transaction_is_input_required(state.active_transaction));

        if((wait_result & WAITEVENT_POLL_ERROR) != 0)
            continue;

        if((wait_result & WAITEVENT_CAN_READ_DRCP) != 0)
        {
            if(try_preallocate_buffer(&state.drcp_buffer, &files->drcp_fifo) &&
               dynamic_buffer_fill_from_fd(&state.drcp_buffer,
                                           files->drcp_fifo.in_fd, true,
                                           "DRCP data"))
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

        if(!handle_reopen_connections(wait_result, files, dot, &state))
        {
            keep_running = false;
            continue;
        }

        handle_register_change(wait_result, register_changed_fd, &state);

        handle_connman_manager_events(wait_result, connman);

        if((wait_result & WAITEVENT_CAN_READ_FROM_SERVER_SOCKET) != 0)
            dot_handle_incoming(dot);

        dot_handle_outgoing(dot,
                            (wait_result & WAITEVENT_CAN_READ_DCP_FROM_PEER_SOCKET) != 0,
                            (wait_result & WAITEVENT_DCP_CONNECTION_PEER_SOCKET_DIED) != 0);

        if((wait_result & WAITEVENT_CAN_READ_FROM_SMARTPHONE_SOCKET) != 0)
            appconn_handle_incoming(appconn);

        appconn_handle_outgoing(appconn,
                                (wait_result & WAITEVENT_CAN_READ_XLINK_FROM_PEER_SOCKET) != 0,
                                (wait_result & WAITEVENT_SMARTPHONE_QUEUE_HAS_COMMANDS) != 0,
                                (wait_result & WAITEVENT_SMARTPHONE_PEER_SOCKET_DIED) != 0);

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
            in_fd = dot->peer_fd;
            out_fd = dot->peer_fd;
            break;
        }

        struct transaction_exception e;
        switch(transaction_process(state.active_transaction, in_fd, out_fd, &e))
        {
          case TRANSACTION_IN_PROGRESS:
            break;

          case TRANSACTION_PUSH_BACK:
            transaction_queue_add(&state.master_transaction_queue,
                                  state.active_transaction);
            state.active_transaction = NULL;
            try_dequeue_next_transaction(&state);
            break;

          case TRANSACTION_FINISHED:
          case TRANSACTION_ERROR:
            terminate_active_transaction(&state, dot);
            try_dequeue_next_transaction(&state);
            break;

          case TRANSACTION_EXCEPTION:
            handle_transaction_exception(&state, &e);
            break;
        }
    }

    transaction_free(&state.preallocated_spi_slave_transaction);
    transaction_free(&state.preallocated_inet_slave_transaction);
}

static void register_own_config_keys(Configuration::ConfigManager<Configuration::ApplianceValues> &config_manager)
{
    auto managed_keys(config_manager.keys());
    auto keys(static_cast<char **>(g_malloc_n(managed_keys.size() + 1, sizeof(char *))));

    size_t i = 0;
    for(auto &k : managed_keys)
        keys[i++] = g_strdup(k);

    keys[i] = nullptr;

    configproxy_register_local_configuration_owner(Configuration::ApplianceValues::OWNER_NAME, keys);
}

struct parameters
{
    enum MessageVerboseLevel verbose_level;
    bool run_in_foreground;
    bool connect_to_session_dbus;
    bool with_connman;
    bool is_fixing_broken_update_state;
    bool is_upgrade_enforced;
    bool is_upgrade_strongly_enforced;
};

static bool main_loop_init(const struct parameters *parameters,
                           Configuration::ConfigManager<Configuration::ApplianceValues> &config_manager,
                           struct smartphone_app_connection_data *appconn,
                           struct DBusSignalManagerData **connman,
                           struct dcp_over_tcp_data *dot, bool is_upgrading)
{
    configproxy_init();

    Configuration::register_configuration_manager(config_manager);
    register_own_config_keys(config_manager);
    config_manager.load();

    static const char network_preferences_dir[] = "/var/local/etc";
    static const char network_preferences_file[] = "network.ini";
    static const char connman_config_dir[] = "/var/local/etc/connman";
    static char network_preferences_full_file[sizeof(network_preferences_dir) +
                                              sizeof(network_preferences_file)];

    snprintf(network_preferences_full_file, sizeof(network_preferences_full_file),
             "%s/%s", network_preferences_dir, network_preferences_file);

    network_prefs_init(network_preferences_dir, network_preferences_full_file);

    dcpregs_appliance_id_init();

    if(!is_upgrading)
        network_prefs_migrate_old_network_configuration_files(connman_config_dir);

    register_init(push_register_to_slave);
    dcpregs_filetransfer_set_picture_provider(dcpregs_playstream_get_picture_provider());

    transaction_init_allocator();

    *connman = dbussignal_connman_manager_init(try_connect_to_managed_wlan,
                                               deferred_connman_refresh,
                                               parameters->with_connman);

    applink_init();

    bool ret = true;

    if(appconn_init(appconn, process_smartphone_outgoing_queue) < 0)
        ret = false;

    if(dot_init(dot) < 0)
        ret = false;

    return ret;
}

/*!
 * Open devices, daemonize.
 */
static int setup(const struct parameters *parameters, struct files *files,
                 int *primitive_command_queue_read_fd,
                 int *reg_changed_read_fd)
{
    msg_enable_syslog(!parameters->run_in_foreground);
    msg_enable_glib_message_redirection();
    msg_set_verbose_level(parameters->verbose_level);

    if(!parameters->run_in_foreground)
        openlog("dcpd", LOG_PID, LOG_DAEMON);

    files->drcp_fifo.in_fd = files->drcp_fifo.out_fd =
        files->dcpspi_fifo.in_fd = files->dcpspi_fifo.out_fd = -1;
    *primitive_command_queue_read_fd = primitive_command_queue_write_fd = -1;
    *reg_changed_read_fd = register_changed_write_fd = -1;

    if(!parameters->run_in_foreground)
    {
        if(daemon(0, 0) < 0)
        {
            msg_error(errno, LOG_EMERG, "Failed to run as daemon");
            goto error_daemon;
        }
    }

    log_version_info();

    msg_vinfo(MESSAGE_LEVEL_DEBUG, "Attempting to open named pipes");

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

    int fds[2];

    if(pipe(fds) < 0)
    {
        msg_error(errno, LOG_ERR, "Failed creating pipe for smartphone");
        goto error_smartphone_pipe_to_self;
    }

    *primitive_command_queue_read_fd = fds[0];
    primitive_command_queue_write_fd = fds[1];

    if(pipe(fds) < 0)
    {
        msg_error(errno, LOG_ERR, "Failed creating pipe for register changes");
        goto error_regchange_pipe_to_self;
    }

    *reg_changed_read_fd = fds[0];
    register_changed_write_fd = fds[1];

    return 0;

error_smartphone_pipe_to_self:
error_regchange_pipe_to_self:
    fifo_close(&files->dcpspi_fifo.out_fd);

error_dcpspi_fifo_out:
    fifo_close_and_delete(&files->drcp_fifo.out_fd, files->drcp_fifo_out_name);

error_drcp_fifo_out:
    fifo_close_and_delete(&files->drcp_fifo.in_fd, files->drcp_fifo_in_name);

error_drcp_fifo_in:
    fifo_close(&files->dcpspi_fifo.in_fd);

error_daemon:
error_dcpspi_fifo_in:
    return -1;
}

/*!
 * Check whether or not opkg state is consistent, trigger update if not.
 */
static bool is_system_update_required(void)
{
    if(os_path_get_type("/tmp/dcpd_avoid_update_check.stamp") == OS_PATH_TYPE_FILE)
    {
        /* someone doesn't want us to do this check */
        return false;
    }

    const int result =
        os_system(true, "/bin/sh -c 'test -z \"$(sudo /usr/bin/opkg list-upgradable)\"'");

    return result != EXIT_SUCCESS;
}

static void push_register_to_nowhere(uint8_t reg_number) {}

static int trigger_system_upgrade(bool is_enforced)
{
    msg_set_verbose_level(MESSAGE_LEVEL_INFO_MAX);

    if(is_enforced)
    {
        msg_info("**** Forced system upgrade ****");
        os_file_close(os_file_new("/tmp/force_system_upgrade.stamp"));
    }
    else
        msg_info("**** Incomplete or broken upgrade state detected ****");

    register_init(push_register_to_nowhere);

    static const uint8_t update_command[] =
    {
        HCR_COMMAND_CATEGORY_UPDATE_FROM_INET,
        HCR_COMMAND_UPDATE_MAIN_SYSTEM,
    };

    if(dcpregs_write_40_download_control(update_command,
                                         sizeof(update_command)) != 0)
        return EXIT_FAILURE;

    sleep(60);

    return EXIT_SUCCESS;
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
           "  --version      Print version information to stdout.\n"
           "  --fg           Run in foreground, don't run as daemon.\n"
           "  --verbose lvl  Set verbosity level to given level.\n"
           "  --quiet        Short for \"--verbose quite\".\n"
           "  --ispi  name   Name of the named pipe the DCPSPI daemon writes to.\n"
           "  --ospi  name   Name of the named pipe the DCPSPI daemon reads from.\n"
           "  --idrcp name   Name of the named pipe the DRCP daemon writes to.\n"
           "  --odrcp name   Name of the named pipe the DRCP daemon reads from.\n"
           "  --no-connman   Disable use of Connman (no network support).\n"
           "  --upgrade      Enforce upgrading the system.\n"
           "  --force-upgrade  No, really do it regardless of circumstances.\n"
           "  --session-dbus Connect to session D-Bus.\n"
           "  --system-dbus  Connect to system D-Bus.\n",
           program_name);
}

static int process_command_line(int argc, char *argv[],
                                struct parameters *parameters,
                                struct files *files)
{
    parameters->verbose_level = MESSAGE_LEVEL_NORMAL;
    parameters->run_in_foreground = false;
    parameters->connect_to_session_dbus = true;
    parameters->with_connman = true;
    parameters->is_fixing_broken_update_state = false;
    parameters->is_upgrade_enforced = false;
    parameters->is_upgrade_strongly_enforced = false;

    files->dcpspi_fifo_in_name = "/tmp/spi_to_dcp";
    files->dcpspi_fifo_out_name = "/tmp/dcp_to_spi";
    files->drcp_fifo_in_name = "/tmp/drcpd_to_dcpd";
    files->drcp_fifo_out_name = "/tmp/dcpd_to_drcpd";

    bool seen_unknown_parameters = false;

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
        else if(strcmp(argv[i], "--version") == 0)
            return 2;
        else if(strcmp(argv[i], "--fg") == 0)
            parameters->run_in_foreground = true;
        else if(strcmp(argv[i], "--verbose") == 0)
        {
            CHECK_ARGUMENT();
            parameters->verbose_level = msg_verbose_level_name_to_level(argv[i]);

            if(parameters->verbose_level == MESSAGE_LEVEL_IMPOSSIBLE)
            {
                fprintf(stderr,
                        "Invalid verbosity \"%s\". "
                        "Valid verbosity levels are:\n", argv[i]);

                const char *const *names = msg_get_verbose_level_names();

                for(const char *name = *names; name != NULL; name = *++names)
                    fprintf(stderr, "    %s\n", name);

                return -1;
            }
        }
        else if(strcmp(argv[i], "--quiet") == 0)
            parameters->verbose_level = MESSAGE_LEVEL_QUIET;
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
        else if(strcmp(argv[i], "--no-connman") == 0)
            parameters->with_connman = false;
        else if(strcmp(argv[i], "--upgrade") == 0)
            parameters->is_upgrade_enforced = true;
        else if(strcmp(argv[i], "--force-upgrade") == 0)
        {
            parameters->is_upgrade_enforced = true;
            parameters->is_upgrade_strongly_enforced = true;
        }
        else
        {
            fprintf(stderr, "Unknown option \"%s\". Please try --help.\n", argv[i]);
            seen_unknown_parameters = true;
        }
    }

#undef CHECK_ARGUMENT

    if(seen_unknown_parameters && parameters->run_in_foreground)
        return -1;

    return 0;
}

static void signal_handler(int signum, siginfo_t *info, void *ucontext)
{
    keep_running = false;
}

static bool delay_seconds(int seconds)
{
    while(seconds > 0)
    {
        if(!keep_running)
            return false;

        static const struct timespec one_second = { .tv_sec = 1, };
        os_nanosleep(&one_second);

        --seconds;
    }

    return true;
}

static void *update_watchdog_main(void *user_data)
{
    msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
              "UPDOG: Update in progress, watching opkg");

    sigset_t sigset;

    sigfillset(&sigset);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);

    bool is_opkg_running = true;

    for(int tries = 90; tries > 0; --tries)
    {
        if(os_system(false, "/usr/bin/pgrep opkg") != EXIT_SUCCESS)
        {
            is_opkg_running = false;
            break;
        }

        if(!keep_running)
            break;

        if(tries > 1)
        {
            msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                      "UPDOG: Opkg still running, check again later...");

            if(!delay_seconds(10))
                break;
        }
    }

    if(keep_running)
    {
        if(is_opkg_running)
            msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                      "UPDOG: Opkg is STILL running, rebooting now");
        else
        {
            msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                      "UPDOG: Opkg is not running anymore, rebooting soon");

            /* we should give the system some time to shut down by itself in
             * case opkg has just finished and shutdown is already in progress
             * anyway */
            delay_seconds(60);
        }
    }

    if(!keep_running)
    {
        /* we've been killed */
        msg_vinfo(MESSAGE_LEVEL_IMPORTANT, "UPDOG: Killed, shutting down");
        return NULL;
    }

    /*
     * We have checked on that opkg process for 15 minutes, but it doesn't seem
     * to make any progress. Also, no one has terminated us. Pull the emergency
     * brake and restart.
     */
    dcpregs_hcr_send_shutdown_request(false);

    return NULL;
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
    else if(ret == 2)
    {
        show_version_info();
        return EXIT_SUCCESS;
    }

    /*!
     * File descriptor for write notifications to smartphone apps.
     *
     * The fd always reads 0. The only purpose of this pipe is to break the
     * poll(2) in the main loop so that the smartphone app protocol code can
     * process its output queue.
     */
    int primitive_queue_fd;

    /*!
     * File descriptor from which register changes can be read.
     *
     * The fd is supposed to be read byte by byte. Each byte corresponds to a
     * register that has changed and whose content should be pushed to the
     * slave.
     */
    int register_changed_fd;

    if(setup(&parameters, &files, &primitive_queue_fd, &register_changed_fd) < 0)
        parameters.is_fixing_broken_update_state = true;

    const bool is_upgrading = dcpregs_hcr_is_system_update_in_progress();

    if(is_upgrading)
    {
        /* revert the possible decision to fix a broken state as we are in the
         * middle of an update and things may not be as they should be under
         * normal conditions; only do it if really forced to */
        parameters.is_fixing_broken_update_state = false;
        parameters.is_upgrade_enforced = parameters.is_upgrade_strongly_enforced;
        push_register_filter_set(17);
    }

    if(!is_upgrading && !parameters.is_fixing_broken_update_state &&
       !parameters.is_upgrade_enforced)
        parameters.is_fixing_broken_update_state = is_system_update_required();

    if(parameters.is_fixing_broken_update_state ||
       parameters.is_upgrade_enforced)
        return trigger_system_upgrade(parameters.is_upgrade_enforced);

    if(is_upgrading)
    {
        errno = 0;

        static pthread_t th;

        if(pthread_create(&th, NULL, update_watchdog_main, NULL) != 0)
            msg_error(errno, LOG_ERR,
                      "Failed creating update script watchdog thread");
        else
            pthread_detach(th);
    }

    /*!
     * Data for smartphone connection.
     */
    static struct smartphone_app_connection_data appconn;

    /*!
     * Data for net.connman.Manager D-Bus signal handlers.
     */
    static struct DBusSignalManagerData *connman;

    /*!
     * Data for de.tahifi.Configuration interfaces.
     */
    static const char appliance_ini_file[] = "/var/local/etc/appliance.ini";
    static Configuration::ApplianceValues appliance_ini_defaults(
                std::move(std::string("!unknown!")));
    Configuration::ConfigManager<Configuration::ApplianceValues>
        config_manager(appliance_ini_file, appliance_ini_defaults);

    /*!
     * Data for handling DCP over TCP/IP.
     */
    static struct dcp_over_tcp_data dot;

    main_loop_init(&parameters, config_manager, &appconn, &connman, &dot, is_upgrading);

    if(dbus_setup(parameters.connect_to_session_dbus,
                  parameters.with_connman, &appconn, connman,
                  reinterpret_cast<struct ConfigurationManagementData *>(&config_manager)) < 0)
    {
        shutdown(&files);
        return EXIT_FAILURE;
    }

    static struct sigaction action;

    action.sa_sigaction = signal_handler;
    action.sa_flags = SA_SIGINFO | SA_RESETHAND;

    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    if(parameters.with_connman)
        connman_wlan_power_on();

    dbus_lock_shutdown_sequence("Notify SPI slave");

    dcpregs_appliance_id_configure();

    main_loop(&files, &dot, &appconn, connman,
              primitive_queue_fd, register_changed_fd);

    msg_vinfo(MESSAGE_LEVEL_IMPORTANT, "Shutting down");

    dot_close(&dot);
    appconn_close(&appconn);

    shutdown(&files);
    dbus_unlock_shutdown_sequence();
    dbus_shutdown();
    register_deinit();
    network_prefs_deinit();
    configproxy_deinit();

    return EXIT_SUCCESS;
}
