/*
 * Copyright (C) 2015--2022  T+A elektroakustik GmbH & Co. KG
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

#include "named_pipe.h"
#include "dcp_over_tcp.h"
#include "smartphone_app.hh"
#include "network_dispatcher.hh"
#include "mainloop.hh"
#include "messages.h"
#include "messages_glib.h"
#include "transactions.hh"
#include "drcp.hh"
#include "dbus_iface.hh"
#include "dbus_handlers_connman_manager.hh"
#include "registers.hh"
#include "dcpregs_appliance.hh"
#include "dcpregs_status.hh"
#include "dcpregs_filetransfer.hh"
#include "dcpregs_filetransfer_priv.h"
#include "dcpregs_audiosources.hh"
#include "dcpregs_playstream.hh"
#include "dcpregs_upnpname.hh"
#include "dcpregs_upnpserver.hh"
#include "dcpregs_accesspoint.hh"
#include "connman_scan.hh"
#include "networkprefs.h"
#include "accesspoint_manager.hh"
#include "rest_api.hh"
#include "ethernet_connection_workaround.hh"
#include "configproxy.h"
#include "configuration_dcpd.hh"
#include "configuration.hh"
#include "os.h"
#include "versioninfo.h"

#include <string>
#include <cstdio>
#include <cstring>
#include <csignal>
#include <cerrno>
#include <glib.h>

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

/* internal events */
#define WAITEVENT_REGISTER_CHANGED                      (1U << 9)
#define WAITEVENT_SMARTPHONE_QUEUE_HAS_COMMANDS         (1U << 10)
#define WAITEVENT_CONNECT_TO_WLAN_REQUESTED             (1U << 11)
#define WAITEVENT_REFRESH_CONNMAN_SERVICES_REQUESTED    (1U << 12)
#define WAITEVENT_QUEUED_WORK_AVAILABLE                 (1U << 13)

enum PrimitiveQueueCommand
{
    PRIMITIVE_QUEUECMD_PROCESS_APP_QUEUE,
    PRIMITIVE_QUEUECMD_CONNECT_TO_MANAGED_WLAN,
    PRIMITIVE_QUEUECMD_REFRESH_CONNMAN_SERVICES,
    PRIMITIVE_QUEUECMD_PROCESS_QUEUED_WORK,
};

/*!
 * Global state of the DCP machinery.
 */
struct DCPDState
{
    /*!
     * The transaction that is currently going on between dcpspi and dcpd.
     *
     * If this pointer is nullptr, then there is no transaction going on,
     * meaning that the DCP is in idle state.
     */
    std::unique_ptr<TransactionQueue::Transaction> active_transaction;

    /*!
     * A queue of transactions initiated by the master.
     */
    TransactionQueue::Queue master_transaction_queue;

    /*!
     * String for holding XML data from drcpd.
     *
     * This string is filled while receiving XML data from drcpd. As soon as
     * drcpd is finished, one or more transactions are constructed and queued
     * in the #DCPDState::master_transaction_queue queue.
     */
    std::string drcp_buffer;
    size_t drcp_buffer_expected_size;

    /*!
     * Pointer to an immortal SPI slave transaction object.
     *
     * This is allocated on startup and never freed. We just want to make sure
     * that there is always space for the single slave transaction that may be
     * active at a time.
     */
    std::unique_ptr<TransactionQueue::Transaction> preallocated_spi_slave_transaction;
    TransactionQueue::Transaction *preallocated_spi_slave_transaction_raw_pointer;

    /*!
     * Pointer to an immortal network slave transaction object.
     */
    std::unique_ptr<TransactionQueue::Transaction> preallocated_inet_slave_transaction;
    TransactionQueue::Transaction *preallocated_inet_slave_transaction_raw_pointer;
};

ssize_t (*os_read)(int fd, void *dest, size_t count) = read;
ssize_t (*os_write)(int fd, const void *buf, size_t count) = write;
int (*os_poll)(struct pollfd *fds, nfds_t nfds, int timeout) = poll;

#if LOGGED_LOCKS_ENABLED && LOGGED_LOCKS_THREAD_CONTEXTS
thread_local LoggedLock::Context LoggedLock::context;
#endif

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

static void show_version_info()
{
    printf("%s\n"
           "Revision %s%s\n"
           "         %s+%d, %s\n",
           PACKAGE_STRING,
           VCS_FULL_HASH, VCS_WC_MODIFIED ? " (tainted)" : "",
           VCS_TAG, VCS_TICK, VCS_DATE);
}

static void log_version_info()
{
    msg_vinfo(MESSAGE_LEVEL_IMPORTANT, "Rev %s%s, %s+%d, %s",
              VCS_FULL_HASH, VCS_WC_MODIFIED ? " (tainted)" : "",
              VCS_TAG, VCS_TICK, VCS_DATE);
}

static void schedule_transaction(DCPDState &state, std::unique_ptr<TransactionQueue::Transaction> t)
{
    msg_log_assert(state.active_transaction == nullptr);

    if(t != nullptr)
        state.active_transaction = std::move(t);
}

static void try_dequeue_next_transaction(DCPDState &state)
{
    if(state.active_transaction != nullptr)
        return;

    if(!state.master_transaction_queue.empty())
        schedule_transaction(state, state.master_transaction_queue.pop());
}

static unsigned int try_schedule_slave_transaction(DCPDState &state,
                                                   std::unique_ptr<TransactionQueue::Transaction> &t,
                                                   unsigned int retcode)
{
    if(state.active_transaction != nullptr)
        return retcode;

    msg_log_assert(t != nullptr);

    t->reset_for_slave();

    /* bypass queue because slave requests always have priority */
    schedule_transaction(state, std::move(t));

    return retcode;
}

static unsigned int handle_dcp_fifo_in_events(int fd, short revents,
                                              DCPDState &state)
{
    unsigned int result = 0;

    if(revents & POLLIN)
        result |= try_schedule_slave_transaction(state,
                                                 state.preallocated_spi_slave_transaction,
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
                                           DCPDState &state)
{
    unsigned int result = 0;

    if((revents & POLLIN) && network_have_data(fd))
        result |= try_schedule_slave_transaction(state,
                                                 state.preallocated_inet_slave_transaction,
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
                    static_cast<enum PrimitiveQueueCommand>(commands[i]);

                switch(cmd)
                {
                  case PRIMITIVE_QUEUECMD_PROCESS_APP_QUEUE:
                    result |= WAITEVENT_SMARTPHONE_QUEUE_HAS_COMMANDS;
                    break;

                  case PRIMITIVE_QUEUECMD_CONNECT_TO_MANAGED_WLAN:
                    result |= WAITEVENT_CONNECT_TO_WLAN_REQUESTED;
                    break;

                  case PRIMITIVE_QUEUECMD_REFRESH_CONNMAN_SERVICES:
                    result |= WAITEVENT_REFRESH_CONNMAN_SERVICES_REQUESTED;
                    break;

                  case PRIMITIVE_QUEUECMD_PROCESS_QUEUED_WORK:
                    result |= WAITEVENT_QUEUED_WORK_AVAILABLE;
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

static unsigned int wait_for_events(DCPDState &state,
                                    const int drcp_fifo_in_fd,
                                    const int dcpspi_fifo_in_fd,
                                    const int dcp_server_socket_fd,
                                    const int dcp_peer_socket_fd,
                                    const int primitive_queue_fd,
                                    const int register_changed_fd,
                                    bool do_block)
{
    const auto &nwdispatcher(Network::Dispatcher::get_singleton());

    /*
     * Local constant for array layout below.
     */
    static constexpr size_t FIRST_NWDISPATCH_INDEX = 6;

    std::vector<struct pollfd> fds(FIRST_NWDISPATCH_INDEX + nwdispatcher.get_number_of_fds());

    fds[0] = {dcpspi_fifo_in_fd,    POLLIN, 0};
    fds[1] = {drcp_fifo_in_fd,      POLLIN, 0};
    fds[2] = {dcp_server_socket_fd, POLLIN, 0};
    fds[3] = {dcp_peer_socket_fd,   POLLIN, 0};
    fds[4] = {primitive_queue_fd,   POLLIN, 0};
    fds[5] = {register_changed_fd,  POLLIN, 0};

    nwdispatcher.scatter_fds(&fds[FIRST_NWDISPATCH_INDEX], POLLIN);

    int ret = os_poll(fds.data(), fds.size(), do_block ? -1 : 0);

    if(ret <= 0)
    {
        if(ret == 0)
            return WAITEVENT_POLL_TIMEOUT;

        if(errno != EINTR)
            msg_error(errno, LOG_CRIT, "poll() failed");

        return WAITEVENT_POLL_ERROR;
    }

    nwdispatcher.process(&fds[FIRST_NWDISPATCH_INDEX]);

    unsigned int return_value = 0;

    return_value |= handle_dcp_fifo_in_events(dcpspi_fifo_in_fd,   fds[0].revents, state);
    return_value |= handle_dcp_fifo_out_events(drcp_fifo_in_fd,    fds[1].revents);
    return_value |= handle_dcp_server_events(dcp_server_socket_fd, fds[2].revents);
    return_value |= handle_dcp_peer_events(dcp_peer_socket_fd,     fds[3].revents, state);
    return_value |= handle_primqueue_events(primitive_queue_fd,    fds[4].revents);
    return_value |= handle_register_events(register_changed_fd,    fds[5].revents);

    return return_value;
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

static bool process_drcp_input(DCPDState &state,
                               TransactionQueue::Channel channel)
{
    if(state.drcp_buffer.empty())
    {
        msg_error(EINVAL, LOG_NOTICE, "Received empty DRCP buffer");
        return false;
    }

    auto fragments(TransactionQueue::fragments_from_data(
            state.master_transaction_queue,
            reinterpret_cast<const uint8_t *>(state.drcp_buffer.data()),
            state.drcp_buffer.size(), 71, channel));
    return state.master_transaction_queue.append(std::move(fragments));
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

static void terminate_active_transaction(DCPDState &state,
                                         struct dcp_over_tcp_data *dot)
{
    switch(state.active_transaction->get_channel())
    {
      case TransactionQueue::Channel::SPI:
        break;

      case TransactionQueue::Channel::INET:
        if(!network_have_data(dot->peer_fd))
            dot_close_peer(dot);

        break;
    }

    if(!state.active_transaction->is_pinned())
        state.active_transaction = nullptr;
    else
    {
        if(state.active_transaction.get() == state.preallocated_spi_slave_transaction_raw_pointer)
            state.preallocated_spi_slave_transaction = std::move(state.active_transaction);
        else if(state.active_transaction.get() == state.preallocated_inet_slave_transaction_raw_pointer)
            state.preallocated_inet_slave_transaction = std::move(state.active_transaction);
        else
        {
            MSG_BUG("Unknown pinned active transaction %p",
                    static_cast<const void *>(state.active_transaction.get()));
            state.active_transaction = nullptr;
        }
    }
}

static bool handle_reopen_connections(unsigned int wait_result,
                                      struct files *files,
                                      struct dcp_over_tcp_data *dot,
                                      DCPDState &state)
{
    if((wait_result & (WAITEVENT_DRCP_CONNECTION_DIED |
                       WAITEVENT_DCP_CONNECTION_DIED)) == 0)
        return true;

    if(state.active_transaction != nullptr)
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

MainLoop::Queue MainLoop::detail::queued_work;

static void handle_queued_work(unsigned int wait_result)
{
    if((wait_result & WAITEVENT_QUEUED_WORK_AVAILABLE) == 0)
        return;

    const auto work(MainLoop::detail::queued_work.take());

    for(const auto &fn : work)
        fn();
}

static void handle_register_change(unsigned int wait_result, int fd,
                                   DCPDState &state)
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
        TransactionQueue::push_register_to_slave(state.master_transaction_queue,
                                                 reg_number,
                                                 TransactionQueue::Channel::SPI);
}

static void handle_connman_manager_events(unsigned int wait_result,
                                          Connman::WLANManager &wman)
{
    if((wait_result & WAITEVENT_REFRESH_CONNMAN_SERVICES_REQUESTED) != 0)
        Connman::refresh_services();

    if((wait_result & WAITEVENT_CONNECT_TO_WLAN_REQUESTED) != 0)
        Connman::connect_our_wlan(wman);
}

static struct
{
    bool is_filter_active;
    std::array<uint32_t, 8> regs;
}
push_register_filter;

static void push_register_filter_set(uint8_t reg_number)
{
    const uint32_t mask = 1U << (reg_number & 0x1f);

    push_register_filter.is_filter_active = true;
    push_register_filter.regs[reg_number >> 5] |= mask;
    msg_info("Blocking emission of register %u", reg_number);
}

static void push_register_filter_clear(uint8_t reg_number)
{
    const uint32_t mask = 1U << (reg_number & 0x1f);

    push_register_filter.regs[reg_number >> 5] &= ~mask;
    push_register_filter.is_filter_active =
        std::any_of(push_register_filter.regs.begin(),
                    push_register_filter.regs.end(),
                    [] (const auto &r) { return r != 0; });
    msg_info("Allowing emission of register %u", reg_number);
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
    const uint8_t cmd_as_byte = static_cast<uint8_t>(cmd);
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

void MainLoop::detail::notify_main_loop()
{
    primitive_queue_send(PRIMITIVE_QUEUECMD_PROCESS_QUEUED_WORK,
                         "processing queued work");
}

static void process_smartphone_outgoing_queue(int fd)
{
    primitive_queue_send(PRIMITIVE_QUEUECMD_PROCESS_APP_QUEUE,
                         "processing smartphone queue");
}

static void try_connect_to_managed_wlan()
{
    primitive_queue_send(PRIMITIVE_QUEUECMD_CONNECT_TO_MANAGED_WLAN,
                         "connecting to WLAN");
}

static void deferred_connman_refresh()
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
static void replace_active_transaction(DCPDState &state,
                                       std::unique_ptr<TransactionQueue::Transaction> new_active)
{
    state.master_transaction_queue.prepend(std::move(state.active_transaction));
    state.active_transaction = std::move(new_active);
}

/*!
 * Possibly replace active transaction by some other transaction.
 */
static void handle_transaction_exception(DCPDState &state,
                                         TransactionQueue::ProtocolException &&e)
{
    msg_log_assert(state.active_transaction != nullptr);

    std::unique_ptr<TransactionQueue::Transaction> t(nullptr);
    auto result = TransactionQueue::ProcessResult::ERROR;

    if(auto *collision = dynamic_cast<TransactionQueue::CollisionException *>(&e))
    {
        /* colliding slave transaction must be processed next because there
         * might be more data in the pipe buffer that belongs to the
         * transaction */
        msg_log_assert(collision->transaction_ != nullptr);
        msg_log_assert(collision->transaction_ != state.active_transaction);

        replace_active_transaction(state, std::move(collision->transaction_));

        /* avoid false BUG message */
        result = TransactionQueue::ProcessResult::IN_PROGRESS;
    }
    else if(auto *oooack = dynamic_cast<TransactionQueue::OOOAckException *>(&e))
    {
        bool applied = false;
        result = state.master_transaction_queue.apply_to_dcpsync_serial(
                        oooack->serial_,
                        [oooack, &applied]
                        (TransactionQueue::Transaction &tr)
                        {
                            applied = true;
                            return tr.process_out_of_order_ack(*oooack);
                        });

        if(!applied)
        {
            MSG_BUG("Packet serial 0x%04x unknown, dropping out-of-order ACK",
                    oooack->serial_);
            result = TransactionQueue::ProcessResult::ERROR;
        }
    }
    else if(auto *ooonack = dynamic_cast<TransactionQueue::OOONackException *>(&e))
    {
        bool applied = false;
        result = state.master_transaction_queue.apply_to_dcpsync_serial(
                        ooonack->serial_,
                        [ooonack, &applied]
                        (TransactionQueue::Transaction &tr)
                        {
                            applied = true;
                            return tr.process_out_of_order_nack(*ooonack);
                        });

        if(!applied)
        {
            MSG_BUG("Packet serial 0x%04x unknown, dropping out-of-order NACK",
                    ooonack->serial_);
            result = TransactionQueue::ProcessResult::ERROR;
        }
    }

    switch(result)
    {
      case TransactionQueue::ProcessResult::IN_PROGRESS:
        break;

      case TransactionQueue::ProcessResult::PUSH_BACK:
      case TransactionQueue::ProcessResult::FINISHED:
      case TransactionQueue::ProcessResult::ERROR:
        MSG_BUG("Unimplemented outcome of transaction exception handling");
        break;
    }
}

/*!
 * Process DCP.
 */
static void main_loop(struct files *files,
                      struct dcp_over_tcp_data *dot,
                      Applink::AppConnections &appconn,
                      Connman::WLANManager &connman, bool is_upgrading,
                      int primitive_queue_fd, int register_changed_fd)
{
    static struct DCPDState state;

    state.preallocated_spi_slave_transaction =
        TransactionQueue::Transaction::new_for_queue(
            state.master_transaction_queue,
            TransactionQueue::InitialType::SLAVE_BY_SLAVE,
            TransactionQueue::Channel::SPI,
            TransactionQueue::Transaction::Pinned::INTENDED_AS_PREALLOCATED);
    state.preallocated_spi_slave_transaction_raw_pointer = state.preallocated_spi_slave_transaction.get();

    state.preallocated_inet_slave_transaction =
        TransactionQueue::Transaction::new_for_queue(
            state.master_transaction_queue,
            TransactionQueue::InitialType::SLAVE_BY_SLAVE,
            TransactionQueue::Channel::INET,
            TransactionQueue::Transaction::Pinned::INTENDED_AS_PREALLOCATED);
    state.preallocated_inet_slave_transaction_raw_pointer = state.preallocated_inet_slave_transaction.get();

    state.drcp_buffer.clear();
    state.drcp_buffer_expected_size = 0;

    Regs::StrBoStatus::set_ready(is_upgrading, false);

    msg_info("Ready for accepting traffic");

    while(keep_running)
    {
        const unsigned int wait_result =
            wait_for_events(state,
                            files->drcp_fifo.in_fd, files->dcpspi_fifo.in_fd,
                            dot->server_fd, dot->peer_fd,
                            primitive_queue_fd, register_changed_fd,
                            state.active_transaction == nullptr ||
                            state.active_transaction->is_input_required());

        if((wait_result & WAITEVENT_POLL_ERROR) != 0)
            continue;

        if((wait_result & WAITEVENT_CAN_READ_DRCP) != 0)
        {
            if(Drcp::determine_xml_size(files->drcp_fifo.in_fd, state.drcp_buffer,
                                        state.drcp_buffer_expected_size) &&
               Drcp::read_xml(files->drcp_fifo.in_fd, state.drcp_buffer,
                              state.drcp_buffer_expected_size))
            {
                if(state.drcp_buffer.size() >= state.drcp_buffer_expected_size)
                {
                    Drcp::finish_request(files->drcp_fifo.out_fd,
                                         process_drcp_input(state,
                                                            TransactionQueue::Channel::SPI));
                    state.drcp_buffer.clear();
                    state.drcp_buffer_expected_size = 0;
                }
            }
            else
            {
                Drcp::finish_request(files->drcp_fifo.out_fd, false);
                state.drcp_buffer.clear();
                state.drcp_buffer_expected_size = 0;
            }
        }

        if(!handle_reopen_connections(wait_result, files, dot, state))
        {
            keep_running = false;
            continue;
        }

        handle_queued_work(wait_result);

        handle_register_change(wait_result, register_changed_fd, state);

        handle_connman_manager_events(wait_result, connman);

        if((wait_result & WAITEVENT_CAN_READ_FROM_SERVER_SOCKET) != 0)
            dot_handle_incoming(dot);

        dot_handle_outgoing(dot,
                            (wait_result & WAITEVENT_CAN_READ_DCP_FROM_PEER_SOCKET) != 0,
                            (wait_result & WAITEVENT_DCP_CONNECTION_PEER_SOCKET_DIED) != 0);

        if((wait_result & WAITEVENT_SMARTPHONE_QUEUE_HAS_COMMANDS) != 0)
            appconn.process_out_queue();

        try_dequeue_next_transaction(state);

        if(state.active_transaction == nullptr)
            continue;

        int in_fd = -1;
        int out_fd = -1;
        enum MessageVerboseLevel dump_sent_data_verbose_level = MESSAGE_LEVEL_TRACE;

        switch(state.active_transaction->get_channel())
        {
          case TransactionQueue::Channel::SPI:
            in_fd = files->dcpspi_fifo.in_fd;
            out_fd = files->dcpspi_fifo.out_fd;
            break;

          case TransactionQueue::Channel::INET:
            in_fd = dot->peer_fd;
            out_fd = dot->peer_fd;
            dump_sent_data_verbose_level = MESSAGE_LEVEL_NORMAL;
            break;
        }

        try
        {
            switch(state.active_transaction->process(
                        in_fd, out_fd,
                        msg_is_verbose(dump_sent_data_verbose_level)
                        ? (TransactionQueue::DUMP_SENT_DCP_HEADER |
                           TransactionQueue::DUMP_SENT_DCP_PAYLOAD |
                           TransactionQueue::DUMP_SENT_MERGE_ALL)
                        : TransactionQueue::DUMP_SENT_NONE))
            {
              case TransactionQueue::ProcessResult::IN_PROGRESS:
                break;

              case TransactionQueue::ProcessResult::PUSH_BACK:
                state.master_transaction_queue.append(std::move(state.active_transaction));
                try_dequeue_next_transaction(state);
                break;

              case TransactionQueue::ProcessResult::FINISHED:
              case TransactionQueue::ProcessResult::ERROR:
                terminate_active_transaction(state, dot);
                try_dequeue_next_transaction(state);
                break;
            }
        }
        catch(TransactionQueue::ProtocolException &e)
        {
            handle_transaction_exception(state, std::move(e));
        }
    }

    state.preallocated_spi_slave_transaction = nullptr;
    state.preallocated_inet_slave_transaction = nullptr;
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
    Connman::Mode with_connman;
};

static bool main_loop_init(const struct parameters *parameters,
                           Configuration::ConfigManager<Configuration::ApplianceValues> &config_manager,
                           Applink::AppConnections &appconn,
                           Connman::WLANTools &wlan_tools,
                           Connman::WLANManager *&connman,
                           const Regs::PlayStream::StreamingRegistersIface &streaming_regs,
                           struct dcp_over_tcp_data *dot)
{
    Connman::set_networking_mode(parameters->with_connman);

    Regs::UPnPName::init();
    configproxy_init();

    Configuration::register_configuration_manager(config_manager);
    register_own_config_keys(config_manager);
    config_manager.load();

    static const char network_preferences_dir[] = "/var/local/etc";
    static const char network_preferences_file[] = "network.ini";
    static char network_preferences_full_file[sizeof(network_preferences_dir) +
                                              sizeof(network_preferences_file)];

    snprintf(network_preferences_full_file, sizeof(network_preferences_full_file),
             "%s/%s", network_preferences_dir, network_preferences_file);

    network_prefs_init(network_preferences_dir, network_preferences_full_file);

    Regs::Appliance::init();
    Regs::init(push_register_to_slave, &wlan_tools);
    Regs::FileTransfer::set_picture_provider(streaming_regs.get_picture_provider());

    connman = init_wlan_manager(try_connect_to_managed_wlan,
                                deferred_connman_refresh,
                                &wlan_tools);

    /*
     * The port number is ASCII "TB" (meaning T + A + 1).
     */
    bool ret = appconn.listen(8466);

    if(dot_init(dot) < 0)
        ret = false;

    Rest::init();

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

    LoggedLock::set_context_name("Main");

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
           "  --fake-connman Fake use of Connman (fake network support).\n"
           "  --enable-phy-reset  Periodically reset the Ethernet PHY\n"
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
    parameters->with_connman = Connman::Mode::REGULAR;

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

                for(const char *name = *names; name != nullptr; name = *++names)
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
            parameters->with_connman = Connman::Mode::NONE;
        else if(strcmp(argv[i], "--fake-connman") == 0)
            parameters->with_connman = Connman::Mode::FAKE_CONNMAN;
        else if(strcmp(argv[i], "--enable-phy-reset") == 0)
            EthernetConnectionWorkaround::required_on_this_kernel(true);
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

static gboolean check_update_progress(gpointer user_data)
{
    if(Regs::FileTransfer::hcr_is_system_update_in_progress())
        return TRUE;

    msg_info("System update completed");
    push_register_filter_clear(17);
    Regs::StrBoStatus::set_ready(false, true);
    return FALSE;
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
        return EXIT_FAILURE;

    const bool is_upgrading = Regs::FileTransfer::hcr_is_system_update_in_progress();

    if(is_upgrading)
    {
        push_register_filter_set(17);
        g_timeout_add(3000, check_update_progress, nullptr);
    }

    /*!
     * Data for smartphone connection.
     */
    static Applink::AppConnections appconn(process_smartphone_outgoing_queue);

    /*!
     * Data for net.connman.Manager D-Bus signal handlers.
     */
    static Connman::WLANManager *connman;

    /*!
     * Data for de.tahifi.Configuration interfaces.
     */
    static const char appliance_ini_file[] = "/var/local/etc/appliance.ini";
    static Configuration::ApplianceValues appliance_ini_defaults(
                std::move(std::string("!unknown!")),
                "", false);
    Configuration::ConfigManager<Configuration::ApplianceValues>
        config_manager(appliance_ini_file, appliance_ini_defaults);

    /*!
     * Data for handling DCP over TCP/IP.
     */
    static struct dcp_over_tcp_data dot;

    /*!
     * WLAN stuff
     */
    static Connman::TechnologyRegistry tech_reg;
    static Connman::WLANTools wlan_tools(tech_reg);
    static Network::AccessPoint ap(tech_reg);
    static Network::AccessPointManager apman(ap);
    static auto streaming_regs(Regs::PlayStream::mk_streaming_registers());

    main_loop_init(&parameters, config_manager, appconn, wlan_tools,
                   connman, *streaming_regs, &dot);

    if(connman == nullptr ||
       DBus::setup(parameters.connect_to_session_dbus,
                   parameters.with_connman == Connman::Mode::REGULAR,
                   appconn, *connman, config_manager, apman, *streaming_regs,
                   Regs::UPnPServer::connected,
                   Regs::AudioSources::check_external_service_credentials) < 0)
    {
        shutdown(&files);
        return EXIT_FAILURE;
    }

    tech_reg.connect_to_connman();
    tech_reg.register_property_watcher(
        [] (Connman::TechnologyPropertiesWIFI::Property property,
            Connman::TechnologyPropertiesBase::StoreResult result,
            Connman::TechnologyPropertiesWIFI &props)
        {
            switch(property)
            {
              case Connman::TechnologyPropertiesWIFI::Property::POWERED:
                if(!props.get<Connman::TechnologyPropertiesWIFI::Property::POWERED>())
                    wlan_tools.power_on();
                break;

              case Connman::TechnologyPropertiesWIFI::Property::CONNECTED:
              case Connman::TechnologyPropertiesWIFI::Property::NAME:
              case Connman::TechnologyPropertiesWIFI::Property::TYPE:
              case Connman::TechnologyPropertiesWIFI::Property::TETHERING:
              case Connman::TechnologyPropertiesWIFI::Property::TETHERING_IDENTIFIER:
              case Connman::TechnologyPropertiesWIFI::Property::TETHERING_PASSPHRASE:
                break;
            }
        });

    apman.start();

    Regs::WLANAccessPoint::init(apman, tech_reg);
    Regs::PlayStream::DCP::init(*streaming_regs);
    streaming_regs->late_init();

    static struct sigaction action;

    action.sa_sigaction = signal_handler;
    action.sa_flags = SA_SIGINFO | SA_RESETHAND;

    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, nullptr);
    sigaction(SIGTERM, &action, nullptr);

    switch(parameters.with_connman)
    {
      case Connman::Mode::REGULAR:
        wlan_tools.power_on();
        break;

      case Connman::Mode::NONE:
      case Connman::Mode::FAKE_CONNMAN:
        break;
    }

    DBus::lock_shutdown_sequence("Notify SPI slave");

    Regs::Appliance::configure();

    main_loop(&files, &dot, appconn, *connman, is_upgrading,
              primitive_queue_fd, register_changed_fd);

    msg_vinfo(MESSAGE_LEVEL_IMPORTANT, "Shutting down");

    dot_close(&dot);
    appconn.close();

    shutdown(&files);
    DBus::unlock_shutdown_sequence();
    DBus::shutdown();
    Regs::deinit();
    network_prefs_deinit();
    configproxy_deinit();

    return EXIT_SUCCESS;
}
