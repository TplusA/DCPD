#include <config.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>

#include "named_pipe.h"
#include "messages.h"
#include "transactions.h"
#include "dynamic_buffer.h"

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
     * Whether or not to free the active transaction after processing.
     *
     * This flag is invalid as long as the #state::active_transaction pointer
     * is NULL.
     */
    bool free_active_transaction;

    /*!
     * A queue of transactions initiated by the master.
     */
    struct transaction *master_transaction_queue;

    /*!
     * Pointer to a DRCP transaction that is currently constructed.
     *
     * This pointer in usually NULL and only points to a transaction object
     * while exchanging XML data with drcpd. As soon as the data is complete,
     * the constructed transaction is moved to the
     * #state::master_transaction_queue queue.
     */
    struct transaction *current_drcp_transaction;

    /*!
     * Whether or not the DRCP transaction is ready.
     *
     * While the #state::current_drcp_transaction is under construction, this
     * flag is false. When the object is complete and ready for execution, the
     * flag is set to true.
     *
     * This flag is invalid as long as the #state::current_drcp_transaction
     * pointer is NULL.
     */
    bool is_drcp_transaction_object_ready;

    /*!
     * Pointer to an immortal slave transaction object.
     *
     * This is allocated on startup and never freed. We just want to make sure
     * that there is always space for the single slave transaction that may be
     * active at a time.
     */
    struct transaction *preallocated_slave_transaction;
};

/*!
 * Global flag that gets cleared in the SIGTERM signal handler.
 *
 * For clean shutdown.
 */
static volatile bool keep_running = true;

static int read_to_buffer(uint8_t *dest, size_t count, int fd)
{
    while(count > 0)
    {
        ssize_t len = read(fd, dest, count);

        if(len < 0)
        {
            msg_error(errno, LOG_ERR, "Failed reading from fd %d", fd);
            return -1;
        }

        dest += len;
        count -= len;
    }

    return 0;
}

static struct transaction *begin_master_transaction(struct transaction **head,
                                                    uint8_t register_address)
{
    struct transaction *t = transaction_alloc(false);

    if(t == NULL)
    {
        msg_error(ENOMEM, LOG_CRIT, "DCP congestion: no free transaction slot");
        return NULL;
    }

    if(transaction_set_address_for_master(t, register_address))
        transaction_queue_add_one(head, t);
    else
        transaction_free(&t);

    return t;
}

/*!
 * \bug Not really implemented.
 */
static struct transaction *begin_drcp_transaction(int fd, bool *is_ready)
{
    *is_ready = false;

    struct transaction *t = NULL;

    /* FIXME: Must read from fd, don't hard-code 71 */
    if(begin_master_transaction(&t, 71) != NULL)
        return t;
    else
        return NULL;
}

static void end_active_transaction(struct state *state)
{
    transaction_queue_remove(&state->active_transaction);

    if(state->free_active_transaction)
        transaction_free(&state->active_transaction);

    state->active_transaction = NULL;
}

static void schedule_transaction(struct state *state, struct transaction *t,
                                 bool free_after_use)
{
    assert(state->active_transaction == NULL);

    if(t == NULL)
        return;

    state->active_transaction = t;
    state->free_active_transaction = free_after_use;
}

static void try_dequeue_next_transaction(struct state *state)
{
    if(state->active_transaction != NULL)
        return;

    if(state->master_transaction_queue != NULL)
        schedule_transaction(state,
                             transaction_queue_remove(&state->master_transaction_queue),
                             true);
}

static int wait_for_events(struct state *state, const int drcp_fifo_in_fd,
                           const int dcpspi_fifo_in_fd, bool do_block,
                           bool *can_read_drcp, bool *can_read_dcpspi)
{
    *can_read_drcp = false;
    *can_read_dcpspi = false;

    struct pollfd fds[2] =
    {
        {
            .fd = dcpspi_fifo_in_fd,
            .events = POLLIN,
        },
        {
            .fd = drcp_fifo_in_fd,
            .events = POLLIN,
        },
    };

    if(do_block)
        msg_info("Waiting for activities.");
    else
        msg_info("Checking for activities.");

    int ret = poll(fds, sizeof(fds) / sizeof(fds[0]), do_block ? -1 : 0);

    if(ret <= 0)
    {
        /* timeout? */
        if(ret == 0)
            return 2;

        if(errno != EINTR)
            msg_error(errno, LOG_CRIT, "poll() failed");

        return -1;
    }

    if(fds[0].revents & POLLIN)
    {
        msg_info("DCP input data");

        if(state->active_transaction == NULL)
        {
            transaction_reset_for_slave(state->preallocated_slave_transaction);

            /* bypass queue because slave requests always have priority */
            schedule_transaction(state, state->preallocated_slave_transaction, false);
        }
        else
        {
            msg_error(EAGAIN, LOG_NOTICE, "Slave request during transaction");
            *can_read_dcpspi = true;
        }
    }

    if(fds[0].revents & POLLHUP)
    {
        msg_error(0, LOG_ERR, "DCP daemon died, terminating");
        keep_running = false;
    }

    if(fds[0].revents & ~(POLLIN | POLLHUP))
        msg_error(EINVAL, LOG_WARNING,
                  "Unexpected poll() events on DCP fifo %d: %04x",
                  dcpspi_fifo_in_fd, fds[0].revents);

    if(fds[1].revents & POLLIN)
    {
        msg_info("DRCP input data");

        if(!state->current_drcp_transaction)
            state->current_drcp_transaction =
                begin_drcp_transaction(drcp_fifo_in_fd,
                                       &state->is_drcp_transaction_object_ready);
        else
            *can_read_drcp = true;
    }

    if(fds[1].revents & POLLHUP)
    {
        msg_error(0, LOG_ERR, "DRCP daemon died, terminating");
        keep_running = false;
    }

    if(fds[1].revents & ~(POLLIN | POLLHUP))
        msg_error(EINVAL, LOG_WARNING,
                  "Unexpected poll() events on DRCP fifo_fd %d: %04x",
                  drcp_fifo_in_fd, fds[1].revents);

    return keep_running ? ((*can_read_dcpspi || *can_read_drcp) ? 1 : 0) : -1;
}

static bool construct_drcp_transaction(struct state *state, int fd)
{
    if(state->current_drcp_transaction == NULL)
        return false;

    if(state->is_drcp_transaction_object_ready)
        return true;

    struct dynamic_buffer *payload =
        transaction_get_payload(state->current_drcp_transaction);

    /* FIXME: buffer is not allocated */
    /* FIXME: required buffer size should be taken from command header */
    if(read_to_buffer(payload->data, payload->size, fd) < 0)
        return false;

    return false;
}

/*!
 * Process DCP.
 */
static void main_loop(const int drcp_fifo_in_fd, const int drcp_fifo_out_fd,
                      const int dcpspi_fifo_in_fd, const int dcpspi_fifo_out_fd)
{
    static struct state state;

    state.preallocated_slave_transaction = transaction_alloc(true),

    msg_info("Ready for accepting traffic");

    while(keep_running)
    {
        msg_info("W active %p queue %p",
                 state.active_transaction, state.master_transaction_queue);

        bool can_read_drcp;
        bool can_read_dcpspi;
        const int wait_result =
            wait_for_events(&state,
                            drcp_fifo_in_fd, dcpspi_fifo_in_fd,
                            transaction_is_input_required(state.active_transaction),
                            &can_read_drcp, &can_read_dcpspi);

        if(wait_result < 0)
            continue;

        if(can_read_drcp && construct_drcp_transaction(&state, drcp_fifo_in_fd))
        {
            /* reading XML data complete, now stored in RAM */
            transaction_queue_add_one(&state.master_transaction_queue,
                                      state.current_drcp_transaction);
            state.current_drcp_transaction = NULL;
        }

        msg_info("w active %p queue %p",
                 state.active_transaction, state.master_transaction_queue);

        assert(state.active_transaction != NULL ||
               state.master_transaction_queue != NULL ||
               state.current_drcp_transaction != NULL);

        try_dequeue_next_transaction(&state);

        msg_info("D active %p queue %p",
                 state.active_transaction, state.master_transaction_queue);

        if(state.active_transaction == NULL)
            continue;

        switch(transaction_process(state.active_transaction,
                                   dcpspi_fifo_in_fd, dcpspi_fifo_out_fd))
        {
          case TRANSACTION_IN_PROGRESS:
            break;

          case TRANSACTION_FINISHED:
          case TRANSACTION_ERROR:
            end_active_transaction(&state);
            try_dequeue_next_transaction(&state);
            break;
        }
    }

    transaction_free(&state.preallocated_slave_transaction);
}

struct parameters
{
    const char *dcpspi_fifo_in_name;
    const char *dcpspi_fifo_out_name;
    const char *drcp_fifo_in_name;
    const char *drcp_fifo_out_name;
    bool run_in_foreground;
};

/*!
 * Open devices, daemonize.
 */
static int setup(const struct parameters *parameters,
                 int *drcp_fifo_in_fd, int *drcp_fifo_out_fd,
                 int *dcpspi_fifo_in_fd, int *dcpspi_fifo_out_fd)
{
    msg_enable_syslog(!parameters->run_in_foreground);

    if(!parameters->run_in_foreground)
        openlog("dcpd", LOG_PID, LOG_DAEMON);

    *dcpspi_fifo_in_fd = fifo_open(parameters->dcpspi_fifo_in_name, false);
    if(*dcpspi_fifo_in_fd < 0)
        goto error_dcpspi_fifo_in;

    *drcp_fifo_in_fd = fifo_create_and_open(parameters->drcp_fifo_in_name, false);
    if(*drcp_fifo_in_fd < 0)
        goto error_drcp_fifo_in;

    *drcp_fifo_out_fd = fifo_create_and_open(parameters->drcp_fifo_out_name, true);
    if(*drcp_fifo_out_fd < 0)
        goto error_drcp_fifo_out;

    *dcpspi_fifo_out_fd = fifo_open(parameters->dcpspi_fifo_out_name, true);
    if(*dcpspi_fifo_out_fd < 0)
        goto error_dcpspi_fifo_out;

    if(!parameters->run_in_foreground)
    {
        if(daemon(0, 0) < 0)
        {
            msg_error(errno, LOG_EMERG, "Failed to run as daemon");
            goto error_daemon;
        }
    }

    return 0;

error_daemon:
    fifo_close(*dcpspi_fifo_out_fd);

error_dcpspi_fifo_out:
    fifo_close_and_delete(*drcp_fifo_out_fd, parameters->drcp_fifo_out_name);

error_drcp_fifo_out:
    fifo_close_and_delete(*drcp_fifo_in_fd, parameters->drcp_fifo_in_name);

error_drcp_fifo_in:
    fifo_close(*dcpspi_fifo_in_fd);

error_dcpspi_fifo_in:
    return -1;
}

static void usage(const char *program_name)
{
    printf("Usage: %s --ififo name --ofifo name\n"
           "\n"
           "Options:\n"
           "  --ififo name   Name of the named pipe the DRCP daemon writes to.\n"
           "  --ofifo name   Name of the named pipe the DRCP daemon reads from.\n"
           "  --idcp  name   Name of the named pipe the DCP daemon reads from.\n"
           "  --odcp  name   Name of the named pipe the DCP daemon writes to.\n",
           program_name);
}

static int process_command_line(int argc, char *argv[],
                                struct parameters *parameters)
{
    parameters->drcp_fifo_in_name = "/tmp/drcpd_to_dcpd";
    parameters->drcp_fifo_out_name = "/tmp/dcpd_to_drcpd";
    parameters->dcpspi_fifo_in_name = "/tmp/spi_to_dcp";
    parameters->dcpspi_fifo_out_name = "/tmp/dcp_to_spi";
    parameters->run_in_foreground = true;

    return 0;
}

static void signal_handler(int signum, siginfo_t *info, void *ucontext)
{
    keep_running = false;
}

int main(int argc, char *argv[])
{
    static struct parameters parameters;

    int ret = process_command_line(argc, argv, &parameters);

    if(ret == -1)
        return EXIT_FAILURE;
    else if(ret == 1)
    {
        usage(argv[0]);
        return EXIT_SUCCESS;
    }

    int drcp_fifo_in_fd, drcp_fifo_out_fd;
    int dcpspi_fifo_in_fd, dcpspi_fifo_out_fd;

    if(setup(&parameters, &drcp_fifo_in_fd, &drcp_fifo_out_fd,
             &dcpspi_fifo_in_fd, &dcpspi_fifo_out_fd) < 0)
        return EXIT_FAILURE;

    static struct sigaction action =
    {
        .sa_sigaction = signal_handler,
        .sa_flags = SA_SIGINFO | SA_RESETHAND,
    };

    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    transaction_init_allocator();

    main_loop(drcp_fifo_in_fd, drcp_fifo_out_fd,
              dcpspi_fifo_in_fd, dcpspi_fifo_out_fd);

    msg_info("Terminated, shutting down");

    fifo_close_and_delete(drcp_fifo_in_fd, parameters.drcp_fifo_in_name);
    fifo_close_and_delete(drcp_fifo_out_fd, parameters.drcp_fifo_out_name);
    fifo_close(dcpspi_fifo_in_fd);
    fifo_close(dcpspi_fifo_out_fd);

    return EXIT_SUCCESS;
}
