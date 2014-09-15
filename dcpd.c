#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>

#include "named_pipe.h"
#include "messages.h"
#include "transactions.h"
#include "dynamic_buffer.h"

#define WAITEVENT_POLL_ERROR            (1U << 0)
#define WAITEVENT_POLL_TIMEOUT          (1U << 1)
#define WAITEVENT_CAN_READ_DCP          (1U << 2)
#define WAITEVENT_CAN_READ_DRCP         (1U << 3)
#define WAITEVENT_DCP_CONNECTION_DIED   (1U << 4)
#define WAITEVENT_DRCP_CONNECTION_DIED  (1U << 5)

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
     * Dynamically growing buffer for holding XML data from drcpd.
     *
     * This buffer is filled while receiving XML data from drcpd. As soon as
     * drcpd is finished, one or more transactions are constructed and queued
     * in the #state::master_transaction_queue queue.
     */
    struct dynamic_buffer drcp_buffer;

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

static struct transaction *mk_master_transaction(struct transaction **head,
                                                 uint8_t register_address)
{
    struct transaction *t = transaction_alloc(false);

    if(t == NULL)
    {
        msg_error(ENOMEM, LOG_CRIT, "DCP congestion: no free transaction slot");
        return NULL;
    }

    if(transaction_set_address_for_master(t, register_address))
        transaction_queue_add(head, t);
    else
        transaction_free(&t);

    return t;
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

static unsigned int wait_for_events(struct state *state,
                                    const int drcp_fifo_in_fd,
                                    const int dcpspi_fifo_in_fd,
                                    bool do_block)
{
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

    if(fds[0].revents & POLLIN)
    {
        if(state->active_transaction == NULL)
        {
            transaction_reset_for_slave(state->preallocated_slave_transaction);

            /* bypass queue because slave requests always have priority */
            schedule_transaction(state, state->preallocated_slave_transaction, false);
        }
        else
        {
            msg_error(EAGAIN, LOG_NOTICE, "Slave request during transaction");
            return_value |= WAITEVENT_CAN_READ_DCP;
        }
    }

    if(fds[0].revents & POLLHUP)
    {
        msg_error(EPIPE, LOG_ERR, "DCP daemon died, need to reopen");
        return_value |= WAITEVENT_DCP_CONNECTION_DIED;
    }

    if(fds[0].revents & ~(POLLIN | POLLHUP))
        msg_error(EINVAL, LOG_WARNING,
                  "Unexpected poll() events on DCP fifo %d: %04x",
                  dcpspi_fifo_in_fd, fds[0].revents);

    if(fds[1].revents & POLLIN)
        return_value |= WAITEVENT_CAN_READ_DRCP;

    if(fds[1].revents & POLLHUP)
    {
        msg_error(EPIPE, LOG_ERR, "DRCP daemon died, need to reopen");
        return_value |= WAITEVENT_DRCP_CONNECTION_DIED;
    }

    if(fds[1].revents & ~(POLLIN | POLLHUP))
        msg_error(EINVAL, LOG_WARNING,
                  "Unexpected poll() events on DRCP fifo_fd %d: %04x",
                  drcp_fifo_in_fd, fds[1].revents);

    return return_value;
}

static int try_read_to_buffer(struct dynamic_buffer *buffer, int fd)
{
    uint8_t *dest = buffer->data + buffer->pos;
    size_t count = buffer->size - buffer->pos;
    int retval = 0;

    while(count > 0)
    {
        const ssize_t len = read(fd, dest, count);

        if(len == 0)
            break;

        if(len < 0)
            return errno == EAGAIN ? 0 : -1;

        dest += len;
        count -= len;
        buffer->pos += len;
        retval = 1;
    }

    return retval;
}

static bool read_size_from_fd(struct dynamic_buffer *buffer, int fd,
                              size_t *expected_size, size_t *payload_offset)
{
    if(try_read_to_buffer(buffer, fd) < 0)
    {
        msg_error(errno, LOG_CRIT, "Reading XML size failed");
        return false;
    }

    static const char size_header[] = "Size: ";

    if(buffer->pos < sizeof(size_header))
    {
        msg_error(EINVAL, LOG_CRIT, "Too short input, expected XML size");
        return false;
    }

    if(memcmp(buffer->data, size_header, sizeof(size_header) - 1) != 0)
    {
        msg_error(EINVAL, LOG_CRIT, "Invalid input, expected XML size");
        return false;
    }

    uint8_t *const eol = memchr(buffer->data, '\n', buffer->pos);
    if(!eol)
    {
        msg_error(EINVAL, LOG_CRIT, "Incomplete XML size");
        return false;
    }

    *eol = '\0';

    char *endptr;
    const char *number_string =
        (const char *)buffer->data + sizeof(size_header) - 1;
    unsigned long temp = strtoul(number_string, &endptr, 10);

    if(*endptr != '\0')
    {
        msg_error(EINVAL, LOG_CRIT,
                  "Malformed XML size \"%s\"", number_string);
        return false;
    }

    if(temp > UINT16_MAX || (temp == ULONG_MAX && errno == ERANGE))
    {
        msg_error(ERANGE, LOG_CRIT, "Too large XML size %s", number_string);
        return false;
    }

    *expected_size = temp;
    *payload_offset = (eol - buffer->data) + 1;

    return true;
}

static bool try_preallocate_buffer(struct dynamic_buffer *buffer, int fd)
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
    if(!read_size_from_fd(buffer, fd, &expected_size, &xml_data_offset))
    {
        dynamic_buffer_free(buffer);
        return false;
    }
    buffer->size = prealloc_size;

    assert(buffer->pos >= xml_data_offset);

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

static bool fill_drcp_buffer(struct dynamic_buffer *buffer, int fd)
{
    assert(buffer != NULL);

    while(buffer->pos < buffer->size)
    {
        int ret =try_read_to_buffer(buffer, fd);

        if(ret == 0)
            return true;

        if(ret < 0)
        {
            msg_error(errno, LOG_ERR, "Failed reading DRCP data from fd %d", fd);
            return false;
        }
    }

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

static struct transaction *dcp_transactions_from_drcp(const struct dynamic_buffer *buffer)
{
    assert(buffer != NULL);
    assert(buffer->pos > 0);

    struct transaction *head = NULL;
    size_t i = 0;

    while(i < buffer->pos)
    {
        struct transaction *t = mk_master_transaction(&head, 71);

        if(t == NULL)
            break;

        uint16_t size = transaction_get_max_data_size(t);

        if(i + size >= buffer->pos)
            size = buffer->pos - i;

        assert(size > 0);

        if(!transaction_set_payload(t, buffer->data + i, size))
            break;

        i += size;
    }

    if(i < buffer->pos && head != NULL)
        transaction_free(&head);

    return head;
}

static const char *process_drcp_input(struct state *state, struct files *files)
{
    static const char ok_result[] = "OK\n";
    static const char error_result[] = "FF\n";

    const struct dynamic_buffer *buffer = &state->drcp_buffer;

    if(dynamic_buffer_is_empty(buffer))
    {
        msg_error(EINVAL, LOG_NOTICE, "Received empty DRCP buffer");
        return error_result;
    }

    struct transaction *head = dcp_transactions_from_drcp(buffer);
    if(head == NULL)
        return error_result;

    transaction_queue_add(&state->master_transaction_queue, head);

    return ok_result;
}

static void drcp_report(const char *two_bytes_plus_eol, int fd)
{
    (void)fifo_write_from_buffer((const uint8_t *)two_bytes_plus_eol, 3, fd);
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

static void terminate_active_transaction(struct state *state)
{
    if(state->free_active_transaction)
        transaction_free(&state->active_transaction);

    state->active_transaction = NULL;
}

static bool handle_reopen_connections(unsigned int wait_result,
                                      struct files *files, struct state *state)
{
    if((wait_result & (WAITEVENT_DRCP_CONNECTION_DIED |
                       WAITEVENT_DCP_CONNECTION_DIED)) == 0)
        return true;

    if(state->active_transaction != NULL)
        terminate_active_transaction(state);

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

/*!
 * Process DCP.
 */
static void main_loop(struct files *files)
{
    static struct state state;

    state.preallocated_slave_transaction = transaction_alloc(true);
    dynamic_buffer_init(&state.drcp_buffer);

    msg_info("Ready for accepting traffic");

    while(keep_running)
    {
        const unsigned int wait_result =
            wait_for_events(&state,
                            files->drcp_fifo.in_fd, files->dcpspi_fifo.in_fd,
                            transaction_is_input_required(state.active_transaction));

        if((wait_result & WAITEVENT_POLL_ERROR) != 0)
            continue;

        if((wait_result & WAITEVENT_CAN_READ_DRCP) != 0)
        {
            if(try_preallocate_buffer(&state.drcp_buffer,
                                      files->drcp_fifo.in_fd) &&
               fill_drcp_buffer(&state.drcp_buffer, files->drcp_fifo.in_fd))
            {
                if(state.drcp_buffer.pos >= state.drcp_buffer.size)
                {
                    const char *result = process_drcp_input(&state, files);
                    dynamic_buffer_free(&state.drcp_buffer);
                    drcp_report(result, files->drcp_fifo.out_fd);
                }
            }
            else
            {
                dynamic_buffer_free(&state.drcp_buffer);
                drcp_report("FF\n", files->drcp_fifo.out_fd);
            }
        }

        if(!handle_reopen_connections(wait_result, files, &state))
        {
            keep_running = false;
            continue;
        }

        try_dequeue_next_transaction(&state);

        if(state.active_transaction == NULL)
            continue;

        switch(transaction_process(state.active_transaction,
                                   files->dcpspi_fifo.in_fd,
                                   files->dcpspi_fifo.out_fd))
        {
          case TRANSACTION_IN_PROGRESS:
            break;

          case TRANSACTION_FINISHED:
          case TRANSACTION_ERROR:
            terminate_active_transaction(&state);
            try_dequeue_next_transaction(&state);
            break;
        }
    }

    transaction_free(&state.preallocated_slave_transaction);
}

struct parameters
{
    bool run_in_foreground;
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

static void usage(const char *program_name)
{
    printf("Usage: %s [options]\n"
           "\n"
           "Options:\n"
           "  --help         Show this help.\n"
           "  --fg           Run in foreground, don't run as daemon.\n"
           "  --ispi  name   Name of the named pipe the DCPSPI daemon writes to.\n"
           "  --ospi  name   Name of the named pipe the DCPSPI daemon reads from.\n"
           "  --idrcp name   Name of the named pipe the DRCP daemon writes to.\n"
           "  --odrcp name   Name of the named pipe the DRCP daemon reads from.\n",
           program_name);
}

static int process_command_line(int argc, char *argv[],
                                struct parameters *parameters,
                                struct files *files)
{
    parameters->run_in_foreground = false;

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
        else
        {
            fprintf(stderr, "Unknown option \"%s\". Please try --help.\n", argv[i]);
            return -1;
        }
    }

#undef CHECK_ARGUMENT

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

    fifo_close_and_delete(&files.drcp_fifo.in_fd, files.drcp_fifo_in_name);
    fifo_close_and_delete(&files.drcp_fifo.out_fd, files.drcp_fifo_out_name);
    fifo_close(&files.dcpspi_fifo.in_fd);
    fifo_close(&files.dcpspi_fifo.out_fd);

    return EXIT_SUCCESS;
}
