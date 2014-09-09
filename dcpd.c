#include <config.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>

#include "named_pipe.h"
#include "messages.h"

/*!
 * Global flag that gets cleared in the SIGTERM signal handler.
 *
 * For clean shutdown.
 */
static volatile bool keep_running = true;

/*!
 * Process DCP.
 */
static void main_loop(const int drcp_fifo_in_fd, const int drcp_fifo_out_fd,
                      const int dcp_fifo_in_fd, const int dcp_fifo_out_fd)
{
    msg_info("Ready for accepting traffic");

    while(keep_running)
    {
    }
}

struct parameters
{
    const char *dcp_fifo_in_name;
    const char *dcp_fifo_out_name;
    const char *drcp_fifo_in_name;
    const char *drcp_fifo_out_name;
    bool run_in_foreground;
};

/*!
 * Open devices, daemonize.
 */
static int setup(const struct parameters *parameters,
                 int *drcp_fifo_in_fd, int *drcp_fifo_out_fd,
                 int *dcp_fifo_in_fd, int *dcp_fifo_out_fd)
{
    msg_enable_syslog(!parameters->run_in_foreground);

    if(!parameters->run_in_foreground)
        openlog("dcpd", LOG_PID, LOG_DAEMON);

    *dcp_fifo_in_fd = fifo_open(parameters->dcp_fifo_in_name, false);
    if(*dcp_fifo_in_fd < 0)
        goto error_dcp_fifo_in;

    *dcp_fifo_out_fd = fifo_open(parameters->dcp_fifo_out_name, true);
    if(*dcp_fifo_out_fd < 0)
        goto error_dcp_fifo_out;

    *drcp_fifo_in_fd = fifo_create_and_open(parameters->drcp_fifo_in_name, false);
    if(*drcp_fifo_in_fd < 0)
        goto error_drcp_fifo_in;

    *drcp_fifo_out_fd = fifo_create_and_open(parameters->drcp_fifo_out_name, true);
    if(*drcp_fifo_out_fd < 0)
        goto error_drcp_fifo_out;

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
    fifo_close_and_delete(*drcp_fifo_out_fd, parameters->drcp_fifo_out_name);

error_drcp_fifo_out:
    fifo_close_and_delete(*drcp_fifo_in_fd, parameters->drcp_fifo_in_name);

error_drcp_fifo_in:
    fifo_close(*dcp_fifo_out_fd);

error_dcp_fifo_out:
    fifo_close(*dcp_fifo_in_fd);

error_dcp_fifo_in:
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
    parameters->dcp_fifo_in_name = "/tmp/spi_to_dcp";
    parameters->dcp_fifo_out_name = "/tmp/dcp_to_spi";
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
    int dcp_fifo_in_fd, dcp_fifo_out_fd;

    if(setup(&parameters, &drcp_fifo_in_fd, &drcp_fifo_out_fd,
             &dcp_fifo_in_fd, &dcp_fifo_out_fd) < 0)
        return EXIT_FAILURE;

    static struct sigaction action =
    {
        .sa_sigaction = signal_handler,
        .sa_flags = SA_SIGINFO | SA_RESETHAND,
    };

    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    main_loop(drcp_fifo_in_fd, drcp_fifo_out_fd,
              dcp_fifo_in_fd, dcp_fifo_out_fd);

    msg_info("Terminated, shutting down");

    fifo_close_and_delete(drcp_fifo_in_fd, parameters.drcp_fifo_in_name);
    fifo_close_and_delete(drcp_fifo_out_fd, parameters.drcp_fifo_out_name);
    fifo_close(dcp_fifo_in_fd);
    fifo_close(dcp_fifo_out_fd);

    return EXIT_SUCCESS;
}
