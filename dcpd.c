#define _BSD_SOURCE
#define _XOPEN_SOURCE 500

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
static void main_loop(const int fifo_in_fd, const int fifo_out_fd)
{
    msg_info("Ready for accepting traffic");

    while(keep_running)
    {
    }
}

struct parameters
{
    const char *fifo_in_name;
    const char *fifo_out_name;
    bool run_in_foreground;
};

/*!
 * Open devices, daemonize.
 */
static int setup(const struct parameters *parameters,
                 int *fifo_in_fd, int *fifo_out_fd)
{
    msg_enable_syslog(!parameters->run_in_foreground);

    if(!parameters->run_in_foreground)
        openlog("dcpd", LOG_PID, LOG_DAEMON);

    *fifo_in_fd = fifo_create_and_open(parameters->fifo_in_name, false);
    if(*fifo_in_fd < 0)
        return -1;

    *fifo_out_fd = fifo_create_and_open(parameters->fifo_out_name, true);
    if(*fifo_out_fd < 0)
    {
        fifo_close_and_delete(*fifo_in_fd, parameters->fifo_in_name);
        return -1;
    }

    if(!parameters->run_in_foreground)
    {
        if(daemon(0, 0) < 0)
        {
            msg_error(errno, LOG_EMERG, "Failed to run as daemon");
            return -1;
        }
    }

    return 0;
}

static void usage(const char *program_name)
{
    printf("Usage: %s --ififo name --ofifo name\n"
           "\n"
           "Options:\n"
           "  --ififo name   Name of the named pipe the DRC daemon writes to.\n"
           "  --ofifo name   Name of the named pipe the DRC daemon reads from.\n",
           program_name);
}

static int process_command_line(int argc, char *argv[],
                                struct parameters *parameters)
{
    parameters->fifo_in_name = "/tmp/dcpd_to_drcpd";
    parameters->fifo_out_name = "/tmp/drcpd_to_dcpd";
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

    int fifo_in_fd, fifo_out_fd;

    if(setup(&parameters, &fifo_in_fd, &fifo_out_fd) < 0)
        return EXIT_FAILURE;

    static struct sigaction action =
    {
        .sa_sigaction = signal_handler,
        .sa_flags = SA_SIGINFO | SA_RESETHAND,
    };

    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    main_loop(fifo_in_fd, fifo_out_fd);

    msg_info("Terminated, shutting down");

    fifo_close_and_delete(fifo_in_fd, parameters.fifo_in_name);
    fifo_close_and_delete(fifo_out_fd, parameters.fifo_out_name);

    return EXIT_SUCCESS;
}
