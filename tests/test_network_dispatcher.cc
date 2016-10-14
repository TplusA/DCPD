/*
 * Copyright (C) 2015, 2016  T+A elektroakustik GmbH & Co. KG
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

#include <cppcutter.h>

#include "network_dispatcher.h"

#include "mock_messages.hh"
#include "mock_os.hh"

/*!
 * \addtogroup network_dispatcher_tests Unit tests
 * \ingroup network_dispatcher
 *
 * Network dispatcher unit tests.
 */
/*!@{*/

namespace network_dispatcher_tests
{

static MockMessages *mock_messages;
static MockOs *mock_os;

static struct
{
    size_t handle_incoming_data_called;
    size_t handle_incoming_data_expected;

    size_t connection_died_called;
    size_t connection_died_expected;
}
iface_check_data;

static int handle_incoming_data_callback(int fd, void *user_data)
{
    ++iface_check_data.handle_incoming_data_called;
    return 0;
}

static void connection_died_callback(int fd, void *user_data)
{
    ++iface_check_data.connection_died_called;;
}

static const struct nwdispatch_iface dispatch_fd =
{
    .handle_incoming_data = handle_incoming_data_callback,
    .connection_died = connection_died_callback,
};

void cut_setup()
{
    memset(&iface_check_data, 0, sizeof(iface_check_data));

    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_os = new MockOs;
    cppcut_assert_not_null(mock_os);
    mock_os->init();
    mock_os_singleton = mock_os;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    nwdispatch_init();
}

void cut_teardown()
{
    mock_messages->check();
    mock_os->check();

    mock_messages_singleton = nullptr;
    mock_os_singleton = nullptr;

    delete mock_messages;
    delete mock_os;

    mock_messages = nullptr;
    mock_os = nullptr;

    cppcut_assert_equal(iface_check_data.handle_incoming_data_expected,
                        iface_check_data.handle_incoming_data_called);
    cppcut_assert_equal(iface_check_data.connection_died_expected,
                        iface_check_data.connection_died_called);
}

/*!\test
 * Any file descriptor can be registered only once, second try emits bug
 * message.
 */
void test_fd_cannot_be_registered_twice()
{
    cppcut_assert_equal(0, nwdispatch_register(42, &dispatch_fd, NULL));

    mock_messages->expect_msg_error_formatted(0, LOG_CRIT,
                                              "BUG: Attempted to register already registered fd 42");
    cppcut_assert_equal(-1, nwdispatch_register(42, &dispatch_fd, NULL));
}

/*!\test
 * Registered file descriptors are filled into array of matching size for use
 * with \c poll(2).
 */
void test_registered_fds_are_scattered_over_big_enough_array()
{
    cppcut_assert_equal(0, nwdispatch_register(5, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(7, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(9, &dispatch_fd, NULL));

    struct pollfd fds[5] = { 0 };

    cppcut_assert_equal(size_t(3), nwdispatch_scatter_fds(&fds[1], 3, POLLIN));

    cppcut_assert_equal(0, fds[0].fd);
    cppcut_assert_equal(0, fds[sizeof(fds) / sizeof(fds[0]) - 1].fd);

    cppcut_assert_equal(5, fds[1].fd);
    cppcut_assert_equal(7, fds[2].fd);
    cppcut_assert_equal(9, fds[3].fd);
}

/*!\test
 * Registered file descriptors are filled into array for use with \c poll(2),
 * excess elements are filled with -1 fds.
 */
void test_too_big_scatter_array_is_filled_up()
{
    cppcut_assert_equal(0, nwdispatch_register(15, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(17, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(19, &dispatch_fd, NULL));

    struct pollfd fds[6] = { 0 };

    cppcut_assert_equal(size_t(3), nwdispatch_scatter_fds(&fds[1], 4, POLLIN));

    cppcut_assert_equal(0, fds[0].fd);
    cppcut_assert_equal(0, fds[sizeof(fds) / sizeof(fds[0]) - 1].fd);

    cppcut_assert_equal(15, fds[1].fd);
    cppcut_assert_equal(17, fds[2].fd);
    cppcut_assert_equal(19, fds[3].fd);
    cppcut_assert_equal(-1, fds[4].fd);
}

/*!\test
 * If no file descriptors are registered, the array for \c poll(2) is filled
 * with -1 fds.
 */
void test_scatter_array_is_filled_up_even_if_no_fds_are_registered()
{
    struct pollfd fds[5] = { 0 };

    cppcut_assert_equal(size_t(0), nwdispatch_scatter_fds(&fds[1], 3, POLLIN));

    cppcut_assert_equal(0, fds[0].fd);
    cppcut_assert_equal(0, fds[sizeof(fds) / sizeof(fds[0]) - 1].fd);

    cppcut_assert_equal(-1, fds[1].fd);
    cppcut_assert_equal(-1, fds[2].fd);
    cppcut_assert_equal(-1, fds[3].fd);
}

/*!\test
 * The array for \c poll(2) is filled with a subset of registered file
 * descriptors if the target array is too small, and a warning is emitted.
 */
void test_first_few_registered_fds_are_scattered_over_too_small_array()
{
    cppcut_assert_equal(0, nwdispatch_register(25, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(27, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(29, &dispatch_fd, NULL));

    struct pollfd fds[4] = { 0 };

    mock_messages->expect_msg_error_formatted(0, LOG_NOTICE,
        "Cannot pass all connections to poll(2), target array too small");
    cppcut_assert_equal(size_t(2), nwdispatch_scatter_fds(&fds[1], 2, POLLIN));

    cppcut_assert_equal(0, fds[0].fd);
    cppcut_assert_equal(0, fds[sizeof(fds) / sizeof(fds[0]) - 1].fd);

    cppcut_assert_equal(25, fds[1].fd);
    cppcut_assert_equal(27, fds[2].fd);
}

/*!\test
 * There is a limit of #NWDISPATCH_MAX_CONNECTIONS on the number of
 * dispatchable connections.
 */
void test_number_of_connections_is_limited()
{
    cppcut_assert_equal(0, nwdispatch_register(10, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(20, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(30, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(40, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(50, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(60, &dispatch_fd, NULL));

    mock_messages->expect_msg_error_formatted(0, LOG_NOTICE,
                                              "Maximum number of connections exceeded");
    cppcut_assert_equal(-1, nwdispatch_register(70, &dispatch_fd, NULL));
}

/*!\test
 * A registered file descriptors can be unregistered.
 */
void test_unregister_single_registered_fd()
{
    cppcut_assert_equal(0, nwdispatch_register(5, &dispatch_fd, NULL));

    mock_os->expect_os_file_close(5);
    cppcut_assert_equal(0, nwdispatch_unregister_and_close(5));

    struct pollfd dummy;
    cppcut_assert_equal(size_t(0), nwdispatch_scatter_fds(&dummy, 1, POLLIN));
}

/*!\test
 * The first registered file descriptor can be unregistered from a set of
 * multiple fds.
 */
void test_unregister_first_registered_fd()
{
    cppcut_assert_equal(0, nwdispatch_register(100, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(101, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(102, &dispatch_fd, NULL));

    mock_os->expect_os_file_close(100);
    cppcut_assert_equal(0, nwdispatch_unregister_and_close(100));

    struct pollfd fds[4];
    cppcut_assert_equal(size_t(2), nwdispatch_scatter_fds(fds, 4, POLLIN));

    cppcut_assert_equal(101, fds[0].fd);
    cppcut_assert_equal(102, fds[1].fd);
    cppcut_assert_equal(-1, fds[2].fd);
}

/*!\test
 * The last registered file descriptor can be unregistered from a set of
 * multiple fds.
 */
void test_unregister_last_registered_fd()
{
    cppcut_assert_equal(0, nwdispatch_register(100, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(101, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(102, &dispatch_fd, NULL));

    mock_os->expect_os_file_close(102);
    cppcut_assert_equal(0, nwdispatch_unregister_and_close(102));

    struct pollfd fds[4];
    cppcut_assert_equal(size_t(2), nwdispatch_scatter_fds(fds, 4, POLLIN));

    cppcut_assert_equal(100, fds[0].fd);
    cppcut_assert_equal(101, fds[1].fd);
    cppcut_assert_equal(-1, fds[2].fd);
}

/*!\test
 * Some registered file descriptor can be unregistered from the middle of a
 * full set of multiple fds.
 *
 * This leaves a hole in the internal array.
 */
void test_unregister_from_center_of_full_fd_registry()
{
    cppcut_assert_equal(0, nwdispatch_register(15, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(25, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(35, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(45, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(55, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(65, &dispatch_fd, NULL));

    mock_messages->expect_msg_error_formatted(0, LOG_NOTICE,
                                              "Maximum number of connections exceeded");
    cppcut_assert_equal(-1, nwdispatch_register(60, &dispatch_fd, NULL));

    mock_os->expect_os_file_close(35);
    cppcut_assert_equal(0, nwdispatch_unregister_and_close(35));

    struct pollfd fds[8];
    cppcut_assert_equal(size_t(5), nwdispatch_scatter_fds(fds, 8, POLLIN));

    cppcut_assert_equal(15, fds[0].fd);
    cppcut_assert_equal(25, fds[1].fd);
    cppcut_assert_equal(45, fds[2].fd);
    cppcut_assert_equal(55, fds[3].fd);
    cppcut_assert_equal(65, fds[4].fd);
    cppcut_assert_equal(-1, fds[5].fd);
}

/*!\test
 * Attempting to unregister a file descriptor with registering any file
 * descriptor before is a programming error.
 */
void test_unregister_unregistered_fd_from_empty_registry_returns_error()
{
    mock_messages->expect_msg_error_formatted(0, LOG_CRIT,
                                              "BUG: Attempted to unregister nonexistent fd 1");
    cppcut_assert_equal(-1, nwdispatch_unregister_and_close(1));
}

/*!\test
 * Attempting to unregister a file descriptor that has not been registered
 * before is a programming error.
 */
void test_unregister_unregistered_fd_returns_error()
{
    cppcut_assert_equal(0, nwdispatch_register(2, &dispatch_fd, NULL));

    mock_messages->expect_msg_error_formatted(0, LOG_CRIT,
                                              "BUG: Attempted to unregister nonexistent fd 1");
    cppcut_assert_equal(-1, nwdispatch_unregister_and_close(1));
}

/*!\test
 * In case \c poll(2) tells us that there is data for the only registered fd,
 * it is dispatched accordingly.
 */
void test_registered_callback_is_called_when_data_arrives_for_single_fd()
{
    cppcut_assert_equal(0, nwdispatch_register(15, &dispatch_fd, NULL));

    struct pollfd fds[NWDISPATCH_MAX_CONNECTIONS] = { 0 };
    cppcut_assert_equal(size_t(1), nwdispatch_scatter_fds(fds, NWDISPATCH_MAX_CONNECTIONS, POLLIN));

    fds[0].revents = POLLIN;

    iface_check_data.handle_incoming_data_expected = 1;

    cppcut_assert_equal(iface_check_data.handle_incoming_data_expected,
                        nwdispatch_handle_events(fds, NWDISPATCH_MAX_CONNECTIONS));
}

/*!\test
 * In case \c poll(2) tells us that there is data for some of the registered
 * fds, they are dispatched accordingly.
 */
void test_registered_callbacks_are_called_when_data_arrives_for_many_fds()
{
    cppcut_assert_equal(0, nwdispatch_register(20, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(21, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(22, &dispatch_fd, NULL));

    struct pollfd fds[NWDISPATCH_MAX_CONNECTIONS] = { 0 };
    cppcut_assert_equal(size_t(3), nwdispatch_scatter_fds(fds, NWDISPATCH_MAX_CONNECTIONS, POLLIN));

    fds[0].revents = POLLIN;
    fds[2].revents = POLLIN;

    iface_check_data.handle_incoming_data_expected = 2;

    cppcut_assert_equal(iface_check_data.handle_incoming_data_expected,
                        nwdispatch_handle_events(fds, NWDISPATCH_MAX_CONNECTIONS));
}

/*!\test
 * In case \c poll(2) tells us that the single registered connection has died,
 * the event is dispatched accordingly.
 */
void test_registered_callback_is_called_when_connection_dies_for_single_fd()
{
    cppcut_assert_equal(0, nwdispatch_register(25, &dispatch_fd, NULL));

    struct pollfd fds[NWDISPATCH_MAX_CONNECTIONS] = { 0 };
    cppcut_assert_equal(size_t(1), nwdispatch_scatter_fds(fds, NWDISPATCH_MAX_CONNECTIONS, POLLIN));

    fds[0].revents = POLLHUP;

    iface_check_data.connection_died_expected = 1;

    cppcut_assert_equal(iface_check_data.connection_died_expected,
                        nwdispatch_handle_events(fds, NWDISPATCH_MAX_CONNECTIONS));
}

/*!\test
 * In case \c poll(2) tells us that some registered connections have died, the
 * events are dispatched accordingly.
 */
void test_registered_callbacks_are_called_when_connection_dies_for_many_fds()
{
    cppcut_assert_equal(0, nwdispatch_register(30, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(31, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(32, &dispatch_fd, NULL));

    struct pollfd fds[NWDISPATCH_MAX_CONNECTIONS] = { 0 };
    cppcut_assert_equal(size_t(3), nwdispatch_scatter_fds(fds, NWDISPATCH_MAX_CONNECTIONS, POLLIN));

    fds[0].revents = POLLHUP;
    fds[2].revents = POLLHUP;

    iface_check_data.connection_died_expected = 2;

    cppcut_assert_equal(iface_check_data.connection_died_expected,
                        nwdispatch_handle_events(fds, NWDISPATCH_MAX_CONNECTIONS));
}

/*!\test
 * Registering and unregistering fds shuffles them and leaves holes in the
 * internal array, but this doesn't affect correct handling of events.
 */
void test_registered_callbacks_are_called_after_reg_unreg()
{
    cppcut_assert_equal(0, nwdispatch_register(200, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(210, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(220, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(230, &dispatch_fd, NULL));
    cppcut_assert_equal(0, nwdispatch_register(240, &dispatch_fd, NULL));

    mock_os->expect_os_file_close(240);
    cppcut_assert_equal(0, nwdispatch_unregister_and_close(240));
    cppcut_assert_equal(0, nwdispatch_register(100, &dispatch_fd, NULL));

    mock_os->expect_os_file_close(210);
    cppcut_assert_equal(0, nwdispatch_unregister_and_close(210));
    mock_os->expect_os_file_close(230);
    cppcut_assert_equal(0, nwdispatch_unregister_and_close(230));
    cppcut_assert_equal(0, nwdispatch_register(80, &dispatch_fd, NULL));

    mock_os->expect_os_file_close(200);
    cppcut_assert_equal(0, nwdispatch_unregister_and_close(200));

    struct pollfd fds[NWDISPATCH_MAX_CONNECTIONS] = { 0 };
    cppcut_assert_equal(size_t(3), nwdispatch_scatter_fds(fds, NWDISPATCH_MAX_CONNECTIONS, POLLIN));

    fds[0].revents = POLLIN | POLLHUP;
    fds[1].revents = POLLIN | POLLHUP;
    fds[2].revents = POLLIN | POLLHUP;

    iface_check_data.handle_incoming_data_expected = 3;
    iface_check_data.connection_died_expected = 3;

    cppcut_assert_equal(iface_check_data.handle_incoming_data_expected +
                        iface_check_data.connection_died_expected,
                        nwdispatch_handle_events(fds, NWDISPATCH_MAX_CONNECTIONS));
}

}

/*!@}*/
