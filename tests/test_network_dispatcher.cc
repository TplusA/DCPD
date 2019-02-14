/*
 * Copyright (C) 2015, 2016, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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
#include <algorithm>
#include <array>

#include "network_dispatcher.hh"

#include "mock_messages.hh"
#include "mock_os.hh"

#if LOGGED_LOCKS_ENABLED && LOGGED_LOCKS_THREAD_CONTEXTS
thread_local LoggedLock::Context LoggedLock::context;
#endif

#if !LOGGED_LOCKS_ENABLED

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

static bool handle_incoming_data_callback(int fd)
{
    ++iface_check_data.handle_incoming_data_called;
    return true;
}

static void connection_died_callback(int fd)
{
    ++iface_check_data.connection_died_called;;
}

static const Network::DispatchHandlers dispatch_fd
{
    .handle_incoming_data = handle_incoming_data_callback,
    .connection_died = connection_died_callback,
};

static Network::Dispatcher &nwdispatcher(Network::Dispatcher::get_singleton());

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

    nwdispatcher.reset();
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

template <size_t N>
static void expect_fds(const std::array<int, N> &expected_fds,
                       const struct pollfd *fds)
{
    cppcut_assert_not_null(fds);

    if(N == 0)
        return;

    std::vector<int> unique_expected_fds;
    std::unique_copy(expected_fds.begin(), expected_fds.end(),
                     std::back_inserter(unique_expected_fds));
    cppcut_assert_equal(N, unique_expected_fds.size());
    std::sort(unique_expected_fds.begin(), unique_expected_fds.end());

    std::array<int, N> have_fds;
    for(size_t i = 0; i < N; ++i)
        have_fds[i] = fds[i].fd;

    std::vector<int> unique_fds;
    std::unique_copy(have_fds.begin(), have_fds.end(),
                     std::back_inserter(unique_fds));
    cppcut_assert_equal(N, unique_fds.size());
    std::sort(unique_fds.begin(), unique_fds.end());

    cut_assert_equal_memory(unique_expected_fds.data(),
                            unique_expected_fds.size() * sizeof(int),
                            unique_fds.data(),
                            unique_fds.size() * sizeof(int));
}

/*!\test
 * Any file descriptor can be registered only once, second try emits bug
 * message.
 */
void test_fd_cannot_be_registered_twice()
{
    cut_assert_true(nwdispatcher.add_connection(42, dispatch_fd));

    mock_messages->expect_msg_error_formatted(0, LOG_CRIT,
                                              "BUG: Attempted to register already registered fd 42");
    cut_assert_false(nwdispatcher.add_connection(42, dispatch_fd));
}

/*!\test
 * Registered file descriptors are filled into array of matching size for use
 * with \c poll(2).
 */
void test_registered_fds_are_scattered_over_big_enough_array()
{
    cut_assert_true(nwdispatcher.add_connection(5, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(7, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(9, dispatch_fd));

    struct pollfd fds[5] = { 0 };

    cppcut_assert_equal(size_t(3), nwdispatcher.scatter_fds(&fds[1], POLLIN));

    cppcut_assert_equal(0, fds[0].fd);
    cppcut_assert_equal(0, fds[sizeof(fds) / sizeof(fds[0]) - 1].fd);

    expect_fds(std::array<int, 3>{5, 7, 9}, &fds[1]);
}

/*!\test
 * Registered file descriptors are filled into array for use with \c poll(2),
 * excess elements are left untouched.
 */
void test_excess_scatter_elements_are_left_untouched()
{
    cut_assert_true(nwdispatcher.add_connection(15, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(17, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(19, dispatch_fd));

    struct pollfd fds[6] = { 0 };

    cppcut_assert_equal(size_t(3), nwdispatcher.scatter_fds(&fds[1], POLLIN));

    cppcut_assert_equal(0, fds[0].fd);
    cppcut_assert_equal(0, fds[sizeof(fds) / sizeof(fds[0]) - 1].fd);
    cppcut_assert_equal(0, fds[4].fd);

    expect_fds(std::array<int, 3>{15, 17, 19}, &fds[1]);
}

/*!\test
 * If no file descriptors are registered, the array for \c poll(2) is filled
 * with -1 fds.
 */
void test_scatter_array_is_left_untouched_if_no_fds_are_registered()
{
    struct pollfd fds[5] = { 0 };

    cppcut_assert_equal(size_t(0), nwdispatcher.scatter_fds(&fds[1], POLLIN));

    cppcut_assert_equal(0, fds[0].fd);
    cppcut_assert_equal(0, fds[1].fd);
    cppcut_assert_equal(0, fds[2].fd);
    cppcut_assert_equal(0, fds[3].fd);
    cppcut_assert_equal(0, fds[sizeof(fds) / sizeof(fds[0]) - 1].fd);
}

/*!\test
 * There is no practical limit on the number of dispatchable connections.
 */
void test_number_of_connections_is_limited()
{
    for(int i = 1; i < 500; ++i)
        cut_assert_true(nwdispatcher.add_connection(i * 10, dispatch_fd));
}

/*!\test
 * A registered file descriptors can be unregistered.
 */
void test_unregister_single_registered_fd()
{
    cut_assert_true(nwdispatcher.add_connection(5, dispatch_fd));

    mock_os->expect_os_file_close(0, 5);
    cut_assert_true(nwdispatcher.remove_connection(5));

    struct pollfd dummy { 0 };
    cppcut_assert_equal(size_t(0), nwdispatcher.scatter_fds(&dummy, POLLIN));
}

/*!\test
 * The first registered file descriptor can be unregistered from a set of
 * multiple fds.
 */
void test_unregister_first_registered_fd()
{
    cut_assert_true(nwdispatcher.add_connection(100, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(101, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(102, dispatch_fd));

    mock_os->expect_os_file_close(0, 100);
    cut_assert_true(nwdispatcher.remove_connection(100));

    struct pollfd fds[4] { 0 };
    cppcut_assert_equal(size_t(2), nwdispatcher.scatter_fds(fds, POLLIN));

    cppcut_assert_equal(0, fds[2].fd);
    expect_fds(std::array<int, 2>{101, 102}, fds);
}

/*!\test
 * The last registered file descriptor can be unregistered from a set of
 * multiple fds.
 */
void test_unregister_last_registered_fd()
{
    cut_assert_true(nwdispatcher.add_connection(100, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(101, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(102, dispatch_fd));

    mock_os->expect_os_file_close(0, 102);
    cut_assert_true(nwdispatcher.remove_connection(102));

    struct pollfd fds[4] { 0 };
    cppcut_assert_equal(size_t(2), nwdispatcher.scatter_fds(fds, POLLIN));

    cppcut_assert_equal(0, fds[2].fd);
    expect_fds(std::array<int, 2>{100, 101}, fds);
}

/*!\test
 * Some registered file descriptor can be unregistered from the middle of a
 * full set of multiple fds.
 *
 * This leaves a hole in the internal array.
 */
void test_unregister_from_center_of_full_fd_registry()
{
    cut_assert_true(nwdispatcher.add_connection(15, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(25, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(35, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(45, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(55, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(65, dispatch_fd));

    mock_os->expect_os_file_close(0, 35);
    cut_assert_true(nwdispatcher.remove_connection(35));

    struct pollfd fds[8] { 0 };
    cppcut_assert_equal(size_t(5), nwdispatcher.scatter_fds(fds, POLLIN));

    cppcut_assert_equal(0, fds[5].fd);
    expect_fds(std::array<int, 5>{15, 25, 45, 55, 65}, fds);
}

/*!\test
 * Attempting to unregister a file descriptor with registering any file
 * descriptor before is a programming error.
 */
void test_unregister_unregistered_fd_from_empty_registry_returns_error()
{
    mock_messages->expect_msg_error_formatted(0, LOG_CRIT,
                                              "BUG: Attempted to unregister nonexistent fd 1");
    cut_assert_false(nwdispatcher.remove_connection(1));
}

/*!\test
 * Attempting to unregister a file descriptor that has not been registered
 * before is a programming error.
 */
void test_unregister_unregistered_fd_returns_error()
{
    cut_assert_true(nwdispatcher.add_connection(2, dispatch_fd));

    mock_messages->expect_msg_error_formatted(0, LOG_CRIT,
                                              "BUG: Attempted to unregister nonexistent fd 1");
    cut_assert_false(nwdispatcher.remove_connection(1));
}

/*!\test
 * In case \c poll(2) tells us that there is data for the only registered fd,
 * it is dispatched accordingly.
 */
void test_registered_callback_is_called_when_data_arrives_for_single_fd()
{
    cut_assert_true(nwdispatcher.add_connection(15, dispatch_fd));

    struct pollfd fds[5] = { 0 };
    cppcut_assert_equal(size_t(1), nwdispatcher.scatter_fds(fds, POLLIN));

    fds[0].revents = POLLIN;

    iface_check_data.handle_incoming_data_expected = 1;

    cppcut_assert_equal(iface_check_data.handle_incoming_data_expected,
                        nwdispatcher.process(fds));
}

/*!\test
 * In case \c poll(2) tells us that there is data for some of the registered
 * fds, they are dispatched accordingly.
 */
void test_registered_callbacks_are_called_when_data_arrives_for_many_fds()
{
    cut_assert_true(nwdispatcher.add_connection(20, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(21, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(22, dispatch_fd));

    struct pollfd fds[5] = { 0 };
    cppcut_assert_equal(size_t(3), nwdispatcher.scatter_fds(fds, POLLIN));

    fds[0].revents = POLLIN;
    fds[2].revents = POLLIN;

    iface_check_data.handle_incoming_data_expected = 2;

    cppcut_assert_equal(iface_check_data.handle_incoming_data_expected,
                        nwdispatcher.process(fds));
}

/*!\test
 * In case \c poll(2) tells us that the single registered connection has died,
 * the event is dispatched accordingly.
 */
void test_registered_callback_is_called_when_connection_dies_for_single_fd()
{
    cut_assert_true(nwdispatcher.add_connection(25, dispatch_fd));

    struct pollfd fds[5] = { 0 };
    cppcut_assert_equal(size_t(1), nwdispatcher.scatter_fds(fds, POLLIN));

    fds[0].revents = POLLHUP;

    iface_check_data.connection_died_expected = 1;

    cppcut_assert_equal(iface_check_data.connection_died_expected,
                        nwdispatcher.process(fds));
}

/*!\test
 * In case \c poll(2) tells us that some registered connections have died, the
 * events are dispatched accordingly.
 */
void test_registered_callbacks_are_called_when_connection_dies_for_many_fds()
{
    cut_assert_true(nwdispatcher.add_connection(30, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(31, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(32, dispatch_fd));

    struct pollfd fds[5] = { 0 };
    cppcut_assert_equal(size_t(3), nwdispatcher.scatter_fds(fds, POLLIN));

    fds[0].revents = POLLHUP;
    fds[2].revents = POLLHUP;

    iface_check_data.connection_died_expected = 2;

    cppcut_assert_equal(iface_check_data.connection_died_expected,
                        nwdispatcher.process(fds));
}

/*!\test
 * Registering and unregistering fds shuffles them and leaves holes in the
 * internal array, but this doesn't affect correct handling of events.
 */
void test_registered_callbacks_are_called_after_reg_unreg()
{
    cut_assert_true(nwdispatcher.add_connection(200, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(210, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(220, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(230, dispatch_fd));
    cut_assert_true(nwdispatcher.add_connection(240, dispatch_fd));

    mock_os->expect_os_file_close(0, 240);
    cut_assert_true(nwdispatcher.remove_connection(240));
    cut_assert_true(nwdispatcher.add_connection(100, dispatch_fd));

    mock_os->expect_os_file_close(0, 210);
    cut_assert_true(nwdispatcher.remove_connection(210));
    mock_os->expect_os_file_close(0, 230);
    cut_assert_true(nwdispatcher.remove_connection(230));
    cut_assert_true(nwdispatcher.add_connection(80, dispatch_fd));

    mock_os->expect_os_file_close(0, 200);
    cut_assert_true(nwdispatcher.remove_connection(200));

    struct pollfd fds[10] = { 0 };
    cppcut_assert_equal(size_t(3), nwdispatcher.scatter_fds(fds, POLLIN));

    fds[0].revents = POLLIN | POLLHUP;
    fds[1].revents = POLLIN | POLLHUP;
    fds[2].revents = POLLIN | POLLHUP;

    iface_check_data.handle_incoming_data_expected = 3;
    iface_check_data.connection_died_expected = 3;

    cppcut_assert_equal(iface_check_data.handle_incoming_data_expected +
                        iface_check_data.connection_died_expected,
                        nwdispatcher.process(fds));
}

}

/*!@}*/

#endif /* !LOGGED_LOCKS_ENABLED  */
