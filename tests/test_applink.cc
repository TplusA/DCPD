/*
 * Copyright (C) 2016--2020  T+A elektroakustik GmbH & Co. KG
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

#include <cppcutter.h>
#include <algorithm>

#include "smartphone_app.hh"
#include "network_dispatcher.hh"

#include "mock_messages.hh"
#include "mock_backtrace.hh"
#include "mock_network.hh"
#include "mock_dbus_iface.hh"
#include "mock_airable_dbus.hh"
#include "mock_credentials_dbus.hh"
#include "mock_os.hh"

/*
 * Uh... See \c test_registers.cc for why this is bad.
 */
#include "dbus_common.c"

#if LOGGED_LOCKS_ENABLED && LOGGED_LOCKS_THREAD_CONTEXTS
thread_local LoggedLock::Context LoggedLock::context;
#endif

#if !LOGGED_LOCKS_ENABLED

struct fill_buffer_data_t
{
    std::string data_;
    int errno_value_;
    int return_value_;

    void set(const char *data, int err, int ret)
    {
        data_ = data;
        errno_value_ = err;
        return_value_ = ret;
    }
};

namespace applink_protocol_tests
{

static MockMessages *mock_messages;
static MockBacktrace *mock_backtrace;
static MockOs *mock_os;

static Applink::InputBuffer *in_buf;
static fill_buffer_data_t *fill_buffer_data;
static int default_peer_fd = 42;

void cut_setup()
{
    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_backtrace = new MockBacktrace;
    cppcut_assert_not_null(mock_backtrace);
    mock_backtrace->init();
    mock_backtrace_singleton = mock_backtrace;

    mock_os = new MockOs;
    cppcut_assert_not_null(mock_os);
    mock_os->init();
    mock_os_singleton = mock_os;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    fill_buffer_data = new fill_buffer_data_t;

    in_buf = new Applink::InputBuffer;
    cppcut_assert_not_null(in_buf);
}

void cut_teardown()
{
    delete in_buf;

    mock_messages->check();
    mock_backtrace->check();
    mock_os->check();

    mock_messages_singleton = nullptr;
    mock_backtrace_singleton = nullptr;
    mock_os_singleton = nullptr;

    delete mock_messages;
    delete mock_backtrace;
    delete mock_os;
    delete fill_buffer_data;

    mock_messages = nullptr;
    mock_backtrace = nullptr;
    mock_os = nullptr;
    fill_buffer_data = nullptr;
}

/*!
 * Local mock implementation of #os_try_read_to_buffer().
 */
static int fill_buffer(void *dest, size_t count, size_t *add_bytes_read,
                       int fd, bool suppress_error_on_eagain)
{
    uint8_t *dest_ptr = static_cast<uint8_t *>(dest);

    cppcut_assert_not_null(add_bytes_read);
    cppcut_assert_equal(default_peer_fd, fd);
    cut_assert_true(suppress_error_on_eagain);

    const size_t n = std::min(count, fill_buffer_data->data_.length());
    std::copy_n(fill_buffer_data->data_.begin(), n, dest_ptr + *add_bytes_read);
    *add_bytes_read += n;

    errno = fill_buffer_data->errno_value_;

    return fill_buffer_data->return_value_;
}

static void check_expected_command(const Applink::Command &command,
                                   const char *expected_variable)
{
    cut_assert_true(command.is_request());
    const Applink::Variable *variable = command.get_variable();
    cppcut_assert_not_null(variable);
    cppcut_assert_equal(expected_variable, variable->name);

    if(variable->number_of_request_parameters > 0)
        cut_assert_false(command.parser_data_.parameters_buffer_.empty());
    else
        cut_assert_true(command.parser_data_.parameters_buffer_.empty());
}

static void check_expected_answer(const Applink::Command &command,
                                  const char *expected_variable)
{
    cut_assert_false(command.is_request());
    const Applink::Variable *variable = command.get_variable();
    cppcut_assert_not_null(variable);
    cppcut_assert_equal(expected_variable, variable->name);

    if(variable->number_of_answer_parameters > 0)
        cut_assert_false(command.parser_data_.parameters_buffer_.empty());
    else
        cut_assert_true(command.parser_data_.parameters_buffer_.empty());
}

static void expect_read_but_return_nothing()
{
    mock_os->expect_os_try_read_to_buffer_callback(0, fill_buffer);
    fill_buffer_data->set("", 0, 0);
}

/*!\test
 * Basic lookup of predefined variable by name.
 */
void test_lookup_airable_password_variable()
{
    const auto *const variable = Applink::lookup("AIRABLE_PASSWORD", 0);

    cppcut_assert_not_null(variable);
    cppcut_assert_equal("AIRABLE_PASSWORD", variable->name);
    cppcut_assert_equal(static_cast<uint16_t>(Applink::Variables::AIRABLE_PASSWORD),
                        variable->variable_id);
    cppcut_assert_equal(2U, variable->number_of_request_parameters);
    cppcut_assert_equal(1U, variable->number_of_answer_parameters);
}

/*!\test
 * If there is nothing to read, then the result is empty.
 */
void test_read_nothing()
{
    expect_read_but_return_nothing();

    Applink::ParserResult result;
    auto cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::EMPTY), int(result));
    cppcut_assert_null(cmd.get());
}

/*!\test
 * Empty lines are ignored.
 */
void test_read_empty_lines()
{
    mock_os->expect_os_try_read_to_buffer_callback(0, fill_buffer);
    fill_buffer_data->set("\n   \n \n\n", 0, 0);

    Applink::ParserResult result;
    auto cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::EMPTY), int(result));
    cppcut_assert_null(cmd.get());
}

/*!\test
 * Parse a single request.
 */
void test_read_single_variable_request()
{
    mock_os->expect_os_try_read_to_buffer_callback(0, fill_buffer);
    fill_buffer_data->set("GET AIRABLE_PASSWORD test\\ token test\\ password\n", 0, 0);

    Applink::ParserResult result;
    auto cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::HAVE_COMMAND), int(result));
    cppcut_assert_not_null(cmd.get());

    check_expected_command(*cmd, "AIRABLE_PASSWORD");

    static const char expected_parameters[] = "test\\ token test\\ password";
    cut_assert_equal_memory(expected_parameters, sizeof(expected_parameters) - 1,
                            cmd->parser_data_.parameters_buffer_.data(),
                            cmd->parser_data_.parameters_buffer_.size());

    std::array<char, 512> buffer;
    cmd->get_parameter(0, buffer);
    cppcut_assert_equal("test token", static_cast<const char *>(buffer.data()));

    cmd->get_parameter(1, buffer);
    cppcut_assert_equal("test password", static_cast<const char *>(buffer.data()));
}

/*!\test
 * Parse a single request after a few empty lines.
 */
void test_read_single_variable_request_after_empty_lines()
{
    mock_os->expect_os_try_read_to_buffer_callback(0, fill_buffer);
    fill_buffer_data->set("\n\n     \n  GET AIRABLE_PASSWORD some\\ token password\n", 0, 0);

    Applink::ParserResult result;
    auto cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::HAVE_COMMAND), int(result));
    cppcut_assert_not_null(cmd.get());

    check_expected_command(*cmd, "AIRABLE_PASSWORD");

    static const char expected_parameters[] = "some\\ token password";
    cut_assert_equal_memory(expected_parameters, sizeof(expected_parameters) - 1,
                            cmd->parser_data_.parameters_buffer_.data(),
                            cmd->parser_data_.parameters_buffer_.size());

    std::array<char, 512> buffer;
    cmd->get_parameter(0, buffer);
    cppcut_assert_equal("some token", static_cast<const char *>(buffer.data()));

    cmd->get_parameter(1, buffer);
    cppcut_assert_equal("password", static_cast<const char *>(buffer.data()));

    /* done */
    expect_read_but_return_nothing();
    cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::EMPTY), int(result));
    cppcut_assert_null(cmd.get());
}

/*!\test
 * Parse single request coming in as multiple fragments.
 */
void test_read_scattered_variable_request()
{
    mock_os->expect_os_try_read_to_buffer_callback(0, fill_buffer);
    fill_buffer_data->set("GET A", 0, 0);
    Applink::ParserResult result;
    auto cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::NEED_MORE_DATA), int(result));
    cppcut_assert_null(cmd.get());

    mock_os->expect_os_try_read_to_buffer_callback(0, fill_buffer);
    fill_buffer_data->set("IRABLE_PASS", 0, 0);
    cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::NEED_MORE_DATA), int(result));
    cppcut_assert_null(cmd.get());

    mock_os->expect_os_try_read_to_buffer_callback(0, fill_buffer);
    fill_buffer_data->set("WORD token passwor", 0, 0);
    cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::NEED_MORE_DATA), int(result));
    cppcut_assert_null(cmd.get());

    mock_os->expect_os_try_read_to_buffer_callback(0, fill_buffer);
    fill_buffer_data->set("d", 0, 0);
    cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::NEED_MORE_DATA), int(result));
    cppcut_assert_null(cmd.get());

    mock_os->expect_os_try_read_to_buffer_callback(0, fill_buffer);
    fill_buffer_data->set("\n", 0, 0);
    cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::HAVE_COMMAND), int(result));
    cppcut_assert_not_null(cmd.get());

    check_expected_command(*cmd, "AIRABLE_PASSWORD");

    static const char expected_parameters[] = "token password";
    cut_assert_equal_memory(expected_parameters, sizeof(expected_parameters) - 1,
                            cmd->parser_data_.parameters_buffer_.data(),
                            cmd->parser_data_.parameters_buffer_.size());

    std::array<char, 512> buffer;
    cmd->get_parameter(0, buffer);
    cppcut_assert_equal("token", static_cast<const char *>(buffer.data()));

    cmd->get_parameter(1, buffer);
    cppcut_assert_equal("password", static_cast<const char *>(buffer.data()));

    /* done */
    expect_read_but_return_nothing();
    cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::EMPTY), int(result));
    cppcut_assert_null(cmd.get());
}

/*!\test
 * Parse two requests coming in as multiple fragments.
 */
void test_read_two_scattered_variable_requests()
{
    mock_os->expect_os_try_read_to_buffer_callback(0, fill_buffer);
    fill_buffer_data->set("GET AIRABLE_PASS", 0, 0);
    Applink::ParserResult result;
    auto cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::NEED_MORE_DATA), int(result));
    cppcut_assert_null(cmd.get());

    mock_os->expect_os_try_read_to_buffer_callback(0, fill_buffer);
    fill_buffer_data->set("WORD token password\nGET SERVICE_CREDE", 0, 0);
    cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::HAVE_COMMAND), int(result));
    cppcut_assert_not_null(cmd.get());

    check_expected_command(*cmd, "AIRABLE_PASSWORD");

    static const char expected_parameters_first[] = "token password";
    cut_assert_equal_memory(expected_parameters_first,
                            sizeof(expected_parameters_first) - 1,
                            cmd->parser_data_.parameters_buffer_.data(),
                            cmd->parser_data_.parameters_buffer_.size());

    std::array<char, 512> buffer;
    cmd->get_parameter(0, buffer);
    cppcut_assert_equal("token", static_cast<const char *>(buffer.data()));

    cmd->get_parameter(1, buffer);
    cppcut_assert_equal("password", static_cast<const char *>(buffer.data()));

    /* more to come */
    mock_os->expect_os_try_read_to_buffer_callback(0, fill_buffer);
    fill_buffer_data->set("NTIALS qobuz\n", 0, 0);
    cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::HAVE_COMMAND), int(result));
    cppcut_assert_not_null(cmd.get());

    check_expected_command(*cmd, "SERVICE_CREDENTIALS");

    static const char expected_parameters_second[] = "qobuz";
    cut_assert_equal_memory(expected_parameters_second,
                            sizeof(expected_parameters_second) - 1,
                            cmd->parser_data_.parameters_buffer_.data(),
                            cmd->parser_data_.parameters_buffer_.size());

    cmd->get_parameter(0, buffer);
    cppcut_assert_equal("qobuz", static_cast<const char *>(buffer.data()));

    /* done */
    expect_read_but_return_nothing();
    cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::EMPTY), int(result));
    cppcut_assert_null(cmd.get());
}

/*!\test
 * Parse single request containing short parameters
 */
void test_read_single_variable_request_with_one_character_parameters()
{
    mock_os->expect_os_try_read_to_buffer_callback(0, fill_buffer);
    fill_buffer_data->set("GET AIRABLE_PASSWORD ab 1\n", 0, 0);

    Applink::ParserResult result;
    auto cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::HAVE_COMMAND), int(result));
    cppcut_assert_not_null(cmd.get());

    check_expected_command(*cmd, "AIRABLE_PASSWORD");

    static const char expected_parameters[] = "ab 1";
    cut_assert_equal_memory(expected_parameters, sizeof(expected_parameters) - 1,
                            cmd->parser_data_.parameters_buffer_.data(),
                            cmd->parser_data_.parameters_buffer_.size());

    std::array<char, 512> buffer;
    cmd->get_parameter(0, buffer);
    cppcut_assert_equal("ab", static_cast<const char *>(buffer.data()));

    cmd->get_parameter(1, buffer);
    cppcut_assert_equal("1", static_cast<const char *>(buffer.data()));

    /* done */
    expect_read_but_return_nothing();
    cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::EMPTY), int(result));
    cppcut_assert_null(cmd.get());
}

/*!\test
 * Parse multiple requests that can in through a single read(2).
 */
void test_read_multiple_variable_request_after_empty_lines()
{
    mock_os->expect_os_try_read_to_buffer_callback(0, fill_buffer);
    fill_buffer_data->set("GET AIRABLE_ROOT_URL\n"
                          "GET AIRABLE_AUTH_URL en-US 192.168.1.1\n"
                          "GET SERVICE_CREDENTIALS tidal\n",
                          0, 0);

    Applink::ParserResult result;
    auto cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::HAVE_COMMAND), int(result));
    cppcut_assert_not_null(cmd.get());
    check_expected_command(*cmd, "AIRABLE_ROOT_URL");

    expect_read_but_return_nothing();
    cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::HAVE_COMMAND), int(result));
    cppcut_assert_not_null(cmd.get());
    check_expected_command(*cmd, "AIRABLE_AUTH_URL");

    expect_read_but_return_nothing();
    cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::HAVE_COMMAND), int(result));
    cppcut_assert_not_null(cmd.get());
    check_expected_command(*cmd, "SERVICE_CREDENTIALS");

    /* done */
    expect_read_but_return_nothing();
    cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::EMPTY), int(result));
    cppcut_assert_null(cmd.get());
}

/*!\test
 * Garbage lines are rejected.
 */
void test_read_garbage_command()
{
    mock_os->expect_os_try_read_to_buffer_callback(0, fill_buffer);
    fill_buffer_data->set("This is not a command\n", 0, 0);

    mock_messages->expect_msg_error(EINVAL, LOG_ERR,
                                    "Failed parsing applink command (command ignored)");

    Applink::ParserResult result;
    auto cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::EMPTY), int(result));
    cppcut_assert_null(cmd.get());
}

/*!\test
 * Construct an answer for a named variable.
 */
void test_generate_answer_line_for_named_variable()
{
    std::ostringstream os;
    cut_assert_true(Applink::make_answer_for_name(os, "SERVICE_CREDENTIALS",
                                                  { "service", "known",
                                                    "here is the login",
                                                    "and here is the password" }));

    auto result(os.str());
    cut_assert_false(result.empty());

    static const char expected_line[] =
        "SERVICE_CREDENTIALS: service known here\\ is\\ the\\ login and\\ here\\ is\\ the\\ password\n";
    cut_assert_equal_memory(expected_line, sizeof(expected_line) - 1,
                            result.c_str(), result.size());
}

/*!\test
 * Construct an answer for a variable structure.
 */
void test_generate_answer_line_for_variable()
{
    const auto *const variable = Applink::lookup("SERVICE_CREDENTIALS", 0);
    cppcut_assert_not_null(variable);

    std::ostringstream os;
    Applink::make_answer_for_var(os, *variable,
                                 { "service", "known", "here is the login",
                                   "and here is the password" });

    auto result(os.str());
    cut_assert_false(result.empty());

    static const char expected_line[] =
        "SERVICE_CREDENTIALS: service known here\\ is\\ the\\ login and\\ here\\ is\\ the\\ password\n";
    cut_assert_equal_memory(expected_line, sizeof(expected_line) - 1,
                            result.c_str(), result.size());
}

/*!\test
 * The app may send answers to set variables.
 */
void test_single_unrequested_answer_from_app()
{
    mock_os->expect_os_try_read_to_buffer_callback(0, fill_buffer);
    fill_buffer_data->set("SERVICE_LOGGED_IN: tidal test\\ account\n", 0, 0);

    Applink::ParserResult result;
    auto cmd = in_buf->get_next_command(default_peer_fd, result);
    cppcut_assert_equal(int(Applink::ParserResult::HAVE_ANSWER), int(result));
    cppcut_assert_not_null(cmd.get());

    check_expected_answer(*cmd, "SERVICE_LOGGED_IN");

    static const char expected_parameters[] = "tidal test\\ account";
    cut_assert_equal_memory(expected_parameters, sizeof(expected_parameters) - 1,
                            cmd->parser_data_.parameters_buffer_.data(),
                            cmd->parser_data_.parameters_buffer_.size());

    std::array<char, 512> buffer;
    cmd->get_parameter(0, buffer);
    cppcut_assert_equal("tidal", static_cast<const char *>(buffer.data()));

    cmd->get_parameter(1, buffer);
    cppcut_assert_equal("test account", static_cast<const char *>(buffer.data()));
}

/*!\test
 * Taking a command from an empty queue does not crash, but returns nullptr.
 */
void test_take_command_from_empty_queue_returns_null()
{
    Applink::Peer peer(default_peer_fd,
                       [] (int) { cut_fail("unexpected call"); },
                       [] (int, bool) { cut_fail("unexpected call"); });
    cut_assert_false(peer.send_one_from_queue_to_peer(default_peer_fd));
}

/*!\test
 * Empty command is reported as a bug.
 */
void test_sending_empty_command_triggers_bug_message()
{
    static size_t notifications;
    Applink::Peer peer(default_peer_fd,
                       [] (int) { ++notifications; },
                       [] (int, bool) { cut_fail("unexpected call"); });
    mock_messages->expect_msg_error_formatted(0, LOG_CRIT,
            "BUG: Ignoring empty applink command in out queue for peer 42");
    peer.send_to_queue(default_peer_fd, std::string());
    cppcut_assert_equal(size_t(1), notifications);
    cut_assert_true(peer.send_one_from_queue_to_peer(default_peer_fd));
}

/*!\test
 * Push single answer through output command queue.
 */
void test_put_single_answer_into_output_queue_and_remove()
{
    static size_t notifications;
    Applink::Peer peer(default_peer_fd,
                       [] (int) { ++notifications; },
                       [] (int, bool) { cut_fail("unexpected call"); });
    static const std::string command("Testing");
    mock_os->expect_os_write_from_buffer(0, 0, false, command.size(), default_peer_fd);
    peer.send_to_queue(default_peer_fd, std::string(command));
    cppcut_assert_equal(size_t(1), notifications);
    cut_assert_true(peer.send_one_from_queue_to_peer(default_peer_fd));
}

/*!\test
 * Push multiple answers through output command queue.
 */
void test_put_multiple_answers_into_output_queue_and_remove()
{
    static size_t notifications;
    Applink::Peer peer(default_peer_fd,
                       [] (int) { ++notifications; },
                       [] (int, bool) { cut_fail("unexpected call"); });

    std::array<std::string, 4> commands = { "A", "BCD", "foo bar", "x", };

    for(auto &cmd : commands)
        peer.send_to_queue(default_peer_fd, std::string(cmd));

    cppcut_assert_equal(commands.size(), notifications);

    for(const auto &cmd : commands)
    {
        mock_os->expect_os_write_from_buffer(0, 0, false, cmd.size(), default_peer_fd);
        cut_assert_true(peer.send_one_from_queue_to_peer(default_peer_fd));
    }

    cut_assert_false(peer.send_one_from_queue_to_peer(default_peer_fd));
}

}

namespace app_connections_tests
{

static tdbusAirable *const dbus_airable_iface_dummy =
    reinterpret_cast<tdbusAirable *>(0xac9122f4);

static tdbuscredentialsRead *const dbus_cred_read_iface_dummy =
    reinterpret_cast<tdbuscredentialsRead *>(0x2b8bbe90);

static MockMessages *mock_messages;
static MockNetwork *mock_network;
static MockDBusIface *mock_dbus_iface;
static MockAirableDBus *mock_airable_dbus;
static MockCredentialsDBus *mock_credentials_dbus;
static MockOs *mock_os;

static std::map<int, size_t> commands_in_queue;
static Applink::AppConnections *connections;
static fill_buffer_data_t *fill_buffer_data;
static fill_buffer_data_t *fill_buffer_data_second;
static constexpr int default_server_fd = 86;

static Network::Dispatcher &nwdispatcher(Network::Dispatcher::get_singleton());

void cut_setup()
{
    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_network = new MockNetwork;
    cppcut_assert_not_null(mock_network);
    mock_network->init();
    mock_network_singleton = mock_network;

    mock_dbus_iface = new MockDBusIface;
    cppcut_assert_not_null(mock_dbus_iface);
    mock_dbus_iface->init();
    mock_dbus_iface_singleton = mock_dbus_iface;

    mock_airable_dbus = new MockAirableDBus;
    cppcut_assert_not_null(mock_airable_dbus);
    mock_airable_dbus->init();
    mock_airable_dbus_singleton = mock_airable_dbus;

    mock_credentials_dbus = new MockCredentialsDBus;
    cppcut_assert_not_null(mock_credentials_dbus);
    mock_credentials_dbus->init();
    mock_credentials_dbus_singleton = mock_credentials_dbus;

    mock_os = new MockOs;
    cppcut_assert_not_null(mock_os);
    mock_os->init();
    mock_os_singleton = mock_os;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    fill_buffer_data = new fill_buffer_data_t;
    fill_buffer_data_second = new fill_buffer_data_t;

    nwdispatcher.reset();

    commands_in_queue.clear();
    connections = new Applink::AppConnections([] (int fd) { ++commands_in_queue[fd]; });
    cppcut_assert_not_null(connections);

    mock_network->expect_create_socket(default_server_fd, 1234, SOMAXCONN);
    cut_assert_true(connections->listen(1234));
}

void cut_teardown()
{
    cut_assert_true(commands_in_queue.empty());

    delete connections;

    mock_messages->check();
    mock_network->check();
    mock_dbus_iface->check();
    mock_airable_dbus->check();
    mock_credentials_dbus->check();
    mock_os->check();

    mock_messages_singleton = nullptr;
    mock_network_singleton = nullptr;
    mock_dbus_iface_singleton = nullptr;
    mock_airable_dbus_singleton = nullptr;
    mock_credentials_dbus_singleton = nullptr;
    mock_os_singleton = nullptr;

    delete mock_messages;
    delete mock_network;
    delete mock_dbus_iface;
    delete mock_airable_dbus;
    delete mock_credentials_dbus;
    delete mock_os;
    delete fill_buffer_data;
    delete fill_buffer_data_second;

    mock_messages = nullptr;
    mock_network = nullptr;
    mock_dbus_iface = nullptr;
    mock_airable_dbus = nullptr;
    mock_credentials_dbus = nullptr;
    mock_os = nullptr;
    fill_buffer_data = nullptr;
    fill_buffer_data_second = nullptr;
}

static void fd_events(struct pollfd *fds, size_t fds_max, short revents = 0)
{
    for(size_t i = 0; i < fds_max; ++i)
        fds[i].revents = revents;
}

template <size_t N>
static void fd_events(std::array<struct pollfd, N> &fds, short revents = 0)
{
    fd_events(fds.data(), N, revents);
}

static void fd_events(struct pollfd *fds, size_t fds_max, int fd, short revents,
                      bool clear_the_rest = true)
{
    if(clear_the_rest)
        fd_events(fds, fds_max);

    cppcut_assert_operator(nwdispatcher.get_number_of_fds(), <=, fds_max);
    auto it(std::find_if(fds, fds + nwdispatcher.get_number_of_fds(),
                         [fd] (const struct pollfd &poll) { return poll.fd == fd; }));

    if(it >= fds + nwdispatcher.get_number_of_fds())
        cut_fail("fd %d not found in scatter array", fd);

    it->revents = revents;
}

template <size_t N>
static void fd_events(std::array<struct pollfd, N> &fds, int fd, short revents,
                      bool clear_the_rest = true)
{
    fd_events(fds.data(), N, fd, revents, clear_the_rest);
}

static size_t connect_peer(struct pollfd *fds, size_t fds_max,
                           const int server_fd, const int expected_peer_id)
{
    const size_t prev_fd_count = nwdispatcher.get_number_of_fds();
    cppcut_assert_operator(prev_fd_count, <=, fds_max);
    cppcut_assert_operator(size_t(0), <, prev_fd_count);
    nwdispatcher.scatter_fds(fds, POLLIN);

    fd_events(fds, fds_max, server_fd, POLLIN);

    mock_network->expect_accept_peer_connection(expected_peer_id, server_fd, true,
                                                MESSAGE_LEVEL_NORMAL);

    std::ostringstream expected_message;
    expected_message << "Accepted smartphone connection, fd " << expected_peer_id;
    mock_messages->expect_msg_info_formatted(expected_message.str().c_str());

    cppcut_assert_equal(size_t(1), nwdispatcher.process(fds));

    cppcut_assert_equal(prev_fd_count + 1, nwdispatcher.get_number_of_fds());

    return prev_fd_count + 1;

}

template <size_t N>
static size_t connect_peer(std::array<struct pollfd, N> &fds,
                           const int server_fd, const int expected_peer_id)
{
    return connect_peer(fds.data(), fds.size(), server_fd, expected_peer_id);
}

/*!
 * Local mock implementation of #os_try_read_to_buffer().
 */
static int fill_this_or_that_buffer(void *dest, size_t count, size_t *add_bytes_read,
                                    int fd, bool suppress_error_on_eagain,
                                    int expected_fd, int take_second)
{
    uint8_t *dest_ptr = static_cast<uint8_t *>(dest);

    cppcut_assert_not_null(add_bytes_read);

    if(expected_fd != INT_MIN)
        cppcut_assert_equal(expected_fd, fd);

    cut_assert_true(suppress_error_on_eagain);

    fill_buffer_data_t *const fbd = take_second ? fill_buffer_data_second : fill_buffer_data;

    const size_t n = std::min(count, fbd->data_.length());
    std::copy_n(fbd->data_.begin(), n, dest_ptr + *add_bytes_read);
    *add_bytes_read += n;

    errno = fbd->errno_value_;

    return fbd->return_value_;
}

static int return_nothing(void *dest, size_t count, size_t *add_bytes_read,
                          int fd, bool suppress_error_on_eagain)
{
    cppcut_assert_not_null(dest);
    cppcut_assert_not_null(add_bytes_read);
    cppcut_assert_operator(0, <=, fd);
    return 0;
}

static void check_and_reset_queue_size(int fd, size_t expected_size,
                                       bool ignore_the_rest = false)
{
    cut_assert(commands_in_queue.find(fd) != commands_in_queue.end());
    cppcut_assert_equal(expected_size, commands_in_queue[fd]);
    commands_in_queue.erase(fd);

    if(ignore_the_rest)
        return;

    for(const auto &count : commands_in_queue)
    {
        if(count.first != fd)
            cppcut_assert_equal(size_t(0), count.second);
    }
}

/*!\test
 * Trying to send always works, even in case there is no app connected.
 *
 * In case no app is connected, nothing happens and the message is lost.
 */
void test_sending_broadcast_answer_to_no_connection_works()
{
    cut_assert_true(commands_in_queue.empty());
    connections->send_to_all_peers("Test answer to none");
    cut_assert_true(commands_in_queue.empty());
}

/*!\test
 * Processing empty queue is a NOP.
 */
void test_processing_empty_queue_is_nop()
{
    connections->process_out_queue();
}

/*!\test
 * Peer can connect, disconnect, and connect again.
 */
void test_peer_reconnect_after_clean_disconnect()
{
    static constexpr int peer_fd = 512;

    std::array<struct pollfd, 2> fds;

    /* first connect */
    connect_peer(fds, default_server_fd, peer_fd);

    /* clean disconnect */
    cppcut_assert_equal(size_t(2), nwdispatcher.scatter_fds(fds.data(), POLLIN));
    cut_assert_true(commands_in_queue.empty());
    fd_events(fds, peer_fd, POLLHUP);
    mock_network->expect_close(peer_fd);
    mock_messages->expect_msg_info_formatted("Smartphone direct connection disconnected (fd 512)");

    cppcut_assert_equal(size_t(1), nwdispatcher.process(fds.data()));

    cut_assert_true(commands_in_queue.empty());
    connections->send_to_all_peers("Into the void");
    cut_assert_true(commands_in_queue.empty());

    /* connect again */
    connect_peer(fds, default_server_fd, peer_fd + 10);
}

/*!\test
 * Disconnect peer by write error.
 */
void test_peer_reconnect_after_disconnect_on_write_error()
{
    static constexpr int peer_fd = 32;

    std::array<struct pollfd, 2> fds;

    /* first connect */
    connect_peer(fds, default_server_fd, peer_fd);

    /* try and fail to send something */
    cppcut_assert_equal(size_t(2), nwdispatcher.scatter_fds(fds.data(), POLLIN));
    cut_assert_true(commands_in_queue.empty());
    connections->send_to_all_peers("Never received by peer");
    check_and_reset_queue_size(peer_fd, 1);

    mock_os->expect_os_write_from_buffer_callback(
            0,
            [] (const void *src, size_t count, int fd)
            {
                cppcut_assert_not_null(src);
                cppcut_assert_operator(size_t(0), <, count);
                cppcut_assert_equal(peer_fd, fd);
                errno = EPIPE;
                return -1;
            });
    mock_messages->expect_msg_error_formatted(EPIPE, LOG_ERR,
            "Sending data to app fd 32 failed (Broken pipe)");
    mock_messages->expect_msg_info_formatted("Applink connection on fd 32 died");
    mock_messages->expect_msg_info_formatted("Smartphone direct connection disconnected (fd 32)");
    mock_network->expect_close(peer_fd);

    connections->process_out_queue();

    /* HUP may be noticed a bit later, but will not be processed (HUP
     * notification function is called directly after the error has been
     * detected) */
    fd_events(fds, peer_fd, POLLHUP);
    cppcut_assert_equal(size_t(1), nwdispatcher.get_number_of_fds());
    cppcut_assert_equal(size_t(0), nwdispatcher.process(fds.data()));

    /* connect again */
    connect_peer(fds, default_server_fd, peer_fd + 5);
}

/*!\test
 * Disconnect peer by read error.
 */
void test_peer_reconnect_after_disconnect_on_read_error()
{
    static constexpr int peer_fd = 753;

    std::array<struct pollfd, 2> fds;

    /* first connect */
    connect_peer(fds, default_server_fd, peer_fd);

    /* try and fail to read something */
    cppcut_assert_equal(size_t(2), nwdispatcher.scatter_fds(fds.data(), POLLIN));
    cut_assert_true(commands_in_queue.empty());

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG,
                                              "Smartphone app over TCP/IP on fd 753");
    mock_network->expect_have_data(true, peer_fd);
    mock_os->expect_os_try_read_to_buffer_callback(
            0,
            [] (void *dest, size_t count, size_t *add_bytes_read,
                int fd, bool suppress_error_on_eagain) -> int
            {
                cppcut_assert_not_null(dest);
                cppcut_assert_equal(size_t(4096), count);
                cppcut_assert_not_null(add_bytes_read);
                cppcut_assert_equal(size_t(0), *add_bytes_read);
                cppcut_assert_equal(peer_fd, fd);
                cut_assert_true(suppress_error_on_eagain);

                errno = EINVAL;

                return -1;
            });
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_CRIT,
            "Failed reading app commands from fd 753 (Invalid argument)");
    mock_messages->expect_msg_info_formatted("Applink connection on fd 753 died");
    mock_messages->expect_msg_info_formatted("Smartphone direct connection disconnected (fd 753)");
    mock_network->expect_close(peer_fd);

    fd_events(fds, peer_fd, POLLIN);
    cppcut_assert_equal(size_t(1), nwdispatcher.process(fds.data()));

    cut_assert_true(commands_in_queue.empty());

    /* HUP may be noticed a bit later, but will not be processed (HUP
     * notification function is called directly after the error has been
     * detected) */
    fd_events(fds, peer_fd, POLLHUP);
    cppcut_assert_equal(size_t(1), nwdispatcher.get_number_of_fds());
    cppcut_assert_equal(size_t(0), nwdispatcher.process(fds.data()));

    /* connect again */
    connect_peer(fds, default_server_fd, peer_fd + 5);
}

/*!\test
 * A peer may have something to read, but disconnect before its data has been
 * processed.
 */
void test_peer_ready_to_read_and_disconnected()
{
    static constexpr int peer_fd = 63;

    std::array<struct pollfd, 2> fds;

    connect_peer(fds, default_server_fd, peer_fd);

    cppcut_assert_equal(size_t(2), nwdispatcher.scatter_fds(fds.data(), POLLIN));
    cut_assert_true(commands_in_queue.empty());

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG,
                                              "Smartphone app over TCP/IP on fd 63");
    mock_network->expect_have_data(true, peer_fd);
    mock_os->expect_os_try_read_to_buffer_callback(
            0,
            [] (void *dest, size_t count, size_t *add_bytes_read,
                int fd, bool suppress_error_on_eagain) -> int
            {
                cppcut_assert_not_null(dest);
                cppcut_assert_equal(size_t(4096), count);
                cppcut_assert_not_null(add_bytes_read);
                cppcut_assert_equal(size_t(0), *add_bytes_read);
                cppcut_assert_equal(peer_fd, fd);
                cut_assert_true(suppress_error_on_eagain);

                errno = ETIMEDOUT;

                return -1;
            });
    mock_messages->expect_msg_error_formatted(ETIMEDOUT, LOG_CRIT,
            "Failed reading app commands from fd 63 (Connection timed out)");
    mock_messages->expect_msg_info_formatted("Applink connection on fd 63 died");
    mock_messages->expect_msg_info_formatted("Smartphone direct connection disconnected (fd 63)");
    mock_network->expect_close(peer_fd);

    fd_events(fds, peer_fd, POLLIN | POLLHUP);
    cppcut_assert_equal(size_t(1), nwdispatcher.process(fds.data()));

    cut_assert_true(commands_in_queue.empty());

}

/*!\test
 * Send message to single connected peer.
 */
void test_sending_broadcast_answer_to_single_peer()
{
    static constexpr int peer_fd = 420;

    std::array<struct pollfd, 2> fds;

    connect_peer(fds, default_server_fd, peer_fd);

    static const std::string command("Test answer to single");

    cppcut_assert_equal(size_t(2), nwdispatcher.scatter_fds(fds.data(), POLLIN));
    cut_assert_true(commands_in_queue.empty());

    connections->send_to_all_peers(std::string(command));

    check_and_reset_queue_size(peer_fd, 1);

    mock_os->expect_os_write_from_buffer(0, 0, false, command.size(), peer_fd);
    connections->process_out_queue();
}

/*!\test
 * Send message to multiple connected peers.
 */
void test_sending_broadcast_answer_to_multiple_peers()
{
    static constexpr int anton = 123;
    static constexpr int berta = 456;
    static constexpr int chuck = 789;

    std::array<struct pollfd, 4> fds;

    connect_peer(fds, default_server_fd, anton);
    connect_peer(fds, default_server_fd, berta);
    connect_peer(fds, default_server_fd, chuck);

    static const std::string command("Test answer to many");

    cppcut_assert_equal(size_t(4), nwdispatcher.scatter_fds(fds.data(), POLLIN));
    cut_assert_true(commands_in_queue.empty());

    connections->send_to_all_peers(std::string(command));

    check_and_reset_queue_size(anton, 1, true);
    check_and_reset_queue_size(berta, 1, true);
    check_and_reset_queue_size(chuck, 1, true);

    mock_os->expect_os_write_from_buffer(0, 0, false, command.size(), anton);
    mock_os->expect_os_write_from_buffer(0, 0, false, command.size(), berta);
    mock_os->expect_os_write_from_buffer(0, 0, false, command.size(), chuck);
    connections->process_out_queue();
}

static void setup_request_expectations(int peer_fd,
                                       const std::string &service_id,
                                       const std::string &expected_login,
                                       const std::string &expected_password,
                                       bool take_second_fill_buffer = false)
{
    std::ostringstream os;
    os << "Smartphone app over TCP/IP on fd " << peer_fd;
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, os.str().c_str());

    mock_network->expect_have_data(true, peer_fd);
    mock_os->expect_os_try_read_to_buffer_callback(
            0,
            [peer_fd, take_second_fill_buffer]
            (void *dest, size_t count, size_t *add_bytes_read, int fd,
             bool suppress_error_on_eagain) -> int
            {
                return fill_this_or_that_buffer(dest, count, add_bytes_read, fd,
                                                suppress_error_on_eagain,
                                                peer_fd, take_second_fill_buffer);
            });

    mock_os->expect_os_try_read_to_buffer_callback(0, return_nothing);
    (take_second_fill_buffer ? fill_buffer_data_second : fill_buffer_data)->set(("GET SERVICE_CREDENTIALS " + service_id + '\n').c_str(), 0, 0);
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG,
                                              "App request: SERVICE_CREDENTIALS");
    mock_dbus_iface->expect_dbus_get_airable_sec_iface(dbus_airable_iface_dummy);
    mock_dbus_iface->expect_dbus_get_credentials_read_iface(dbus_cred_read_iface_dummy);
    mock_dbus_iface->expect_dbus_get_credentials_read_iface(dbus_cred_read_iface_dummy);
    mock_credentials_dbus->expect_tdbus_credentials_read_call_get_default_credentials_sync(
            TRUE, dbus_cred_read_iface_dummy, service_id.c_str(),
            expected_login.c_str(), expected_password.c_str());
}

static void peer_requests_service_credentials(struct pollfd *fds,
                                              size_t fds_max, const int peer_fd,
                                              const std::string &service_id,
                                              const std::string &expected_login,
                                              const std::string &expected_password)
{
    cppcut_assert_not_null(fds);
    cppcut_assert_operator(size_t(0), <, fds_max);
    cppcut_assert_operator(0, <=, peer_fd);

    cppcut_assert_equal(fds_max, nwdispatcher.scatter_fds(fds, POLLIN));
    cut_assert_true(commands_in_queue.empty());

    setup_request_expectations(peer_fd, service_id, expected_login, expected_password);

    fd_events(fds, fds_max, peer_fd, POLLIN);
    cppcut_assert_equal(size_t(1), nwdispatcher.process(fds));
    check_and_reset_queue_size(peer_fd, 1);

    std::string written;
    mock_os->expect_os_write_from_buffer_callback(
            0,
            [&peer_fd, &written]
            (const void *src, size_t count, int fd) -> int
            {
                cppcut_assert_equal(peer_fd, fd);
                std::copy_n(static_cast<const char *>(src), count, std::back_inserter(written));
                return 0;
            });

    connections->process_out_queue();

    const std::string expected_answer("SERVICE_CREDENTIALS: " + service_id +
                                      " known " + expected_login + " " +
                                      expected_password + '\n');
    cppcut_assert_equal(expected_answer, written);
}

/*!\test
 * Answer a peer request to the only connected peer.
 */
void test_variable_requested_by_single_connected_peer()
{
    static constexpr int peer_fd = 194;

    std::array<struct pollfd, 2> fds;
    connect_peer(fds, default_server_fd, peer_fd);

    peer_requests_service_credentials(fds.data(), fds.size(), peer_fd,
                                      "tidal", "the_tidal_login@unit-testing.org", "passw0rd");
}

/*!\test
 * Answer a peer request from one out of multiple connected peers.
 */
void test_variable_requested_by_one_of_several_peers()
{
    static constexpr int peer_fd = 307;

    std::array<struct pollfd, 4> fds;
    connect_peer(fds, default_server_fd, peer_fd);
    connect_peer(fds, default_server_fd, peer_fd + 10);
    connect_peer(fds, default_server_fd, peer_fd + 11);

    peer_requests_service_credentials(fds.data(), fds.size(), peer_fd,
                                      "qobuz", "quak@frog-eaters.org", "mot");
}

/*!\test
 * Answer two concurrent requests from two different peers.
 */
void test_variable_requested_by_two_concurrent_peers()
{
    static constexpr int anton = 81;
    static constexpr int berta = 84;

    std::array<struct pollfd, 6> fds;
    connect_peer(fds, default_server_fd, 80);
    connect_peer(fds, default_server_fd, anton);
    connect_peer(fds, default_server_fd, 82);
    connect_peer(fds, default_server_fd, 83);
    connect_peer(fds, default_server_fd, berta);

    cppcut_assert_equal(fds.size(), nwdispatcher.scatter_fds(fds.data(), POLLIN));
    cut_assert_true(commands_in_queue.empty());

    bool take_second_buffer = false;
    for(const auto &it : fds)
    {
        if(it.fd == anton)
        {
            setup_request_expectations(anton, "tidal", "antony@anarchy.org", "aaa",
                                       take_second_buffer);
            take_second_buffer = true;
        }
        else if(it.fd == berta)
        {
            setup_request_expectations(berta, "qobuz", "berthilda@blub.com", "bbb",
                                       take_second_buffer);
            take_second_buffer = true;
        }
    }

    fd_events(fds, anton, POLLIN);
    fd_events(fds, berta, POLLIN, false);
    cppcut_assert_equal(size_t(2), nwdispatcher.process(fds.data()));
    check_and_reset_queue_size(anton, 1, true);
    check_and_reset_queue_size(berta, 1);
}

}

#endif /* !LOGGED_LOCKS_ENABLED  */
