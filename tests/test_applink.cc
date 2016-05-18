/*
 * Copyright (C) 2016  T+A elektroakustik GmbH & Co. KG
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

#include "applink.h"

#include "mock_messages.hh"
#include "mock_os.hh"

namespace applink_protocol_tests
{

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

static MockMessages *mock_messages;
static MockOs *mock_os;

static struct ApplinkConnection conn;
static fill_buffer_data_t *fill_buffer_data;
static int default_peer_fd = 42;

static struct ApplinkCommand default_command;

void cut_setup()
{
    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_os = new MockOs;
    cppcut_assert_not_null(mock_os);
    mock_os->init();
    mock_os_singleton = mock_os;

    fill_buffer_data = new fill_buffer_data_t;

    cppcut_assert_equal(0, applink_connection_init(&conn));
    applink_connection_associate(&conn, default_peer_fd);

    cppcut_assert_equal(0, applink_command_init(&default_command));
}

void cut_teardown()
{
    applink_command_free(&default_command);
    applink_connection_free(&conn);

    mock_messages->check();
    mock_os->check();

    mock_messages_singleton = nullptr;
    mock_os_singleton = nullptr;

    delete mock_messages;
    delete mock_os;
    delete fill_buffer_data;

    mock_messages = nullptr;
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

static void check_expected_command(const struct ApplinkCommand &command,
                                   const char *expected_variable)
{
    cut_assert_true(command.is_request);
    cppcut_assert_not_null(command.variable);
    cppcut_assert_equal(expected_variable, command.variable->name);

    if(command.variable->number_of_request_parameters > 0)
        cut_assert_false(dynamic_buffer_is_empty(&command.private_data.parameters_buffer));
    else
        cut_assert_true(dynamic_buffer_is_empty(&command.private_data.parameters_buffer));
}

static void check_expected_answer(const struct ApplinkCommand &command,
                                  const char *expected_variable)
{
    cut_assert_false(command.is_request);
    cppcut_assert_not_null(command.variable);
    cppcut_assert_equal(expected_variable, command.variable->name);

    if(command.variable->number_of_answer_parameters > 0)
        cut_assert_false(dynamic_buffer_is_empty(&command.private_data.parameters_buffer));
    else
        cut_assert_true(dynamic_buffer_is_empty(&command.private_data.parameters_buffer));
}

static void expect_read_but_return_nothing()
{
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer);
    fill_buffer_data->set("", 0, 0);
}

/*!\test
 * Basic lookup of predefined variable by name.
 */
void test_lookup_airable_password_variable()
{
    const auto *const variable = applink_lookup("AIRABLE_PASSWORD", 0);

    cppcut_assert_not_null(variable);
    cppcut_assert_equal("AIRABLE_PASSWORD", variable->name);
    cppcut_assert_equal(static_cast<uint16_t>(VAR_AIRABLE_PASSWORD),
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

    cppcut_assert_equal(APPLINK_RESULT_EMPTY,
                        applink_get_next_command(&conn, &default_command));

    cut_assert_false(default_command.is_request);
    cppcut_assert_null(default_command.variable);
    cut_assert_true(dynamic_buffer_is_empty(&default_command.private_data.parameters_buffer));
}

/*!\test
 * Empty lines are ignored.
 */
void test_read_empty_lines()
{
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer);
    fill_buffer_data->set("\n   \n \n\n", 0, 0);

    cppcut_assert_equal(APPLINK_RESULT_EMPTY,
                        applink_get_next_command(&conn, &default_command));

    cut_assert_false(default_command.is_request);
    cppcut_assert_null(default_command.variable);
    cut_assert_true(dynamic_buffer_is_empty(&default_command.private_data.parameters_buffer));
}

/*!\test
 * Parse a single request.
 */
void test_read_single_variable_request()
{
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer);
    fill_buffer_data->set("GET AIRABLE_PASSWORD test\\ token test\\ password\n", 0, 0);

    cppcut_assert_equal(APPLINK_RESULT_HAVE_COMMAND,
                        applink_get_next_command(&conn, &default_command));

    check_expected_command(default_command, "AIRABLE_PASSWORD");

    static const char expected_parameters[] = "test\\ token test\\ password";
    cut_assert_equal_memory(expected_parameters, sizeof(expected_parameters) - 1,
                            default_command.private_data.parameters_buffer.data,
                            default_command.private_data.parameters_buffer.pos);

    char buffer[512];
    applink_command_get_parameter(&default_command, 0, buffer, sizeof(buffer));
    cppcut_assert_equal("test token", static_cast<const char *>(buffer));

    applink_command_get_parameter(&default_command, 1, buffer, sizeof(buffer));
    cppcut_assert_equal("test password", static_cast<const char *>(buffer));
}

/*!\test
 * Parse a single request after a few empty lines.
 */
void test_read_single_variable_request_after_empty_lines()
{
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer);
    fill_buffer_data->set("\n\n     \n  GET AIRABLE_PASSWORD some\\ token password\n", 0, 0);

    cppcut_assert_equal(APPLINK_RESULT_HAVE_COMMAND,
                        applink_get_next_command(&conn, &default_command));

    check_expected_command(default_command, "AIRABLE_PASSWORD");

    static const char expected_parameters[] = "some\\ token password";
    cut_assert_equal_memory(expected_parameters, sizeof(expected_parameters) - 1,
                            default_command.private_data.parameters_buffer.data,
                            default_command.private_data.parameters_buffer.pos);

    char buffer[512];
    applink_command_get_parameter(&default_command, 0, buffer, sizeof(buffer));
    cppcut_assert_equal("some token", static_cast<const char *>(buffer));

    applink_command_get_parameter(&default_command, 1, buffer, sizeof(buffer));
    cppcut_assert_equal("password", static_cast<const char *>(buffer));

    /* done */
    expect_read_but_return_nothing();
    cppcut_assert_equal(APPLINK_RESULT_EMPTY,
                        applink_get_next_command(&conn, &default_command));
}

/*!\test
 * Parse multiple requests that can in through a single read(2).
 */
void test_read_multiple_variable_request_after_empty_lines()
{
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer);
    fill_buffer_data->set("GET AIRABLE_ROOT_URL\n"
                          "GET AIRABLE_AUTH_URL en-US 192.168.1.1\n"
                          "GET SERVICE_CREDENTIALS tidal\n",
                          0, 0);

    cppcut_assert_equal(APPLINK_RESULT_HAVE_COMMAND,
                        applink_get_next_command(&conn, &default_command));
    check_expected_command(default_command, "AIRABLE_ROOT_URL");

    expect_read_but_return_nothing();
    cppcut_assert_equal(APPLINK_RESULT_HAVE_COMMAND,
                        applink_get_next_command(&conn, &default_command));
    check_expected_command(default_command, "AIRABLE_AUTH_URL");

    expect_read_but_return_nothing();
    cppcut_assert_equal(APPLINK_RESULT_HAVE_COMMAND,
                        applink_get_next_command(&conn, &default_command));
    check_expected_command(default_command, "SERVICE_CREDENTIALS");

    /* done */
    expect_read_but_return_nothing();
    cppcut_assert_equal(APPLINK_RESULT_EMPTY,
                        applink_get_next_command(&conn, &default_command));
}

/*!\test
 * Garbage lines are rejected.
 */
void test_read_garbage_command()
{
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer);
    fill_buffer_data->set("This is not a command\n", 0, 0);

    mock_messages->expect_msg_error(EINVAL, LOG_ERR,
                                    "Failed parsing applink command (command ignored)");

    cppcut_assert_equal(APPLINK_RESULT_EMPTY,
                        applink_get_next_command(&conn, &default_command));

    cut_assert_false(default_command.is_request);
    cppcut_assert_null(default_command.variable);
    cut_assert_true(dynamic_buffer_is_empty(&default_command.private_data.parameters_buffer));
}

/*!\test
 * Construct an answer for a named variable.
 */
void test_generate_answer_line_for_named_variable()
{
    char buffer[512];
    ssize_t len = applink_make_answer_for_name(buffer, sizeof(buffer),
                                               "SERVICE_CREDENTIALS",
                                               "service",
                                               "known",
                                               "here is the login",
                                               "and here is the password");

    cppcut_assert_operator(ssize_t(0), <, len);

    static const char expected_line[] =
        "SERVICE_CREDENTIALS: service known here\\ is\\ the\\ login and\\ here\\ is\\ the\\ password\n";
    cut_assert_equal_memory(expected_line, sizeof(expected_line) - 1,
                            buffer, len);
}

/*!\test
 * Construct an answer for a variable structure.
 */
void test_generate_answer_line_for_variable()
{
    const auto *const variable = applink_lookup("SERVICE_CREDENTIALS", 0);
    cppcut_assert_not_null(variable);

    char buffer[512];
    ssize_t len = applink_make_answer_for_var(buffer, sizeof(buffer),
                                              variable,
                                              "service",
                                               "known",
                                              "here is the login",
                                              "and here is the password");

    cppcut_assert_operator(ssize_t(0), <, len);

    static const char expected_line[] =
        "SERVICE_CREDENTIALS: service known here\\ is\\ the\\ login and\\ here\\ is\\ the\\ password\n";
    cut_assert_equal_memory(expected_line, sizeof(expected_line) - 1,
                            buffer, len);
}

/*!\test
 * The app may send answers to set variables.
 */
void test_single_unrequested_answer_from_app()
{
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer);
    fill_buffer_data->set("SERVICE_LOGGED_IN: tidal test\\ account\n", 0, 0);

    cppcut_assert_equal(APPLINK_RESULT_HAVE_ANSWER,
                        applink_get_next_command(&conn, &default_command));

    check_expected_answer(default_command, "SERVICE_LOGGED_IN");

    static const char expected_parameters[] = "tidal test\\ account";
    cut_assert_equal_memory(expected_parameters, sizeof(expected_parameters) - 1,
                            default_command.private_data.parameters_buffer.data,
                            default_command.private_data.parameters_buffer.pos);

    char buffer[512];
    applink_command_get_parameter(&default_command, 0, buffer, sizeof(buffer));
    cppcut_assert_equal("tidal", static_cast<const char *>(buffer));

    applink_command_get_parameter(&default_command, 1, buffer, sizeof(buffer));
    cppcut_assert_equal("test account", static_cast<const char *>(buffer));
}

}
