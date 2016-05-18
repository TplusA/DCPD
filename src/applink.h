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

#ifndef APPLINK_H
#define APPLINK_H

#include "applink_variables.h"
#include "dynamic_buffer.h"

/*!
 * \addtogroup app_link Connection with smartphone app.
 */
/*!@{*/

enum ApplinkSupportedVariables
{
    VAR_AIRABLE_ROOT_URL = 1,
    VAR_AIRABLE_AUTH_URL,
    VAR_AIRABLE_PASSWORD,
    VAR_SERVICE_CREDENTIALS,
    VAR_SERVICE_LOGGED_IN,
    VAR_SERVICE_LOGGED_OUT,

    VAR_FIRST_SUPPORTED_VARIABLE = VAR_AIRABLE_ROOT_URL,
    VAR_LAST_SUPPORTED_VARIABLE = VAR_SERVICE_LOGGED_OUT,
};

enum ApplinkResult
{
    /*! Parsed nothing, input buffer empty. */
    APPLINK_RESULT_EMPTY,

    /*! Found a command, input buffer may contain more. */
    APPLINK_RESULT_HAVE_COMMAND,

    /*! Found an answer, input buffer may contain more. */
    APPLINK_RESULT_HAVE_ANSWER,

    /*! Found possible partial command, line incomplete. */
    APPLINK_RESULT_NEED_MORE_DATA,

    /*! I/O error while reading data from network. */
    APPLINK_RESULT_IO_ERROR,

    /*! Not enough memory. */
    APPLINK_RESULT_OUT_OF_MEMORY,
};

struct ApplinkConnection
{
    int peer_fd;
    struct dynamic_buffer input_buffer;

    size_t scan_pos;
};

struct ApplinkCommandPrivate_
{
    struct dynamic_buffer parameters_buffer;
    size_t offsets[5];
    size_t lengths[5];
    size_t number_of_parameters;
};

struct ApplinkCommand
{
    bool is_request;
    const struct ApplinkVariable *variable;

    struct ApplinkCommandPrivate_ private_data;
};

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Initialize connection structure.
 *
 * The structure is not initially associated with a network connection.
 */
int applink_connection_init(struct ApplinkConnection *conn);

/*!
 * Associate connection structure with network connection.
 */
void applink_connection_associate(struct ApplinkConnection *conn, int peer_fd);

/*!
 * Detach connection structure from network connection.
 *
 * The structure may be reused for a later connection. It is not necessary to
 * free the connection structure.
 */
void applink_connection_release(struct ApplinkConnection *conn);

/*!
 * Free data associated with connection structure.
 *
 * The structure itself is not freed. This is the responsibility of the caller.
 */
void applink_connection_free(struct ApplinkConnection *conn);

/*!
 * Look up a protocol variable by name.
 *
 * \param name
 *     Name of the variable.
 *
 * \param length
 *     Length of the variable if known. If greater than 0, then \p name does
 *     not need to be zero-terminated. Pass 0 to have the function determine
 *     the length (in which case \p name \e must be zero-terminated).
 */
const struct ApplinkVariable *applink_lookup(const char *name, size_t length);

/*!
 * Initialize a command structure for received commands.
 *
 * The structure is not initially associated with a specific commnd. It may be
 * reused for successive commands.
 */
int applink_command_init(struct ApplinkCommand *command);

/*!
 * Free command structure.
 */
void applink_command_free(struct ApplinkCommand *command);

/*!
 * Parse next command or answer from connection.
 *
 * \param conn
 *     The connection to parse the next command from, if any.
 *
 * \param command
 *     On success, the parsed command is returned in this structure.
 *
 * \returns
 *     Any #ApplinkResult, #APPLINK_RESULT_HAVE_COMMAND on success.
 */
enum ApplinkResult applink_get_next_command(struct ApplinkConnection *conn,
                                            struct ApplinkCommand *command);

/*!
 * Return the n'th parameter passed with given command.
 *
 * \param command
 *     The command whose parameter list shall be parsed.
 *
 * \param n
 *     Which parameter to return.
 *
 * \param buffer
 *     Buffer the parameter shall be copied to as zero-terminated string.
 *
 * \param buffer_size
 *     Size of the return buffer.
 */
void applink_command_get_parameter(const struct ApplinkCommand *command,
                                   size_t n, char *buffer, size_t buffer_size);

/*!
 * Generate answer for protocol variable of given name.
 *
 * \see
 *     #applink_make_answer_for_var()
 */
ssize_t applink_make_answer_for_name(char *buffer, size_t buffer_size,
                                     const char *variable_name, ...);

/*!
 * Generate answer for given protocol variable.
 *
 * The parameters for the answer are taken from the variadic function
 * parameters, all of which must be zero-terminated strings or \c NULL. This
 * function expects #ApplinkVariable::number_of_answer_parameters parameters as
 * defined for the \p variable.
 *
 * Parameters which are set to \c NULL are skipped, but be aware that \c NULL
 * does \e not indicate the end of the parameter list.
 *
 * The returned answer is not zero-terminated.
 *
 * \param buffer, buffer_size
 *     Buffer and its size for the generated answer. The buffer is not going to
 *     be zero-terminated.
 *
 * \param variable
 *     Variable for which the answer shall be generated.
 *
 * \returns
 *     The number of bytes written to \p buffer, -1 in case the buffer was too
 *     small for the answer.
 */
ssize_t applink_make_answer_for_var(char *buffer, size_t buffer_size,
                                    const struct ApplinkVariable *variable,
                                    ...);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !APPLINK_H */
