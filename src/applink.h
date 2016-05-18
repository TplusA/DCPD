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

    VAR_FIRST_SUPPORTED_VARIABLE = VAR_AIRABLE_ROOT_URL,
    VAR_LAST_SUPPORTED_VARIABLE = VAR_SERVICE_CREDENTIALS,
};

enum ApplinkResult
{
    /*! Parsed nothing, input buffer empty. */
    APPLINK_RESULT_EMPTY,

    /*! Found a command, input buffer may contain more. */
    APPLINK_RESULT_HAVE_COMMAND,

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

int applink_connection_init(struct ApplinkConnection *conn);
void applink_connection_associate(struct ApplinkConnection *conn, int peer_fd);
void applink_connection_release(struct ApplinkConnection *conn);
void applink_connection_free(struct ApplinkConnection *conn);

const struct ApplinkVariable *applink_lookup(const char *name, size_t length);

int applink_command_init(struct ApplinkCommand *command);
void applink_command_free(struct ApplinkCommand *command);

enum ApplinkResult applink_get_next_command(struct ApplinkConnection *conn,
                                            struct ApplinkCommand *command);
void applink_command_get_parameter(const struct ApplinkCommand *command,
                                   size_t n, char *buffer, size_t buffer_size);
ssize_t applink_make_answer_for_name(char *buffer, size_t buffer_size,
                                     const char *variable_name, ...);
ssize_t applink_make_answer_for_var(char *buffer, size_t buffer_size,
                                    const struct ApplinkVariable *variable,
                                    ...);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !APPLINK_H */
