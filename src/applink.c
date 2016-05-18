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

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#include "applink.h"
#include "dynamic_buffer_util.h"
#include "messages.h"

struct ParserContext
{
    const char *const line;
    const size_t line_length;

    size_t pos;

    size_t token_pos;
    size_t token_length;
};

int applink_connection_init(struct ApplinkConnection *conn)
{
    log_assert(conn != NULL);

    conn->peer_fd = -1;
    dynamic_buffer_init(&conn->input_buffer);

    if(!dynamic_buffer_check_space(&conn->input_buffer))
        return msg_out_of_memory("Applink input buffer");

    return 0;
}

void applink_connection_associate(struct ApplinkConnection *conn, int peer_fd)
{
    log_assert(conn != NULL);
    log_assert(peer_fd >= 0);

    if(conn->peer_fd >= 0)
        applink_connection_release(conn);

    conn->peer_fd = peer_fd;
    conn->scan_pos = 0;
}

void applink_connection_release(struct ApplinkConnection *conn)
{
    conn->peer_fd = -1;
    dynamic_buffer_clear(&conn->input_buffer);
}

void applink_connection_free(struct ApplinkConnection *conn)
{
    dynamic_buffer_free(&conn->input_buffer);
}

int applink_command_init(struct ApplinkCommand *command)
{
    command->is_request = false;
    command->variable = NULL;
    dynamic_buffer_init(&command->private_data.parameters_buffer);

    return dynamic_buffer_check_space(&command->private_data.parameters_buffer) ? 0 : -1;
}

void applink_command_free(struct ApplinkCommand *command)
{
    dynamic_buffer_free(&command->private_data.parameters_buffer);
}

static void remove_processed_data_from_buffer(struct ApplinkConnection *conn)
{
    log_assert(conn->scan_pos <= conn->input_buffer.pos);

    if(conn->scan_pos == 0)
        return;

    conn->input_buffer.pos -= conn->scan_pos;

    if(conn->input_buffer.pos > 0)
        memmove(conn->input_buffer.data, conn->input_buffer.data + conn->scan_pos,
                conn->input_buffer.pos);

    conn->scan_pos = 0;
}

static int skip_spaces(struct ParserContext *ctx)
{
    for(/* nothing */; ctx->pos < ctx->line_length; ++ctx->pos)
    {
        if(ctx->line[ctx->pos] != ' ')
            return 0;
    }

    return ctx->pos < ctx->line_length ? 0 : -1;
}

static size_t scan_token(struct ParserContext *ctx)
{
    char previous_character = '\0';

    ctx->token_pos = ctx->pos;

    for(/* nothing */; ctx->pos < ctx->line_length; ++ctx->pos)
    {
        const char ch = ctx->line[ctx->pos];

        if(ch == ' ' && previous_character != '\\')
            break;

        previous_character = ch;
    }

    ctx->token_length = ctx->pos - ctx->token_pos;

    return ctx->token_length;
}

static inline bool token_equals(const struct ParserContext *ctx,
                                const char *token)
{
    if(ctx->token_length > 0)
        return strncmp(token, ctx->line + ctx->token_pos, ctx->token_length) == 0;
    else
        return false;
}

static size_t count_parameters(struct ParserContext *ctx,
                               struct ApplinkCommand *command,
                               const size_t parameters_pos)
{
    bool overflow = false;
    size_t count = 0;

    while(skip_spaces(ctx) == 0 && scan_token(ctx) > 0)
    {
        if(count < sizeof(command->private_data.offsets) / sizeof(command->private_data.offsets[0]))
        {
            command->private_data.offsets[count] = ctx->token_pos - parameters_pos;
            command->private_data.lengths[count] = ctx->token_length;
        }
        else
            overflow = true;

        ++count;

    }

    if(overflow)
    {
        msg_error(ERANGE, LOG_ERR, "Too many parameters in applink %s",
                  command->is_request ? "request" : "answer");
        command->private_data.number_of_parameters = 0;
    }
    else
        command->private_data.number_of_parameters = count;

    return count;
}

static enum ApplinkResult parse_parameters(struct ParserContext *ctx,
                                           struct ApplinkCommand *command,
                                           const enum ApplinkResult success_code)
{
    if(command->variable == NULL)
        return APPLINK_RESULT_IO_ERROR;

    (void)skip_spaces(ctx);
    const size_t parameters_pos = ctx->pos;

    const size_t count = count_parameters(ctx, command, parameters_pos);

    if(command->is_request &&
       command->variable->number_of_request_parameters != count)
    {
        msg_error(EINVAL, LOG_ERR,
                  "Expected %u parameters in applink command, but got %zu",
                  command->variable->number_of_request_parameters, count);
        return APPLINK_RESULT_IO_ERROR;
    }
    else if(!command->is_request &&
            command->variable->number_of_answer_parameters != count)
    {
        msg_error(EINVAL, LOG_ERR,
                  "Expected %u parameters in applink answer, but got %zu",
                  command->variable->number_of_answer_parameters, count);
        return APPLINK_RESULT_IO_ERROR;
    }

    if(count > 0)
    {
        log_assert(parameters_pos < ctx->pos);

        command->private_data.parameters_buffer.pos = ctx->pos - parameters_pos;
        memcpy(command->private_data.parameters_buffer.data,
               &ctx->line[parameters_pos],
               command->private_data.parameters_buffer.pos);
    }

    return success_code;
}

static enum ApplinkResult parse_request_line(struct ParserContext *ctx,
                                             struct ApplinkCommand *command)
{
    dynamic_buffer_clear(&command->private_data.parameters_buffer);

    if(skip_spaces(ctx) < 0)
        return APPLINK_RESULT_IO_ERROR;

    if(scan_token(ctx) == 0)
        return APPLINK_RESULT_IO_ERROR;

    command->variable =
        applink_lookup(ctx->line + ctx->token_pos, ctx->token_length);

    return parse_parameters(ctx, command, APPLINK_RESULT_HAVE_COMMAND);
}

static enum ApplinkResult parse_answer_line(struct ParserContext *ctx,
                                            struct ApplinkCommand *command)
{
    dynamic_buffer_clear(&command->private_data.parameters_buffer);

    if(ctx->token_length < 2)
        return APPLINK_RESULT_IO_ERROR;

    command->variable =
        applink_lookup(ctx->line + ctx->token_pos, ctx->token_length - 1);

    return parse_parameters(ctx, command, APPLINK_RESULT_HAVE_ANSWER);
}

/*!
 * Parse a single applink command line.
 */
static enum ApplinkResult parse_line(struct ApplinkConnection *conn,
                                     struct ApplinkCommand *command,
                                     const size_t begin_pos)
{
    log_assert(conn->scan_pos >= begin_pos);
    log_assert(conn->scan_pos < conn->input_buffer.pos);
    log_assert(conn->input_buffer.data[conn->scan_pos] == '\n');

    struct ParserContext ctx =
    {
        .line = ((const char *)conn->input_buffer.data) + begin_pos,
        .line_length = conn->scan_pos - begin_pos,
    };

    if(skip_spaces(&ctx) < 0)
        return APPLINK_RESULT_EMPTY;

    if(scan_token(&ctx) == 0)
        return APPLINK_RESULT_IO_ERROR;

    enum ApplinkResult retval;

    command->is_request = token_equals(&ctx, "GET");

    if(command->is_request)
        retval = parse_request_line(&ctx, command);
    else if(ctx.token_length > 0 &&
            ctx.token_pos + ctx.token_length - 1 < ctx.line_length &&
            ctx.line[ctx.token_pos + ctx.token_length - 1] == ':')
        retval = parse_answer_line(&ctx, command);
    else
        return APPLINK_RESULT_IO_ERROR;

    remove_processed_data_from_buffer(conn);

    return retval;
}

static enum ApplinkResult parse_command_or_answer(struct ApplinkConnection *conn,
                                                  struct ApplinkCommand *command)
{
    size_t begin_pos = 0;

    for(/* nothing */; conn->scan_pos < conn->input_buffer.pos; ++conn->scan_pos)
    {
        if(conn->input_buffer.data[conn->scan_pos] != '\n')
            continue;

        const enum ApplinkResult result = parse_line(conn, command, begin_pos);

        switch(result)
        {
          case APPLINK_RESULT_HAVE_COMMAND:
          case APPLINK_RESULT_HAVE_ANSWER:
          case APPLINK_RESULT_OUT_OF_MEMORY:
            return result;

          case APPLINK_RESULT_EMPTY:
            break;

          case APPLINK_RESULT_IO_ERROR:
            msg_error(EINVAL, LOG_ERR,
                      "Failed parsing applink command (command ignored)");
            break;

          case APPLINK_RESULT_NEED_MORE_DATA:
            BUG("Unexpected applink result while parsing command");
            break;
        }

        begin_pos = conn->scan_pos + 1;
    }

    remove_processed_data_from_buffer(conn);

    return conn->scan_pos < conn->input_buffer.pos
        ? APPLINK_RESULT_NEED_MORE_DATA
        : APPLINK_RESULT_EMPTY;
}

enum ApplinkResult applink_get_next_command(struct ApplinkConnection *conn,
                                            struct ApplinkCommand *command)
{
    log_assert(conn != NULL);
    log_assert(conn->peer_fd >= 0);
    log_assert(command != NULL);

    enum ApplinkResult result;

    if(!dynamic_buffer_fill_from_fd(&conn->input_buffer, conn->peer_fd,
                                    true, "app commands"))
        result = APPLINK_RESULT_IO_ERROR;
    else
        result = parse_command_or_answer(conn, command);

    switch(result)
    {
      case APPLINK_RESULT_HAVE_COMMAND:
      case APPLINK_RESULT_HAVE_ANSWER:
        return result;

      case APPLINK_RESULT_EMPTY:
      case APPLINK_RESULT_NEED_MORE_DATA:
      case APPLINK_RESULT_IO_ERROR:
      case APPLINK_RESULT_OUT_OF_MEMORY:
        break;
    }

    command->is_request = false;
    command->variable = NULL;
    dynamic_buffer_clear(&command->private_data.parameters_buffer);

    return result;
}

void applink_command_get_parameter(const struct ApplinkCommand *command,
                                   size_t n, char *buffer, size_t buffer_size)
{
    log_assert(command != NULL);
    log_assert(buffer != NULL);
    log_assert(buffer_size > 0);

    if(n >= command->private_data.number_of_parameters)
    {
        BUG("Parameter %zu out of range (have %zu parameters)",
            n, command->private_data.number_of_parameters);
        buffer[0] = '\0';
        return;
    }

    const char *const token =
        &((const char *)command->private_data.parameters_buffer.data)[command->private_data.offsets[n]];
    const size_t token_length = command->private_data.lengths[n];

    log_assert(token_length > 0);

    size_t i;
    size_t src_offset = 0;

    for(i = 0; i < buffer_size; ++i)
    {
        char ch = src_offset < token_length ? token[src_offset++] : '\0';

        if(ch == '\\')
            ch = src_offset < token_length ? token[src_offset++] : '\0';

        buffer[i] = ch;

        if(ch == '\0')
            return;
    }

    buffer[buffer_size - 1] = '\0';
}

static inline bool needs_escaping(const char ch)
{
    return ch == ' ' || ch == '\\';
}

static int append_escaped_parameter(char *buffer, ssize_t buffer_size,
                                    const char *parameter, ssize_t* const pos)
{
    if(*pos >= buffer_size)
        return -1;

    buffer[(*pos)++] = ' ';

    size_t src_offset = 0;

    while(*pos < buffer_size)
    {
        const char ch = parameter[src_offset++];

        if(ch == '\0')
            return 0;

        if(needs_escaping(ch))
        {
            buffer[(*pos)++] = '\\';

            if(*pos >= buffer_size)
                break;
        }

        buffer[(*pos)++] = ch;
    }

    return -1;
}

static ssize_t make_answer(char *buffer, size_t buffer_size,
                           const struct ApplinkVariable *const variable,
                           va_list ap)
{
    log_assert(buffer != NULL);
    log_assert(buffer_size > 0);

    ssize_t pos = (ssize_t)snprintf(buffer, buffer_size, "%s:", variable->name);

    if(pos < 0 || (size_t)pos >= buffer_size)
        return -1;

    for(unsigned int i = 0; i < variable->number_of_answer_parameters; ++i)
    {
        const char *const string = va_arg(ap, const char *);

        if(string == NULL)
            continue;

        if(append_escaped_parameter(buffer, (ssize_t)buffer_size,
                                    string, &pos) < 0)
            return -1;
    }

    if((size_t)pos >= buffer_size)
        return -1;

    buffer[pos++] = '\n';

    return pos;
}

ssize_t applink_make_answer_for_name(char *buffer, size_t buffer_size,
                                     const char *variable_name, ...)
{
    log_assert(variable_name != NULL);

    const struct ApplinkVariable *const variable =
        applink_lookup(variable_name, 0);

    if(variable == NULL)
        return -1;

    va_list ap;
    va_start(ap, variable_name);

    int retval = make_answer(buffer, buffer_size, variable, ap);

    va_end(ap);

    if(retval < 0)
        msg_error(ENOMEM, LOG_ERR, "Applink answer buffer too small");

    return retval;
}

ssize_t applink_make_answer_for_var(char *buffer, size_t buffer_size,
                                    const struct ApplinkVariable *variable,
                                    ...)
{
    log_assert(variable != NULL);

    va_list ap;
    va_start(ap, variable);

    int retval = make_answer(buffer, buffer_size, variable, ap);

    va_end(ap);

    if(retval < 0)
        msg_error(ENOMEM, LOG_ERR, "Applink answer buffer too small");

    return retval;
}

/*!
 * Alphabetically sorted variable definitions.
 *
 * \note
 *     These entries are sorted by name, not by ID.
 *
 * \see
 *     #ApplinkSupportedVariables
 */
static const struct ApplinkVariable sorted_variables[VAR_LAST_SUPPORTED_VARIABLE] =
{
#define MK_VARIABLE(NAME, REQ_PARAMS, ANS_PARAMS) \
    { \
        .name = #NAME, \
        .variable_id = VAR_ ## NAME, \
        .number_of_request_parameters = (REQ_PARAMS), \
        .number_of_answer_parameters = (ANS_PARAMS), \
    }

    MK_VARIABLE(AIRABLE_AUTH_URL,    2, 1),
    MK_VARIABLE(AIRABLE_PASSWORD,    2, 1),
    MK_VARIABLE(AIRABLE_ROOT_URL,    0, 1),
    MK_VARIABLE(SERVICE_CREDENTIALS, 1, 4),
    MK_VARIABLE(SERVICE_LOGGED_IN,   0, 2),
    MK_VARIABLE(SERVICE_LOGGED_OUT,  0, 2),

#undef MK_VARIABLE
};

static const struct ApplinkVariableTable known_variables =
{
    .variables = sorted_variables,
    .number_of_variables = sizeof(sorted_variables) / sizeof(sorted_variables[0]),
};

const struct ApplinkVariable *applink_lookup(const char *name, size_t length)
{
    if(length == 0)
        return applink_variable_lookup(&known_variables, name);
    else
        return applink_variable_lookup_with_length(&known_variables, name, length);
}
