/*
 * Copyright (C) 2015--2019  T+A elektroakustik GmbH & Co. KG
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

#include "applink.hh"

#include <algorithm>
#include <sstream>
#include <cstring>

struct ParserContext
{
    const char *const line;
    const size_t line_length;

    size_t pos;

    size_t token_pos;
    size_t token_length;

    explicit ParserContext(const char *l, size_t llen):
        line(l),
        line_length(llen),
        pos(0),
        token_pos(0),
        token_length(0)
    {}
};

Applink::InputBuffer::AppendResult
Applink::InputBuffer::append_from_fd(int fd, size_t max_total_size)
{
    if(data_.size() == max_total_size)
    {
        msg_error(0, LOG_WARNING, "Applink input buffer full");
        return AppendResult::INPUT_BUFFER_FULL;
    }

    size_t pos = data_.size();

    data_.resize(max_total_size);

    while(pos < max_total_size)
    {
        int ret = os_try_read_to_buffer(data_.data(), max_total_size,
                                        &pos, fd, true);

        if(ret == 0)
            break;

        if(ret < 0)
        {
            msg_error(errno, LOG_CRIT,
                      "Failed reading app commands from fd %d", fd);
            data_.resize(pos);
            return AppendResult::IO_ERROR;
        }
    }

    if(pos == data_.size())
        return AppendResult::CONNECTION_CLOSED;

    data_.resize(pos);
    return AppendResult::OK;
}

void Applink::InputBuffer::remove_processed_data()
{
    log_assert(scan_pos_ <= data_.size());

    if(scan_pos_ == 0)
        return;

    if(data_.size() <= scan_pos_)
        data_.clear();
    else
    {
        std::move(data_.begin() + scan_pos_, data_.end(), data_.begin());
        data_.resize(data_.size() - scan_pos_);
    }

    scan_pos_ = 0;
}

static int skip_spaces(ParserContext &ctx)
{
    for(/* nothing */; ctx.pos < ctx.line_length; ++ctx.pos)
    {
        if(ctx.line[ctx.pos] != ' ')
            return 0;
    }

    return ctx.pos < ctx.line_length ? 0 : -1;
}

static size_t scan_token(ParserContext &ctx)
{
    char previous_character = '\0';

    ctx.token_pos = ctx.pos;

    for(/* nothing */; ctx.pos < ctx.line_length; ++ctx.pos)
    {
        const char ch = ctx.line[ctx.pos];

        if(ch == ' ' && previous_character != '\\')
            break;

        previous_character = ch;
    }

    ctx.token_length = ctx.pos - ctx.token_pos;

    return ctx.token_length;
}

static inline bool token_equals(const ParserContext &ctx, const char *token)
{
    if(ctx.token_length > 0)
        return strncmp(token, ctx.line + ctx.token_pos, ctx.token_length) == 0;
    else
        return false;
}

static size_t count_parameters(ParserContext &ctx,
                               Applink::Command::ParserData &cmd_parser_data,
                               bool command_is_request,
                               const size_t parameters_pos)
{
    bool overflow = false;
    size_t count = 0;

    while(skip_spaces(ctx) == 0 && scan_token(ctx) > 0)
    {
        if(count < cmd_parser_data.offsets_.size())
        {
            cmd_parser_data.offsets_[count] = ctx.token_pos - parameters_pos;
            cmd_parser_data.lengths_[count] = ctx.token_length;
        }
        else
            overflow = true;

        ++count;
    }

    if(overflow)
    {
        msg_error(ERANGE, LOG_ERR, "Too many parameters in applink %s",
                  command_is_request ? "request" : "answer");
        cmd_parser_data.number_of_parameters_ = 0;
    }
    else
        cmd_parser_data.number_of_parameters_ = count;

    return count;
}

static Applink::ParserResult
parse_parameters(ParserContext &ctx, Applink::Command &command,
                 const Applink::ParserResult success_code)
{
    if(command.get_variable() == nullptr)
        return Applink::ParserResult::IO_ERROR;

    (void)skip_spaces(ctx);
    const size_t parameters_pos = ctx.pos;

    const size_t count = count_parameters(ctx, command.parser_data_,
                                          command.is_request(), parameters_pos);

    if(command.is_request() &&
       command.get_variable()->number_of_request_parameters != count)
    {
        msg_error(EINVAL, LOG_ERR,
                  "Expected %u parameters in applink command, but got %zu",
                  command.get_variable()->number_of_request_parameters, count);
        return Applink::ParserResult::IO_ERROR;
    }
    else if(!command.is_request() &&
            command.get_variable()->number_of_answer_parameters != count)
    {
        msg_error(EINVAL, LOG_ERR,
                  "Expected %u parameters in applink answer, but got %zu",
                  command.get_variable()->number_of_answer_parameters, count);
        return Applink::ParserResult::IO_ERROR;
    }

    if(count > 0)
    {
        log_assert(parameters_pos < ctx.pos);

        command.parser_data_.parameters_buffer_.resize(ctx.pos - parameters_pos);
        std::copy_n(&ctx.line[parameters_pos],
                    command.parser_data_.parameters_buffer_.size(),
                    command.parser_data_.parameters_buffer_.begin());
    }

    return success_code;
}

static Applink::ParserResult parse_request_line(ParserContext &ctx,
                                                Applink::Command &command)
{
    command.parser_data_.parameters_buffer_.clear();

    if(skip_spaces(ctx) < 0)
        return Applink::ParserResult::IO_ERROR;

    if(scan_token(ctx) == 0)
        return Applink::ParserResult::IO_ERROR;

    command.set_variable(Applink::lookup(ctx.line + ctx.token_pos, ctx.token_length));

    return parse_parameters(ctx, command, Applink::ParserResult::HAVE_COMMAND);
}

static Applink::ParserResult parse_answer_line(ParserContext &ctx,
                                               Applink::Command &command)
{
    command.parser_data_.parameters_buffer_.clear();

    if(ctx.token_length < 2)
        return Applink::ParserResult::IO_ERROR;

    command.set_variable(Applink::lookup(ctx.line + ctx.token_pos, ctx.token_length - 1));

    return parse_parameters(ctx, command, Applink::ParserResult::HAVE_ANSWER);
}

/*!
 * Parse a single applink command line.
 */
std::unique_ptr<Applink::Command>
Applink::InputBuffer::parse_line(const size_t begin_pos, Applink::ParserResult &result)
{
    struct ParserContext ctx(get_line_at(begin_pos), get_line_length(begin_pos));

    if(skip_spaces(ctx) < 0)
    {
        result = Applink::ParserResult::EMPTY;
        return nullptr;
    }

    if(scan_token(ctx) == 0)
    {
        result = Applink::ParserResult::IO_ERROR;
        return nullptr;
    }

    auto command = std::make_unique<Applink::Command>(token_equals(ctx, "GET"));

    if(command == nullptr)
    {
        result = Applink::ParserResult::OUT_OF_MEMORY;
        return nullptr;
    }

    if(command->is_request())
        result = parse_request_line(ctx, *command);
    else if(ctx.token_length > 0 &&
            ctx.token_pos + ctx.token_length - 1 < ctx.line_length &&
            ctx.line[ctx.token_pos + ctx.token_length - 1] == ':')
        result = parse_answer_line(ctx, *command);
    else
    {
        result = Applink::ParserResult::IO_ERROR;
        return nullptr;
    }

    remove_processed_data();

    return command;
}

std::unique_ptr<Applink::Command>
Applink::InputBuffer::parse_command_or_answer(Applink::ParserResult &result)
{
    size_t begin_pos = 0;

    for(begin_scan(); can_scan(); advance_scan())
    {
        if(get_scan_char() != '\n')
            continue;

        auto command = parse_line(begin_pos, result);

        mark_scan_position();

        switch(result)
        {
          case Applink::ParserResult::HAVE_COMMAND:
          case Applink::ParserResult::HAVE_ANSWER:
            return command;

          case Applink::ParserResult::OUT_OF_MEMORY:
            return nullptr;

          case Applink::ParserResult::EMPTY:
            break;

          case Applink::ParserResult::IO_ERROR:
            msg_error(EINVAL, LOG_ERR,
                      "Failed parsing applink command (command ignored)");
            break;

          case Applink::ParserResult::NEED_MORE_DATA:
            BUG("Unexpected applink result while parsing command");
            break;
        }

        begin_pos = get_marked_scan_position();
    }

    go_to_marked_scan_position();
    remove_processed_data();

    result = can_scan()
        ? Applink::ParserResult::NEED_MORE_DATA
        : Applink::ParserResult::EMPTY;

    return nullptr;
}

std::unique_ptr<Applink::Command>
Applink::InputBuffer::get_next_command(int peer_fd, Applink::ParserResult &result)
{
    log_assert(peer_fd >= 0);

    switch(append_from_fd(peer_fd, 4096))
    {
      case AppendResult::OK:
        return parse_command_or_answer(result);

      case AppendResult::INPUT_BUFFER_FULL:
        result = Applink::ParserResult::OUT_OF_MEMORY;
        break;

      case AppendResult::IO_ERROR:
      case AppendResult::CONNECTION_CLOSED:
        result = Applink::ParserResult::IO_ERROR;
        break;
    }

    return nullptr;
}

void Applink::Command::get_parameter(size_t n, char *buffer, size_t buffer_size) const
{
    if(n >= parser_data_.number_of_parameters_)
    {
        BUG("Parameter %zu out of range (have %zu parameters)",
            n, parser_data_.number_of_parameters_);
        buffer[0] = '\0';
        return;
    }

    const char *const token =
        &((const char *)parser_data_.parameters_buffer_.data())[parser_data_.offsets_[n]];
    const size_t token_length = parser_data_.lengths_[n];

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

static void append_escaped_parameter(std::ostringstream &os,
                                     const char *parameter)
{
    os << ' ';

    for(size_t i = 0; /* nothing */; ++i)
    {
        const char ch = parameter[i];

        if(ch == '\0')
            break;

        if(needs_escaping(ch))
            os << '\\';

        os << ch;
    }
}

void Applink::make_answer_for_var(std::ostringstream &os,
                                  const Applink::Variable &variable,
                                  std::vector<const char *> &&params)
{
    if(params.size() != variable.number_of_answer_parameters)
    {
        msg_error(EDOM, LOG_NOTICE,
                  "Variable %s requires %u answer parameters, but got %zu",
                  variable.name, variable.number_of_answer_parameters,
                  params.size());
        return;
    }

    os << variable.name << ':';

    for(const auto &string : params)
        if(string != nullptr)
            append_escaped_parameter(os, string);

    os << '\n';
}

bool Applink::make_answer_for_name(std::ostringstream &os,
                                   const char *variable_name,
                                   std::vector<const char *> &&params)
{
    log_assert(variable_name != nullptr);

    const auto *const variable = Applink::lookup(variable_name, 0);

    if(variable == nullptr)
        return false;

    make_answer_for_var(os, *variable, std::move(params));

    return true;
}

/*!
 * Alphabetically sorted variable definitions.
 *
 * \note
 *     These entries are sorted by name, not by ID.
 *
 * \see
 *     #Applink::Variables
 */
static const std::array<Applink::Variable, size_t(Applink::Variables::LAST_SUPPORTED_VARIABLE)> sorted_variables
{
#define MK_VARIABLE(NAME, REQ_PARAMS, ANS_PARAMS) \
    Applink::Variable(#NAME, uint16_t(Applink::Variables::NAME), REQ_PARAMS, ANS_PARAMS)

    MK_VARIABLE(AIRABLE_AUTH_URL,    2, 1),
    MK_VARIABLE(AIRABLE_PASSWORD,    2, 1),
    MK_VARIABLE(AIRABLE_ROOT_URL,    0, 1),
    MK_VARIABLE(SERVICE_CREDENTIALS, 1, 4),
    MK_VARIABLE(SERVICE_LOGGED_IN,   0, 2),
    MK_VARIABLE(SERVICE_LOGGED_OUT,  0, 2),

#undef MK_VARIABLE
};

static const Applink::VariableTable known_variables(sorted_variables);

const Applink::Variable *Applink::lookup(const char *name, size_t length)
{
    if(length == 0)
        return known_variables.lookup(name);
    else
        return known_variables.lookup(name, length);
}
