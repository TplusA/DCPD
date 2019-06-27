/*
 * Copyright (C) 2016, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef APPLINK_HH
#define APPLINK_HH

#include "applink_variables.hh"
#include "messages.h"

#include <array>
#include <vector>
#include <memory>

/*!
 * \addtogroup app_link Connection with smartphone app.
 */
/*!@{*/

namespace Applink
{

enum class Variables
{
    AIRABLE_ROOT_URL = 1,
    AIRABLE_AUTH_URL,
    AIRABLE_PASSWORD,
    SERVICE_CREDENTIALS,
    SERVICE_LOGGED_IN,
    SERVICE_LOGGED_OUT,

    FIRST_SUPPORTED_VARIABLE = AIRABLE_ROOT_URL,
    LAST_SUPPORTED_VARIABLE = SERVICE_LOGGED_OUT,
};

enum class ParserResult
{
    /*! Parsed nothing, input buffer empty. */
    EMPTY,

    /*! Found a command, input buffer may contain more. */
    HAVE_COMMAND,

    /*! Found an answer, input buffer may contain more. */
    HAVE_ANSWER,

    /*! Found possible partial command, line incomplete. */
    NEED_MORE_DATA,

    /*! I/O error while reading data from network. */
    IO_ERROR,

    /*! Not enough memory. */
    OUT_OF_MEMORY,
};

class Command
{
  private:
    bool is_request_;
    const Variable *variable_;

  public:
    struct ParserData
    {
        std::vector<uint8_t> parameters_buffer_;
        std::array<size_t, 5> offsets_;
        std::array<size_t, 5> lengths_;
        size_t number_of_parameters_;

        ParserData():
            offsets_{0},
            lengths_{0},
            number_of_parameters_(0)
        {}
    };

    ParserData parser_data_;

    Command(const Command &) = delete;
    Command &operator=(const Command &) = delete;

    explicit Command(bool is_req):
        is_request_(is_req),
        variable_(nullptr)
    {}

    const Variable *get_variable() const { return variable_; }
    const bool is_request() const { return is_request_; }

    void set_variable(const Variable *var)
    {
        variable_ = var;
    }

    /*!
    * Return the n'th parameter passed with given command.
    *
    * \param n
    *     Which parameter to return.
    *
    * \param buffer
    *     Buffer the parameter shall be copied to as zero-terminated string.
    */
    template <size_t N>
    void get_parameter(size_t n, std::array<char, N> &buffer) const
    {
        if(N > 0)
            get_parameter(n, buffer.data(), N);
    }

  private:
    void get_parameter(size_t n, char *buffer, size_t buffer_size) const;
};

class InputBuffer
{
  private:
    std::vector<uint8_t> data_;
    size_t last_scan_pos_;
    size_t scan_pos_;

  public:
    InputBuffer(const InputBuffer &) = delete;
    InputBuffer &operator=(const InputBuffer &) = delete;

    explicit InputBuffer():
        last_scan_pos_(0),
        scan_pos_(0)
    {}

    /*!
     * Parse next command or answer from connection.
     *
     * \param peer_fd
     *     The connection to parse the next command from.
     *
     * \param result
     *     Any #Applink::ParserResult, #Applink::ParserResult::HAVE_COMMAND on
     *     success.
     *
     * \returns
     *     On success, an object representing the parsed command is returned.
     */
    std::unique_ptr<Command> get_next_command(int peer_fd, ParserResult &result);

  private:
    void begin_scan() { last_scan_pos_ = scan_pos_; }
    const bool can_scan() const { return scan_pos_ < data_.size(); }
    void advance_scan() { ++scan_pos_; }
    uint8_t get_scan_char() const { return data_[scan_pos_]; }
    void mark_scan_position() { last_scan_pos_ = scan_pos_ + 1; }
    size_t get_marked_scan_position() const { return last_scan_pos_; }
    void go_to_marked_scan_position() { scan_pos_ = last_scan_pos_; }

    const char *get_line_at(size_t pos) const
    {
        log_assert(scan_pos_ >= pos);
        log_assert(scan_pos_ < data_.size());
        log_assert(data_[scan_pos_] == '\n');

        return reinterpret_cast<const char *>(&data_[pos]);
    }

    const size_t get_line_length(size_t pos) const
    {
        return scan_pos_ - pos;
    }

    std::unique_ptr<Command> parse_command_or_answer(ParserResult &result);
    std::unique_ptr<Command> parse_line(const size_t begin_pos, ParserResult &result);
    bool append_from_fd(int fd, size_t max_total_size);
    void remove_processed_data();
};

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
const Variable *lookup(const char *name, size_t length);

/*!
 * Generate answer for protocol variable of given name.
 *
 * \returns
 *     True on success, false in case the variable is unknown.
 *
 * \see
 *     #make_answer_for_var()
 */
bool make_answer_for_name(std::ostringstream &os, const char *variable_name,
                          std::vector<const char *> &&params);

/*!
 * Generate answer for given protocol variable.
 *
 * The returned answer is not zero-terminated.
 *
 * \param os
 *     Output buffer for the generated answer.
 *
 * \param variable
 *     Variable for which the answer shall be generated.
 *
 * \param params
 *     Parameters for the answer, each either a zero-terminated string or
 *     \c nullptr. The length of this vector must match
 *     #Applink::Variable::number_of_answer_parameters specified for the
 *     variable. Parameters which are set to \c nullptr are skipped, but be
 *     aware that \c nullptr does \e not indicate the end of the parameter
 *     list.
 */
void make_answer_for_var(std::ostringstream &os, const Variable &variable,
                         std::vector<const char *> &&params);

}

/*!@}*/

#endif /* !APPLINK_HH */
