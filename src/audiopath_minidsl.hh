/*
 * Copyright (C) 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef AUDIOPATH_MINIDSL_HH
#define AUDIOPATH_MINIDSL_HH

#include <memory>
#include <vector>
#include <string>
#include <exception>
#include <cstdint>

namespace AudioPaths
{

class ParserError: public std::exception
{
  private:
    std::string what_;

  public:
    explicit ParserError(const std::string &what_arg, size_t offset = SIZE_MAX):
        what_(what_arg)
    {
        append_offset(offset);
    }

    explicit ParserError(const char *what_arg, size_t offset = SIZE_MAX):
        what_(what_arg)
    {
        append_offset(offset);
    }

    const char *what() const noexcept final override { return what_.c_str(); }

  private:
    void append_offset(size_t offset)
    {
        if(offset < SIZE_MAX)
            what_ += " at offset " + std::to_string(offset);
    }
};

class ParserState;

/*!
 * Parser for the audio path language.
 *
 * The audio path language (AuPaL) is a small, domain-specific language for
 * exchanging audio path information between dcpd and the SPI slave. This class
 * can parse AuPaL specifications.
 */
class Parser
{
  private:
    std::unique_ptr<ParserState> state_;

  public:
    Parser(const Parser &) = delete;
    Parser(Parser &&) = default;
    Parser &operator=(const Parser &) = delete;
    Parser &operator=(Parser &&) = default;

    explicit Parser();
    ~Parser();

    /*!
     * Reset parser object to initial state.
     */
    void reset();

    /*!
     * Parse input in AuPaL syntax passed as vector.
     *
     * Throws #AudioPaths::ParserError in case of a parsing error.
     */
    void process(const std::vector<uint8_t> &input);

    /*!
     * Parse input in AuPaL syntax passed as C memory.
     *
     * Throws #AudioPaths::ParserError in case of a parsing error.
     */
    void process(const uint8_t *const input, size_t input_size);

    /*!
     * Turn parsed input into serialized JSON object.
     */
    std::string json_string() const;
};

}

#endif /* !AUDIOPATH_MINIDSL_HH */
