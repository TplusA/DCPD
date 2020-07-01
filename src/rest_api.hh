/*
 * Copyright (C) 2020  T+A elektroakustik GmbH & Co. KG
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

#ifndef REST_API_HH
#define REST_API_HH

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch-enum"
#include "json.hh"
#pragma GCC diagnostic pop

namespace Rest
{

class Error
{
  private:
    std::string message_;

  public:
    Error(const Error &) = delete;
    Error(Error &&) = default;
    Error &operator=(const Error &) = delete;
    Error &operator=(Error &&) = default;

    explicit Error(std::string &&message):
        message_(std::move(message))
    {}

    const std::string &message() const { return message_; }
};

class Result
{
  private:
    unsigned int http_status_code_;
    bool have_answer_;
    nlohmann::json answer_;
    Error error_;

  public:
    Result(const Result &) = delete;
    Result(Result &&) = default;
    Result &operator=(const Result &) = delete;
    Result &operator=(Result &&) = default;

    explicit Result(unsigned int http_status_code, nlohmann::json &&answer):
        http_status_code_(http_status_code),
        have_answer_(true),
        answer_(std::move(answer)),
        error_("")
    {}

    explicit Result(unsigned int http_status_code, Error &&error):
        http_status_code_(http_status_code),
        have_answer_(false),
        error_(std::move(error))
    {}

    explicit Result(Error &&error):
        http_status_code_(0),
        have_answer_(false),
        error_(std::move(error))
    {}

    unsigned int get_status_code() const { return http_status_code_; }
    bool have_answer() const { return have_answer_; }
    const nlohmann::json &answer() const { return answer_; }
    const Error &error() const { return error_; }
};

void init();
const std::string &get_base_url();
void set_base_url(std::string &&url);
Result get_entry(const char *category, const char *sub);
Result get_entry_from_root_json(const nlohmann::json &root_json,
                                const char *category, const char *sub);
std::string mk_url(const nlohmann::json &api_entry);
std::string mk_url(const nlohmann::json &api_entry,
                   const std::function<const char *(const std::string &)> &values);
Result send_request(const std::string &url, nlohmann::json &&request);

}

#endif /* !REST_API_HH */
