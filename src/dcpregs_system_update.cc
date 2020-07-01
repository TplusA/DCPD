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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "dcpregs_system_update.hh"
#include "dcpregs_system_update_json.hh"
#include "rest_api.hh"
#include "messages.h"
#include "maybe.hh"

#include <unordered_map>
#include <string>
#include <algorithm>

bool Regs::SystemUpdate::process_update_request()
{
    msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
              "Attempting to START SYSTEM UPDATE (rpm/images)");

    const nlohmann::json req(get_update_request());

    if(req == nullptr)
    {
        msg_error(0, LOG_ERR,
                  "Cannot trigger StrBo update without undefined arguments");
        return false;
    }

    const Rest::Result api_entry(Rest::get_entry("system", "device_info"));

    if(!api_entry.have_answer())
    {
        msg_error(0, LOG_ERR, "Failed retrieving API node: %s",
                  api_entry.error().message().c_str());
        return false;
    }

    const auto url(Rest::mk_url(api_entry.answer(),
                    [] (const std::string &key)
                    {
                        return key == "id" ? "self" : nullptr;
                    }));
    nlohmann::json req_object;
    req_object["update"] = nlohmann::json::array({req});
    const Rest::Result result(Rest::send_request(url, std::move(req_object)));

    init();

    switch(result.get_status_code())
    {
      case 200:
      case 202:
        return true;

      case 0:
        msg_error(0, LOG_ERR,
                  "Failed sending system update request: %s",
                  result.error().message().c_str());
        break;

      case 303:
        msg_error(0, LOG_NOTICE, "Update already in progress, not restarting");
        break;

      case 400:
        if(result.error().message().empty())
            msg_error(0, LOG_ERR, "Client error");
        else
            msg_error(0, LOG_ERR, "Client error: %s",
                      result.error().message().c_str());
        break;

      case 500:
        if(result.error().message().empty())
            msg_error(0, LOG_ERR, "Server error");
        else
            msg_error(0, LOG_ERR, "Server error: %s",
                      result.error().message().c_str());
        break;
    }

    return false;
}

static const std::string empty_string;

static const std::string &to_request_key(const std::string &token)
{
    static const std::unordered_map<std::string, std::string> keys
    {
        { "url",     "base_url" },
        { "line",    "target_release_line" },
        { "flavor",  "target_flavor" },
        { "version", "target_version" },
    };

    try
    {
        return keys.at(token);
    }
    catch(const std::out_of_range &e)
    {
        msg_error(EINVAL, LOG_WARNING,
                  "Unrecognized request parameter \"%s\"", token.c_str());
        return empty_string;
    }
}

static inline bool is_space(char ch) noexcept { return ch == ' '; }

static inline bool is_space_or_null(char ch) noexcept
{ return ch == ' ' || ch == '\0'; }

static bool parse_parameters(Maybe<std::unordered_map<std::string, std::string>> &params,
                             const char *in_ptr, const char *end_ptr)
{
    params.set_known();
    params->clear();

    if(in_ptr == end_ptr)
        return true;

    const char *pos = std::find_if_not(in_ptr, end_ptr, is_space);
    const char *const end =
        &*std::find_if_not(std::reverse_iterator<const char *>(end_ptr),
                           std::reverse_iterator<const char *>(in_ptr),
                           is_space_or_null) + 1;

    while(pos < end)
    {
        const auto assignment = std::find(pos, end, '=');
        if(assignment == end || pos == assignment)
            return false;

        /* drop spaces at beginning and end of token */
        pos = std::find_if_not(pos, assignment, is_space);
        const auto token_end =
            std::find_if_not(std::reverse_iterator<const char *>(assignment),
                             std::reverse_iterator<const char *>(pos),
                             is_space);
        const std::string raw_token(pos, (&*token_end) + 1);
        const bool configure_api_url = (raw_token == "X-dcpd-rest-api-url");
        const auto &token(configure_api_url ? empty_string : to_request_key(raw_token));

        /* find beginning of assigned value */
        pos = std::find_if_not(std::next(assignment), end, is_space);

        if(*pos != '"')
        {
            /* simple unquoted string */
            const auto value_end = std::find_if(pos, end, is_space);

            if(!token.empty())
                params.get_rw()[token] = std::string(pos, value_end);
            else if(configure_api_url)
                Rest::set_base_url(std::string(pos, value_end));

            if(value_end < end)
                pos = std::next(value_end);
            else
                pos = end;
        }
        else
        {
            /* find matching pair of quotation marks, handle escapes */
            ++pos;
            const auto v(pos);

            while(true)
            {
                pos = std::find_if(pos, end,
                        [] (const char ch) { return ch == '\\' || ch == '"'; });
                if(pos == end)
                    return false;

                if(*pos == '"')
                {
                    /* found closing quotation mark */
                    std::string value;
                    for(const char *ch = v; ch < pos; ++ch)
                    {
                        if(*ch == '\\')
                            ++ch;
                        value += *ch;
                    }

                    if(!token.empty())
                        params.get_rw()[token] = std::move(value);
                    else if(configure_api_url)
                        Rest::set_base_url(std::move(value));

                    ++pos;
                    break;
                }

                /* skip escape sequence */
                pos += 2;
                if(pos  >= end)
                    return false;
            }
        }
    }

    return true;
}

static Maybe<std::unordered_map<std::string, std::string>> strbo_update_parameters;

void Regs::SystemUpdate::init()
{
    strbo_update_parameters.set_unknown();
}

nlohmann::json Regs::SystemUpdate::get_update_request()
{
    if(!strbo_update_parameters.is_known())
        return nullptr;

    nlohmann::json req(strbo_update_parameters.get());
    req["id"] = "strbo";
    return req;
}

int Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 211 handler %p %zu", data, length);

    const char *in = reinterpret_cast<const char *>(data);
    if(parse_parameters(strbo_update_parameters, in, in + length))
        return 0;

    msg_error(0, LOG_ERR, "Failed parsing update request");
    strbo_update_parameters.set_unknown();
    return -1;
}
