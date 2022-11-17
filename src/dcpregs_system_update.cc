/*
 * Copyright (C) 2020, 2021, 2022  T+A elektroakustik GmbH & Co. KG
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
#include "dcpregs_status.hh"
#include "rest_api.hh"
#include "messages.h"
#include "maybe.hh"

#include <unordered_map>
#include <string>
#include <sstream>
#include <algorithm>

Regs::SystemUpdate::UpdateResult
Regs::SystemUpdate::process_update_request()
{
    msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
              "Attempting to START SYSTEM UPDATE (rpm/images)");

    const nlohmann::json req(get_update_request());

    if(req == nullptr)
    {
        msg_error(0, LOG_ERR,
                  "Cannot trigger StrBo update with undefined arguments");
        return UpdateResult::BAD_CLIENT_REQUEST;
    }

    const Rest::Result api_entry(Rest::get_entry("system", "device_info"));

    if(!api_entry.have_answer())
    {
        msg_error(0, LOG_ERR, "Failed retrieving API node: %s",
                  api_entry.error().message().c_str());
        return UpdateResult::FAILURE;
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
        return UpdateResult::SUCCESS;

      case 0:
        msg_error(0, LOG_ERR,
                  "Failed sending system update request: %s",
                  result.error().message().c_str());
        break;

      case 303:
        msg_error(0, LOG_NOTICE, "Update already in progress, not restarting");
        return UpdateResult::SUCCESS;

      case 400:
        if(result.error().message().empty())
            msg_error(0, LOG_ERR, "Client error");
        else
            msg_error(0, LOG_ERR, "Client error: %s",
                      result.error().message().c_str());
        break;

      case 500:
      case 502:
      case 503:
        if(result.error().message().empty())
            msg_error(0, LOG_ERR, "Server error %u", result.get_status_code());
        else
            msg_error(0, LOG_ERR, "Server error %u: %s",
                      result.get_status_code(),
                      result.error().message().c_str());
        break;

      default:
        if(result.error().message().empty())
            MSG_BUG("Unhandled error %u", result.get_status_code());
        else
            MSG_BUG("Unhandled error %u: %s", result.get_status_code(),
                    result.error().message().c_str());
        break;
    }

    return UpdateResult::FAILURE;
}

static const std::string empty_string;
static const std::string error_string("__err__");

static const std::string &to_request_key(const std::string &token,
                                         ptrdiff_t offset)
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
        if(token.empty())
        {
            msg_error(EINVAL, LOG_ERR,
                      "Assignment to nothing at offset %zu", offset);
            return error_string;
        }

        msg_error(EINVAL, LOG_WARNING,
                  "Unrecognized request parameter \"%s\"", token.c_str());
        return empty_string;
    }
}

enum class TokenKind
{
    DIRECT_MAPPING,
    SET_REST_API_URL,
    SET_UPDATE_STYLE,
    MAYBE_STOP_FOR,
    MAYBE_STOP_BELOW,
    MAYBE_STOP_ABOVE,
};

static TokenKind determine_token_kind(const std::string &raw_token)
{
    static const std::unordered_map<std::string, TokenKind> keys
    {
        { "style",               TokenKind::SET_UPDATE_STYLE },
        { "stop",                TokenKind::MAYBE_STOP_FOR },
        { "stop_below",          TokenKind::MAYBE_STOP_BELOW },
        { "stop_above",          TokenKind::MAYBE_STOP_ABOVE },
        { "X-dcpd-rest-api-url", TokenKind::SET_REST_API_URL },
    };

    const auto &found(keys.find(raw_token));
    return found == keys.end() ? TokenKind::DIRECT_MAPPING : found->second;
}

enum class HandleTokenResult
{
    CONTINUE,
    STOP_EVALUATION,
    FAILED,
};

static HandleTokenResult should_stop_for(const std::string &version_spec,
                                         int version)
{
    std::istringstream ss(version_spec);

    while(ss.good())
    {
        std::string temp;
        std::getline(ss, temp, ',');

        if(std::stoi(temp) == version)
            return HandleTokenResult::STOP_EVALUATION;
    }

    return HandleTokenResult::CONTINUE;
}

static HandleTokenResult should_stop_below(const std::string &version_spec,
                                           int version)
{
    return std::stoi(version_spec) > version
        ? HandleTokenResult::STOP_EVALUATION
        : HandleTokenResult::CONTINUE;
}

static HandleTokenResult should_stop_above(const std::string &version_spec,
                                           int version)
{
    return std::stoi(version_spec) < version
        ? HandleTokenResult::STOP_EVALUATION
        : HandleTokenResult::CONTINUE;
}

static HandleTokenResult
handle_token(TokenKind kind, std::string &&value,
             Maybe<std::unordered_map<std::string, std::string>> &params,
             Maybe<std::unordered_map<std::string, bool>> &flags,
             Maybe<bool> &update_parameters_expected)
{
    bool failed = false;

    switch(kind)
    {
      case TokenKind::DIRECT_MAPPING:
        break;

      case TokenKind::SET_UPDATE_STYLE:
        if(value == "force-half-recovery")
        {
            failed = update_parameters_expected == true;
            auto &fl(flags.get_rw());
            fl["force_update_through_image_files"] = true;
            fl["force_recovery_system_update"] = false;
            fl["keep_user_data"] = true;
            update_parameters_expected = false;
        }
        else if(value == "force-recovery")
        {
            failed = update_parameters_expected == true;
            auto &fl(flags.get_rw());
            fl["force_update_through_image_files"] = true;
            fl["force_recovery_system_update"] = false;
            fl["keep_user_data"] = false;
            update_parameters_expected = false;
        }
        else if(value == "force-full-recovery")
        {
            failed = update_parameters_expected == false;
            auto &fl(flags.get_rw());
            fl["force_update_through_image_files"] = true;
            fl["force_recovery_system_update"] = true;
            fl["keep_user_data"] = false;
            update_parameters_expected = true;
        }
        else
            MSG_APPLIANCE_BUG("Bad update style \"%s\" (ignored)", value.c_str());

        if(failed)
        {
            MSG_APPLIANCE_BUG("Update style %s is incompatible with other parameters",
                              value.c_str());
            return HandleTokenResult::FAILED;
        }

        return HandleTokenResult::CONTINUE;

      case TokenKind::SET_REST_API_URL:
        Rest::set_base_url(std::move(value));
        return HandleTokenResult::CONTINUE;

      case TokenKind::MAYBE_STOP_FOR:
        return should_stop_for(value,
                               Regs::SystemUpdate::get_register_protocol_version());

      case TokenKind::MAYBE_STOP_BELOW:
        return should_stop_below(value,
                                 Regs::SystemUpdate::get_register_protocol_version());

      case TokenKind::MAYBE_STOP_ABOVE:
        return should_stop_above(value,
                                 Regs::SystemUpdate::get_register_protocol_version());
    }

    MSG_UNREACHABLE();
    return HandleTokenResult::CONTINUE;
}

static inline bool is_space(char ch) noexcept { return ch == ' '; }

static inline bool is_space_or_null(char ch) noexcept
{ return ch == ' ' || ch == '\0'; }

static bool parse_parameters(Maybe<std::unordered_map<std::string, std::string>> &params,
                             Maybe<std::unordered_map<std::string, bool>> &flags,
                             const char *in_ptr, const char *end_ptr)
{
    params.set_known();
    params->clear();

    flags.set_known();
    flags->clear();
    flags.get_rw()["keep_user_data"] = true;

    if(in_ptr == end_ptr)
        return true;

    Maybe<bool> update_parameters_expected;

    const char *pos = std::find_if_not(in_ptr, end_ptr, is_space);
    const char *const end =
        &*std::find_if_not(std::reverse_iterator<const char *>(end_ptr),
                           std::reverse_iterator<const char *>(in_ptr),
                           is_space_or_null) + 1;

    const auto *const base = in_ptr;
#define LOCATION(P) ((P) - base)

    while(pos < end)
    {
        const auto assignment = std::find(pos, end, '=');
        if(assignment == end)
        {
            msg_error(EINVAL, LOG_ERR,
                      "No assignments found after offset %zu", LOCATION(pos));
            return false;
        }
        else if(pos == assignment)
        {
            msg_error(EINVAL, LOG_ERR,
                      "Assignment to nothing at offset %zu", LOCATION(pos));
            return false;
        }

        /* drop spaces at beginning and end of token */
        pos = std::find_if_not(pos, assignment, is_space);
        const auto token_end =
            std::find_if_not(std::reverse_iterator<const char *>(assignment),
                             std::reverse_iterator<const char *>(pos),
                             is_space);
        const std::string raw_token(pos, (&*token_end) + 1);
        const auto token_kind = determine_token_kind(raw_token);
        const auto &token(token_kind != TokenKind::DIRECT_MAPPING
                          ? empty_string
                          : to_request_key(raw_token, LOCATION(pos)));

        if(token == error_string)
            return false;

        /* find beginning of assigned value */
        pos = std::find_if_not(std::next(assignment), end, is_space);
        auto stop = HandleTokenResult::CONTINUE;

        if(*pos != '"')
        {
            /* simple unquoted string */
            const auto value_end = std::find_if(pos, end, is_space);

            if(token_kind != TokenKind::DIRECT_MAPPING)
                stop = handle_token(token_kind, std::string(pos, value_end),
                                    params, flags, update_parameters_expected);
            else if(!token.empty())
                params.get_rw()[token] = std::string(pos, value_end);

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
                {
                    msg_error(EINVAL, LOG_ERR,
                              "Expected closing double quotes for those opened at offset %zu",
                              LOCATION(v - 1));
                    return false;
                }

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

                    if(token_kind != TokenKind::DIRECT_MAPPING)
                        stop = handle_token(token_kind, std::move(value), params, flags,
                                            update_parameters_expected);
                    else if(!token.empty())
                        params.get_rw()[token] = std::move(value);

                    ++pos;
                    break;
                }

                /* skip escape sequence */
                pos += 2;
                if(pos  >= end)
                {
                    msg_error(EINVAL, LOG_ERR,
                              "Escape character at end of parameter string");
                    return false;
                }
            }
        }

        switch(stop)
        {
          case HandleTokenResult::CONTINUE:
            break;

          case HandleTokenResult::STOP_EVALUATION:
            pos = end;
            break;

          case HandleTokenResult::FAILED:
            return false;
        }
    }

    static const std::array<std::pair<std::string, std::string>, 4> update_parameters
    {
        std::make_pair("base_url", "url"),
        std::make_pair("target_flavor", "flavor"),
        std::make_pair("target_release_line", "line"),
        std::make_pair("target_version", "version"),
    };

    const unsigned int param_count =
        std::count_if(update_parameters.begin(), update_parameters.end(),
                      [&params] (const auto &key)
                      { return params->find(key.first) != params->end(); });

    if(param_count == 0)
    {
        if(update_parameters_expected.pick(false, true, true))
            return true;

        MSG_APPLIANCE_BUG("Recovery update request lacks version and/or url requests");
        return false;
    }

    if(param_count == update_parameters.size())
    {
        if(update_parameters_expected.pick(true, false, true))
            return true;

        MSG_APPLIANCE_BUG("Pure recovery requests cannot be combined with version or url requests");
        return false;
    }

    std::ostringstream os;

    for(const auto &key : update_parameters)
        if(params->find(key.first) == params->end())
            os << ' ' << key.second;

    MSG_APPLIANCE_BUG("Incomplete version specification; missing:%s",
                      os.str().c_str());

    return false;
}

static Maybe<std::unordered_map<std::string, std::string>> strbo_update_parameters;
static Maybe<std::unordered_map<std::string, bool>> strbo_update_flags;

void Regs::SystemUpdate::init()
{
    strbo_update_parameters.set_unknown();
    strbo_update_flags.set_unknown();
}

nlohmann::json Regs::SystemUpdate::get_update_request()
{
    if(!strbo_update_parameters.is_known() || !strbo_update_flags.is_known())
        return nullptr;

    nlohmann::json req(strbo_update_parameters.get());

    for(const auto &kv : strbo_update_flags.get())
        req[kv.first] = kv.second;

    req["id"] = "strbo";
    return req;
}

int Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 211 handler %p %zu", data, length);

    const char *in = reinterpret_cast<const char *>(data);
    if(parse_parameters(strbo_update_parameters, strbo_update_flags, in, in + length))
    {
        Regs::StrBoStatus::set_system_update_request_accepted();
        return 0;
    }

    msg_error(0, LOG_ERR, "Failed parsing update request");
    strbo_update_parameters.set_unknown();
    strbo_update_flags.set_unknown();
    Regs::StrBoStatus::set_system_update_request_rejected();
    return -1;
}
