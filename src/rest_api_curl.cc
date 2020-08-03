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

#include "rest_api.hh"
#include "messages.h"

#include <curlpp/cURLpp.hpp>
#include <curlpp/Easy.hpp>
#include <curlpp/Options.hpp>
#include <curlpp/Infos.hpp>
#include <sstream>

#if LIBCURLPP_VERSION_NUM > 0x000703
#define CONST_GETINFO const
#else
#define CONST_GETINFO
#endif /* LIBCURLPP_VERSION_NUM */

void Rest::init()
{
    curlpp::initialize();
}

static void default_opts(curlpp::Easy &easy)
{
    easy.setOpt(curlpp::Options::NoSignal(true));
    easy.setOpt(curlpp::Options::NoProgress(true));
    easy.setOpt(curlpp::Options::FailOnError(true));
    easy.setOpt(curlpp::Options::UserAgent(PACKAGE_STRING));
}

static Rest::Result mk_error_result(const char *prefix,
                                    CONST_GETINFO curlpp::Easy &easy,
                                    const char *ex_msg, unsigned int code)
{
    std::string err(prefix);

    const auto url = curlpp::Infos::EffectiveUrl::get(easy);
    if(url.empty())
        err += ": ";
    else
    {
        err += " (";
        err += url;
        err += "): ";
    }

    err += ex_msg;

    return Rest::Result(code, Rest::Error(std::move(err)));
}

static Rest::Result mk_error_result(const char *prefix,
                                    CONST_GETINFO curlpp::Easy &easy,
                                    const curlpp::RuntimeError &e)
{
    const auto code = curlpp::Infos::ResponseCode::get(easy);
    return mk_error_result(prefix, easy, e.what(), code >= 0 ? code : 0);
}

static Rest::Result mk_error_result(const char *prefix,
                                    CONST_GETINFO curlpp::Easy &easy,
                                    const std::exception &e)
{
    return mk_error_result(prefix, easy, e.what(), 0);
}

Rest::Result Rest::get_entry(const char *category, const char *sub)
{
    static const std::string accept_hal_json("Accept: application/hal+json");

    curlpp::Easy easy;
    default_opts(easy);

    std::ostringstream json_buffer;
    easy.setOpt(curlpp::Options::Url(get_base_url() + '/'));
    easy.setOpt(curlpp::Options::HttpHeader({accept_hal_json}));
    easy.setOpt(curlpp::Options::WriteStream(&json_buffer));

    try
    {
        easy.perform();
    }
    catch(const curlpp::RuntimeError &e)
    {
        return mk_error_result("REST API get-root error", easy, e);
    }

    nlohmann::json root_json;

    try
    {
        root_json = nlohmann::json::parse(json_buffer.str());
    }
    catch(const std::exception &e)
    {
        return mk_error_result("Failed parsing REST API root", easy, e);
    }

    return get_entry_from_root_json(root_json, category, sub);
}

static size_t read_callback(char *out, size_t size, size_t nmemb,
                            const std::string &json, size_t &json_pos)
{
    if(json_pos >= json.size())
        return 0;

    const auto count =
        json_pos < json.size() ? json.copy(out, size * nmemb, json_pos) : 0;
    json_pos += count;
    return count;
}

Rest::Result Rest::send_request(const std::string &url, nlohmann::json &&request)
{
    static const std::string content_type_json("Content-Type: application/json");

    curlpp::Easy easy;
    default_opts(easy);

    easy.setOpt(curlpp::Options::Post(true));
    easy.setOpt(curlpp::Options::Url(url));
    easy.setOpt(curlpp::Options::HttpHeader({content_type_json}));

    const auto &str(request.dump());
    size_t str_pos = 0;
    easy.setOpt(curlpp::Options::ReadFunction(
        [&str, &str_pos]
        (char *out, size_t size, size_t nmemb)
        {
            return read_callback(out, size, nmemb, str, str_pos);
        }));

    std::ostringstream response;
    easy.setOpt(curlpp::Options::WriteStream(&response));

    try
    {
        easy.perform();
    }
    catch(const curlpp::RuntimeError &e)
    {
        if(!response.str().empty())
            msg_info("REST API error with response: \"%s\"",
                     response.str().c_str());

        return mk_error_result("REST API send-update-request error", easy, e);
    }

    nlohmann::json response_json;

    try
    {
        if(!response.str().empty())
            response_json = nlohmann::json::parse(response.str());
    }
    catch(const std::exception &e)
    {
        response_json = nullptr;
        msg_error(0, LOG_ERR,
                  "Failed parsing send-update-request POST response: \"%s\"",
                  response.str().c_str());
    }

    const auto code = curlpp::Infos::ResponseCode::get(easy);
    return Result(code >= 0 ? code : 0, std::move(response_json));
}
