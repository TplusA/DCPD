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

class RestConfig
{
  private:
    std::string base_url_;

  public:
    RestConfig(const RestConfig &) = delete;
    RestConfig(RestConfig &&) = default;
    RestConfig &operator=(const RestConfig &) = delete;
    RestConfig &operator=(RestConfig &&) = default;

    explicit RestConfig():
        base_url_("http://localhost:8467/v1")
    {}

    const std::string &base_url() const { return base_url_; }
};

static RestConfig rest_config;

const std::string &Rest::get_base_url()
{
    return rest_config.base_url();
}

Rest::Result
Rest::get_entry_from_root_json(const nlohmann::json &root_json,
                               const char *category, const char *sub)
{
    if(!root_json.contains("_links"))
        return Result(Error("No _links entry in API root"));

    if(!root_json["_links"].contains(category))
    {
        std::string err("Category ");
        err += category;
        err += " not found in API root";
        return Result(Error(std::move(err)));
    }

    for(const auto &entry : root_json["_links"][category])
        // cppcheck-suppress useStlAlgorithm
        if(entry.contains("name") && entry["name"].get<std::string>() == sub)
            return Result(200, nlohmann::json(entry));

    std::string err("Entry ");
    err += sub;
    err += " not found in category ";
    err += category;
    err += " in API root";
    return Result(Error(std::move(err)));
}

std::string Rest::mk_url(const nlohmann::json &api_entry)
{
    return mk_url(api_entry, [] (const std::string &) { return nullptr; });
}

std::string
Rest::mk_url(const nlohmann::json &api_entry,
             const std::function<const char *(const std::string &)> &values)
{
    if(!api_entry.contains("href"))
    {
        msg_error(0, LOG_ERR, "No href entry in API entry");
        return "";
    }

    const std::string &href(api_entry["href"].get<std::string>());

    if(!api_entry.contains("templated") || api_entry["templated"] == false)
        return get_base_url() + href;

    std::string url(get_base_url());
    size_t pos = 0;

    while(true)
    {
        const size_t found_pos = href.find('{', pos);

        if(found_pos == std::string::npos)
        {
            url += href.substr(pos);
            return url;
        }

        url += href.substr(pos, found_pos - pos);

        const size_t end_pos = href.find('}', found_pos + 1);
        if(end_pos == std::string::npos)
            break;

        const std::string &key(href.substr(found_pos + 1, end_pos - found_pos - 1));
        if(key.empty())
            break;

        const char *const val(values(key));
        if(val == nullptr)
        {
            msg_error(0, LOG_ERR,
                      "No value for URL template variable \"%s\"",
                      key.c_str());
            return "";
        }

        url += val;
        pos = end_pos + 1;
    }

    msg_error(0, LOG_ERR, "Broken URL template \"%s\"", href.c_str());
    return "";
}
