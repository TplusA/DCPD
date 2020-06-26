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

#include <doctest.h>

#include "dcpregs_system_update.hh"
#include "dcpregs_system_update_json.hh"
#include "rest_api.hh"

#include "mock_messages.hh"

TEST_SUITE_BEGIN("Registers Streaming Board System Update (request parser)");

class FixtureParser
{
  protected:
    std::unique_ptr<MockMessages::Mock> mock_messages;

  public:
    explicit FixtureParser():
        mock_messages(std::make_unique<MockMessages::Mock>())
    {
        MockMessages::singleton = mock_messages.get();
        mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

        Regs::SystemUpdate::init();
    }

    virtual ~FixtureParser()
    {
        try
        {
            mock_messages->done();
        }
        catch(...)
        {
            /* no throwing from dtors */
        }

        MockMessages::singleton = nullptr;
    }
};

TEST_CASE_FIXTURE(FixtureParser,
                  "Empty request triggers system update within "
                  "current release line")
{
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(nullptr, 0) == 0);
    const auto req(Regs::SystemUpdate::get_update_request());
    CHECK(req.is_object());
    CHECK(req.size() == 1);
    CHECK(req.at("id").get<std::string>() == "strbo");
}

static void check_flavor_version_repo_values(const nlohmann::json &req)
{
    CHECK(req.is_object());
    CHECK(req.size() == 4);
    CHECK(req.at("id").get<std::string>() == "strbo");
    CHECK(req.at("base_url").get<std::string>() == "https://packages.ta-hifi.de/StrBo/V2");
    CHECK(req.at("target_version").get<std::string>() == "V2.3.4.5");
    CHECK(req.at("target_flavor").get<std::string>() == "beta");
}

TEST_CASE_FIXTURE(FixtureParser,
                  "Change of flavor, version number, and repository URL "
                  "within the current release line")
{
    const char request[] =
        "url=https://packages.ta-hifi.de/StrBo/V2 flavor=beta version=V2.3.4.5";

    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == 0);
    check_flavor_version_repo_values(Regs::SystemUpdate::get_update_request());
}

TEST_CASE_FIXTURE(FixtureParser,
                  "Spaces and trailing null characters are ignored")
{
    const char request[] =
        "   url= https://packages.ta-hifi.de/StrBo/V2   flavor   =  beta version =V2.3.4.5  \0 ";

    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == 0);
    check_flavor_version_repo_values(Regs::SystemUpdate::get_update_request());
}

TEST_CASE_FIXTURE(FixtureParser, "Values may be quoted")
{
    const char request[] =
        "url=\"https://packages.ta-hifi.de/StrBo/V2\" flavor=\"beta\" version=\"V2.3.4.5\"";

    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == 0);
    check_flavor_version_repo_values(Regs::SystemUpdate::get_update_request());
}

TEST_CASE_FIXTURE(FixtureParser, "Quoted values may contains spaces")
{
    const char request[] =
        "url = \"https://packages.ta-hifi.de/StrBo/V2\" flavor = \"beta carotene\" version  =   \"  V space \"      ";

    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == 0);
    const auto req(Regs::SystemUpdate::get_update_request());
    CHECK(req.is_object());
    CHECK(req.size() == 4);
    CHECK(req.at("id").get<std::string>() == "strbo");
    CHECK(req.at("base_url").get<std::string>() == "https://packages.ta-hifi.de/StrBo/V2");
    CHECK(req.at("target_version").get<std::string>() == "  V space ");
    CHECK(req.at("target_flavor").get<std::string>() == "beta carotene");
}

TEST_CASE_FIXTURE(FixtureParser,
                  "Quoted values may contains escaped characters, "
                  "including quotation marks")
{
    const char request[] =
        "url=\"https\\://packages\\.ta-hifi.de\\/StrBo/V2\" flavor=\"\\ beta carotene (\\\"carot\\\")\" version=\"V\\ \\\"\\\\\\\\5\"";

    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == 0);
    const auto req(Regs::SystemUpdate::get_update_request());
    CHECK(req.is_object());
    CHECK(req.size() == 4);
    CHECK(req.at("id").get<std::string>() == "strbo");
    CHECK(req.at("base_url").get<std::string>() == "https://packages.ta-hifi.de/StrBo/V2");
    CHECK(req.at("target_version").get<std::string>() == "V \"\\\\5");
    CHECK(req.at("target_flavor").get<std::string>() == " beta carotene (\"carot\")");
}

static void check_line_flavor_version_repo_values(const nlohmann::json &req)
{
    CHECK(req.is_object());
    CHECK(req.size() == 5);
    CHECK(req.at("id").get<std::string>() == "strbo");
    CHECK(req.at("base_url").get<std::string>() == "https://packages.ta-hifi.de/StrBo/V4");
    CHECK(req.at("target_version").get<std::string>() == "V4.1.0.2");
    CHECK(req.at("target_flavor").get<std::string>() == "beta");
    CHECK(req.at("target_release_line").get<std::string>() == "V4");
}

TEST_CASE_FIXTURE(FixtureParser,
                  "Change of flavor, version number, repository URL, "
                  "and release line")
{
    const char request[] =
        "url=https://packages.ta-hifi.de/StrBo/V4 flavor=beta version=V4.1.0.2 line=V4";

    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == 0);
    check_line_flavor_version_repo_values(Regs::SystemUpdate::get_update_request());
}

TEST_CASE_FIXTURE(FixtureParser, "Unknown keys are ignored and dumped to log")
{
    const char request[] =
        "dummy=1 url=https://packages.ta-hifi.de/StrBo/V4 flavor=beta foo=bar version=V4.1.0.2 qux=\"hello world\" line=V4";

    expect<MockMessages::MsgError>(
            mock_messages, EINVAL, LOG_WARNING,
            "Unrecognized request parameter \"dummy\" (Invalid argument)",
            false);
    expect<MockMessages::MsgError>(
            mock_messages, EINVAL, LOG_WARNING,
            "Unrecognized request parameter \"foo\" (Invalid argument)",
            false);
    expect<MockMessages::MsgError>(
            mock_messages, EINVAL, LOG_WARNING,
            "Unrecognized request parameter \"qux\" (Invalid argument)",
            false);
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == 0);
    check_line_flavor_version_repo_values(Regs::SystemUpdate::get_update_request());
}

TEST_SUITE_END();


Rest::Result Rest::get_entry(const char *category, const char *sub)
{
    CHECK(category == std::string("system"));
    CHECK(sub == std::string("device_info"));
    const nlohmann::json root_json = R"(
        {
          "_links": {
            "self": {
              "href": "/"
            },
            "system": [
              {
                "href": "/system",
                "title": "T+A HiFi system",
                "name": "hifi_system"
              },
              {
                "href": "/system/devices",
                "title": "List of all T+A devices connected to the system",
                "name": "all_devices"
              },
              {
                "href": "/system/devices/{id}",
                "title": "Accessing a specific device in the T+A HiFi system",
                "name": "device_info",
                "templated": true
              }
            ],
            "airable": [
              {
                "href": "/airable",
                "title": "Interfacing with Airable",
                "name": "info"
              }
            ],
            "recovery_data": [
              {
                "href": "/recovery/data/status",
                "title": "Status of the recovery data",
                "name": "data_info"
              }
            ],
            "network_config": [
              {
                "href": "/network",
                "title": "Configuration of network services",
                "name": "network_config"
              }
            ]
          },
          "api_version": {
            "major": 0,
            "minor": 7
          },
          "monitor_port": 8468
        })"_json;

    return Rest::get_entry_from_root_json(root_json, category, sub);
}

Rest::Result Rest::send_request(const std::string &url, nlohmann::json &&request)
{
    CHECK(url == "http://localhost:8467/v1/system/devices/self");
    CHECK(request.is_object());
    CHECK(request.size() == 1);
    CHECK(request.at("update").is_array());
    CHECK(request["update"].size() == 1);
    check_line_flavor_version_repo_values(request["update"][0]);
    return Rest::Result(200, {});
}


TEST_SUITE_BEGIN("Registers Streaming Board System Update (request processing)");

class FixtureProcess
{
  protected:
    std::unique_ptr<MockMessages::Mock> mock_messages;

  public:
    explicit FixtureProcess():
        mock_messages(std::make_unique<MockMessages::Mock>())
    {
        MockMessages::singleton = mock_messages.get();
        mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

        Regs::SystemUpdate::init();
    }

    virtual ~FixtureProcess()
    {
        try
        {
            mock_messages->done();
        }
        catch(...)
        {
            /* no throwing from dtors */
        }

        MockMessages::singleton = nullptr;
    }
};

TEST_CASE_FIXTURE(FixtureProcess,
                  "Processing fails if parameters have not been set")
{
    expect<MockMessages::MsgVinfo>(
            mock_messages, MESSAGE_LEVEL_IMPORTANT,
            "Attempting to START SYSTEM UPDATE (rpm/images)", false);
    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_ERR,
            "Cannot trigger StrBo update without undefined arguments", false);
    CHECK_FALSE(Regs::SystemUpdate::process_update_request());
}

TEST_CASE_FIXTURE(FixtureProcess, "Full set of parameters")
{
    const char request[] =
        "url=https://packages.ta-hifi.de/StrBo/V4 flavor=beta version=V4.1.0.2 line=V4";

    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == 0);

    expect<MockMessages::MsgVinfo>(
            mock_messages, MESSAGE_LEVEL_IMPORTANT,
            "Attempting to START SYSTEM UPDATE (rpm/images)", false);
    CHECK(Regs::SystemUpdate::process_update_request());
}

TEST_SUITE_END();
