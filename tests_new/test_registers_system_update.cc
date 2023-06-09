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

#include <doctest.h>

#include "dcpregs_system_update.hh"
#include "dcpregs_system_update_json.hh"
#include "dcpregs_status.hh"
#include "rest_api.hh"

#define MOCK_EXPECTATION_WITH_EXPECTATION_SEQUENCE_SINGLETON
#include "mock_messages.hh"

std::shared_ptr<MockExpectationSequence> mock_expectation_sequence_singleton =
    std::make_shared<MockExpectationSequence>();

static bool expect_update_request_accepted;
static bool called_update_request_accepted;
static bool expect_update_request_rejected;
static bool called_update_request_rejected;

void Regs::StrBoStatus::set_system_update_request_accepted()
{
    CHECK(expect_update_request_accepted);
    CHECK_FALSE(called_update_request_accepted);
    called_update_request_accepted = true;
}

void Regs::StrBoStatus::set_system_update_request_rejected()
{
    CHECK(expect_update_request_rejected);
    CHECK_FALSE(called_update_request_rejected);
    called_update_request_rejected = true;
}


TEST_SUITE_BEGIN("Registers Streaming Board System Update (request parser)");

class FixtureParser
{
  protected:
    std::unique_ptr<MockMessages::Mock> mock_messages;

  public:
    explicit FixtureParser():
        mock_messages(std::make_unique<MockMessages::Mock>())
    {
        mock_expectation_sequence_singleton->reset();
        expect_update_request_accepted = false;
        called_update_request_accepted = false;
        expect_update_request_rejected = false;
        called_update_request_rejected = false;

        MockMessages::singleton = mock_messages.get();
        mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

        Regs::SystemUpdate::init();
    }

    virtual ~FixtureParser()
    {
        try
        {
            mock_expectation_sequence_singleton->done();
            mock_messages->done();
            CHECK(expect_update_request_accepted == called_update_request_accepted);
            CHECK(expect_update_request_rejected == called_update_request_rejected);
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
    expect_update_request_accepted = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(nullptr, 0) == 0);
    const auto req(Regs::SystemUpdate::get_update_request());
    REQUIRE(req.is_object());
    CHECK(req.size() == 2);
    CHECK(req.at("id").get<std::string>() == "strbo");
    CHECK(req.at("keep_user_data").get<bool>());
}

static void check_flavor_version_repo_values(const nlohmann::json &req)
{
    REQUIRE(req.is_object());
    CHECK(req.size() == 6);
    CHECK(req.at("id").get<std::string>() == "strbo");
    CHECK(req.at("base_url").get<std::string>() == "https://packages.ta-hifi.de/StrBo/V2");
    CHECK(req.at("target_release_line").get<std::string>() == "V2");
    CHECK(req.at("target_version").get<std::string>() == "V2.3.4.5");
    CHECK(req.at("target_flavor").get<std::string>() == "beta");
    CHECK(req.at("keep_user_data").get<bool>());
}

TEST_CASE_FIXTURE(FixtureParser, "Assignment to nothingness is an error")
{
    const char request[] =
        "url=https://packages.ta-hifi.de/StrBo/V2 =foo flavor=beta";

    expect<MockMessages::MsgError>(
            mock_messages, EINVAL, LOG_ERR,
            "Assignment to nothing at offset 41 (Invalid argument)", false);
    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_ERR, "Failed parsing update request", false);
    expect_update_request_rejected = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == -1);
    CHECK(Regs::SystemUpdate::get_update_request() == nullptr);
}

TEST_CASE_FIXTURE(FixtureParser, "Assignment to nothingness with trailing spaces is an error")
{
    const char request[] =
        "url=https://packages.ta-hifi.de/StrBo/V2    =foo flavor=beta";

    expect<MockMessages::MsgError>(
            mock_messages, EINVAL, LOG_ERR,
            "Assignment to nothing at offset 44 (Invalid argument)", false);
    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_ERR, "Failed parsing update request", false);
    expect_update_request_rejected = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == -1);
    CHECK(Regs::SystemUpdate::get_update_request() == nullptr);
}

TEST_CASE_FIXTURE(FixtureParser, "Missing assigning is an error")
{
    const char request[] =
        "url=https://packages.ta-hifi.de/StrBo/V2 line V2";

    expect<MockMessages::MsgError>(
            mock_messages, EINVAL, LOG_ERR,
            "No assignments found after offset 41 (Invalid argument)", false);
    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_ERR, "Failed parsing update request", false);
    expect_update_request_rejected = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == -1);
    CHECK(Regs::SystemUpdate::get_update_request() == nullptr);
}

TEST_CASE_FIXTURE(FixtureParser, "Missing closing double quotation mark")
{
    const char request[] =
        "url=\"https://packages.ta-hifi.de/StrBo/V2 =foo flavor=beta";

    expect<MockMessages::MsgError>(
            mock_messages, EINVAL, LOG_ERR,
            "Expected closing double quotes for those opened at offset 4 (Invalid argument)", false);
    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_ERR, "Failed parsing update request", false);
    expect_update_request_rejected = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == -1);
    CHECK(Regs::SystemUpdate::get_update_request() == nullptr);
}

TEST_CASE_FIXTURE(FixtureParser,
                  "Escape character at end of parameter string is detected")
{
    const char request[] =
        "url=\"https://packages.ta-hifi.de/StrBo/V2\\";

    expect<MockMessages::MsgError>(
            mock_messages, EINVAL, LOG_ERR,
            "Escape character at end of parameter string (Invalid argument)", false);
    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_ERR, "Failed parsing update request", false);
    expect_update_request_rejected = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == -1);
    CHECK(Regs::SystemUpdate::get_update_request() == nullptr);
}

TEST_CASE_FIXTURE(FixtureParser,
                  "Change of flavor, version number, and repository URL "
                  "without specifying release line is an error")
{
    const char request[] =
        "url=https://packages.ta-hifi.de/StrBo/V2 flavor=beta version=V2.3.4.5";

    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_CRIT,
            "APPLIANCE BUG: Incomplete version specification; missing: line",
            false);
    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_ERR, "Failed parsing update request", false);
    expect_update_request_rejected = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == -1);
    CHECK(Regs::SystemUpdate::get_update_request() == nullptr);
}

TEST_CASE_FIXTURE(FixtureParser,
                  "Spaces and trailing null characters are ignored")
{
    const char request[] =
        "   url= https://packages.ta-hifi.de/StrBo/V2   flavor   =  beta version =V2.3.4.5 line   = V2 \0 ";

    expect_update_request_accepted = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == 0);
    check_flavor_version_repo_values(Regs::SystemUpdate::get_update_request());
}

TEST_CASE_FIXTURE(FixtureParser, "Values may be quoted")
{
    const char request[] =
        "url=\"https://packages.ta-hifi.de/StrBo/V2\" flavor=\"beta\" version=\"V2.3.4.5\" line=\"V2\"";

    expect_update_request_accepted = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == 0);
    check_flavor_version_repo_values(Regs::SystemUpdate::get_update_request());
}

TEST_CASE_FIXTURE(FixtureParser,
                  "Request evaluation can be stopped for too low register versions")
{
    REQUIRE(Regs::SystemUpdate::get_register_protocol_version() == 0);

    const char request[] =
        "url=https://packages.ta-hifi.de/StrBo/V2 flavor=beta version=V2.3.4.5 "
        "stop_below=1 line=V2 future=extension";

    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_CRIT,
            "APPLIANCE BUG: Incomplete version specification; missing: line",
            false);
    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_ERR, "Failed parsing update request", false);
    expect_update_request_rejected = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == -1);
    CHECK(Regs::SystemUpdate::get_update_request() == nullptr);
}

TEST_CASE_FIXTURE(FixtureParser,
                  "Request evaluation can be stopped for too high register versions")
{
    REQUIRE(Regs::SystemUpdate::get_register_protocol_version() == 0);

    const char request[] =
        "url=https://packages.ta-hifi.de/StrBo/V2 flavor=beta version=V2.3.4.5 "
        "stop_above=-1 line=V2 future=extension";

    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_CRIT,
            "APPLIANCE BUG: Incomplete version specification; missing: line",
            false);
    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_ERR, "Failed parsing update request", false);
    expect_update_request_rejected = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == -1);
    CHECK(Regs::SystemUpdate::get_update_request() == nullptr);
}

TEST_CASE_FIXTURE(FixtureParser,
                  "Request evaluation can be stopped for certain register versions")
{
    REQUIRE(Regs::SystemUpdate::get_register_protocol_version() == 0);

    const char request[] =
        "url=https://packages.ta-hifi.de/StrBo/V2 flavor=beta version=V2.3.4.5 "
        "stop=2,6,3,0 line=V2 future=extension";

    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_CRIT,
            "APPLIANCE BUG: Incomplete version specification; missing: line",
            false);
    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_ERR, "Failed parsing update request", false);
    expect_update_request_rejected = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == -1);
    CHECK(Regs::SystemUpdate::get_update_request() == nullptr);
}

TEST_CASE_FIXTURE(FixtureParser,
                  "Request evaluation does not stop for lower than current version")
{
    REQUIRE(Regs::SystemUpdate::get_register_protocol_version() == 0);

    const char request[] =
        "url=https://packages.ta-hifi.de/StrBo/V2 flavor=beta version=V2.3.4.5 "
        "stop_below=0 line=V2";

    expect_update_request_accepted = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == 0);

    const auto &req(Regs::SystemUpdate::get_update_request());
    REQUIRE(req.is_object());
    CHECK(req.size() == 6);
    CHECK(req.at("target_version").get<std::string>() == "V2.3.4.5");
    CHECK(req.at("target_release_line").get<std::string>() == "V2");
}

TEST_CASE_FIXTURE(FixtureParser,
                  "Request evaluation does not stop for higher than current version")
{
    REQUIRE(Regs::SystemUpdate::get_register_protocol_version() == 0);

    const char request[] =
        "url=https://packages.ta-hifi.de/StrBo/V2 flavor=beta version=V2.3.4.5 "
        "stop_above=0 line=V2";

    expect_update_request_accepted = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == 0);

    const auto &req(Regs::SystemUpdate::get_update_request());
    REQUIRE(req.is_object());
    CHECK(req.size() == 6);
    CHECK(req.at("target_version").get<std::string>() == "V2.3.4.5");
    CHECK(req.at("target_release_line").get<std::string>() == "V2");
}

TEST_CASE_FIXTURE(FixtureParser,
                  "Request evaluation does not stop if condition is not met")
{
    REQUIRE(Regs::SystemUpdate::get_register_protocol_version() == 0);

    const char request[] =
        "url=https://packages.ta-hifi.de/StrBo/V2 flavor=beta version=V2.3.4.5 "
        "stop=2,6,3 line=V2";

    expect_update_request_accepted = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == 0);

    const auto &req(Regs::SystemUpdate::get_update_request());
    REQUIRE(req.is_object());
    CHECK(req.size() == 6);
    CHECK(req.at("target_version").get<std::string>() == "V2.3.4.5");
    CHECK(req.at("target_release_line").get<std::string>() == "V2");
}

TEST_CASE_FIXTURE(FixtureParser, "Quoted values may contains spaces")
{
    const char request[] =
        "url = \"https://packages.ta-hifi.de/StrBo/V2\" flavor = \"beta carotene\" version  =   \"  V space \"   line = \"red  line  \"     ";

    expect_update_request_accepted = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == 0);
    const auto req(Regs::SystemUpdate::get_update_request());
    REQUIRE(req.is_object());
    CHECK(req.size() == 6);
    CHECK(req.at("id").get<std::string>() == "strbo");
    CHECK(req.at("base_url").get<std::string>() == "https://packages.ta-hifi.de/StrBo/V2");
    CHECK(req.at("target_release_line").get<std::string>() == "red  line  ");
    CHECK(req.at("target_version").get<std::string>() == "  V space ");
    CHECK(req.at("target_flavor").get<std::string>() == "beta carotene");
    CHECK(req.at("keep_user_data").get<bool>());
}

TEST_CASE_FIXTURE(FixtureParser,
                  "Quoted values may contains escaped characters, "
                  "including quotation marks")
{
    const char request[] =
        "url=\"https\\://packages\\.ta-hifi.de\\/StrBo/V2\" flavor=\"\\ beta carotene (\\\"carot\\\")\" version=\"V\\ \\\"\\\\\\\\5\" line=\"\\\"red, red line\\\"\"";

    expect_update_request_accepted = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == 0);
    const auto req(Regs::SystemUpdate::get_update_request());
    REQUIRE(req.is_object());
    CHECK(req.size() == 6);
    CHECK(req.at("id").get<std::string>() == "strbo");
    CHECK(req.at("base_url").get<std::string>() == "https://packages.ta-hifi.de/StrBo/V2");
    CHECK(req.at("target_release_line").get<std::string>() == "\"red, red line\"");
    CHECK(req.at("target_version").get<std::string>() == "V \"\\\\5");
    CHECK(req.at("target_flavor").get<std::string>() == " beta carotene (\"carot\")");
    CHECK(req.at("keep_user_data").get<bool>());
}

static void check_line_flavor_version_repo_values(const nlohmann::json &req)
{
    REQUIRE(req.is_object());
    CHECK(req.size() == 6);
    CHECK(req.at("id").get<std::string>() == "strbo");
    CHECK(req.at("base_url").get<std::string>() == "https://packages.ta-hifi.de/StrBo/V4");
    CHECK(req.at("target_version").get<std::string>() == "V4.1.0.2");
    CHECK(req.at("target_flavor").get<std::string>() == "beta");
    CHECK(req.at("target_release_line").get<std::string>() == "V4");
    CHECK(req.at("keep_user_data").get<bool>());
}

TEST_CASE_FIXTURE(FixtureParser,
                  "Change of flavor, version number, repository URL, "
                  "and release line")
{
    const char request[] =
        "url=https://packages.ta-hifi.de/StrBo/V4 flavor=beta version=V4.1.0.2 line=V4";

    expect_update_request_accepted = true;
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
    expect_update_request_accepted = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == 0);
    check_line_flavor_version_repo_values(Regs::SystemUpdate::get_update_request());
}

TEST_CASE_FIXTURE(FixtureParser, "Base URL is missing")
{
    const char request[] = "flavor=beta version=V4.1.0.2 line=V4";

    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_CRIT,
            "APPLIANCE BUG: Incomplete version specification; missing: url",
            false);
    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_ERR, "Failed parsing update request", false);
    expect_update_request_rejected = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == -1);
}

TEST_CASE_FIXTURE(FixtureParser, "Only Base URL is specified")
{
    const char request[] = "url=http://packages.org/strbo";

    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_CRIT,
            "APPLIANCE BUG: Incomplete version specification; missing: flavor line version",
            false);
    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_ERR, "Failed parsing update request", false);
    expect_update_request_rejected = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == -1);
}

TEST_CASE_FIXTURE(FixtureParser, "Target flavor is missing")
{
    const char request[] = "url=http://packages.org/strbo version=V4.1.0.2 line=V4";

    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_CRIT,
            "APPLIANCE BUG: Incomplete version specification; missing: flavor",
            false);
    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_ERR, "Failed parsing update request", false);
    expect_update_request_rejected = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == -1);
}

TEST_CASE_FIXTURE(FixtureParser, "Target version is missing")
{
    const char request[] = "url=http://packages.org/strbo flavor=beta line=V4";

    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_CRIT,
            "APPLIANCE BUG: Incomplete version specification; missing: version",
            false);
    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_ERR, "Failed parsing update request", false);
    expect_update_request_rejected = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == -1);
}

TEST_CASE_FIXTURE(FixtureParser, "Target line is missing")
{
    const char request[] = "url=http://packages.org/strbo flavor=beta version=V4.1.0.2";

    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_CRIT,
            "APPLIANCE BUG: Incomplete version specification; missing: line",
            false);
    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_ERR, "Failed parsing update request", false);
    expect_update_request_rejected = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == -1);
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

static std::function<void(const nlohmann::json &)> send_request_check;

Rest::Result Rest::send_request(const std::string &url, nlohmann::json &&request)
{
    CHECK(url == "http://localhost:8467/v1/system/devices/self");
    REQUIRE(request.is_object());
    CHECK(request.size() == 1);
    CHECK(request.at("update").is_array());
    CHECK(request["update"].size() == 1);

    REQUIRE(send_request_check != nullptr);
    send_request_check(request["update"][0]);
    send_request_check = nullptr;

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
        mock_expectation_sequence_singleton->reset();
        expect_update_request_accepted = false;
        called_update_request_accepted = false;
        expect_update_request_rejected = false;
        called_update_request_rejected = false;

        MockMessages::singleton = mock_messages.get();
        mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

        Regs::SystemUpdate::init();
    }

    virtual ~FixtureProcess()
    {
        try
        {
            mock_expectation_sequence_singleton->done();
            mock_messages->done();
            CHECK(expect_update_request_accepted == called_update_request_accepted);
            CHECK(expect_update_request_rejected == called_update_request_rejected);
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
            "Cannot trigger StrBo update with undefined arguments", false);
    CHECK(Regs::SystemUpdate::process_update_request() == Regs::SystemUpdate::UpdateResult::BAD_CLIENT_REQUEST);
}

TEST_CASE_FIXTURE(FixtureProcess, "Full set of parameters")
{
    const char request[] =
        "url=https://packages.ta-hifi.de/StrBo/V4 flavor=beta version=V4.1.0.2 line=V4";

    expect_update_request_accepted = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == 0);

    expect<MockMessages::MsgVinfo>(
            mock_messages, MESSAGE_LEVEL_IMPORTANT,
            "Attempting to START SYSTEM UPDATE (rpm/images)", false);
    send_request_check = check_line_flavor_version_repo_values;
    CHECK(Regs::SystemUpdate::process_update_request() == Regs::SystemUpdate::UpdateResult::SUCCESS);
}

static void check_partial_recovery_request(const nlohmann::json &req, bool with_update_parameters)
{
    REQUIRE(req.is_object());

    if(with_update_parameters)
        CHECK(req.size() == 8);
    else
        CHECK(req.size() == 4);

    CHECK(req.at("id").get<std::string>() == "strbo");

    if(with_update_parameters)
    {
        CHECK(req.at("base_url").get<std::string>() == "https://packages.ta-hifi.de/StrBo/V3");
        CHECK(req.at("target_version").get<std::string>() == "V3.1.99");
        CHECK(req.at("target_flavor").get<std::string>() == "foo");
        CHECK(req.at("target_release_line").get<std::string>() == "V3");
    }
}

static void check_full_recovery_request(const nlohmann::json &req)
{
    check_partial_recovery_request(req, true);
    CHECK(req.at("force_update_through_image_files").get<bool>());
    CHECK(req.at("force_recovery_system_update").get<bool>());
    CHECK_FALSE(req.at("keep_user_data").get<bool>());
}

static void check_regular_recovery_request(const nlohmann::json &req)
{
    check_partial_recovery_request(req, false);
    CHECK(req.at("force_update_through_image_files").get<bool>());
    CHECK_FALSE(req.at("force_recovery_system_update").get<bool>());
    CHECK_FALSE(req.at("keep_user_data").get<bool>());
}

static void check_half_recovery_request(const nlohmann::json &req)
{
    check_partial_recovery_request(req, false);
    CHECK(req.at("force_update_through_image_files").get<bool>());
    CHECK_FALSE(req.at("force_recovery_system_update").get<bool>());
    CHECK(req.at("keep_user_data").get<bool>());
}

TEST_CASE_FIXTURE(FixtureProcess,
                  "Force full recovery (update recovery system, update "
                  "recovery data, recovery with wiping user data)")
{
    const char request[] =
        "url=https://packages.ta-hifi.de/StrBo/V3 flavor=foo version=V3.1.99 line=V3 "
        "style=force-full-recovery";

    expect_update_request_accepted = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == 0);

    expect<MockMessages::MsgVinfo>(
            mock_messages, MESSAGE_LEVEL_IMPORTANT,
            "Attempting to START SYSTEM UPDATE (rpm/images)", false);
    send_request_check = check_full_recovery_request;
    CHECK(Regs::SystemUpdate::process_update_request() == Regs::SystemUpdate::UpdateResult::SUCCESS);
}

TEST_CASE_FIXTURE(FixtureProcess,
                  "Force regular recovery (recovery with wiping user data)")
{
    const char request[] = "style=force-recovery";

    expect_update_request_accepted = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == 0);

    expect<MockMessages::MsgVinfo>(
            mock_messages, MESSAGE_LEVEL_IMPORTANT,
            "Attempting to START SYSTEM UPDATE (rpm/images)", false);
    send_request_check = check_regular_recovery_request;
    CHECK(Regs::SystemUpdate::process_update_request() == Regs::SystemUpdate::UpdateResult::SUCCESS);
}

TEST_CASE_FIXTURE(FixtureProcess,
                  "Force half recovery (recovery, keep user data)")
{
    const char request[] = "style=force-half-recovery";

    expect_update_request_accepted = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == 0);

    expect<MockMessages::MsgVinfo>(
            mock_messages, MESSAGE_LEVEL_IMPORTANT,
            "Attempting to START SYSTEM UPDATE (rpm/images)", false);
    send_request_check = check_half_recovery_request;
    CHECK(Regs::SystemUpdate::process_update_request() == Regs::SystemUpdate::UpdateResult::SUCCESS);
}

TEST_CASE_FIXTURE(FixtureParser, "Cannot specify url and version for pure recovery")
{
    const char request[] =
        "line=V2 flavor=stable version=V1.999.20 style=force-half-recovery "
        "url=http://www.ta-hifi.de/fileadmin/auto_download/StrBo";

    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_CRIT,
            "APPLIANCE BUG: Pure recovery requests cannot be combined with version or url requests",
            false);
    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_ERR, "Failed parsing update request", false);
    expect_update_request_rejected = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == -1);
    CHECK(Regs::SystemUpdate::get_update_request() == nullptr);
}

TEST_CASE_FIXTURE(FixtureParser,
                  "Must specify url and version for update via images")
{
    const char request[] = "style=force-full-recovery";

    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_CRIT,
            "APPLIANCE BUG: Recovery update request lacks version and/or url requests",
            false);
    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_ERR, "Failed parsing update request", false);
    expect_update_request_rejected = true;
    CHECK(Regs::SystemUpdate::DCP::write_211_strbo_update_parameters(
                reinterpret_cast<const uint8_t *>(request),
                sizeof(request) - 1) == -1);
    CHECK(Regs::SystemUpdate::get_update_request() == nullptr);
}

TEST_SUITE_END();
