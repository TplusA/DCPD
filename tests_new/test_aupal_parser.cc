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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <doctest.h>

#include "audiopath_minidsl.hh"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch-enum"
#include "json.hh"
#pragma GCC diagnostic pop

TEST_SUITE_BEGIN("AuPaL parser");

class Fixture
{
  protected:
    AudioPaths::Parser parser;

    explicit Fixture() {}

    template <size_t N>
    void process(const char (&s)[N])
    {
        const std::vector<uint8_t> input(s, s + N - 1);
        parser.process(input);
    }

    auto diff(const nlohmann::json &expected)
    {
        return nlohmann::json::diff(nlohmann::json::parse(parser.json_string()),
                                    expected);
    }

    void expect_equal(const nlohmann::json &expected)
    {
        const auto d(diff(expected));

        if(d.empty())
            return;

        MESSAGE("Diff: " << d);
        CHECK(parser.json_string() == expected);
    }
};

TEST_CASE_FIXTURE(Fixture,
                  "Serialization of fresh parser yields null object")
{
    CHECK(parser.json_string() == "null");
}

TEST_CASE_FIXTURE(Fixture,
                  "Serialization of empty input yields empty JSON object")
{
    parser.process({});
    CHECK(parser.json_string() == "{}");
}

TEST_CASE_FIXTURE(Fixture, "Reset parser behaves like fresh parser")
{
    parser.process({});
    parser.reset();
    CHECK(parser.json_string() == "null");
}

TEST_CASE_FIXTURE(Fixture, "Declare single appliance instance")
{
    static constexpr const char input[] = "IMP3100HV\0self\0";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                { "op": "add_instance", "name": "self", "id": "MP3100HV" }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Declare two appliance instances")
{
    process("IMP3100HV\0self\0IPA3100HV\0pa\0");

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                { "op": "add_instance", "name": "self", "id": "MP3100HV" },
                { "op": "add_instance", "name": "pa",   "id": "PA3100HV" }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture,
                  "Appliance instances and their removals are reported in order")
{
    process("IMP3100HV\0self\0IPA3100HV\0pa0\0IPA3100HV\0pa1\0");
    process("ipa0\0");
    process("IPA3100HV\0pa2\0");
    process("ipa1\0ipa2\0");

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                { "op": "add_instance", "name": "self", "id": "MP3100HV" },
                { "op": "add_instance", "name": "pa0",  "id": "PA3100HV" },
                { "op": "add_instance", "name": "pa1",  "id": "PA3100HV" },
                { "op": "rm_instance",  "name": "pa0" },
                { "op": "add_instance", "name": "pa2",  "id": "PA3100HV" },
                { "op": "rm_instance",  "name": "pa1" },
                { "op": "rm_instance",  "name": "pa2" }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Delete all instances from knowledge base")
{
    static constexpr const char input[] = "I\0\0";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                { "op": "clear_instances" }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture,
                  "Connect output of appliance to input of another appliance")
{
    static constexpr const char input[] = "Cself.analog_line_out\0pa.analog_in_1\0";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                { "op": "connect", "from": "self.analog_line_out", "to": "pa.analog_in_1" }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture,
                  "Remove specific audio connection between appliances")
{
    static constexpr const char input[] = "cself.analog_line_out\0pa.analog_in_1\0";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                { "op": "disconnect", "from": "self.analog_line_out", "to": "pa.analog_in_1" }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Remove all audio connections between appliances")
{
    static constexpr const char input[] = "cself\0pa\0";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                { "op": "disconnect", "from": "self", "to": "pa" }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture,
                  "Remove all outgoing audio connections from an appliance")
{
    static constexpr const char input[] = "cself\0\0";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                { "op": "disconnect", "from": "self" }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture,
                  "Remove all ingoing audio connections to an appliances")
{
    static constexpr const char input[] = "c\0pa\0";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                { "op": "disconnect", "to": "pa" }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Disconnect all audio connections")
{
    static constexpr const char input[] = "c\0\0";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                { "op": "disconnect" }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Set values of a set of controls in an element")
{
    static constexpr const char input[] =
        "Sself.dsp\0\x02""filter\0siir_bezier\0phase_invert\0b\x01"
        "Sself.dsd_out_filter\0\x01mode\0snormal\0";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                {
                    "op": "set", "element": "self.dsp",
                    "kv": {
                        "filter": {
                            "type": "s",
                            "value": "iir_bezier"
                        },
                        "phase_invert": {
                            "type": "b",
                            "value": true
                        }
                    }
                },
                {
                    "op": "set", "element": "self.dsd_out_filter",
                    "kv": {
                        "mode": {
                            "type": "s",
                            "value": "normal"
                        }
                    }
                }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Unset values of all controls in an element")
{
    static constexpr const char input[] =
        "Sself.dsp\0\x00"
        "Sself.dsd_out_filter\0\x00";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                { "op": "unset_all", "element": "self.dsp" },
                { "op": "unset_all", "element": "self.dsd_out_filter" }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Update values of a set of controls in an element")
{
    static constexpr const char input[] =
        "Uself.dsp\0\x02""filter\0siir_bezier\0phase_invert\0b\x01"
        "Uself.dsd_out_filter\0\x01mode\0snormal\0";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                {
                    "op": "update", "element": "self.dsp",
                    "kv": {
                        "filter": {
                            "type": "s",
                            "value": "iir_bezier"
                        },
                        "phase_invert": {
                            "type": "b",
                            "value": true
                        }
                    }
                },
                {
                    "op": "update", "element": "self.dsd_out_filter",
                    "kv": {
                        "mode": {
                            "type": "s",
                            "value": "normal"
                        }
                    }
                }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Update nothing yields empty object")
{
    static constexpr const char input[] = "Uself.dsp\0\x00";
    process(input);
    expect_equal(nlohmann::json({}));
}

TEST_CASE_FIXTURE(Fixture, "Update string value")
{
    static constexpr const char input[] = "ua.b\0c\0sHello world!\0";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                {
                    "op": "update", "element": "a.b",
                    "kv": { "c": { "type": "s", "value": "Hello world!" } }
                }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Update empty string value")
{
    static constexpr const char input[] = "ua.b\0c\0s\0";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                {
                    "op": "update", "element": "a.b",
                    "kv": { "c": { "type": "s", "value": "" } }
                }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Update boolean value")
{
    static constexpr const char input[] = "ua.b\0c\0b\x00ud.e\0f\0b\x01";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                {
                    "op": "update", "element": "a.b",
                    "kv": { "c": { "type": "b", "value": false } }
                },
                {
                    "op": "update", "element": "d.e",
                    "kv": { "f": { "type": "b", "value": true } }
                }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Setting boolean value with invalid value throws")
{
    static constexpr const char input1[] = "ua.b\0c\0b\x02";
    CHECK_THROWS_WITH(process(input1), "boolean value out of range at offset 8");

    static constexpr const char input2[] = "ua.b\0c\0b\xff";
    CHECK_THROWS_WITH(process(input2), "boolean value out of range at offset 8");
}

TEST_CASE_FIXTURE(Fixture, "Update signed 8-bit value")
{
    static constexpr const char input[] = "ua.b\0c\0Y\x83";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                {
                    "op": "update", "element": "a.b",
                    "kv": { "c": { "type": "Y", "value": -125 } }
                }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Update unsigned 8-bit value")
{
    static constexpr const char input[] = "ua.b\0c\0y\x83";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                {
                    "op": "update", "element": "a.b",
                    "kv": { "c": { "type": "y", "value": 131 } }
                }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Update signed 16-bit value")
{
    static constexpr const char input[] = "ua.b\0c\0n\xd4\x31";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                {
                    "op": "update", "element": "a.b",
                    "kv": { "c": { "type": "n", "value": -11215 } }
                }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Update unsigned 16-bit value")
{
    static constexpr const char input[] = "ua.b\0c\0q\xd4\x31";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                {
                    "op": "update", "element": "a.b",
                    "kv": { "c": { "type": "q", "value": 54321 } }
                }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Update signed 32-bit value")
{
    static constexpr const char input[] = "ua.b\0c\0i\xd5\x48\x64\xe1";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                {
                    "op": "update", "element": "a.b",
                    "kv": { "c": { "type": "i", "value": -716675871 } }
                }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Update unsigned 32-bit value")
{
    static constexpr const char input[] = "ua.b\0c\0u\xd5\x48\x64\xe1";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                {
                    "op": "update", "element": "a.b",
                    "kv": { "c": { "type": "u", "value": 3578291425 } }
                }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Update signed 64-bit value")
{
    static constexpr const char input[] = "ua.b\0c\0x\xb1\x26\x02\xc4\xc0\x7f\x72\x75";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                {
                    "op": "update", "element": "a.b",
                    "kv": { "c": { "type": "x", "value": -5681850835814878603 } }
                }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Update unsigned 64-bit value")
{
    static constexpr const char input[] = "ua.b\0c\0t\xb1\x26\x02\xc4\xc0\x7f\x72\x75";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                {
                    "op": "update", "element": "a.b",
                    "kv": { "c": { "type": "t", "value": 12764893237894673013 } }
                }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Update big positive T+A 14-bit fix point value")
{
    static constexpr const char input[] = "ua.b\0c\0D\x12\xcd";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                {
                    "op": "update", "element": "a.b",
                    "kv": { "c": { "type": "D", "value": 300.8125 } }
                }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Update small negative T+A 14-bit fix point value")
{
    static constexpr const char input[] = "ua.b\0c\0D\x32\xcd";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                {
                    "op": "update", "element": "a.b",
                    "kv": { "c": { "type": "D", "value": -300.8125 } }
                }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Update positive T+A 14-bit fix point value near 0")
{
    static constexpr const char input[] = "ua.b\0c\0D\x00\x03";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                {
                    "op": "update", "element": "a.b",
                    "kv": { "c": { "type": "D", "value": 0.1875 } }
                }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Update negative T+A 14-bit fix point value near 0")
{
    static constexpr const char input[] = "ua.b\0c\0D\x20\x03";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                {
                    "op": "update", "element": "a.b",
                    "kv": { "c": { "type": "D", "value": -0.1875 } }
                }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Update NaN T+A 14-bit fix point value")
{
    static constexpr const char input[] = "ua.b\0c\0D\x20\x00";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                {
                    "op": "update", "element": "a.b",
                    "kv": { "c": { "type": "D", "value": null } }
                }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Unset a specific value")
{
    static constexpr const char input[] = "da.b\0c\0";
    process(input);

    const auto expected_json = R"(
        {
            "audio_path_changes": [
                { "op": "unset", "element": "a.b", "v": "c" }
            ]
        })"_json;

    expect_equal(expected_json);
}

TEST_CASE_FIXTURE(Fixture, "Update value with invalid type identifier throws")
{
    static constexpr const char input[] = "ua.b\0c\0z\x42";
    CHECK_THROWS_WITH(process(input), "invalid type ID at offset 7");
}

TEST_SUITE_END();
