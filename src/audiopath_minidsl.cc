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

#include "audiopath_minidsl.hh"
#include "fixpoint.hh"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch-enum"
#include "json.hh"
#pragma GCC diagnostic pop

class AudioPaths::ParserState
{
  private:
    const uint8_t *input_begin_;
    const uint8_t *input_end_;
    const uint8_t *pos_;

    nlohmann::json out_;

  public:
    ParserState(const ParserState &) = delete;
    ParserState(ParserState &&) = default;
    ParserState &operator=(const ParserState &) = delete;
    ParserState &operator=(ParserState &&) = default;

    explicit ParserState():
        input_begin_(nullptr),
        input_end_(nullptr),
        pos_(nullptr),
        out_({})
    {}

    void process(const uint8_t *const input, size_t input_size);
    const nlohmann::json &json() const { return out_; }

  private:
    size_t pos() const { return std::distance(input_begin_, pos_); }

    void assert_input_available() const
    {
        if(pos_ == input_end_)
            throw AudioPaths::ParserError("end of input", pos());
    }

    std::string take_byte_as_string()
    {
        assert_input_available();

        const auto v = *pos_++;
        if(isprint(v))
            return std::string(1, char(v));

        throw AudioPaths::ParserError("expected ASCII character", pos());
    }

    uint8_t take_unsigned_byte()
    {
        assert_input_available();
        return *pos_++;
    }

    template <typename T>
    T take()
    {
        T value = 0;

        for(size_t i = 0; i < sizeof(T); ++i)
            value = value << 8 | take_unsigned_byte();

        return value;
    }

    bool is_asciiz_empty() const
    {
        assert_input_available();
        return *pos_ == '\0';
    }

    std::string copy_asciiz(bool may_be_empty = false)
    {
        const auto end(std::find(pos_, input_end_, '\0'));

        if(end == input_end_)
            throw AudioPaths::ParserError("end of input", pos());

        if(end == pos_ && !may_be_empty)
            throw AudioPaths::ParserError("empty string", pos());

        auto result = std::move(std::string(pos_, end));
        pos_ = std::next(end);

        return result;
    }

    nlohmann::json parse_command(uint8_t cmd);
    nlohmann::json parse_add_instance();
    nlohmann::json parse_remove_instance();
    nlohmann::json parse_connect_instances();
    nlohmann::json parse_disconnect_instances();
    nlohmann::json parse_set_or_update_values(bool is_set);
    nlohmann::json parse_update_value();
    nlohmann::json parse_unset_value();
    nlohmann::json parse_variant();
};

nlohmann::json AudioPaths::ParserState::parse_command(uint8_t cmd)
{
    switch(cmd)
    {
      case 'I':
        return parse_add_instance();

      case 'i':
        return parse_remove_instance();

      case 'C':
        return parse_connect_instances();

      case 'c':
        return parse_disconnect_instances();

      case 'S':
        return parse_set_or_update_values(true);

      case 'U':
        return parse_set_or_update_values(false);

      case 'u':
        return parse_update_value();

      case 'd':
        return parse_unset_value();

      default:
        std::advance(pos_, -1);
        throw ParserError("invalid command", pos());
    }
}

nlohmann::json AudioPaths::ParserState::parse_add_instance()
{
    if(std::distance(pos_, input_end_) < 2)
        throw ParserError("input too short", pos());

    if(*pos_ == '\0' && *std::next(pos_) == '\0')
    {
        std::advance(pos_, 2);
        return { { "op", "clear_instances" } };
    }

    return {
        { "op", "add_instance" },
        { "id", std::move(copy_asciiz()) },
        { "name", std::move(copy_asciiz()) },
    };
}

nlohmann::json AudioPaths::ParserState::parse_remove_instance()
{
    return {
        { "op", "rm_instance" },
        { "name", std::move(copy_asciiz()) },
    };
}

nlohmann::json AudioPaths::ParserState::parse_connect_instances()
{
    return {
        { "op", "connect" },
        { "from", std::move(copy_asciiz()) },
        { "to", std::move(copy_asciiz()) },
    };
}

nlohmann::json AudioPaths::ParserState::parse_disconnect_instances()
{
    nlohmann::json result = { { "op", "disconnect" } };

    if(is_asciiz_empty())
        std::advance(pos_, 1);
    else
        result["from"] = std::move(copy_asciiz());

    if(is_asciiz_empty())
        std::advance(pos_, 1);
    else
        result["to"] = std::move(copy_asciiz());

    return result;
}

nlohmann::json AudioPaths::ParserState::parse_set_or_update_values(bool is_set)
{
    nlohmann::json result = { { "element", std::move(copy_asciiz()) } };

    const auto count = take_unsigned_byte();

    if(count == 0)
    {
        if(is_set)
        {
            result["op"] = "unset_all";
            return result;
        }
        else
            return nullptr;
    }

    nlohmann::json kv;

    for(unsigned int i = 0; i < count; ++i)
    {
        std::string control_name(std::move(copy_asciiz()));
        kv[std::move(control_name)] = std::move(parse_variant());
    }

    result["op"] = is_set ? "set" : "update";
    result["kv"] = std::move(kv);
    return result;
}

nlohmann::json AudioPaths::ParserState::parse_update_value()
{
    nlohmann::json result = {
        { "op", "update" },
        { "element", std::move(copy_asciiz()) },
    };

    std::string control_name(std::move(copy_asciiz()));
    result["kv"][std::move(control_name)] = std::move(parse_variant());
    return result;
}

nlohmann::json AudioPaths::ParserState::parse_unset_value()
{
    return {
        { "op", "unset" },
        { "element", std::move(copy_asciiz()) },
        { "v", std::move(copy_asciiz()) },
    };
}

nlohmann::json AudioPaths::ParserState::parse_variant()
{
    nlohmann::json v;
    auto type_id = take_byte_as_string();

    switch(type_id[0])
    {
      case 's':
        v["value"] = std::move(copy_asciiz(true));
        break;

      case 'b':
        switch(take<uint8_t>())
        {
          case 0:
            v["value"] = false;
            break;

          case 1:
            v["value"] = true;
            break;

          default:
            std::advance(pos_, -1);
            throw ParserError("boolean value out of range", pos());
        }

        break;

      case 'D':
        {
            const std::array<uint8_t, 2> buffer { take<uint8_t>(), take<uint8_t>() };

            if((buffer[0] & 0xc0) != 0)
            {
                std::advance(pos_, -2);
                throw ParserError("fix point value contains junk bits", pos());
            }

            v["value"] = FixPoint(buffer.data(), buffer.size()).to_double();
        }

        break;

      case 'Y':
        v["value"] = take<int8_t>();
        break;

      case 'y':
        v["value"] = take<uint8_t>();
        break;

      case 'n':
        v["value"] = take<int16_t>();
        break;

      case 'q':
        v["value"] = take<uint16_t>();
        break;

      case 'i':
        v["value"] = take<int32_t>();
        break;

      case 'u':
        v["value"] = take<uint32_t>();
        break;

      case 'x':
        v["value"] = take<int64_t>();
        break;

      case 't':
        v["value"] = take<uint64_t>();
        break;

      default:
        std::advance(pos_, -1);
        throw AudioPaths::ParserError("invalid type ID", pos());
    }

    v["type"] = std::move(type_id);

    return v;
}

void AudioPaths::ParserState::process(const uint8_t *const input,
                                      size_t input_size)
{
    if(input_size == 0)
        return;

    input_begin_ = input;
    input_end_ = input + input_size;
    pos_ = input;

    while(pos_ != input_end_)
    {
        const auto cmd = *pos_;
        std::advance(pos_, 1);

        auto op = parse_command(cmd);
        if(op != nullptr)
            out_["audio_path_changes"].emplace_back(std::move(op));
    }
}

AudioPaths::Parser::Parser() = default;

AudioPaths::Parser::~Parser() = default;

void AudioPaths::Parser::reset() { state_ = nullptr; }

void AudioPaths::Parser::process(const std::vector<uint8_t> &input)
{
    if(state_ == nullptr)
        state_ = std::make_unique<AudioPaths::ParserState>();

    state_->process(input.data(), input.size());
}

void AudioPaths::Parser::process(const uint8_t *const input,
                                 size_t input_size)
{
    if(state_ == nullptr)
        state_ = std::make_unique<AudioPaths::ParserState>();

    state_->process(input, input_size);
}

std::string AudioPaths::Parser::json_string() const
{
    return (state_ != nullptr ? state_->json() : nlohmann::json()).dump();
}
