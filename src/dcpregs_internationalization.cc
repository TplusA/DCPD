/*
 * Copyright (C) 2017, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#include "dcpregs_internationalization.hh"
#include "configproxy.h"
#include "messages.h"

#include <array>
#include <algorithm>

static const char system_language_code_key[]     = "@drcpd::i18n:language_code";
static const char system_language_variant_key[]  = "@drcpd::i18n:country_code";
static const char airable_language_code_key[]    = "@airable::i18n:language_code";
static const char airable_language_variant_key[] = "@airable::i18n:country_code";

ssize_t Regs::I18n::DCP::read_47_language_settings(uint8_t *response,
                                                   size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 47 handler %p %zu", response, length);

    size_t offset = 0;
    ssize_t len;

    len = configproxy_get_value_as_string(system_language_code_key,
                                          reinterpret_cast<char *>(&response[offset]),
                                          length - offset, nullptr);

    if(len < 0)
        return -1;

    offset += len + 1;
    len = configproxy_get_value_as_string(system_language_variant_key,
                                          reinterpret_cast<char *>(&response[offset]),
                                          length - offset, nullptr);

    if(len < 0)
        return -1;

    offset += len + 1;
    len = configproxy_get_value_as_string(airable_language_code_key,
                                          reinterpret_cast<char *>(&response[offset]),
                                          length - offset, nullptr);

    if(len < 0)
        return -1;

    offset += len + 1;
    len = configproxy_get_value_as_string(airable_language_variant_key,
                                          reinterpret_cast<char *>(&response[offset]),
                                          length - offset, nullptr);

    if(len < 0)
        return -1;

    offset += len + 1;

    return offset;
}

static bool find_tokens(const uint8_t *data, size_t length,
                        std::array<const char *, 4> &tokens)
{
    size_t t = 0;
    const uint8_t *token = data;

    for(size_t i = 0; i < length; ++i)
    {
        if(data[i] != '\0')
            continue;

        tokens[t++] = reinterpret_cast<const char *>(token);

        if(t == tokens.size())
        {
            if(i < length - 1)
                msg_info("Ignoring excess data in language specification");

            return true;
        }

        token = &data[i + 1];
    }

    msg_error(EINVAL, LOG_ERR, "Language specification incomplete");

    return false;
}

static std::string parse_alpha2_code(const char *str, bool must_be_defined,
                                     bool convert_to_uppercase)
{
    std::string temp;

    for(size_t i = 0; i < 2; ++i)
    {
        const char ch = str[i];

        if(!isalpha(ch))
            break;

        temp.push_back(convert_to_uppercase ? toupper(ch) : tolower(ch));
    }

    if(temp.length() == 2 && str[2] == '\0')
        return temp;

    if(!temp.empty())
        throw std::invalid_argument("Invalid alpha-2 code");

    if(must_be_defined)
        throw std::invalid_argument("Missing alpha-2 code");

    return temp;
}

static void fixup_empty_airable_language_code(std::string &airable_lc,
                                              const std::string &system_lc)
{
    if(!airable_lc.empty())
        return;

    if(!system_lc.empty())
    {
        static const std::array<const char *const, 5> supported { "de", "en", "es", "fr", "it", };

        if(std::any_of(supported.begin(), supported.end(),
            [&system_lc] (const char *lang) { return system_lc == lang; }))
        {
            airable_lc = system_lc;
            return;
        }
    }

    airable_lc = "en";
}

int Regs::I18n::DCP::write_47_language_settings(const uint8_t *data,
                                                size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 47 handler %p %zu", data, length);

    std::array<const char *, 4> tokens;

    if(!find_tokens(data, length, tokens))
        return -1;

    try
    {
        const std::string system_language_code(parse_alpha2_code(tokens[0], true, false));
        const std::string system_language_variation(parse_alpha2_code(tokens[1], true, true));
        std::string airable_language_code(parse_alpha2_code(tokens[2], false, false));
        const std::string airable_country_code(parse_alpha2_code(tokens[3], true, true));

        fixup_empty_airable_language_code(airable_language_code,
                                          system_language_code);

        if(configproxy_set_string(nullptr, system_language_code_key,
                                  system_language_code.c_str()))
            configproxy_set_string(nullptr, system_language_variant_key,
                                   system_language_variation.c_str());

        if(configproxy_set_string(nullptr, airable_language_code_key,
                                  airable_language_code.c_str()))
            configproxy_set_string(nullptr, airable_language_variant_key,
                                   airable_country_code.c_str());

        return 0;
    }
    catch(const std::exception &e)
    {
        msg_error(EINVAL, LOG_ERR, "%s", e.what());
        return -1;
    }
}
