/*
 * Copyright (C) 2017, 2018, 2019, 2022  T+A elektroakustik GmbH & Co. KG
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

#include "connman_service.hh"

#include <array>
#include <algorithm>

template <typename ArrayType>
static typename ArrayType::value_type::second_type
map_string_to_enum_value(const ArrayType &table, const char *method,
                         typename ArrayType::value_type::second_type result_for_empty_input,
                         typename ArrayType::value_type::second_type result_for_unknown)
{
    if(method == nullptr || method[0] == '\0')
        return result_for_empty_input;

    const auto &found =
        std::find_if(table.begin(), table.end(),
                     [method] (const typename ArrayType::value_type &m) -> bool
                     {
                         return strcmp(m.first, method) == 0;
                     });

    return found != table.end() ? found->second : result_for_unknown;
}

Connman::DHCPV4Method Connman::parse_connman_dhcp_v4_method(const char *method)
{
    static constexpr std::array<const std::pair<const char *, const DHCPV4Method>,
                                size_t(DHCPV4Method::LAST_VALUE) - 1> methods
    {
        std::make_pair("dhcp",   DHCPV4Method::ON),
        std::make_pair("off",    DHCPV4Method::OFF),
        std::make_pair("manual", DHCPV4Method::MANUAL),
        std::make_pair("fixed",  DHCPV4Method::FIXED),
    };

    return map_string_to_enum_value(methods, method,
                                    DHCPV4Method::NOT_AVAILABLE,
                                    DHCPV4Method::UNKNOWN_METHOD);
}

Connman::DHCPV6Method Connman::parse_connman_dhcp_v6_method(const char *method)
{
    static constexpr std::array<const std::pair<const char *, const DHCPV6Method>,
                                size_t(DHCPV6Method::LAST_VALUE) - 1> methods
    {
        std::make_pair("auto",   DHCPV6Method::ON),
        std::make_pair("off",    DHCPV6Method::OFF),
        std::make_pair("manual", DHCPV6Method::MANUAL),
        std::make_pair("6to4",   DHCPV6Method::SIX_TO_FOUR),
        std::make_pair("fixed",  DHCPV6Method::FIXED),
    };

    return map_string_to_enum_value(methods, method,
                                    DHCPV6Method::NOT_AVAILABLE,
                                    DHCPV6Method::UNKNOWN_METHOD);
}

Connman::ProxyMethod Connman::parse_connman_proxy_method(const char *method)
{
    static constexpr std::array<const std::pair<const char *, const ProxyMethod>,
                                size_t(ProxyMethod::LAST_VALUE) - 1> methods
    {
        std::make_pair("direct", ProxyMethod::DIRECT),
        std::make_pair("auto",   ProxyMethod::AUTO),
        std::make_pair("manual", ProxyMethod::MANUAL),
    };

    return map_string_to_enum_value(methods, method,
                                    ProxyMethod::NOT_AVAILABLE,
                                    ProxyMethod::UNKNOWN_METHOD);
}

Connman::Technology Connman::parse_connman_technology(const char *technology)
{
    static constexpr std::array<const std::pair<const char *, const Technology>,
                                size_t(Technology::LAST_VALUE)> techs
    {
        std::make_pair("ethernet", Technology::ETHERNET),
        std::make_pair("wifi",     Technology::WLAN),
    };

    return map_string_to_enum_value(techs, technology,
                                    Technology::UNKNOWN_TECHNOLOGY,
                                    Technology::UNKNOWN_TECHNOLOGY);
}

Connman::ServiceState Connman::parse_connman_service_state(const char *state)
{
    static constexpr std::array<const std::pair<const char *, const ServiceState>,
                                size_t(ServiceState::LAST_VALUE) - 1> states
    {
        std::make_pair("idle",          ServiceState::IDLE),
        std::make_pair("failure",       ServiceState::FAILURE),
        std::make_pair("association",   ServiceState::ASSOCIATION),
        std::make_pair("configuration", ServiceState::CONFIGURATION),
        std::make_pair("ready",         ServiceState::READY),
        std::make_pair("disconnnect",   ServiceState::DISCONNECT),
        std::make_pair("online",        ServiceState::ONLINE),
    };

    return map_string_to_enum_value(states, state,
                                    ServiceState::NOT_AVAILABLE,
                                    ServiceState::UNKNOWN_STATE);
}

Connman::ServiceNameComponents
Connman::ServiceNameComponents::from_service_name(const char *service_name)
{
    if(service_name == nullptr)
        throw std::domain_error("Service name is null");

    const char *const end = service_name + strlen(service_name) + 1;

    if(std::distance(service_name, end) == 0)
        throw std::domain_error("Service name is empty");

    std::vector<std::pair<const char * const, const size_t>> tokens;

    const char *token_start = service_name;

    do
    {
        const char *const next = std::find(token_start, end, '_');
        auto length = std::distance(token_start, next);

        if(next == end && length > 0)
            --length;

        if(length == 0)
            break;

        tokens.emplace_back(std::make_pair(token_start, length));
        token_start = next + 1;
    }
    while(token_start < end);

    const std::string tech_name(tokens.size() > 0 ? tokens[0].first : "",
                                tokens.size() > 0 ? tokens[0].second : 0);
    const auto tech = parse_connman_technology(tech_name.c_str());


    Address<AddressType::MAC> mac(
        std::string(tokens.size() > 1 ? tokens[1].first : "",
                    tokens.size() > 1 ? tokens[1].second : 0));

    if(tokens.size() == 3)
    {
        /* should be cable */
        if(tech == Technology::ETHERNET)
            return ServiceNameComponents(tech, std::move(mac));
    }
    else if(tokens.size() == 5)
    {
        /* should be WLAN */
        if(tech == Technology::WLAN)
            return ServiceNameComponents(tech, std::move(mac),
                                         tokens[2].first, tokens[2].second,
                                         tokens[4].first, tokens[4].second);
    }

    throw std::domain_error("Service name is invalid");
}

bool Connman::is_locally_administered_mac_address(const Address<AddressType::MAC> &mac_address)
{
    if(mac_address.empty())
        return false;

    const char ch = mac_address.get_string()[1];
    const uint8_t nibble = isdigit(ch) ? ch - '0' : 10 + (ch - 'A');

    return (nibble & 0x02) != 0;
}
