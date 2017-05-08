/*
 * Copyright (C) 2017  T+A elektroakustik GmbH & Co. KG
 *
 * This file is part of DCPD.
 *
 * DCPD is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 3 as
 * published by the Free Software Foundation.
 *
 * DCPD is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with DCPD.  If not, see <http://www.gnu.org/licenses/>.
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <array>
#include <algorithm>
#include <cstring>

#include "connman_service.hh"

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
