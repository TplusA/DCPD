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

#ifndef CONNMAN_ADDRESS_HH
#define CONNMAN_ADDRESS_HH

#include <string>
#include <cstring>

#include "messages.h"

namespace Connman
{

enum class AddressType
{
    MAC,
    IPV4,
    IPV6,
};

enum class Technology
{
    UNKNOWN_TECHNOLOGY,
    ETHERNET,
    WLAN,

    LAST_VALUE = WLAN,
};

enum class DHCPV4Method
{
    NOT_AVAILABLE,
    UNKNOWN_METHOD,
    ON,
    OFF,
    MANUAL,
    FIXED,

    LAST_VALUE = FIXED,
};

enum class DHCPV6Method
{
    NOT_AVAILABLE,
    UNKNOWN_METHOD,
    ON,
    OFF,
    MANUAL,
    SIX_TO_FOUR,
    FIXED,

    LAST_VALUE = FIXED,
};

template <AddressType V>
struct AddressTraits;

template <>
struct AddressTraits<AddressType::MAC>
{
    static constexpr size_t ADDRESS_SIZE = 6;
    static constexpr size_t ADDRESS_STRING_LENGTH = 17;
};

template <>
struct AddressTraits<AddressType::IPV4>
{
    static constexpr size_t ADDRESS_SIZE = 4;
    static constexpr size_t ADDRESS_STRING_LENGTH = 15;
    using DHCPMethod = DHCPV4Method;
};

template <>
struct AddressTraits<AddressType::IPV6>
{
    static constexpr size_t ADDRESS_SIZE = 16;
    static constexpr size_t ADDRESS_STRING_LENGTH = 45;
    using DHCPMethod = DHCPV6Method;
};

template <AddressType AType, class Traits = AddressTraits<AType>>
class Address
{
  private:
    std::string address_;

  public:
    Address(const Address &) = default;
    Address(Address &&) = default;
    Address &operator=(const Address &) = default;

    explicit Address()
    {
        address_.reserve(Traits::ADDRESS_STRING_LENGTH);
    }

    bool set(const char *address)
    {
        log_assert(address != nullptr);

        const size_t addrlen = strlen(address);

        if(addrlen > Traits::ADDRESS_STRING_LENGTH)
        {
            BUG("Length of address \"%s\" exceeds %zu",
                address, Traits::ADDRESS_STRING_LENGTH);
            return false;
        }

        if(addrlen > 0)
            address_ = address;
        else
            unset();

        return true;
    }

    void unset() { address_.clear(); }

    bool empty() const { return address_.empty(); }

    const std::string &get_string() const { return address_; }

    bool operator==(const Address &other) const
    {
        if(address_.length() != other.address_.length())
            return false;

        if(address_.empty() == 0)
            return true;

        return std::equal(address_.begin(), address_.end(),
                          other.address_.begin(),
                          [] (const char &a, const char &b) { return toupper(a) == toupper(b); });
    }

    bool operator!=(const Address &other) const
    {
        return !(*this == other);
    }

    bool operator==(const char *other) const
    {
        if(other == nullptr)
            return address_.empty();

        for(size_t i = 0; i < address_.length(); ++i)
        {
            if(other[i] == '\0')
                return false;

            if(toupper(other[i] != toupper(address_[i])))
                return false;
        }

        return other[address_.length()] == '\0';
    }

    bool operator!=(const char *other) const
    {
        return !(*this == other);
    }
};

}

#endif /* !CONNMAN_ADDRESS_HH */
