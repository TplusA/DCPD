/*
 * Copyright (C) 2017, 2018  T+A elektroakustik GmbH & Co. KG
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

#include "messages.h"

#include <string>
#include <cstring>
#include <stdexcept>

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
    static constexpr size_t ADDRESS_STRING_LENGTH_MIN = 6 * 2 + 5;
    static constexpr size_t ADDRESS_STRING_LENGTH_MAX = ADDRESS_STRING_LENGTH_MIN;

    static inline bool is_input_string_length_in_range(size_t addrlen)
    {
        return addrlen == 6 * 2 || addrlen == ADDRESS_STRING_LENGTH_MAX;
    }

    static inline bool sanitize_and_patch(std::string &addr_string)
    {
        if(addr_string.length() == ADDRESS_STRING_LENGTH_MAX)
        {
            /* colons must be in correct place */
            for(size_t i = 2; i < ADDRESS_STRING_LENGTH_MAX; i += 3)
            {
                if(addr_string[i] != ':')
                    return false;
            }
        }
        else
        {
            /* weave in some colons */
            std::string temp(addr_string, 0, 2);

            for(size_t i = 2; i < addr_string.length(); i += 2)
            {
                temp += ':';
                temp += addr_string[i + 0];
                temp += addr_string[i + 1];
            }

            addr_string.swap(temp);

            if(addr_string.length() != ADDRESS_STRING_LENGTH_MAX)
                return false;
        }

        /* must have hexadecimal digits in between, converted to uppercase on
         * the fly */
        for(size_t i = 0; i < ADDRESS_STRING_LENGTH_MAX; i += 3)
        {
            if(!isxdigit(addr_string[i]) || !isxdigit(addr_string[i + 1]))
                return false;

            addr_string[i + 0] = toupper(addr_string[i + 0]);
            addr_string[i + 1] = toupper(addr_string[i + 1]);
        }

        return true;
    }
};

template <>
struct AddressTraits<AddressType::IPV4>
{
    static constexpr size_t ADDRESS_STRING_LENGTH_MIN = 4 * 1 + 3;
    static constexpr size_t ADDRESS_STRING_LENGTH_MAX = 4 * 3 + 3;

    using DHCPMethod = DHCPV4Method;

    static inline bool is_input_string_length_in_range(size_t addrlen)
    {
        return addrlen >= ADDRESS_STRING_LENGTH_MIN &&
               addrlen <= ADDRESS_STRING_LENGTH_MAX;
    }

    static inline bool sanitize_and_patch(std::string &addr_string)
    {
        /* TODO: Proper implementation */
        return true;
    }
};

template <>
struct AddressTraits<AddressType::IPV6>
{
    static constexpr size_t ADDRESS_STRING_LENGTH_MIN = 2;
    static constexpr size_t ADDRESS_STRING_LENGTH_MAX =
        6 * 4 + 6 +
        AddressTraits<AddressType::IPV4>::ADDRESS_STRING_LENGTH_MAX;

    using DHCPMethod = DHCPV6Method;

    static inline bool is_input_string_length_in_range(size_t addrlen)
    {
        return addrlen >= ADDRESS_STRING_LENGTH_MIN &&
               addrlen <= ADDRESS_STRING_LENGTH_MAX;
    }

    static inline bool sanitize_and_patch(std::string &addr_string)
    {
        /* TODO: Proper implementation */
        return true;
    }
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

    explicit Address() {}

    explicit Address(const char *address)
    {
        set(address);
    }

    explicit Address(std::string &&address)
    {
        set(std::move(address));
    }

    void set(const char *address)
    {
        log_assert(address != nullptr);

        const size_t addrlen = strlen(address);

        if(addrlen > 0)
        {
            if(!Traits::is_input_string_length_in_range(addrlen))
                throw std::domain_error("Incorrect address length");

            address_ = address;

            if(!Traits::sanitize_and_patch(address_))
            {
                address_.clear();
                throw std::domain_error("Failed parsing address");
            }
        }
        else
            unset();
    }

    void set(std::string &&address)
    {
        if(!address.empty())
        {
            if(!Traits::is_input_string_length_in_range(address.length()))
                throw std::domain_error("Incorrect address length");

            address_ = std::move(address);

            if(!Traits::sanitize_and_patch(address_))
            {
                address_.clear();
                throw std::domain_error("Failed parsing address");
            }
        }
        else
            unset();
    }

    void unset() { address_.clear(); }

    bool empty() const { return address_.empty(); }

    const std::string &get_string() const { return address_; }

    bool operator==(const Address &other) const
    {
        if(address_.length() != other.address_.length())
            return false;

        if(address_.empty())
            return true;

        return address_ == other.address_;
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

            if(toupper(other[i] != address_[i]))
                return false;
        }

        return other[address_.length()] == '\0';
    }

    bool operator!=(const char *other) const
    {
        return !(*this == other);
    }
};

bool is_locally_administered_mac_address(const Address<AddressType::MAC> &mac_address);

}

#endif /* !CONNMAN_ADDRESS_HH */
