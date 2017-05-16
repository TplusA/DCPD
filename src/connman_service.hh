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

#ifndef CONNMAN_SERVICE_HH
#define CONNMAN_SERVICE_HH

#include <vector>
#include <string>
#include <cstring>

#include "maybe.hh"
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

enum class ServiceState
{
    NOT_AVAILABLE,
    UNKNOWN_STATE,
    IDLE,
    FAILURE,
    ASSOCIATION,
    CONFIGURATION,
    READY,
    DISCONNECT,
    ONLINE,

    LAST_VALUE = ONLINE,
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

template <AddressType IPType>
class IPSettings
{
  public:
    using IPAddressType = Address<IPType>;
    using DHCPMethod = typename AddressTraits<IPType>::DHCPMethod;

  private:
    DHCPMethod dhcp_method_;
    IPAddressType address_;
    IPAddressType netmask_;
    IPAddressType gateway_;

  public:
    IPSettings(const IPSettings &) = default;
    IPSettings(IPSettings &&) = default;
    IPSettings &operator=(const IPSettings &) = default;

    explicit IPSettings():
        dhcp_method_(DHCPMethod::NOT_AVAILABLE)
    {}

    void set_address(const char *addr) { address_.set(addr); }
    void set_netmask(const char *addr) { netmask_.set(addr); }
    void set_gateway(const char *addr) { gateway_.set(addr); }
    void set_dhcp_method(DHCPMethod dhcp_method) { dhcp_method_ = dhcp_method; }

    DHCPMethod get_dhcp_method() const { return dhcp_method_; }

    const IPAddressType &get_address() const { return address_; }
    const IPAddressType &get_netmask() const { return netmask_; }
    const IPAddressType &get_gateway() const { return gateway_; }

    bool is_configuration_valid() const
    {
        return !address_.empty() && !netmask_.empty() && !gateway_.empty();
    }

    bool operator==(const IPSettings &other) const
    {
        return (dhcp_method_ == other.dhcp_method_ &&
                address_ == other.address_ &&
                netmask_ == other.netmask_ &&
                gateway_ == other.gateway_);
    }

    bool operator!=(const IPSettings &other) const
    {
        return !(*this == other);
    }
};

struct ServiceData
{
    Address<AddressType::MAC> mac_address_;

    Maybe<bool> is_favorite_;
    Maybe<bool> is_auto_connect_;
    Maybe<bool> is_immutable_;
    Maybe<ServiceState> state_;

    Maybe<IPSettings<AddressType::IPV4>> ip_settings_v4_;
    Maybe<IPSettings<AddressType::IPV6>> ip_settings_v6_;
    Maybe<IPSettings<AddressType::IPV4>> ip_configuration_v4_;
    Maybe<IPSettings<AddressType::IPV6>> ip_configuration_v6_;
    Maybe<std::vector<std::string>> dns_servers_;

    ServiceData(const ServiceData &) = default;
    ServiceData(ServiceData &&) = default;
    ServiceData &operator=(const ServiceData &) = default;

    explicit ServiceData() {}

    bool operator==(const ServiceData &other) const
    {
        return (mac_address_ == other.mac_address_ &&
                is_favorite_ == other.is_favorite_ &&
                is_auto_connect_ == other.is_auto_connect_ &&
                is_immutable_ == other.is_immutable_ &&
                state_ == other.state_ &&
                ip_settings_v4_ == other.ip_settings_v4_ &&
                ip_settings_v6_ == other.ip_settings_v6_ &&
                dns_servers_ == other.dns_servers_);
    }

    bool operator!=(const ServiceData &other) const
    {
        return !(*this == other);
    }
};

template <Technology TECH>
struct TechData;

template <>
struct TechData<Technology::ETHERNET>
{
    TechData(const TechData &) = default;
    TechData(TechData &&) = default;
    TechData &operator=(const TechData &) = default;

    explicit TechData() = default;

    bool operator==(const TechData &other) const { return true; }
    bool operator!=(const TechData &other) const { return false; }
};

template <>
struct TechData<Technology::WLAN>
{
    Maybe<std::string> network_name_;
    Maybe<std::string> network_ssid_;
    Maybe<std::string> passphrase_;
    Maybe<std::string> security_;
    Maybe<bool> is_wps_available_;
    Maybe<uint8_t> strength_;

    TechData(const TechData &) = default;
    TechData(TechData &&) = default;
    TechData &operator=(const TechData &) = default;

    explicit TechData() = default;

    bool operator==(const TechData &other) const
    {
        return (network_name_ == other.network_name_ &&
                network_ssid_ == other.network_ssid_ &&
                passphrase_ == other.passphrase_ &&
                security_ == other.security_ &&
                is_wps_available_ == other.is_wps_available_ &&
                strength_ == other.strength_);
    }

    bool operator!=(const TechData &other) const
    {
        return !(*this == other);
    }
};

class ServiceBase
{
  protected:
    const bool is_ours_;

    ServiceData service_data_store_[2];
    ServiceData *service_data_;
    bool have_new_service_data_;

    explicit ServiceBase(struct ServiceData &&data, bool ours):
        is_ours_(ours),
        service_data_store_{ std::move(data), std::move(ServiceData()) },
        service_data_(&service_data_store_[0]),
        have_new_service_data_(true)
    {}

    void put_service_data_changes(ServiceData &&service_data)
    {
        if(service_data == *service_data_)
            return;

        service_data_ = (service_data_ == &service_data_store_[0]
                         ? &service_data_store_[1]
                         : &service_data_store_[0]);

        *service_data_ = std::move(service_data);
        have_new_service_data_ = true;
    }

  public:
    ServiceBase(const ServiceBase &) = delete;
    ServiceBase &operator=(const ServiceBase &) = delete;

    virtual ~ServiceBase() {}

    bool is_ours() const { return is_ours_; }

    bool is_active() const
    {
        if(service_data_->state_.is_known())
        {
            switch(service_data_->state_.get())
            {
              case Connman::ServiceState::ASSOCIATION:
              case Connman::ServiceState::CONFIGURATION:
              case Connman::ServiceState::READY:
              case Connman::ServiceState::ONLINE:
                return true;

              case Connman::ServiceState::NOT_AVAILABLE:
              case Connman::ServiceState::UNKNOWN_STATE:
              case Connman::ServiceState::IDLE:
              case Connman::ServiceState::FAILURE:
              case Connman::ServiceState::DISCONNECT:
                break;
            }
        }

        return false;
    }

    virtual void processed() { have_new_service_data_ = false; }
    virtual bool needs_processing() { return have_new_service_data_; }

    virtual Technology get_technology() const = 0;

    const ServiceData &get_service_data() const { return *service_data_; }
};

template <Technology TECH>
class Service: public ServiceBase
{
  public:
    using TechDataType = TechData<TECH>;

  private:
    TechDataType tech_data_store_[2];
    TechDataType *tech_data_;
    bool have_new_tech_data_;

  public:
    Service(const Service &) = delete;
    Service &operator=(const Service &) = delete;

    explicit Service(ServiceData &&service_data, TechDataType &&tech_data,
                     bool ours):
        ServiceBase(std::move(service_data), ours),
        tech_data_store_{ std::move(tech_data), std::move(TechDataType()) },
        tech_data_(&tech_data_store_[0]),
        have_new_tech_data_(true)
    {}

    /*!
     * Update service data.
     *
     * No return value, use #Connman::ServiceBase::needs_processing() to find
     * out if the service has been changed.
     */
    void put_changes(ServiceData &&service_data, TechDataType &&tech_data)
    {
        put_service_data_changes(std::move(service_data));

        if(tech_data == *tech_data_)
            return;

        tech_data_ = (tech_data_ == &tech_data_store_[0]
                      ? &tech_data_store_[1]
                      : &tech_data_store_[0]);

        *tech_data_ = std::move(tech_data);
        have_new_tech_data_ = true;
    }

    void processed() final override
    {
        ServiceBase::processed();
        have_new_tech_data_ = false;
    }

    bool needs_processing() final override
    {
        return have_new_tech_data_ || ServiceBase::needs_processing();
    }

    const TechDataType &get_tech_data() const { return *tech_data_; }
    Technology get_technology() const final override { return TECH; }
};

DHCPV4Method parse_connman_dhcp_v4_method(const char *method);
DHCPV6Method parse_connman_dhcp_v6_method(const char *method);
Technology parse_connman_technology(const char *technology);
ServiceState parse_connman_service_state(const char *state);

}

#endif /* !CONNMAN_SERVICE_HH */
