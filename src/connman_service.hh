/*
 * Copyright (C) 2017, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#include "network_device.hh"
#include "maybe.hh"

#include <vector>
#include <memory>

namespace Connman
{

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
    IPSettings &operator=(IPSettings &&) = default;

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

enum class ProxyMethod
{
    NOT_AVAILABLE,
    UNKNOWN_METHOD,
    DIRECT,
    AUTO,
    MANUAL,

    LAST_VALUE = MANUAL,
};

class ProxySettings
{
  private:
    ProxyMethod proxy_method_;
    std::string pac_url_;
    std::vector<std::string> servers_;
    std::vector<std::string> excluded_;

  public:
    ProxySettings(const ProxySettings &) = default;
    ProxySettings(ProxySettings &&) = default;
    ProxySettings &operator=(const ProxySettings &) = delete;
    ProxySettings &operator=(ProxySettings &&) = default;

    explicit ProxySettings():
        proxy_method_(ProxyMethod::NOT_AVAILABLE)
    {}

    void set_method(ProxyMethod method) { proxy_method_ = method; }
    void set_pac_url(std::string &&url) { pac_url_ = std::move(url); }
    void set_proxy_servers(std::vector<std::string> &&servers) { servers_ = std::move(servers); }
    void set_excluded_hosts(std::vector<std::string> &&excluded) { excluded_ = std::move(excluded); }

    ProxyMethod get_method() const { return proxy_method_; }
    const std::string &get_pac_url() const { return pac_url_; }
    const std::vector<std::string> &get_proxy_servers() const { return servers_; }
    const std::vector<std::string> &get_excluded_hosts() const { return excluded_; }

    bool operator==(const ProxySettings &other) const
    {
        return (proxy_method_ == other.proxy_method_ &&
                pac_url_ == other.pac_url_ &&
                servers_ == other.servers_ &&
                excluded_ == other.excluded_);
    }
};

struct ServiceData
{
    std::shared_ptr<const NetworkDevice> device_;

    Maybe<bool> is_favorite_;
    Maybe<bool> is_auto_connect_;
    Maybe<bool> is_immutable_;
    Maybe<ServiceState> state_;

    struct Settings
    {
        Maybe<IPSettings<AddressType::IPV4>> ipsettings_v4_;
        Maybe<IPSettings<AddressType::IPV6>> ipsettings_v6_;
        Maybe<ProxySettings> proxy_;
        Maybe<std::vector<std::string>> dns_servers_;
        Maybe<std::vector<std::string>> time_servers_;
        Maybe<std::vector<std::string>> domains_;

        Settings(const Settings &) = default;
        Settings(Settings &&) = default;
        Settings &operator=(const Settings &) = delete;
        Settings &operator=(Settings &&) = default;

        explicit Settings() = default;

        bool operator==(const Settings &other) const
        {
            return (ipsettings_v4_ == other.ipsettings_v4_ &&
                    ipsettings_v6_ == other.ipsettings_v6_ &&
                    proxy_ == other.proxy_ &&
                    dns_servers_ == other.dns_servers_ &&
                    time_servers_ == other.time_servers_ &&
                    domains_ == other.domains_);
        }
    };

    Settings active_;
    Settings configured_;

    ServiceData(const ServiceData &) = default;
    ServiceData(ServiceData &&) = default;
    ServiceData &operator=(const ServiceData &) = delete;
    ServiceData &operator=(ServiceData &&) = default;

    explicit ServiceData() = default;

    bool operator==(const ServiceData &other) const
    {
        return (device_.get() == other.device_.get() &&
                is_favorite_ == other.is_favorite_ &&
                is_auto_connect_ == other.is_auto_connect_ &&
                is_immutable_ == other.is_immutable_ &&
                state_ == other.state_ &&
                active_ == other.active_ &&
                configured_ == other.configured_);
    }

    bool operator!=(const ServiceData &other) const
    {
        return !(*this == other);
    }
};

enum class WPSCapability
{
    NONE,
    POSSIBLE,
    ACTIVE,
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
    Maybe<WPSCapability> wps_capability_;
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
                wps_capability_ == other.wps_capability_ &&
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
    ServiceData service_data_store_[2];
    ServiceData *service_data_;
    bool have_new_service_data_;

    explicit ServiceBase(struct ServiceData &&data):
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

    bool is_ours() const
    {
        log_assert(service_data_ != nullptr);

        return (service_data_->device_ != nullptr)
            ? service_data_->device_->is_auto_selected_device()
            : false;
    }

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

    explicit Service(ServiceData &&service_data, TechDataType &&tech_data):
        ServiceBase(std::move(service_data)),
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
    void put_changes(ServiceData &&service_data, TechDataType &&tech_data,
                     bool force_refresh = false)
    {
        put_service_data_changes(std::move(service_data));

        if(tech_data == *tech_data_)
        {
            have_new_tech_data_ = force_refresh;
            return;
        }

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
ProxyMethod parse_connman_proxy_method(const char *method);
Technology parse_connman_technology(const char *technology);
ServiceState parse_connman_service_state(const char *state);

class ServiceNameComponents
{
  public:
    const Technology technology_;
    const Address<AddressType::MAC> mac_address_;
    const std::string ssid_;
    const std::string security_;

    ServiceNameComponents(const ServiceNameComponents &) = delete;
    ServiceNameComponents(ServiceNameComponents &&) = default;
    ServiceNameComponents &operator=(const ServiceNameComponents &) = delete;

  private:
    explicit ServiceNameComponents(Technology tech,
                                   Address<AddressType::MAC> &&mac,
                                   const char *ssid, size_t ssid_length,
                                   const char *sec, size_t sec_length):
        technology_(tech),
        mac_address_(std::move(mac)),
        ssid_(ssid, ssid_length),
        security_(sec, sec_length)
    {}

    explicit ServiceNameComponents(Technology tech,
                                   Address<AddressType::MAC> &&mac):
        technology_(tech),
        mac_address_(std::move(mac))
    {}

  public:
    static ServiceNameComponents from_service_name(const char *service_name);
};

}

#endif /* !CONNMAN_SERVICE_HH */
