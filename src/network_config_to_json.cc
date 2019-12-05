/*
 * Copyright (C) 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#include "network_config_to_json.hh"
#include "network_netlink.hh"
#include "networkprefs.h"
#include "md5.hh"

#include <sstream>
#include <algorithm>
#include <functional>
#include <jsoncpp/json.h>

static void add_to_hash(MD5::Context &ctx, size_t size)
{
    static const uint8_t marker[] = { 0x60, 0xca };
    MD5::update(ctx, marker, sizeof(marker));
    MD5::update(ctx, reinterpret_cast<const uint8_t *>(&size), sizeof(size));
}

static void add_to_hash(MD5::Context &ctx, const MD5::Hash &hash)
{
    static const uint8_t marker[] = { 0xcb, 0x49 };
    MD5::update(ctx, marker, sizeof(marker));
    MD5::update(ctx, hash.data(), hash.size());
}

static void add_missing_to_hash(MD5::Context &ctx)
{
    static const uint8_t marker[] = { 0x9b, 0xe3 };
    MD5::update(ctx, marker, sizeof(marker));
}

static void add_empty_to_hash(MD5::Context &ctx)
{
    static const uint8_t marker[] = { 0xf8, 0x0a };
    MD5::update(ctx, marker, sizeof(marker));
}

static void add_to_hash(MD5::Context &ctx, const std::string &s)
{
    if(s.empty())
        add_empty_to_hash(ctx);
    else
    {
        static const uint8_t marker[] = { 0x1b, 0x41 };
        MD5::update(ctx, marker, sizeof(marker));
        MD5::update(ctx, s);
    }
}

static void add_to_hash(MD5::Context &ctx, const Json::Value &obj, const char *field)
{
    if(obj.isMember(field))
        add_to_hash(ctx, obj[field].asString());
    else
        add_missing_to_hash(ctx);
}

enum class IsCached
{
    FRESH,
    CACHED,
    PHYSICALLY_AVAILABLE,
};

static void add_nic_entry(
        Json::Value &nics,
        const Connman::Address<Connman::AddressType::MAC> &mac,
        Connman::Technology technology, bool is_secondary,
        IsCached is_cached, const std::string *devname = nullptr)
{
    if(mac.empty())
        throw std::runtime_error("Need MAC to make NIC entry");

    if(nics.isMember(mac.get_string()))
    {
        if(devname != nullptr || is_cached == IsCached::PHYSICALLY_AVAILABLE)
        {
            auto &nic(nics[mac.get_string()]);

            if(devname != nullptr && !nic.isMember("device_name"))
                nic["device_name"] = *devname;

            if(is_cached == IsCached::PHYSICALLY_AVAILABLE)
                nic["cached"] = false;
        }

        return;
    }

    const char *tech_name = nullptr;

    switch(technology)
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
        throw std::runtime_error("Need technology to make NIC entry");

      case Connman::Technology::ETHERNET:
        tech_name = "ethernet";
        break;

      case Connman::Technology::WLAN:
        tech_name = "wifi";
        break;
    }

    Json::Value nic;

    nic["technology"] = tech_name;
    nic["cached"] = is_cached == IsCached::CACHED;

    if(is_secondary)
        nic["is_secondary"] = true;

    if(devname != nullptr)
        nic["device_name"] = *devname;

    nics[mac.get_string()].swap(nic);
}

/*!
 * Add the up to two "primary" NICs.
 */
static void add_nics_from_prefs(Json::Value &nics,
                                const Connman::NetworkDeviceList &devices,
                                bool is_cached)
{
    const auto is_cached_param(is_cached ? IsCached::CACHED : IsCached::FRESH);

    try
    {
        add_nic_entry(nics,
                      devices.get_auto_select_mac_address(Connman::Technology::ETHERNET),
                      Connman::Technology::ETHERNET, false, is_cached_param);
    }
    catch(const std::exception &e)
    {
        /* ignore this NIC */
    }

    try
    {
        add_nic_entry(nics,
                      devices.get_auto_select_mac_address(Connman::Technology::WLAN),
                      Connman::Technology::WLAN, false, is_cached_param);
    }
    catch(const std::exception &e)
    {
        /* ignore this NIC */
    }
}

/*!
 * Add any NIC known from Connman (contains non-primary NICs as well).
 */
static void add_nics_from_connman_devices(Json::Value &nics,
                                          const Connman::NetworkDeviceList &devices,
                                          bool is_cached)
{
    const auto is_cached_param(is_cached ? IsCached::CACHED : IsCached::FRESH);

    for(const auto &dev : devices)
    {
        const Connman::NetworkDevice &d(*dev.second);

        if(!d.is_real_)
            continue;

        try
        {
            add_nic_entry(nics, d.mac_address_, d.technology_,
                          !d.is_auto_selected_device(), is_cached_param);
        }
        catch(const std::exception &e)
        {
            /* ignore this NIC */
        }
    }
}

/*!
 * Add NICs found via netlink (also contains NICs with no Connman services).
 */
static void add_nics_from_netlink(Json::Value &nics)
{
    const auto &devices(Network::os_get_network_devices());

    for(const auto &dev : devices)
    {
        try
        {
            add_nic_entry(nics, std::get<1>(dev), std::get<2>(dev), true,
                          IsCached::PHYSICALLY_AVAILABLE, &std::get<0>(dev));
        }
        catch(const std::exception &e)
        {
            /* ignore this NIC */
        }
    }
}

template <typename T>
static void set_if_known(Json::Value &item, const char *field,
                         MD5::Context &ctx, const Maybe<T> &value)
{
    if(value.is_known())
    {
        item[field] = value.get();
        add_to_hash(ctx, item[field].asString());
    }
    else
        add_missing_to_hash(ctx);
}

template <typename InT, typename OutT>
static void set_if_known(Json::Value &item, const char *field,
                         MD5::Context &ctx, const Maybe<InT> &value,
                         const std::function<const OutT &(const Maybe<InT> &)> &get)
{
    if(value.is_known())
    {
        item[field] = get(value);
        add_to_hash(ctx, item[field].asString());
    }
    else
        add_missing_to_hash(ctx);
}

static bool fill_ipv4_settings(Json::Value &json, MD5::Context &ctx,
                               const Connman::IPSettings<Connman::AddressType::IPV4> &ipv4)
{
    if(ipv4.get_dhcp_method() != Connman::DHCPV4Method::NOT_AVAILABLE)
    {
        static const std::array<const std::string,
                                static_cast<size_t>(Connman::DHCPV4Method::LAST_VALUE) + 1> dhcp_names
        {
            "", "unknown", "dhcp", "off", "manual", "fixed"
        };

        json["dhcp_method"] = dhcp_names[static_cast<size_t>(ipv4.get_dhcp_method())];
    }

    if(!ipv4.get_address().empty())
        json["address"] = ipv4.get_address().get_string();

    if(!ipv4.get_netmask().empty())
        json["netmask"] = ipv4.get_netmask().get_string();

    if(!ipv4.get_gateway().empty())
        json["gateway"] = ipv4.get_gateway().get_string();

    add_to_hash(ctx, json, "dhcp_method");
    add_to_hash(ctx, json, "address");
    add_to_hash(ctx, json, "netmask");
    add_to_hash(ctx, json, "gateway");

    return !json.isNull();
}

static bool fill_ipv6_settings(Json::Value &json, MD5::Context &ctx,
                               const Connman::IPSettings<Connman::AddressType::IPV6> &ipv6)
{
    if(ipv6.get_dhcp_method() != Connman::DHCPV6Method::NOT_AVAILABLE)
    {
        static const std::array<const std::string,
                                static_cast<size_t>(Connman::DHCPV6Method::LAST_VALUE) + 1> dhcp_names
        {
            "", "unknown", "dhcp", "off", "manual", "6to4", "fixed"
        };

        json["dhcp_method"] = dhcp_names[static_cast<size_t>(ipv6.get_dhcp_method())];
    }

    if(!ipv6.get_address().empty())
        json["address"] = ipv6.get_address().get_string();

    if(!ipv6.get_netmask().empty())
        json["prefix_length"] = ipv6.get_netmask().get_string();

    if(!ipv6.get_gateway().empty())
        json["gateway"] = ipv6.get_gateway().get_string();

    add_to_hash(ctx, json, "dhcp_method");
    add_to_hash(ctx, json, "address");
    add_to_hash(ctx, json, "prefix_length");
    add_to_hash(ctx, json, "gateway");

    return !json.isNull();
}

static void fill_string_array(Json::Value &json, const char *field,
                              MD5::Context &ctx,
                              const std::vector<std::string> &a,
                              bool allow_empty)
{
    if(a.empty() && !allow_empty)
    {
        add_missing_to_hash(ctx);
        return;
    }

    Json::Value temp(Json::arrayValue);

    if(a.empty())
        add_empty_to_hash(ctx);
    else
    {
        for(const auto &s : a)
        {
            temp.append(s);
            add_to_hash(ctx, s);
        }
    }

    json[field].swap(temp);
}

static void fill_string_array(Json::Value &json, const char *field,
                              MD5::Context &ctx,
                              const Maybe<std::vector<std::string>> &a,
                              bool allow_empty)
{
    if(a.is_known())
        fill_string_array(json, field, ctx, a.get(), allow_empty);
    else
        add_missing_to_hash(ctx);
}

static void fill_proxy_settings(Json::Value &json, MD5::Context &ctx,
                                const Connman::ProxySettings &proxy,
                                bool allow_empty)
{
    if(proxy.get_method() != Connman::ProxyMethod::NOT_AVAILABLE)
    {
        static const std::array<const std::string,
                                static_cast<size_t>(Connman::ProxyMethod::LAST_VALUE) + 1> methods
        {
            "", "unknown", "direct", "auto", "manual"
        };

        json["method"] = methods[static_cast<size_t>(proxy.get_method())];
    }

    if(!proxy.get_pac_url().empty())
        json["auto_config_pac_url"] = proxy.get_pac_url();

    add_to_hash(ctx, json, "method");
    add_to_hash(ctx, json, "auto_config_pac_url");

    fill_string_array(json, "proxy_servers", ctx, proxy.get_proxy_servers(), allow_empty);
    fill_string_array(json, "excluded_hosts", ctx, proxy.get_excluded_hosts(), allow_empty);
}

static bool fill_in_service_configuration(
        Json::Value &config, MD5::Context &ctx, bool allow_empty,
        const Maybe<Connman::IPSettings<Connman::AddressType::IPV4>> &ipv4,
        const Maybe<Connman::IPSettings<Connman::AddressType::IPV6>> &ipv6,
        const Maybe<Connman::ProxySettings> &proxy,
        const Maybe<std::vector<std::string>> &dns_servers,
        const Maybe<std::vector<std::string>> &time_servers,
        const Maybe<std::vector<std::string>> &domains)
{
    config = Json::Value();

    if(ipv4.is_known())
    {
        Json::Value temp;
        if(fill_ipv4_settings(temp, ctx, ipv4.get()))
            config["ipv4_config"].swap(temp);
    }
    else
        add_missing_to_hash(ctx);

    if(ipv6.is_known())
    {
        Json::Value temp;
        if(fill_ipv6_settings(temp, ctx, ipv6.get()))
            config["ipv6_config"].swap(temp);
    }
    else
        add_missing_to_hash(ctx);

    if(proxy.is_known())
    {
        Json::Value temp;
        fill_proxy_settings(temp, ctx, proxy.get(), allow_empty);

        if(!temp.isNull())
            config["proxy_config"].swap(temp);
    }

    fill_string_array(config, "dns_servers", ctx, dns_servers, allow_empty);
    fill_string_array(config, "time_servers", ctx, time_servers, allow_empty);
    fill_string_array(config, "domains", ctx, domains, allow_empty);

    return !config.isNull();
}

static std::string get_service_id(const std::string &path)
{
    const auto &slash_pos(std::find(path.rbegin(), path.rend(), '/'));

    return slash_pos != path.rend()
        ? path.substr(std::distance(slash_pos, path.rend()))
        : path;
}

static void add_services_from_connman(Json::Value &srv,
                                      std::vector<std::pair<std::string, MD5::Hash>> &service_hashes,
                                      const Connman::ServiceList &services, bool is_cached)
{
    for(const auto &service : services)
    {
        const Connman::ServiceBase &s(*service.second);
        const Connman::ServiceData &sd(s.get_service_data());
        MD5::Context ctx;
        MD5::init(ctx);

        Json::Value item;
        item["id"] = get_service_id(service.first);
        item["cached"] = is_cached;

        add_to_hash(ctx, item, "id");

        set_if_known<Connman::ServiceState, std::string>(
            item, "state", ctx, sd.state_,
            [] (const Maybe<Connman::ServiceState> &state) -> const std::string &
            {
                static const std::array<const std::string,
                                        static_cast<size_t>(Connman::ServiceState::LAST_VALUE) + 1> names
                {
                    "unavailable", "unknown", "idle", "failure", "association",
                    "configuration", "ready", "disconnect", "online",
                };
                return names[static_cast<size_t>(state.get())];
            });

        set_if_known(item, "is_system_service", ctx, sd.is_immutable_);
        set_if_known(item, "is_favorite", ctx, sd.is_favorite_);
        set_if_known(item, "is_auto_connect", ctx, sd.is_auto_connect_);

        Json::Value config;

        if(fill_in_service_configuration(config, ctx, false,
                                         sd.active_.ipsettings_v4_,
                                         sd.active_.ipsettings_v6_,
                                         sd.active_.proxy_,
                                         sd.active_.dns_servers_,
                                         sd.active_.time_servers_,
                                         sd.active_.domains_))
            item["active_config"].swap(config);

        if(fill_in_service_configuration(config, ctx, true,
                                         sd.configured_.ipsettings_v4_,
                                         sd.configured_.ipsettings_v6_,
                                         sd.configured_.proxy_,
                                         sd.configured_.dns_servers_,
                                         sd.configured_.time_servers_,
                                         sd.configured_.domains_))
            item["supposed_config"].swap(config);

        switch(s.get_technology())
        {
          case Connman::Technology::UNKNOWN_TECHNOLOGY:
            continue;

          case Connman::Technology::ETHERNET:
            item["name"] = "Ethernet (wired)";
            add_to_hash(ctx, item, "name");
            break;

          case Connman::Technology::WLAN:
            {
                const auto &tech_data(static_cast<const Connman::Service<Connman::Technology::WLAN> &>(s).get_tech_data());

                if(tech_data.network_name_.is_known())
                {
                    item["name"] = tech_data.network_name_.get();
                    add_to_hash(ctx, item, "name");
                }
                else
                {
                    item["name"] = nullptr;
                    add_empty_to_hash(ctx);
                }

                set_if_known(item, "ssid", ctx, tech_data.network_ssid_);
                set_if_known(item, "security", ctx, tech_data.security_);
                set_if_known(item, "strength", ctx, tech_data.strength_);

                if(tech_data.wps_capability_.is_known())
                {
                    switch(tech_data.wps_capability_.get())
                    {
                      case Connman::WPSCapability::NONE:
                        item["wps_capability"] = false;
                        item["wps_active"] = false;
                        break;

                      case Connman::WPSCapability::POSSIBLE:
                        item["wps_capability"] = true;
                        item["wps_active"] = false;
                        break;

                      case Connman::WPSCapability::ACTIVE:
                        item["wps_capability"] = true;
                        item["wps_active"] = true;
                        break;
                    }

                    add_to_hash(ctx, item, "wps_capability");
                    add_to_hash(ctx, item, "wps_active");
                }
                else
                    add_missing_to_hash(ctx);
            }
        }

        const auto &mac_string(sd.device_->mac_address_.get_string());

        if(srv.isMember(mac_string))
            srv[mac_string][srv[mac_string].size()].swap(item);
        else
        {
            srv[mac_string] = Json::Value(Json::arrayValue);
            srv[mac_string][0].swap(item);
        }

        service_hashes.emplace_back(item["id"].asString(), MD5::Hash());
        MD5::finish(ctx, service_hashes[service_hashes.size() - 1].second);
    }
}

static void add_service_from_prefs(Json::Value &srv,
                                   std::vector<std::pair<std::string, MD5::Hash>> &service_hashes,
                                   const struct network_prefs *prefs,
                                   const Connman::Technology tech,
                                   const Connman::ServiceList &services)
{
    if(prefs == nullptr)
        return;

    std::array<char, 256> buffer;
    if(network_prefs_generate_service_name(prefs, buffer.data(), buffer.size(),
                                           true) == 0)
        return;

    if(services[buffer.data()] != nullptr)
    {
        /* already filled in from Connman services */
        return;
    }

    if(network_prefs_generate_service_name(prefs, buffer.data(), buffer.size(),
                                           false) == 0)
        return;

    Json::Value item;
    item["id"] = buffer.data();
    item["state"] = "unknown";
    item["is_system_service"] = false;
    item["is_favorite"] = true;
    item["is_auto_connect"] = true;

    bool with_dhcp;
    const char *address;
    const char *netmask;
    const char *gateway;
    const char *dns1;
    const char *dns2;

    if(network_prefs_get_ipv4_settings(prefs, &with_dhcp, &address, &netmask,
                                       &gateway, &dns1, &dns2))
    {
        Json::Value config;

        config["dhcp_method"] = with_dhcp ? "dhcp" : "off";

        if(address != nullptr)
            config["address"] = address;

        if(netmask != nullptr)
            config["netmask"] = netmask;

        if(gateway != nullptr)
            config["gateway"] = gateway;

        if(dns1 != nullptr || dns2 != nullptr)
        {
            Json::Value dns(Json::arrayValue);

            if(dns1 != nullptr)
                dns.append(dns1);

            if(dns2 != nullptr)
                dns.append(dns2);

            config["dns_servers"].swap(dns);
        }

        item["supposed_config"].swap(config);
    }

    switch(tech)
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
        return;

      case Connman::Technology::ETHERNET:
        item["name"] = "Ethernet (wired)";
        break;

      case Connman::Technology::WLAN:
        {
            const char *temp = network_prefs_get_name(prefs);
            if(temp != nullptr)
                item["name"] = temp;

            temp = network_prefs_get_ssid(prefs);
            if(temp != nullptr)
                item["ssid"] = temp;

            temp = network_prefs_get_security(prefs);
            if(temp != nullptr)
                item["security"] = temp;
        }
    }

    const char *const mac_raw_string(network_prefs_get_mac(prefs));

    if(mac_raw_string == nullptr)
        return;

    Connman::Address<Connman::AddressType::MAC> mac;

    try
    {
        mac.set(mac_raw_string);
    }
    catch(const std::domain_error &e)
    {
        return;
    }

    const auto &mac_string(mac.get_string());

    if(srv.isMember(mac_string))
        srv[mac_string][srv[mac_string].size()].swap(item);
    else
    {
        srv[mac_string] = Json::Value(Json::arrayValue);
        srv[mac_string][0].swap(item);
    }
}

static void add_services_from_prefs(Json::Value &srv,
                                    std::vector<std::pair<std::string, MD5::Hash>> &service_hashes,
                                    const Connman::ServiceList &services)
{
    const struct network_prefs *ethernet_prefs;
    const struct network_prefs *wlan_prefs;
    struct network_prefs_handle *cfg =
        network_prefs_open_ro(&ethernet_prefs, &wlan_prefs);

    if(cfg == nullptr)
        return;

    add_service_from_prefs(srv, service_hashes, ethernet_prefs,
                           Connman::Technology::ETHERNET, services);
    add_service_from_prefs(srv, service_hashes, wlan_prefs,
                           Connman::Technology::WLAN, services);

    network_prefs_close(cfg);
}

static void hash_sorted_nic_macs(MD5::Context &ctx, const Json::Value &nics)
{
    std::vector<std::string> macs(nics.getMemberNames());
    std::sort(macs.begin(), macs.end());

    add_to_hash(ctx, macs.size());

    for(const auto &mac : macs)
    {
        add_to_hash(ctx, mac);

        const auto &nic(nics[mac]);
        add_to_hash(ctx, nic, "technology");
        add_to_hash(ctx, nic, "device_name");
        add_to_hash(ctx, nic, "is_secondary");
    }
}

static void hash_sorted_services(
        MD5::Context &ctx,
        const std::vector<std::pair<std::string, MD5::Hash>> &service_hashes)
{
    std::vector<size_t> service_indices;
    service_indices.reserve(service_hashes.size());
    for(size_t i = 0; i < service_hashes.size(); ++i)
        service_indices.push_back(i);

    std::sort(service_indices.begin(), service_indices.end(),
        [&service_hashes] (const size_t &a, const size_t &b)
        {
            return service_hashes[a].first < service_hashes[b].first;
        });

    add_to_hash(ctx, service_hashes.size());

    for(const auto &i : service_indices)
    {
        add_to_hash(ctx, service_hashes[i].first);
        add_to_hash(ctx, service_hashes[i].second);
    }
}

static std::string compute_version(
        const Json::Value &nics,
        const std::vector<std::pair<std::string, MD5::Hash>> &service_hashes)
{
    MD5::Context ctx;
    MD5::init(ctx);

    hash_sorted_nic_macs(ctx, nics);
    hash_sorted_services(ctx, service_hashes);

    MD5::Hash hash;
    MD5::finish(ctx, hash);

    std::string result;
    MD5::to_string(hash, result);

    return result;
}

std::string Network::configuration_to_json(const Connman::ServiceList &services,
                                           const Connman::NetworkDeviceList &devices,
                                           const std::string &have_version,
                                           bool is_cached, std::string &version)
{
    Json::Value nics(Json::objectValue);

    add_nics_from_prefs(nics, devices, is_cached);
    add_nics_from_connman_devices(nics, devices, is_cached);
    add_nics_from_netlink(nics);

    std::vector<std::pair<std::string, MD5::Hash>> service_hashes;

    Json::Value srv(Json::objectValue);
    add_services_from_connman(srv, service_hashes, services, is_cached);
    add_services_from_prefs(srv, service_hashes, services);

    version = compute_version(nics, service_hashes);

    if(version == have_version)
        return "";

    Json::Value root;
    root["nics"].swap(nics);
    root["services"].swap(srv);

    Json::StreamWriterBuilder builder;
    builder["commentStyle"] = "None";
    builder["indentation"] = "";
    std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
    std::ostringstream json;
    writer->write(root, &json);

    return json.str();
}
