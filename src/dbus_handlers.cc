/*
 * Copyright (C) 2015--2019  T+A elektroakustik GmbH & Co. KG
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

#include "dbus_handlers.h"
#include "dcpregs_audiosources.hh"
#include "dcpregs_audiopaths.hh"
#include "dcpregs_appliance.hh"
#include "dcpregs_networkconfig.hh"
#include "dcpregs_upnpname.hh"
#include "dcpregs_filetransfer.hh"
#include "dcpregs_playstream.hh"
#include "dcpregs_upnpserver.hh"
#include "dcpregs_status.hh"
#include "mainloop.hh"
#include "network_config_to_json.hh"
#include "accesspoint_manager.hh"
#include "volume_control.hh"
#include "smartphone_app_send.hh"
#include "configproxy.h"
#include "actor_id.h"
#include "messages.h"

#include <cstring>
#include <cerrno>
#include <jsoncpp/json.h>

static void unknown_signal(const char *iface_name, const char *signal_name,
                           const char *sender_name)
{
    msg_error(ENOSYS, LOG_NOTICE, "Got unknown signal %s.%s from %s",
              iface_name, signal_name, sender_name);
}

static void check_parameter_assertions(GVariant *parameters,
                                       guint expected_number_of_parameters)
{
    /* we may use #log_assert() here because the GDBus code is supposed to do
     * any type checks before calling us---here, we just make sure we can
     * trust those type checks */
    log_assert(g_variant_type_is_tuple(g_variant_get_type(parameters)));
    log_assert(g_variant_n_children(parameters) == expected_number_of_parameters);
}

void dbussignal_logind_manager(GDBusProxy *proxy, const gchar *sender_name,
                               const gchar *signal_name, GVariant *parameters,
                               gpointer user_data)
{
    static const char iface_name[] = "org.freedesktop.login1.Manager";

    if(strcmp(signal_name, "PrepareForShutdown") == 0)
    {
        check_parameter_assertions(parameters, 1);

        GVariant *val = g_variant_get_child_value(parameters, 0);
        gboolean is_active = g_variant_get_boolean(val);
        g_variant_unref(val);

        const auto *const iface =
            static_cast<const struct dbussignal_shutdown_iface *>(user_data);

        if(!iface->is_inhibitor_lock_taken())
            msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                      "Shutting down, but having no inhibit lock");

        Regs::FileTransfer::prepare_for_shutdown();
        Regs::NetworkConfig::prepare_for_shutdown();
        Regs::UPnPName::prepare_for_shutdown();

        if(!is_active)
        {
            msg_error(0, LOG_NOTICE,
                      "Funny PrepareForShutdown message, asking for restart");
            Regs::StrBoStatus::set_reboot_required();
        }

        /*
         * Tell the slave that we are about to shut down now. It will wait for
         * a few seconds before really cutting the power.
         */
        Regs::StrBoStatus::set_ready_to_shutdown();

        /*
         * This must be last because the D-Bus inhibit lock is going to be
         * released by this function. When this function returns, communication
         * with dcpspi may not be possible anymore.
         */
        iface->allow_shutdown();
    }
    else if(strcmp(signal_name, "SeatNew") == 0)
    {
        /* actively ignore irrelevant known signals */
    }
    else
        unknown_signal(iface_name, signal_name, sender_name);
}

void dbussignal_file_transfer(GDBusProxy *proxy, const gchar *sender_name,
                              const gchar *signal_name, GVariant *parameters,
                              gpointer user_data)
{
    static const char iface_name[] = "de.tahifi.FileTransfer";

    if(strcmp(signal_name, "Progress") == 0)
    {
        check_parameter_assertions(parameters, 3);

        GVariant *val = g_variant_get_child_value(parameters, 0);
        uint32_t xfer_id = g_variant_get_uint32(val);
        g_variant_unref(val);

        val = g_variant_get_child_value(parameters, 1);
        uint32_t tick = g_variant_get_uint32(val);
        g_variant_unref(val);

        val = g_variant_get_child_value(parameters, 2);
        uint32_t total_ticks = g_variant_get_uint32(val);
        g_variant_unref(val);

        Regs::FileTransfer::progress_notification(xfer_id, tick, total_ticks);
    }
    else if(strcmp(signal_name, "Done") == 0)
    {
        check_parameter_assertions(parameters, 3);

        GVariant *val = g_variant_get_child_value(parameters, 0);
        uint32_t xfer_id = g_variant_get_uint32(val);
        g_variant_unref(val);

        val = g_variant_get_child_value(parameters, 1);
        uint8_t error_code_raw = g_variant_get_byte(val);
        g_variant_unref(val);

        val = g_variant_get_child_value(parameters, 2);
        gsize path_length;
        const gchar *path = g_variant_get_string(val, &path_length);

        enum DBusListsErrorCode error_code =
            (error_code_raw <= LIST_ERROR_LAST_ERROR_CODE
             ? (enum DBusListsErrorCode)error_code_raw
             : LIST_ERROR_INTERNAL);

        Regs::FileTransfer::done_notification(xfer_id, error_code,
                                              path_length > 0 ? path : NULL);

        g_variant_unref(val);
    }
    else
        unknown_signal(iface_name, signal_name, sender_name);
}

void dbussignal_splay_playback(GDBusProxy *proxy, const gchar *sender_name,
                               const gchar *signal_name, GVariant *parameters,
                               gpointer user_data)
{
    static const char iface_name[] = "de.tahifi.Streamplayer.Playback";

    if(strcmp(signal_name, "NowPlaying") == 0)
    {
        /* some stream started or continued playing */
        check_parameter_assertions(parameters, 5);

        GVariant *val = g_variant_get_child_value(parameters, 0);
        uint16_t stream_id = g_variant_get_uint16(val);
        g_variant_unref(val);

        auto &regs(*static_cast<Regs::PlayStream::StreamingRegistersIface *>(user_data));
        regs.start_notification(ID::Stream::make_from_raw_id(stream_id),
                                g_variant_get_child_value(parameters, 1));
    }
    else if(strcmp(signal_name, "Stopped") == 0 ||
            strcmp(signal_name, "StoppedWithError") == 0)
    {
        /* stream stopped playing */
        GVariant *val = g_variant_get_child_value(parameters, 0);
        uint16_t stream_id = g_variant_get_uint16(val);
        g_variant_unref(val);

        auto &regs(*static_cast<Regs::PlayStream::StreamingRegistersIface *>(user_data));
        regs.stop_notification(ID::Stream::make_from_raw_id(stream_id));
    }
    else if(strcmp(signal_name, "MetaDataChanged") == 0 ||
            strcmp(signal_name, "PositionChanged") == 0 ||
            strcmp(signal_name, "PlaybackModeChanged") == 0 ||
            strcmp(signal_name, "SpeedChanged") == 0 ||
            strcmp(signal_name, "Paused") == 0)
    {
        /* ignore */
    }
    else
        unknown_signal(iface_name, signal_name, sender_name);
}

gboolean dbusmethod_set_stream_info(tdbusdcpdPlayback *object,
                                    GDBusMethodInvocation *invocation,
                                    guint16 raw_stream_id,
                                    const gchar *title, const gchar *url,
                                    gpointer user_data)
{
    auto id(ID::Stream::make_from_raw_id(raw_stream_id));

    if(id.get_source() == STREAM_ID_SOURCE_INVALID)
    {
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
                                              "Invalid source in stream ID");
        return TRUE;
    }

    const bool clear_info =
        (id.get_cookie() == STREAM_ID_COOKIE_INVALID || url[0] == '\0');

    if(clear_info)
        id = ID::Stream::make_complete(id.get_source(), STREAM_ID_COOKIE_INVALID);

    auto &regs(*static_cast<Regs::PlayStream::StreamingRegistersIface *>(user_data));
    regs.set_title_and_url(id, title, url);

    tdbus_dcpd_playback_complete_set_stream_info(object, invocation);

    return TRUE;
}

static void complete_network_get_all(tdbusdcpdNetwork *object,
                                     GDBusMethodInvocation *invocation,
                                     const Connman::ServiceList &services,
                                     const Connman::NetworkDeviceList &devices,
                                     const gchar *have_version, bool is_cached)
{
    std::string version;

    try
    {
        const auto json(Network::configuration_to_json(services, devices,
                                                       have_version, is_cached,
                                                       version));

        tdbus_dcpd_network_complete_get_all(object, invocation,
                                            version.c_str(), json.c_str());
    }
    catch(const std::exception &e)
    {
        g_dbus_method_invocation_return_error(
            invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
            "Failed reading out %sconfiguration: \"%s\"",
            is_cached ? "cached " : "", e.what());
    }
}

gboolean dbusmethod_network_get_all(tdbusdcpdNetwork *object,
                                    GDBusMethodInvocation *invocation,
                                    const gchar *have_version,
                                    gpointer user_data)
{
    const auto &apman = *static_cast<const Network::AccessPointManager *>(user_data);

    switch(apman.get_status())
    {
      case Network::AccessPoint::Status::UNKNOWN:
        /* transient state, unlucky client should try again later */
        g_dbus_method_invocation_return_error(
            invocation, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
            "Failed reading out configuration in unknown state");
        break;

      case Network::AccessPoint::Status::PROBING_STATUS:
        /* transient state, unlucky client should try again later */
        g_dbus_method_invocation_return_error(
            invocation, G_IO_ERROR, G_IO_ERROR_BUSY,
            "Failed reading out configuration while probing AP status");
        break;

      case Network::AccessPoint::Status::DISABLED:
        {
            LOGGED_LOCK_CONTEXT_HINT;
            const auto locked_services(Connman::ServiceList::get_singleton_const());
            const auto &services(locked_services.first);

            LOGGED_LOCK_CONTEXT_HINT;
            const auto locked_devices(Connman::NetworkDeviceList::get_singleton_const());
            const auto &devices(locked_devices.first);

            complete_network_get_all(object, invocation,
                                     services, devices, have_version, false);
        }

        break;

      case Network::AccessPoint::Status::ACTIVATING:
      case Network::AccessPoint::Status::ACTIVE:
        {
            LOGGED_LOCK_CONTEXT_HINT;
            const auto lock(apman.lock_cached());
            complete_network_get_all(object, invocation,
                                     apman.get_cached_service_list(),
                                     apman.get_cached_network_devices(),
                                     have_version, true);
            break;
        }
    }

    return TRUE;
}

static const Json::Value &
lookup_field(GDBusMethodInvocation *invocation,
             const Json::Value &json, const char *field,
             Json::ValueType expected_type = Json::nullValue,
             bool must_exist = true)
{
    const auto &result(json[field]);

    if(result.isNull())
    {
        if(must_exist)
        {
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
                "Required field missing: \"%s\"", field);
            throw std::runtime_error("Required field missing");
        }
    }
    else if(result.type() != expected_type)
    {
        if(expected_type != Json::nullValue)
        {
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
                "Field of unexpected type: \"%s\"", field);
            throw std::runtime_error("Unexpected field type");
        }
    }

    return result;
}

static bool copy_if_available(GDBusMethodInvocation *invocation,
                              const Json::Value &json, const char *field,
                              Maybe<std::string> &dest)
{
    const auto &s(lookup_field(invocation, json, field, Json::stringValue, false));

    if(!s.isString())
        return false;

    dest = s.asString();
    return true;
}

static bool copy_if_available(GDBusMethodInvocation *invocation,
                              const Json::Value &json, const char *field,
                              Maybe<std::vector<std::string>> &dest)
{
    const auto &in(lookup_field(invocation, json, field, Json::arrayValue, false));

    if(!in.isArray())
        return false;

    dest.set_known();
    auto &out(dest.get_rw());

    out.clear();

    for(const auto &s : in)
    {
        if(!s.isString())
        {
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
                "Array contains value of unexpected type: %s", field);
            throw std::runtime_error("Unexpected array value type");
        }

        out.push_back(s.asString());
    }

    return true;
}

static void set_common_service_configuration(GDBusMethodInvocation *invocation,
                                             const Json::Value &json,
                                             Network::ConfigRequest &req)
{
    const auto &cfg(lookup_field(invocation, json,
                                 "configuration", Json::objectValue));

    const auto &ipv4_config(lookup_field(invocation, cfg, "ipv4_config",
                                         Json::objectValue, false));

    if(!ipv4_config.isNull())
    {
        copy_if_available(invocation, ipv4_config, "address", req.ipv4_address_);
        copy_if_available(invocation, ipv4_config, "dhcp_method", req.dhcpv4_mode_);
        copy_if_available(invocation, ipv4_config, "gateway", req.ipv4_gateway_);
        copy_if_available(invocation, ipv4_config, "netmask", req.ipv4_netmask_);
    }

    const auto &ipv6_config(lookup_field(invocation, cfg, "ipv6_config",
                                         Json::objectValue, false));

    if(!ipv6_config.isNull())
    {
        copy_if_available(invocation, ipv6_config, "address", req.ipv6_address_);
        copy_if_available(invocation, ipv6_config, "dhcp_method", req.dhcpv6_mode_);
        copy_if_available(invocation, ipv6_config, "gateway", req.ipv6_gateway_);
        copy_if_available(invocation, ipv6_config, "prefix_length", req.ipv6_prefix_length_);
    }

    const auto &proxy_config(lookup_field(invocation, cfg, "proxy_config",
                                          Json::objectValue, false));

    if(!proxy_config.isNull())
    {
        copy_if_available(invocation, proxy_config, "method", req.proxy_method_);
        copy_if_available(invocation, proxy_config, "auto_config_pac_url", req.proxy_pac_url_);
        copy_if_available(invocation, proxy_config, "proxy_servers", req.proxy_servers_);
        copy_if_available(invocation, proxy_config, "excluded_hosts", req.proxy_excluded_);
    }

    copy_if_available(invocation, json, "dns_servers", req.dns_servers_);
    copy_if_available(invocation, json, "time_servers", req.time_servers_);
    copy_if_available(invocation, json, "domains", req.domains_);
}

static void parse_device_info(GDBusMethodInvocation *invocation,
                              const Json::Value &json,
                              Connman::Technology tech,
                              Connman::Address<Connman::AddressType::MAC> &mac)
{
    switch(tech)
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
        break;

      case Connman::Technology::ETHERNET:
      case Connman::Technology::WLAN:
        return;
    }

    const auto &device_info(lookup_field(invocation, json, "device_info",
                                         Json::objectValue));

    if(!mac.empty())
        return;

    const auto &mac_string(lookup_field(invocation, device_info, "mac",
                                        Json::stringValue).asString());

    try
    {
        mac.set(std::string(mac_string));
    }
    catch(const std::domain_error &e)
    {
        /* handled below */
        g_dbus_method_invocation_return_error(
            invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
            "Bad MAC address: \"%s\"", mac_string.c_str());
        throw;
    }
}

static bool set_wlan_service_configuration(GDBusMethodInvocation *invocation,
                                           const Json::Value &json,
                                           Connman::Technology tech,
                                           Network::ConfigRequest &req)
{
    switch(tech)
    {
      case Connman::Technology::ETHERNET:
        return false;

      case Connman::Technology::UNKNOWN_TECHNOLOGY:
      case Connman::Technology::WLAN:
        break;
    }

    const auto &wlan_settings(lookup_field(invocation, json, "wlan_settings",
                                           Json::objectValue,
                                           tech == Connman::Technology::WLAN));
    if(wlan_settings.isNull())
        return false;

    req.wlan_security_mode_ =
        lookup_field(invocation, wlan_settings, "security",
                     Json::stringValue).asString();

    if(!copy_if_available(invocation, wlan_settings, "ssid", req.wlan_ssid_hex_) &&
       !copy_if_available(invocation, wlan_settings, "name", req.wlan_ssid_ascii_))
    {
        g_dbus_method_invocation_return_error(
            invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
            "Required field missing: \"ssid\" or \"name\"");
        throw std::runtime_error("Required field missing");
    }

    req.wlan_wpa_passphrase_ascii_ =
        lookup_field(invocation, wlan_settings, "passphrase",
                     Json::stringValue).asString();

    return true;
}

static bool set_network_service_configuration(
        GDBusMethodInvocation *invocation, const Json::Value &json,
        Connman::Technology tech, Network::ConfigRequest &req,
        Connman::Address<Connman::AddressType::MAC> &mac)
{
    const auto &auto_connect(lookup_field(invocation, json, "auto_connect",
                                          Json::stringValue).asString());

    if(auto_connect == "no")
        req.when_ = Network::ConfigRequest::ApplyWhen::NEVER;
    else if(auto_connect == "yes")
        req.when_ = Network::ConfigRequest::ApplyWhen::ON_AUTO_CONNECT;
    else if(auto_connect == "now")
        req.when_ = Network::ConfigRequest::ApplyWhen::NOW;
    else
    {
        g_dbus_method_invocation_return_error(
            invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
            "Invalid \"auto_connect\" request \"%s\"", auto_connect.c_str());
        throw std::runtime_error("Invalid \"auto_connect\" value");
    }

    set_common_service_configuration(invocation, json, req);
    const bool has_wlan_settings =
        set_wlan_service_configuration(invocation, json, tech, req);
    parse_device_info(invocation, json, tech, mac);

    return has_wlan_settings;
}

static bool parse_json_from_buffer(GDBusMethodInvocation *invocation,
                                   Json::Value &json, const char *buffer,
                                   size_t buffer_size, const char *what)
{
    Json::CharReaderBuilder reader_builder;
    reader_builder["collectComments"] = false;
    std::unique_ptr<Json::CharReader> reader(reader_builder.newCharReader());
    std::string errors;

    if(reader->parse(buffer, buffer + buffer_size, &json, &errors))
        return true;

    g_dbus_method_invocation_return_error(
        invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
        "Failed parsing JSON data (%s): %s", what, errors.c_str());
    return false;
}

static bool determine_tech_and_mac_from_service_name(
        GDBusMethodInvocation *invocation, const char *service_name,
        Connman::Technology &tech,
        Connman::Address<Connman::AddressType::MAC> &mac)
{
    if(service_name == nullptr || service_name[0] == '\0')
    {
        tech = Connman::Technology::UNKNOWN_TECHNOLOGY;
        return true;
    }

    try
    {
        auto components(Connman::ServiceNameComponents::from_service_name(service_name));
        tech = components.technology_;
        mac = std::move(components.mac_address_);
    }
    catch(const std::domain_error &e)
    {
        tech = Connman::Technology::UNKNOWN_TECHNOLOGY;
    }

    if(tech != Connman::Technology::UNKNOWN_TECHNOLOGY)
        return true;
    else
    {
        g_dbus_method_invocation_return_error(
            invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
            "Invalid service name");
        return false;
    }
}

/*!
 * Wrapper for non-movable objects that should be move captured by a lambda.
 *
 * This is primarily needed for C++ 98 stuff that only knows about swap() and
 * nothing about move semantics.
 *
 * In addition, in case the lambda must be stored in a std::function, this
 * class implements a copy constructor which throws when invoked. This operator
 * is required by std::function because by standard std::function is copyable.
 * Thus, by throwing at runtime, we avoid accidental deep copies of large
 * objects when we really wanted pure move. This also allows move-only objects
 * being passed to std::function objects.
 */
template <typename T>
class MoveToFunction
{
  private:
    T value_;

  public:
    MoveToFunction &operator=(const MoveToFunction &) = delete;

    MoveToFunction(const MoveToFunction &):
        value_{}
    {
        throw std::runtime_error("MoveToFunction objects shall not be copied");
    }

    MoveToFunction(MoveToFunction &&src)
    {
        std::swap(value_, src.value_);
    }

    MoveToFunction &operator=(MoveToFunction &&src)
    {
        std::swap(value_, src.value_);
        return *this;
    }

    explicit MoveToFunction(T &value)
    {
        std::swap(value_, value);
    }

    const T &get() const { return value_; }
    T &get() { return value_; }
};

gboolean
dbusmethod_network_set_service_configuration(tdbusdcpdNetwork *object,
                                             GDBusMethodInvocation *invocation,
                                             const gchar *service_name,
                                             const gchar *configuration,
                                             gpointer user_data)
{
    Json::Value json;
    if(!parse_json_from_buffer(invocation, json,
                               configuration, strlen(configuration),
                               "network configuration request"))
        return TRUE;

    Connman::Technology tech;
    Connman::Address<Connman::AddressType::MAC> mac;

    if(!determine_tech_and_mac_from_service_name(invocation, service_name,
                                                 tech, mac))
        return TRUE;

    MoveToFunction<Json::Value> json_moved(json);

    MainLoop::post(
        [object, invocation, user_data, tech,
         mac(std::move(mac)), json(std::move(json_moved))]
        () mutable
        {
            Network::ConfigRequest req;
            bool has_wlan_settings;

            try
            {
                has_wlan_settings =
                    set_network_service_configuration(invocation, json.get(),
                                                      tech, req, mac);
            }
            catch(const std::runtime_error &e)
            {
                /* some data is missing or unexpected */
                return;
            }
            catch(const std::domain_error &e)
            {
                /* bad MAC address */
                return;
            }

            if(mac.empty())
            {
                g_dbus_method_invocation_return_error(
                    invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
                    "MAC address unknown");
                return;
            }

            if(tech == Connman::Technology::UNKNOWN_TECHNOLOGY && has_wlan_settings)
                tech = Connman::Technology::WLAN;

            auto &apman = *static_cast<Network::AccessPointManager *>(user_data);

            if(Regs::NetworkConfig::request_configuration_for_mac(req, mac, tech, apman))
                tdbus_dcpd_network_complete_set_service_configuration(object, invocation);
            else
                g_dbus_method_invocation_return_error(
                    invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
                    "Invalid configuration request");
        });

    return TRUE;
}

void dbussignal_audiopath_manager(GDBusProxy *proxy, const gchar *sender_name,
                                  const gchar *signal_name, GVariant *parameters,
                                  gpointer user_data)
{
    static const char iface_name[] = "de.tahifi.AudioPath.Manager";

    if(strcmp(signal_name, "PathAvailable") == 0)
    {
        const gchar *source_id;
        const gchar *player_id;

        g_variant_get(parameters, "(&s&s)", &source_id, &player_id);
        Regs::AudioSources::source_available(source_id);
    }
    else if(strcmp(signal_name, "PathActivated") == 0 ||
            strcmp(signal_name, "PathDeferred") == 0)
    {
        const gchar *source_id;
        const gchar *player_id;

        g_variant_get(parameters, "(&s&s)", &source_id, &player_id);
        Regs::AudioSources::selected_source(source_id, strcmp(signal_name, "PathDeferred") == 0);
    }
    else if(strcmp(signal_name, "PlayerRegistered") == 0)
    {
        /* ignore */
    }
    else
        unknown_signal(iface_name, signal_name, sender_name);
}

gboolean dbusmethod_audiopath_source_selected(tdbusaupathSource *object,
                                              GDBusMethodInvocation *invocation,
                                              const char *source_id,
                                              GVariant *request_data,
                                              gpointer user_data)
{
    msg_info("Selected source \"%s\"", source_id);
    auto &regs(*static_cast<Regs::PlayStream::StreamingRegistersIface *>(user_data));
    regs.audio_source_selected();
    tdbus_aupath_source_complete_selected(object, invocation);
    return TRUE;
}

gboolean dbusmethod_audiopath_source_deselected(tdbusaupathSource *object,
                                                GDBusMethodInvocation *invocation,
                                                const char *source_id,
                                                GVariant *request_data,
                                                gpointer user_data)
{
    msg_info("Deselected source \"%s\"", source_id);
    auto &regs(*static_cast<Regs::PlayStream::StreamingRegistersIface *>(user_data));
    regs.audio_source_deselected();
    tdbus_aupath_source_complete_deselected(object, invocation);
    return TRUE;
}

gboolean dbusmethod_mixer_get_controls(tdbusmixerVolume *object,
                                       GDBusMethodInvocation *invocation,
                                       gpointer user_data)
{
    GVariantBuilder builder;
    g_variant_builder_init(&builder, G_VARIANT_TYPE("a(qssddddddy)"));

    LOGGED_LOCK_CONTEXT_HINT;
    const auto &controls(Mixer::VolumeControls::get_singleton());

    for(const auto &ctrl : *controls.first)
    {
        const auto *const props(ctrl->get_properties());

        if(props != nullptr)
        {
            const auto &settings(ctrl->get_settings());

            g_variant_builder_add(&builder, "(qssddddddy)",
                                  ctrl->id_, props->name_.c_str(),
                                  scale_to_string(props->scale_),
                                  props->volume_min_, props->volume_max_,
                                  props->volume_step_,
                                  props->min_db_, props->max_db_,
                                  settings.volume_.get(std::numeric_limits<double>::quiet_NaN()),
                                  settings.is_muted_.pick(1, 0, 2));
        }
    }

    tdbus_mixer_volume_complete_get_controls(object, invocation,
                                             g_variant_builder_end(&builder));

    return TRUE;
}

gboolean dbusmethod_mixer_get_master(tdbusmixerVolume *object,
                                     GDBusMethodInvocation *invocation,
                                     gpointer user_data)
{
    LOGGED_LOCK_CONTEXT_HINT;
    const auto &controls(Mixer::VolumeControls::get_singleton());
    const auto *const master(controls.first->get_master());

    if(master == nullptr)
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                              "Have no master volume control");

    else
    {
        const auto *const props(master->get_properties());

        if(props == nullptr)
            g_dbus_method_invocation_return_error(invocation,
                                                  G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                                  "Master volume control not configured");
        else
        {
            const auto &settings(master->get_settings());

            tdbus_mixer_volume_complete_get_master(object, invocation,
                    master->id_, props->name_.c_str(),
                    scale_to_string(props->scale_),
                    props->volume_min_, props->volume_max_,
                    props->volume_step_,
                    props->min_db_, props->max_db_,
                    settings.volume_.get(std::numeric_limits<double>::quiet_NaN()),
                    settings.is_muted_.pick(1, 0, 2));
        }
    }

    return TRUE;
}

gboolean dbusmethod_mixer_set(tdbusmixerVolume *object,
                              GDBusMethodInvocation *invocation,
                              guint16 id, gdouble volume, gboolean is_muted,
                              gpointer user_data)
{
    LOGGED_LOCK_CONTEXT_HINT;
    switch(Mixer::VolumeControls::get_singleton().first->request(id, volume, is_muted))
    {
      case Mixer::VolumeControls::Result::OK:
      case Mixer::VolumeControls::Result::IGNORED:
        tdbus_mixer_volume_complete_set(object, invocation);
        break;

      case Mixer::VolumeControls::Result::UNKNOWN_ID:
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                              "Cannot set unknown control ID %u",
                                              id);
        break;
    }

    return TRUE;
}

gboolean dbusmethod_mixer_get(tdbusmixerVolume *object,
                              GDBusMethodInvocation *invocation,
                              guint16 id, gpointer user_data)
{
    const Mixer::VolumeSettings *values;

    LOGGED_LOCK_CONTEXT_HINT;
    switch(Mixer::VolumeControls::get_singleton().first->get_current_values(id, values))
    {
      case Mixer::VolumeControls::Result::OK:
        if(values->volume_.is_known() && values->is_muted_.is_known())
            tdbus_mixer_volume_complete_get(object, invocation,
                                            values->volume_.get(std::numeric_limits<double>::quiet_NaN()),
                                            values->is_muted_.pick(1, 0 ,2));
        else
            g_dbus_method_invocation_return_error(invocation,
                                                  G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                                  "Values for control ID %u not known",
                                                  id);

        break;

      case Mixer::VolumeControls::Result::IGNORED:
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                              "Failed getting values for control ID %u",
                                              id);
        break;

      case Mixer::VolumeControls::Result::UNKNOWN_ID:
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                              "Cannot get values for unknown control ID %u",
                                              id);
        break;
    }

    return TRUE;
}

gboolean dbusmethod_appliance_request_power_state_change(tdbusappliancePower *object,
                                                         GDBusMethodInvocation *invocation,
                                                         guchar state, gpointer user_data)
{
    uint8_t current_state;
    bool is_request_pending;

    if(Regs::Appliance::request_standby_state(state, current_state, is_request_pending))
        tdbus_appliance_power_complete_request_state(object, invocation,
                                                     current_state, is_request_pending);
    else
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                              "Invalid power state %u requested",
                                              state);

    return TRUE;
}

gboolean dbusmethod_appliance_get_power_state(tdbusappliancePower *object,
                                              GDBusMethodInvocation *invocation,
                                              gpointer user_data)
{
    tdbus_appliance_power_complete_get_state(object, invocation,
                                             Regs::Appliance::get_standby_state_for_dbus());
    return TRUE;
}

void dbussignal_airable(GDBusProxy *proxy, const gchar *sender_name,
                        const gchar *signal_name, GVariant *parameters,
                        gpointer user_data)
{
    static const char iface_name[] = "de.tahifi.Airable";

    if(strcmp(signal_name, "ExternalServiceLoginStatus") == 0)
    {
        check_parameter_assertions(parameters, 5);

        const gchar *service_id;
        const gchar *info;
        uint8_t actor_id;
        gboolean is_login;
        guchar raw_error_code;

        g_variant_get(parameters, "(&syby&s)",
                      &service_id, &actor_id, &is_login,
                      &raw_error_code, &info);

        if(raw_error_code == 0)
            Regs::AudioSources::set_login_state(service_id, is_login);

        if(actor_id != ACTOR_ID_SMARTPHONE_APP && raw_error_code == 0)
        {
            auto *data = static_cast<Applink::AppConnections *>(user_data);
            log_assert(data != nullptr);

            if(is_login)
                Applink::send_airable_service_logged_in(*data, service_id, info);
            else
                Applink::send_airable_service_logged_out(*data, service_id, info);
        }
        else
        {
            /* ignore silently, not interesting at the moment */
        }
    }
    else
        unknown_signal(iface_name, signal_name, sender_name);
}

void dbussignal_artcache_monitor(GDBusProxy *proxy, const gchar *sender_name,
                                 const gchar *signal_name, GVariant *parameters,
                                 gpointer user_data)
{
    static const char iface_name[] = "de.tahifi.ArtCache.Monitor";
    auto &regs(*static_cast<Regs::PlayStream::StreamingRegistersIface *>(user_data));

    if(strcmp(signal_name, "Associated") == 0)
        check_parameter_assertions(parameters, 2);
    else if(strcmp(signal_name, "Removed") == 0)
    {
        check_parameter_assertions(parameters, 1);
        regs.cover_art_notification(g_variant_get_child_value(parameters, 0));
    }
    else if(strcmp(signal_name, "Added") == 0)
    {
        check_parameter_assertions(parameters, 3);

        GVariant *stream_key_variant = NULL;
        uint8_t stream_key_priority;
        gboolean is_updated;

        g_variant_get(parameters, "(@ayyb)",
                      &stream_key_variant, &stream_key_priority, &is_updated);

        if(is_updated)
            regs.cover_art_notification(stream_key_variant);
        else
            g_variant_unref(stream_key_variant);
    }
    else if(strcmp(signal_name, "Failed") == 0)
    {
        check_parameter_assertions(parameters, 3);
        regs.cover_art_notification(g_variant_get_child_value(parameters, 0));
    }
    else
        unknown_signal(iface_name, signal_name, sender_name);
}

gboolean dbusmethod_configproxy_register(tdbusConfigurationProxy *object,
                                         GDBusMethodInvocation *invocation,
                                         const gchar *id, const gchar *path,
                                         void *user_data)
{
    const char *dest =
        g_dbus_message_get_sender(g_dbus_method_invocation_get_message(invocation));

    if(configproxy_register_configuration_owner(id, dest, path))
        tdbus_configuration_proxy_complete_register(object, invocation);
    else
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                              "Failed registering configuration owner \"%s\"",
                                              id);

    return TRUE;
}

static enum MessageVerboseLevel do_set_debug_level(const char *new_level_name,
                                                   bool must_be_proper_name)
{
    static enum MessageVerboseLevel default_level = MESSAGE_LEVEL_IMPOSSIBLE;

    if(default_level == MESSAGE_LEVEL_IMPOSSIBLE)
        default_level = msg_get_verbose_level();

    enum MessageVerboseLevel old_level = msg_get_verbose_level();
    enum MessageVerboseLevel new_level;

    if(new_level_name == NULL || new_level_name[0] == '\0')
    {
        if(must_be_proper_name)
            new_level = old_level = MESSAGE_LEVEL_IMPOSSIBLE;
        else
        {
            new_level = old_level;
            new_level_name = msg_verbose_level_to_level_name(new_level);
        }
    }
    else if(strcmp(new_level_name, "default") == 0)
    {
        new_level = default_level;
        new_level_name = msg_verbose_level_to_level_name(new_level);
    }
    else
    {
        new_level = msg_verbose_level_name_to_level(new_level_name);

        if(new_level == MESSAGE_LEVEL_IMPOSSIBLE)
            old_level = MESSAGE_LEVEL_IMPOSSIBLE;
    }

    if(new_level != old_level)
    {
        msg_vinfo(MESSAGE_LEVEL_INFO_MIN,
                  "Set debug level \"%s\"", new_level_name);
        msg_set_verbose_level(new_level);
    }
    else if(old_level == MESSAGE_LEVEL_IMPOSSIBLE)
        msg_error(0, LOG_ERR, "Log level \"%s\" invalid", new_level_name);

    return old_level;
}

gboolean dbusmethod_debug_logging_debug_level(tdbusdebugLogging *object,
                                              GDBusMethodInvocation *invocation,
                                              const gchar *arg_new_level,
                                              void *user_data)
{
    const enum MessageVerboseLevel old_level =
        do_set_debug_level(arg_new_level, false);
    const char *name = msg_verbose_level_to_level_name(old_level);

    if(name == NULL)
        name = "";

    tdbus_debug_logging_complete_debug_level(object, invocation, name);

    return TRUE;
}

gboolean dbusmethod_debug_logging_config_set_level(tdbusdebugLoggingConfig *object,
                                                   GDBusMethodInvocation *invocation,
                                                   const gchar *arg_new_level,
                                                   void *user_data)
{
    const enum MessageVerboseLevel old_level =
        do_set_debug_level(arg_new_level, true);

    tdbus_debug_logging_config_complete_set_global_debug_level(object, invocation);

    if(old_level != MESSAGE_LEVEL_IMPOSSIBLE)
        tdbus_debug_logging_config_emit_global_debug_level_changed(object,
                                                                   arg_new_level);

    return TRUE;
}

bool handle_audiopath_json_request(GDBusMethodInvocation *invocation,
                                   const char *json, const char *const *extra,
                                   std::string *result)
{
    Json::Value request;
    if(!parse_json_from_buffer(invocation, request, json, strlen(json),
                               "audio path configuration request"))
        return false;

    const auto &q(request["query"]);
    if(!q.isNull())
    {
        const auto &what(q["what"]);
        if(what.isNull() || !what.isString())
        {
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
                "Invalid audio path configuration query");
            return false;
        }

        if(what == "full_audio_signal_path")
        {
            Regs::AudioPaths::request_full_from_appliance();

            if(result != nullptr)
                *result = "{\"result\":\"ok\"}";

            return true;
        }
        else
        {
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
                "Unknown audio path configuration query \"%s\"", what.asCString());
            return false;
        }
    }
    else
    {
        g_dbus_method_invocation_return_error(
            invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
            "Malformed audio path configuration request");
        return false;
    }
}

gboolean dbusmethod_audiopath_jsonreceiver_notify(tdbusJSONReceiver *object,
                                                  GDBusMethodInvocation *invocation,
                                                  const gchar *json,
                                                  const gchar *const *extra,
                                                  gpointer user_data)
{
    if(handle_audiopath_json_request(invocation, json, extra, nullptr))
        tdbus_jsonreceiver_complete_notify(object, invocation);

    return TRUE;
}

gboolean dbusmethod_audiopath_jsonreceiver_tell(tdbusJSONReceiver *object,
                                                GDBusMethodInvocation *invocation,
                                                const gchar *json,
                                                const gchar *const *extra,
                                                gpointer user_data)
{
    std::string result;

    if(handle_audiopath_json_request(invocation, json, extra, &result))
        tdbus_jsonreceiver_complete_tell(object, invocation,
                                         result.c_str(), extra);

    return TRUE;
}

void dbussignal_gerbera(GDBusProxy *proxy, const gchar *sender_name,
                        const gchar *signal_name, GVariant *parameters,
                        gpointer user_data)
{
    static const char iface_name[] = "io.gerbera.ContentManager";

    if(strcmp(signal_name, "BusyChangedTo") == 0)
    {
        check_parameter_assertions(parameters, 1);

        GVariant *val = g_variant_get_child_value(parameters, 0);
        gboolean is_busy = g_variant_get_boolean(val);
        g_variant_unref(val);

        Regs::UPnPServer::set_busy_state(is_busy);
    }
    else
        unknown_signal(iface_name, signal_name, sender_name);
}
