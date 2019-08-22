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

#include "connman_technology_registry.hh"
#include "net_connman.h"
#include "connman_address.hh"
#include "dbus_common.h"
#include "dbus_iface_deep.h"
#include "mainloop.hh"
#include "gvariantwrapper.hh"
#include "messages.h"

#include <tuple>

namespace Connman
{

const std::array<const std::string, size_t(TechnologyPropertiesWIFI::Property::LAST_PROPERTY) + 1>
TechnologyPropertiesWIFI::Containers::keys
{
    "Powered",
    "Connected",
    "Name",
    "Type",
    "Tethering",
    "TetheringIdentifier",
    "TetheringPassphrase",
};

template <>
void TechnologyPropertiesWIFI::send_property_over_dbus<bool>(Property key, const bool &value)
{
    GVariant *v = g_variant_new("v", g_variant_new("b", value));
    tdbus_connman_technology_call_set_property(
            proxy_, Containers::keys[size_t(key)].c_str(), v, nullptr,
            send_property_over_dbus_done<bool>,
            new std::tuple<TechnologyPropertiesWIFI *, TechnologyPropertiesWIFI::Property>(this, key));
}

template <>
void TechnologyPropertiesWIFI::send_property_over_dbus<std::string>(Property key, const std::string &value)
{
    GVariant *v = g_variant_new("v", g_variant_new("s", value.c_str()));
    tdbus_connman_technology_call_set_property(
            proxy_, Containers::keys[size_t(key)].c_str(), v, nullptr,
            send_property_over_dbus_done<std::string>,
            new std::tuple<TechnologyPropertiesWIFI *, TechnologyPropertiesWIFI::Property>(this, key));
}

}

Connman::TechnologyPropertiesWIFI::~TechnologyPropertiesWIFI()
{
    if(proxy_ != nullptr)
        g_object_unref(proxy_);
}

bool Connman::TechnologyPropertiesWIFI::ensure_dbus_proxy()
{
    if(proxy_ == nullptr && !dbus_object_path_.empty())
        proxy_ = dbus_new_connman_technology_proxy_for_object_path(
                        dbus_object_path_.c_str(),
                        G_CALLBACK(dbus_signal_trampoline), this);

    return proxy_ != nullptr;
}

static bool cache_value(Connman::TechnologyPropertiesWIFI &props,
                        const char *key, GVariant *value, const char *failed_at)
{
    const auto *ptype = g_variant_get_type(value);

    try
    {
        if(g_variant_type_equal(ptype, G_VARIANT_TYPE_BOOLEAN))
            props.cache_value_by_name<bool>(key, g_variant_get_boolean(value));
        else if(g_variant_type_equal(ptype, G_VARIANT_TYPE_STRING))
            props.cache_value_by_name<std::string>(key, std::string(g_variant_get_string(value, nullptr)));
        else
        {
            msg_error(EINVAL, LOG_NOTICE,
                      "Wifi property \"%s\" has unsupported type (%s)",
                      key, failed_at);
            return false;
        }
    }
    catch(const Connman::TechnologyPropertiesWIFI::Exceptions::PropertyUnknown &e)
    {
        msg_error(EINVAL, LOG_NOTICE,
                  "Wifi property \"%s\" not supported (%s)", key, failed_at);
        return false;
    }

    return true;
}

void Connman::TechnologyPropertiesWIFI::technology_signal(
        GDBusProxy *proxy, const char *sender_name, const char *signal_name,
        GVariant *parameters)
{
    static const char iface_name[] = "net.connman.Technology";

    if(strcmp(signal_name, "PropertyChanged") == 0)
    {
        const char *key;
        GVariant *temp;
        g_variant_get(parameters, "(&sv)", &key, &temp);
        GVariantWrapper value(temp, GVariantWrapper::Transfer::JUST_MOVE);
        cache_value(*this, key, GVariantWrapper::get(value), "signal");
    }
    else
        msg_error(ENOSYS, LOG_NOTICE, "Got unknown signal %s.%s from %s",
                  iface_name, signal_name, sender_name);
}

void Connman::TechnologyPropertiesWIFI::notify_watchers(Property property, StoreResult result)
{
    MainLoop::post(
        [this, property, result] ()
        {
            LOGGED_LOCK_CONTEXT_HINT;
            std::lock_guard<LoggedLock::Mutex> lock(watchers_lock_);

            for(const auto &fn : watchers_)
                fn(property, result, *this);
        });
}

void Connman::TechnologyPropertiesWIFI::set_dbus_object_path(std::string &&path)
{
    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::RecMutex> lock(lock_);

    if(proxy_ != nullptr)
    {
        g_object_unref(proxy_);
        proxy_ = nullptr;
    }

    dbus_object_path_ = std::move(path);
    ensure_dbus_proxy();
}

tdbusconnmanTechnology *Connman::TechnologyPropertiesWIFI::get_dbus_proxy()
{
    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::RecMutex> lock(lock_);
    ensure_dbus_proxy();
    return proxy_;
}

void Connman::TechnologyPropertiesWIFI::register_property_watcher(WatcherFn &&fn)
{
    if(fn != nullptr)
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(watchers_lock_);
        watchers_.emplace_back(fn);
    }
}

/*
 * GLib callback in D-Bus context
 */
template <typename T>
void Connman::TechnologyPropertiesWIFI::send_property_over_dbus_done(
        GObject *source_object, GAsyncResult *res, void *user_data)
{
    auto *data = static_cast<std::tuple<TechnologyPropertiesWIFI *,
                                        TechnologyPropertiesWIFI::Property> *>(user_data);
    TechnologyPropertiesWIFI *props;
    TechnologyPropertiesWIFI::Property property;
    std::tie(props, property) = *data;

    GError *error = nullptr;
    tdbus_connman_technology_call_set_property_finish(TDBUS_CONNMAN_TECHNOLOGY(source_object),
                                                      res, &error);

    props->Connman::TechnologyPropertiesWIFI::handle_send_property_over_dbus_done<T>(
            property,
            dbus_common_handle_dbus_error(&error, "Set Connman technology property") < 0);

    delete data;
}

static bool enumerate_technologies(tdbusconnmanManager *iface,
                                   const std::function<void(const char *, GVariantIter *)> &apply)
{
    if(iface == nullptr)
        return false;

    GVariant *temp = nullptr;
    GError *error = nullptr;
    tdbus_connman_manager_call_get_technologies_sync(iface, &temp,
                                                     nullptr, &error);
    (void)dbus_common_handle_dbus_error(&error, "Get network technologies");
    GVariantWrapper technologies(temp);

    if(technologies == nullptr)
    {
        msg_error(0, LOG_CRIT, "Failed getting technologies from Connman");
        return false;
    }

    GVariantIter iter;
    g_variant_iter_init(&iter, GVariantWrapper::get(technologies));
    const char *object_path;
    GVariantIter *properties;

    while(g_variant_iter_loop(&iter, "(oa{sv})", &object_path, &properties))
        apply(object_path, properties);

    return true;
}

static Connman::Technology determine_technology_from_tech_properties(GVariantIter *iter)
{
    const char *key;
    GVariant *value;

    while(g_variant_iter_loop(iter, "{sv}", &key, &value))
    {
        if(strcmp(key, "Type") != 0)
            continue;

        GVariantWrapper cleanup(value, GVariantWrapper::Transfer::JUST_MOVE);
        const char *t;
        g_variant_get(value, "&s", &t);

        if(strcmp(t, "ethernet") == 0)
            return Connman::Technology::ETHERNET;
        else if(strcmp(t, "wifi") == 0)
            return Connman::Technology::WLAN;

        break;
    }

    return Connman::Technology::UNKNOWN_TECHNOLOGY;
}

static void init_wifi_properties(Connman::TechnologyPropertiesWIFI &props,
                                 const char *object_path, GVariantIter *iter)
{
    props.set_dbus_object_path(object_path);

    const char *key;
    GVariant *value;

    while(g_variant_iter_loop(iter, "{sv}", &key, &value))
        cache_value(props, key, value, "preset");
}

void Connman::TechnologyRegistry::connect_to_connman(const void *data)
{
    enumerate_technologies(dbus_get_connman_manager_iface(),
        [this]
        (const char *object_path, GVariantIter *properties)
        {
            GVariantIter temp = *properties;

            switch(determine_technology_from_tech_properties(&temp))
            {
              case Technology::UNKNOWN_TECHNOLOGY:
              case Technology::ETHERNET:
                break;

              case Technology::WLAN:
                init_wifi_properties(wifi_properties_, object_path, properties);
                break;
            }
        });
}
