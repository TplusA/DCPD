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

#include <glib.h>

#include "configuration_dcpd.hh"
#include "dbus_handlers.h"

constexpr char Configuration::ApplianceValues::OWNER_NAME[];
constexpr char Configuration::ApplianceValues::DATABASE_NAME[];
constexpr char Configuration::ApplianceValues::CONFIGURATION_SECTION_NAME[];

static Configuration::InsertResult
unbox_appliance_name(Configuration::UpdateSettings<Configuration::ApplianceValues> &dest,
                     GVariantWrapper &&src)
{
    std::string temp;

    if(!Configuration::default_unbox(temp, std::move(src)))
        return Configuration::InsertResult::VALUE_TYPE_INVALID;

    if(temp.empty())
        return Configuration::InsertResult::VALUE_INVALID;

    if(!dest.appliance_name(temp))
        return Configuration::InsertResult::UNCHANGED;

    return Configuration::InsertResult::UPDATED;
};

const std::array<const Configuration::ConfigKey, Configuration::ApplianceValues::NUMBER_OF_KEYS>
Configuration::ApplianceValues::all_keys
{
#define ENTRY(ID, KEY) \
    Configuration::ConfigKey(Configuration::ApplianceValues::KeyID::ID, \
                             "appliance:appliance:" KEY, \
                             serialize_value<Configuration::ApplianceValues, \
                                             UpdateTraits<Configuration::ApplianceValues::KeyID::ID>>, \
                             deserialize_value<Configuration::ApplianceValues, \
                                               UpdateTraits<Configuration::ApplianceValues::KeyID::ID>>, \
                             box_value<Configuration::ApplianceValues, \
                                       UpdateTraits<Configuration::ApplianceValues::KeyID::ID>>, \
                             unbox_appliance_name)

    ENTRY(APPLIANCE_NAME, "id"),

#undef ENTRY
};

//! \cond Doxygen_Suppress
// Doxygen 1.8.9.1 throws a warning about this.
Configuration::InsertResult
Configuration::UpdateSettings<Configuration::ApplianceValues>::insert_boxed(const char *key,
                                                                            GVariantWrapper &&value)
{
    if(!ConfigManager<ApplianceValues>::to_local_key(key))
        return InsertResult::KEY_UNKNOWN;

    const size_t requested_key_length(strlen(key));

    for(const auto &k : ApplianceValues::all_keys)
    {
        if(k.name_.length() == requested_key_length &&
           strcmp(k.name_.c_str(), key) == 0)
        {
            return k.unbox(*this, std::move(value));
        }
    }

    return InsertResult::KEY_UNKNOWN;
}
//! \endcond

static void enter_config_read_handler(GDBusMethodInvocation *invocation)
{
    static const char iface_name[] = "de.tahifi.Configuration.Read";

    msg_vinfo(MESSAGE_LEVEL_TRACE, "%s method invocation from '%s': %s",
              iface_name, g_dbus_method_invocation_get_sender(invocation),
              g_dbus_method_invocation_get_method_name(invocation));
}

gboolean dbusmethod_config_get_all_keys(tdbusConfigurationRead *object,
                                        GDBusMethodInvocation *invocation,
                                        gpointer user_data)
{
    enter_config_read_handler(invocation);

    auto *cm = static_cast<Configuration::ConfigManager<Configuration::ApplianceValues> *>(user_data);
    log_assert(cm != nullptr);

    auto keys(cm->keys());
    keys.push_back(nullptr);

    tdbus_configuration_read_complete_get_all_keys(object, invocation,
                                                   Configuration::ApplianceValues::OWNER_NAME,
                                                   keys.data());

    return TRUE;
}

gboolean dbusmethod_config_get_value(tdbusConfigurationRead *object,
                                     GDBusMethodInvocation *invocation,
                                     const gchar *key, gpointer user_data)
{
    enter_config_read_handler(invocation);

    auto *cm = static_cast<Configuration::ConfigManager<Configuration::ApplianceValues> *>(user_data);
    log_assert(cm != nullptr);

    auto value = cm->lookup_boxed(key);

    if(value != nullptr)
        tdbus_configuration_read_complete_get_value(object, invocation,
                                                    g_variant_new_variant(GVariantWrapper::move(value)));
    else
        g_dbus_method_invocation_return_error(invocation, G_DBUS_ERROR,
                                              G_DBUS_ERROR_INVALID_ARGS,
                                              "Configuration key \"%s\" unknown",
                                              key);

    return TRUE;
}

gboolean dbusmethod_config_get_all_values(tdbusConfigurationRead *object,
                                          GDBusMethodInvocation *invocation,
                                          const gchar *database, gpointer user_data)
{
    enter_config_read_handler(invocation);

    auto *cm = static_cast<Configuration::ConfigManager<Configuration::ApplianceValues> *>(user_data);
    log_assert(cm != nullptr);

    GVariantDict dict;
    g_variant_dict_init(&dict, nullptr);

    for(const auto &k : cm->keys())
    {
        auto value = cm->lookup_boxed(k);

        if(value != nullptr)
            g_variant_dict_insert_value(&dict, k, GVariantWrapper::move(value));
    }

    tdbus_configuration_read_complete_get_all_values(object, invocation,
                                                     g_variant_dict_end(&dict));

    return TRUE;
}
