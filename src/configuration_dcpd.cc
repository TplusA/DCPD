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

#include <algorithm>
#include <glib.h>

#include "configuration_dcpd.hh"
#include "configuration_dcpd.h"
#include "configproxy.h"
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

class ConfigurationData
{
  public:
    Configuration::ConfigManager<Configuration::ApplianceValues> *cm;

    ConfigurationData(const ConfigurationData &) = delete;
    ConfigurationData &operator=(const ConfigurationData &) = delete;

    explicit ConfigurationData():
        cm(nullptr)
    {}
};

static ConfigurationData configuration_data;

static bool is_key_ours(const char *key, const char *our_key, size_t our_key_length)
{
    const size_t key_length(strlen(key));

    auto beyond_database(std::find(key, key + key_length, ':'));
    const size_t database_name_length(beyond_database - key);

    if(database_name_length >= key_length)
        return false;

    auto beyond_section(std::find(beyond_database + 1, key + key_length, ':'));

    if(beyond_section >= key + key_length)
        return false;

    if(database_name_length != our_key_length)
        return false;

    return strncmp(our_key, key, our_key_length) == 0;
}

bool configuration_set_key(const char *origin, const char *key, GVariant *value)
{
    log_assert(g_variant_n_children(value) == 1);

    GVariantWrapper top_level(value);
    GVariantWrapper v(g_variant_get_child_value(GVariantWrapper::get(top_level), 0),
                      GVariantWrapper::Transfer::JUST_MOVE);

    if(!is_key_ours(key, configuration_data.cm->get_database_name(),
                    strlen(configuration_data.cm->get_database_name())))
    {
        BUG("Attempted to set foreign key %s by %s", key, origin);
        return false;
    }

    auto scope(configuration_data.cm->get_update_scope(origin));
    int err = 0;

    switch(scope().insert_boxed(key, std::move(v)))
    {
      case Configuration::InsertResult::UPDATED:
      case Configuration::InsertResult::UNCHANGED:
        return true;

      case Configuration::InsertResult::KEY_UNKNOWN:
        err = ENOKEY;
        break;

      case Configuration::InsertResult::VALUE_TYPE_INVALID:
        err = EDOM;
        break;

      case Configuration::InsertResult::VALUE_INVALID:
        err = EINVAL;
        break;

      case Configuration::InsertResult::PERMISSION_DENIED:
        err = EPERM;
        break;
    }

    if(err != 0)
        msg_error(err, LOG_NOTICE,
                  "Setting key %s by %s not possible", key, origin);

    return false;
}

GVariant *configuration_get_key(const char *key)
{
    if(!is_key_ours(key, configuration_data.cm->get_database_name(),
                    strlen(configuration_data.cm->get_database_name())))
    {
        msg_error(0, LOG_NOTICE,
                  "Attempted to read out foreign key %s", key);
        return nullptr;
    }

    auto value = configuration_data.cm->lookup_boxed(key);

    return (value != nullptr) ? GVariantWrapper::move(value) : nullptr;
}

static void notify_config_changed(const char *origin,
                                  const std::array<bool, Configuration::ApplianceValues::NUMBER_OF_KEYS> &changed)
{
    std::vector<const char *> vec;

    for(size_t i = 0; i < changed.size(); ++i)
    {
        if(changed[i])
            vec.push_back(Configuration::ApplianceValues::all_keys[i].name_.c_str());
    }

    if(!vec.empty())
    {
        vec.push_back(nullptr);
        configproxy_notify_configuration_changed(origin, vec.data());
    }
}

void Configuration::register_configuration_manager(ConfigManager<ApplianceValues> &cm)
{
    /* FIXME: The configuration manager needs to be implemented by inheritance,
     *        otherwise we'll not be able to add more than a single
     *        configuration manager at a time. There is too much unnecessary
     *        TMP involved. */
    configuration_data.cm = &cm;
    configuration_data.cm->set_updated_notification_callback(notify_config_changed);
}

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
