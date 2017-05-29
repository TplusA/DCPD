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

#ifndef CONFIGURATION_DCPD_HH
#define CONFIGURATION_DCPD_HH

#include <string>
#include <functional>

#include "configuration.hh"
#include "configuration_settings.hh"

namespace Configuration
{

class ConfigKey;

struct ApplianceValues
{
    static constexpr char OWNER_NAME[] = "dcpd";
    static constexpr char DATABASE_NAME[] = "appliance";
    static constexpr char CONFIGURATION_SECTION_NAME[] = "appliance";

    enum class KeyID
    {
        APPLIANCE_NAME,

        LAST_ID = APPLIANCE_NAME,
    };

    static constexpr size_t NUMBER_OF_KEYS = static_cast<size_t>(KeyID::LAST_ID) + 1;

    static const std::array<const ConfigKey, NUMBER_OF_KEYS> all_keys;

    std::string appliance_name_;

    ApplianceValues() {}

    explicit ApplianceValues(std::string &&appliance_name):
        appliance_name_(std::move(appliance_name))
    {}
};

class ConfigKey: public ConfigKeyBase<ApplianceValues>
{
  private:
    const Serializer serialize_;
    const Deserializer deserialize_;
    const Boxer boxer_;
    const Unboxer unboxer_;

  public:
    explicit ConfigKey(ApplianceValues::KeyID id, const char *name,
                       Serializer &&serializer, Deserializer &&deserializer,
                       Boxer &&boxer, Unboxer &&unboxer):
        ConfigKeyBase(id, name, find_varname_offset_in_keyname(name)),
        serialize_(std::move(serializer)),
        deserialize_(std::move(deserializer)),
        boxer_(std::move(boxer)),
        unboxer_(std::move(unboxer))
    {}

    void read(char *dest, size_t dest_size, const ApplianceValues &src) const final override
    {
        serialize_(dest, dest_size, src);
    }

    bool write(ApplianceValues &dest, const char *src) const final override
    {
        return deserialize_(dest, src);
    }

    GVariantWrapper box(const ApplianceValues &src) const final override
    {
        return boxer_(src);
    }

    InsertResult unbox(UpdateSettings<ApplianceValues> &dest, GVariantWrapper &&src) const final override
    {
        return unboxer_(dest, std::move(src));
    }
};

template <ApplianceValues::KeyID ID> struct UpdateTraits;

CONFIGURATION_UPDATE_TRAITS(UpdateTraits, ApplianceValues, APPLIANCE_NAME, appliance_name_);

template <>
class UpdateSettings<ApplianceValues>
{
  private:
    Settings<ApplianceValues> &settings_;

  public:
    UpdateSettings(const UpdateSettings &) = delete;
    UpdateSettings &operator=(const UpdateSettings &) = delete;

    constexpr explicit UpdateSettings<ApplianceValues>(Settings<ApplianceValues> &settings):
        settings_(settings)
    {}

    InsertResult insert_boxed(const char *key, GVariantWrapper &&value);

    bool appliance_name(const std::string &name)
    {
        return settings_.update<ApplianceValues::KeyID::APPLIANCE_NAME,
                                UpdateTraits<ApplianceValues::KeyID::APPLIANCE_NAME>>(name);
    }
};

void register_configuration_manager(ConfigManager<ApplianceValues> &cm);

}

#endif /* !CONFIGURATION_DCPD_HH */