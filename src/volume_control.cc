/*
 * Copyright (C) 2017, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#include "volume_control.hh"
#include "dcpregs_volume.hh"
#include "registers_priv.hh"
#include "dbus_iface_deep.h"
#include "fixpoint.hh"
#include "messages.h"

#include <algorithm>

enum class Subcommand
{
    SET_VOLUME_LEVEL_AND_MUTE_STATE,
    CONFIGURE_VOLUME_CONTROL,
    CLEAR_VOLUME_CONTROL,

    LAST_COMMAND = CLEAR_VOLUME_CONTROL,
};

static double clamp(const Mixer::VolumeControlProperties &properties,
                    double volume)
{
    if(std::isnan(volume))
        return volume;

    if(volume < properties.volume_min_)
        return properties.volume_min_;
    else if(volume > properties.volume_max_)
        return properties.volume_max_;
    else
        return volume;
}

int Regs::ApplianceVolumeControl::DCP::write_64_volume_control(const uint8_t *data, size_t length)
{
    if(length == 0)
        return -1;

    if(data[0] > int(Subcommand::LAST_COMMAND))
    {
        msg_error(EINVAL, LOG_NOTICE,
                  "Invalid volume control subcommand 0x%02x", data[0]);
        return -1;
    }

    LOGGED_LOCK_CONTEXT_HINT;
    auto controls(Mixer::VolumeControls::get_singleton());
    auto master_id = controls.first->get_master_id();

    if(master_id == Mixer::VolumeControls::INVALID_CONTROL_ID)
    {
        msg_error(0, LOG_NOTICE, "No master volume control present");
        return -1;
    }

    const uint8_t *params = &data[1];
    const size_t params_length = length - 1;

    switch(Subcommand(data[0]))
    {
      case Subcommand::SET_VOLUME_LEVEL_AND_MUTE_STATE:
        {
            const FixPoint volume(params, params_length);

            if(volume.is_nan())
            {
                msg_error(EINVAL, LOG_NOTICE, "Invalid volume control values");
                break;
            }

            switch(controls.first->set_values(master_id, volume.to_double(),
                                              (params[0] & (1U << 7)) != 0))
            {
              case Mixer::VolumeControls::Result::OK:
              case Mixer::VolumeControls::Result::IGNORED:
                return 0;

              case Mixer::VolumeControls::Result::UNKNOWN_ID:
                break;
            }
        }

        break;

      case Subcommand::CONFIGURE_VOLUME_CONTROL:
        {
            if(params_length < 14)
                break;

            const FixPoint volume_min_fp(params + 1, params_length - 1);
            const FixPoint volume_max_fp(params + 3, params_length - 3);
            const FixPoint volume_step_fp(params + 5, params_length - 5);
            const FixPoint db_min_fp(params + 7, params_length - 7);
            const FixPoint db_max_fp(params + 9, params_length - 9);
            const FixPoint volume_level(params + 11, params_length - 11);
            const double volume_step(volume_step_fp.to_double());

            if(params[0] > int(Mixer::VolumeScale::LAST_SCALE) ||
               volume_min_fp.is_nan() || volume_max_fp.is_nan() ||
               volume_step_fp.is_nan() ||
               (volume_step <= 0.0 && volume_step >= 0.0))
            {
                msg_error(EINVAL, LOG_NOTICE, "Invalid volume control configuration");
                break;
            }

            auto properties = std::make_unique<Mixer::VolumeControlProperties>(
                    "Master", Mixer::VolumeScale(params[0]),
                    volume_min_fp.to_double(), volume_max_fp.to_double(),
                    volume_step, db_min_fp.to_double(), db_max_fp.to_double());

            if(properties == nullptr)
            {
                msg_out_of_memory("volume control properties");
                break;
            }

            const double clamped_volume_level = clamp(*properties, volume_level.to_double());

            controls.first->replace_control_properties(master_id, std::move(properties),
                                                       volume_level.is_nan()
                                                       ? Maybe<double>()
                                                       : Maybe<double>(clamped_volume_level),
                                                       params[13] > 1
                                                       ? Maybe<bool>()
                                                       : Maybe<bool>(params[13] != 0));

            return 0;
        }

        break;

      case Subcommand::CLEAR_VOLUME_CONTROL:
        controls.first->replace_control_properties(master_id, nullptr,
                                                   Maybe<double>(), Maybe<bool>());
        return 0;
    }

    return -1;
}

ssize_t Regs::ApplianceVolumeControl::DCP::read_64_volume_control(uint8_t *response, size_t length)
{
    if(length < 2)
        return -1;

    LOGGED_LOCK_CONTEXT_HINT;
    auto controls(Mixer::VolumeControls::get_singleton());
    auto *master = controls.first->get_master();

    if(master == nullptr)
    {
        msg_error(0, LOG_NOTICE, "No master volume control configured");
        return -1;
    }

    const auto &req(master->get_request());

    if(!req.volume_.is_known() || !req.is_muted_.is_known())
    {
        BUG("No active volume request");
        return 0;
    }

    const FixPoint volume(req.volume_.get());

    volume.to_buffer(response, 2);

    if(req.is_muted_ == true)
        response[0] |= 1U << 7;

    msg_vinfo(MESSAGE_LEVEL_NORMAL,
              "Requesting appliance volume change: level %f (%f), %smuted",
              volume.to_double(), req.volume_.get(),
              req.is_muted_ == true ? "" : "not ");

    return 2;
}

const Mixer::VolumeControlProperties *
Mixer::VolumeControl::set_properties(std::unique_ptr<Mixer::VolumeControlProperties> properties,
                                     Maybe<double> &&initial_volume_level,
                                     Maybe<bool> &&initial_mute_state)
{
    control_properties_ = std::move(properties);
    requested_.reset();

    if(control_properties_ == nullptr)
        appliance_settings_.reset();
    else
    {
        appliance_settings_.volume_ = std::move(initial_volume_level);
        appliance_settings_.is_muted_ = std::move(initial_mute_state);
    }

    return control_properties_.get();
}

bool Mixer::VolumeControl::set_new_values(double volume, bool is_muted)
{
    if(control_properties_ == nullptr)
    {
        msg_error(0, LOG_ERR,
                  "Ignoring volume report for unconfigured volume control");
        return false;
    }

    appliance_settings_.volume_ = clamp(*control_properties_, volume);
    appliance_settings_.is_muted_ = is_muted;

    tdbus_mixer_volume_emit_updated(dbus_mixer_get_volume_iface(), id_,
                                    appliance_settings_.volume_.get(std::numeric_limits<double>::quiet_NaN()),
                                    appliance_settings_.is_muted_.pick(1, 0, 2));

    return true;
}

bool Mixer::VolumeControl::set_request(double volume, bool is_muted)
{
    if(control_properties_ == nullptr)
        return false;

    requested_.volume_ = clamp(*control_properties_, volume);
    requested_.is_muted_ = is_muted;

    Regs::get_data().register_changed_notification_fn(64);

    return true;
}

static inline bool is_invalid_id(uint16_t id)
{
    return id == Mixer::VolumeControls::INVALID_CONTROL_ID;
}

std::unique_ptr<Mixer::VolumeControl> &
internal_lookup(std::vector<std::unique_ptr<Mixer::VolumeControl>> &controls,
                uint16_t id)
{
    if(is_invalid_id(id))
        throw std::out_of_range("Invalid volume control ID");

    const auto it(std::find_if(controls.begin(), controls.end(),
                               [id] (const std::unique_ptr<Mixer::VolumeControl> &ctrl)
                               {
                                   return ctrl != nullptr && ctrl->id_ == id;
                               }));

    if(it == controls.end())
        throw std::out_of_range("Volume control does not exist");

    log_assert(*it != nullptr);

    return *it;
}

const Mixer::VolumeControl *Mixer::VolumeControls::lookup(uint16_t id) const
{
    return internal_lookup(const_cast<Mixer::VolumeControls *>(this)->controls_, id).get();
}

std::unique_ptr<Mixer::VolumeControl> &Mixer::VolumeControls::lookup_rw(uint16_t id)
{
    return internal_lookup(controls_, id);
}

Mixer::VolumeControls::VolumeControls(std::unique_ptr<VolumeControl> predefined_master)
{
    LoggedLock::configure(lock_, "Mixer::VolumeControls", MESSAGE_LEVEL_DEBUG);
    if(predefined_master != nullptr)
        controls_.emplace_back(std::move(predefined_master));
}

Mixer::VolumeControls::Result
Mixer::VolumeControls::replace_control_properties(uint16_t id,
        std::unique_ptr<Mixer::VolumeControlProperties> properties,
        Maybe<double> &&initial_volume_level, Maybe<bool> &&initial_mute_state)
{
    try
    {
        auto &ctrl = lookup_rw(id);
        const bool changed = ctrl->get_properties() != properties.get();

        if(!changed)
            return Mixer::VolumeControls::Result::IGNORED;

        const bool is_first_initialization = (ctrl->get_properties() == nullptr);
        const auto *const props =
            ctrl->set_properties(std::move(properties),
                                 std::move(initial_volume_level),
                                 std::move(initial_mute_state));

        static const char log_prefix[] = "Volume control configuration: ";

        if(props != nullptr)
        {
            const VolumeSettings &settings(ctrl->get_settings());

            msg_vinfo(MESSAGE_LEVEL_NORMAL, "%sRange %f...%f, step width %f, "
                      "scale \"%s\", dynamic range %f...%f",
                      log_prefix, props->volume_min_, props->volume_max_,
                      props->volume_step_, scale_to_string(props->scale_),
                      props->min_db_, props->max_db_);
            msg_vinfo(MESSAGE_LEVEL_NORMAL,
                      "%sInitial volume level %f, %smuted",
                      log_prefix,
                      settings.volume_.get(std::numeric_limits<double>::quiet_NaN()),
                      settings.is_muted_.pick(static_cast<const char *>(""),
                                              static_cast<const char *>("not "),
                                              static_cast<const char *>("maybe ")));

            tdbus_mixer_volume_emit_control_changed(dbus_mixer_get_volume_iface(),
                                                    is_first_initialization ? UINT16_MAX : id,
                                                    ctrl->id_, props->name_.c_str(),
                                                    scale_to_string(props->scale_),
                                                    props->volume_min_, props->volume_max_,
                                                    props->volume_step_,
                                                    props->min_db_, props->max_db_,
                                                    settings.volume_.get(std::numeric_limits<double>::quiet_NaN()),
                                                    settings.is_muted_.pick(1, 0, 2));
        }
        else
        {
            msg_vinfo(MESSAGE_LEVEL_NORMAL, "%sREMOVED", log_prefix);
            tdbus_mixer_volume_emit_control_changed(dbus_mixer_get_volume_iface(),
                                                    id, UINT16_MAX, "", "",
                                                    0.0, 0.0, 0.0, 0.0, 0.0,
                                                    std::numeric_limits<double>::quiet_NaN(), 2);
        }

        return Mixer::VolumeControls::Result::OK;
    }
    catch(const std::out_of_range &e)
    {
        msg_error(0, LOG_ERR, "Exception: %s", e.what());;
        return Mixer::VolumeControls::Result::UNKNOWN_ID;
    }
}

Mixer::VolumeControls::Result
Mixer::VolumeControls::set_values(uint16_t id, double volume, bool is_muted)
{
    msg_vinfo(MESSAGE_LEVEL_NORMAL,
              "Appliance volume report: level %f, %smuted",
              volume, is_muted ? "" : "not ");

    try
    {
        auto &ctrl = lookup_rw(id);

        if(ctrl->set_new_values(volume, is_muted))
            return Mixer::VolumeControls::Result::OK;
        else
            return Mixer::VolumeControls::Result::IGNORED;
    }
    catch(const std::out_of_range &e)
    {
        msg_error(0, LOG_ERR, "Exception: %s", e.what());;
        return Mixer::VolumeControls::Result::UNKNOWN_ID;
    }
}

Mixer::VolumeControls::Result
Mixer::VolumeControls::request(uint16_t id, double volume, bool is_muted)
{
    try
    {
        auto &ctrl = lookup_rw(id);

        if(ctrl->set_request(volume, is_muted))
            return Mixer::VolumeControls::Result::OK;
        else
            return Mixer::VolumeControls::Result::IGNORED;
    }
    catch(const std::out_of_range &e)
    {
        msg_error(0, LOG_ERR, "Exception: %s", e.what());;
        return Mixer::VolumeControls::Result::UNKNOWN_ID;
    }
}

Mixer::VolumeControls::Result
Mixer::VolumeControls::get_current_values(uint16_t id,
                                          const Mixer::VolumeSettings *&values) const
{
    try
    {
        values = &lookup(id)->get_settings();
        return Mixer::VolumeControls::Result::OK;
    }
    catch(const std::out_of_range &e)
    {
        msg_error(0, LOG_ERR, "Exception: %s", e.what());;
        return Mixer::VolumeControls::Result::UNKNOWN_ID;
    }
}

Mixer::VolumeControls::Result
Mixer::VolumeControls::get_requested_values(uint16_t id,
                                            const Mixer::VolumeSettings *&values) const
{
    try
    {
        values = &lookup(id)->get_request();
        return Mixer::VolumeControls::Result::OK;
    }
    catch(const std::out_of_range &e)
    {
        msg_error(0, LOG_ERR, "Exception: %s", e.what());;
        return Mixer::VolumeControls::Result::UNKNOWN_ID;
    }
}

uint16_t Mixer::VolumeControls::get_master_id() const
{
    /* WARNING:
     * This code is wrong for appliances with multiple volume controls. */
    return controls_.empty() ? INVALID_CONTROL_ID : controls_[0]->id_;
}

const Mixer::VolumeControl *Mixer::VolumeControls::get_master() const
{
    /* WARNING:
     * This code is wrong for appliances with multiple volume controls. */
    return controls_.empty() ? nullptr : controls_[0].get();
}

/*!
 * Our volume controls for this appliance.
 *
 * Note that this initialization assumes there is always one master volume
 * control with a predefined ID on any appliance. Its configuration is left
 * undefined here as this is to be set by the appliance via register 64.
 *
 * The presence of this predefined control makes sure that configuration via
 * register 64 is possible at all in the first place. For appliances that can
 * never have any volume control, this predefined control should be removed
 * such that accesses to register 64 can be recognized as an error.
 */
static Mixer::VolumeControls
global_volume_controls(std::make_unique<Mixer::VolumeControl>(1, nullptr));

std::pair<Mixer::VolumeControls *const, LoggedLock::UniqueLock<LoggedLock::Mutex>>
Mixer::VolumeControls::get_singleton()
{
    return std::make_pair(&global_volume_controls,
                          LoggedLock::UniqueLock<LoggedLock::Mutex>(global_volume_controls.lock_));
}
