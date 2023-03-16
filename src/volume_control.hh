/*
 * Copyright (C) 2017--2020, 2023  T+A elektroakustik GmbH & Co. KG
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

#ifndef VOLUME_CONTROL_HH
#define VOLUME_CONTROL_HH

#include "maybe.hh"
#include "logged_lock.hh"
#include "dump_enum_value.hh"

#include <memory>
#include <vector>

namespace Mixer
{

enum class MuteRequest
{
    UNCHANGED,
    TOGGLE_STATE,
    SET_UNMUTE,
    SET_MUTE,
    LAST_VALUE = SET_MUTE,
};

class VolumeSettings
{
  public:
    Maybe<double> volume_;
    Maybe<bool> is_muted_;

    VolumeSettings(const VolumeSettings &) = delete;
    VolumeSettings &operator=(const VolumeSettings &) = delete;

    explicit VolumeSettings() {}

    void reset()
    {
        volume_.set_unknown();
        is_muted_.set_unknown();
    }
};

class VolumeRequest
{
  public:
    Maybe<double> volume_;
    Maybe<MuteRequest> mute_request_;

    VolumeRequest(const VolumeRequest &) = delete;
    VolumeRequest &operator=(const VolumeRequest &) = delete;

    explicit VolumeRequest() {}

    void reset()
    {
        volume_.set_unknown();
        mute_request_.set_unknown();
    }
};

enum class VolumeScale
{
    STEPS,
    DECIBEL,
    RELATIVE_STEPS,

    LAST_VALUE = RELATIVE_STEPS,
};

static inline const char *to_string(Mixer::VolumeScale scale)
{
    static const std::array<const char *const, 3> names { "steps", "dB", "pm", };
    return enum_to_string(names, scale);
}

class VolumeControlProperties
{
  public:
    const std::string name_;
    const VolumeScale scale_;
    const double volume_min_;
    const double volume_max_;
    const double volume_step_;
    const double min_db_;
    const double max_db_;

    VolumeControlProperties(const VolumeControlProperties &) = delete;
    VolumeControlProperties &operator=(const VolumeControlProperties &) = delete;

    explicit VolumeControlProperties(const char *name,
                                     const VolumeScale scale, double volume_min,
                                     double volume_max, double volume_step,
                                     double min_db, double max_db):
        name_(name),
        scale_(scale),
        volume_min_(volume_min),
        volume_max_(volume_max),
        volume_step_(volume_step),
        min_db_(min_db),
        max_db_(max_db)
    {}
};

enum class VolumeControlResult
{
    OK,
    IGNORED,
    UNKNOWN_ID,
    INVALID,
};

class VolumeControl
{
  public:
    const uint16_t id_;

  private:
    std::unique_ptr<VolumeControlProperties> control_properties_;

    VolumeSettings appliance_settings_;
    VolumeRequest requested_;

  public:
    VolumeControl(const VolumeControl &) = delete;
    VolumeControl &operator=(const VolumeControl &) = delete;

    explicit VolumeControl(uint16_t id, std::unique_ptr<VolumeControlProperties> properties):
        id_(id),
        control_properties_(std::move(properties))
    {}

    const VolumeControlProperties *set_properties(std::unique_ptr<VolumeControlProperties> properties,
                                                  Maybe<double> &&initial_volume_level,
                                                  Maybe<bool> &&initial_mute_state);

    const VolumeControlProperties *get_properties() const
    {
        return control_properties_.get();
    }

    VolumeControlResult set_new_values(double volume, bool is_muted);
    bool set_absolute_request(double volume, bool is_muted);
    bool set_relative_request(double step, MuteRequest mute_request);

    const VolumeSettings &get_settings() const { return appliance_settings_; }
    const VolumeRequest &get_request() const { return requested_; }
};

class VolumeControls
{
  public:
    static constexpr const uint16_t INVALID_CONTROL_ID = UINT16_MAX;

  private:
    mutable LoggedLock::Mutex lock_;
    std::vector<std::unique_ptr<VolumeControl>> controls_;

  public:
    VolumeControls(const VolumeControls &) = delete;
    VolumeControls &operator=(const VolumeControls &) = delete;

    explicit VolumeControls(std::unique_ptr<VolumeControl> predefined_master);

    static std::pair<VolumeControls *const, LoggedLock::UniqueLock<LoggedLock::Mutex>> get_singleton();

    /* replace properties of given control */
    VolumeControlResult
    replace_control_properties(uint16_t id,
                               std::unique_ptr<VolumeControlProperties> properties,
                               Maybe<double> &&initial_volume_level,
                               Maybe<bool> &&initial_mute_state);

    /* set values as reported by the appliance */
    VolumeControlResult set_values(uint16_t id, double volume, bool is_muted);

    /* set request as requested by some part of the Streaming Board */
    VolumeControlResult request_absolute(uint16_t id, double volume, bool is_muted);
    VolumeControlResult request_relative(uint16_t id, double step, MuteRequest mute_request);

    VolumeControlResult get_current_values(uint16_t id, const VolumeSettings *&values) const;
    VolumeControlResult get_requested_values(uint16_t id, const VolumeRequest *&values) const;

    const std::vector<std::unique_ptr<VolumeControl>>::const_iterator begin() const
    {
        return controls_.begin();
    }

    const std::vector<std::unique_ptr<VolumeControl>>::const_iterator end() const
    {
        return controls_.end();
    }

    uint16_t get_master_id() const;
    const VolumeControl *get_master() const;
    const VolumeControl *lookup(uint16_t id) const;

  private:
    std::unique_ptr<VolumeControl> &lookup_rw(uint16_t id);
};

}

#endif /* !VOLUME_CONTROL_HH */
