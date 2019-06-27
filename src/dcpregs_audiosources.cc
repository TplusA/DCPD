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

#include "dcpregs_audiosources.hh"
#include "connman_service_list.hh"
#include "register_response_writer.hh"
#include "register_push_queue.hh"
#include "dbus_iface_deep.h"
#include "dbus_common.h"
#include "string_trim.hh"
#include "gvariantwrapper.hh"
#include "maybe.hh"
#include "messages.h"

#include <string>
#include <vector>
#include <map>
#include <deque>
#include <functional>
#include <algorithm>

enum class AudioSourceState
{
    UNAVAILABLE,
    DEAD,
    ALIVE,
    LOCKED,
    ALIVE_OR_LOCKED,
    ZOMBIE,

    LAST_STATE = ZOMBIE,
};

/*!
 * State of audio source requested by us (i.e., the SPI slave).
 */
enum class SelectionState
{
    IDLE,
    PENDING,
    SELECTING,
    SELECTION_REQUEST_FAILED,
    SELECTION_REQUEST_DONE,
};

enum class AudioSourceEnableRequest
{
    KEEP_AS_IS,
    ENABLE,
    DISABLE,
    INVALID,
};

enum class GetAudioSourcesCommand
{
    READ_ALL = 0x00,
    READ_ONE = 0x01,

    FIRST_REQUESTABLE_COMMAND = READ_ALL,
    LAST_REQUESTABLE_COMMAND = READ_ONE,

    SOURCES_CHANGED = 0x80,
};

class AudioSource
{
  public:
    using Flags = uint16_t;

    /* OR-able flags */
    static constexpr Flags IS_BROWSABLE      = 1U << 0;
    static constexpr Flags REQUIRES_LAN      = 1U << 1;
    static constexpr Flags REQUIRES_INTERNET = 1U << 2;
    static constexpr Flags CAN_BE_LOCKED     = 1U << 3;

    const std::string id_;

  private:
    const std::string default_name_;
    const Flags flags_;
    const std::function<AudioSourceState(const AudioSource &)> check_unlocked_fn_;
    const std::function<bool(const AudioSource &, bool)> invoke_audio_source_fn_;

    bool has_changed_;

    std::string name_override_;
    AudioSourceState state_;

  public:
    AudioSource(const AudioSource &) = delete;
    AudioSource(AudioSource &&) = default;
    AudioSource &operator=(const AudioSource &) = delete;

    explicit AudioSource(std::string &&id):
        id_(std::move(id)),
        default_name_("UNKNOWN"),
        flags_(0),
        has_changed_(false),
        state_(AudioSourceState::ZOMBIE)
    {}

    explicit AudioSource(std::string &&id, std::string &&default_name,
                         const Flags flags /* cppcheck-suppress passedByValue  */,
                         std::function<AudioSourceState(const AudioSource &)> &&check_unlocked_fn = nullptr,
                         std::function<bool(const AudioSource &, bool)> &&invoke_audio_source_fn = nullptr,
                         bool is_dead = false):
        id_(std::move(id)),
        default_name_(std::move(default_name)),
        flags_(flags),
        check_unlocked_fn_(check_unlocked_fn),
        invoke_audio_source_fn_(invoke_audio_source_fn),
        has_changed_(false),
        state_(is_dead ? AudioSourceState::DEAD : AudioSourceState::UNAVAILABLE)
    {}

    void reset(AudioSourceState state)
    {
        name_override_.clear();
        state_ = state;
        has_changed_ = false;
    }

    AudioSourceState get_state() const { return state_; }

    bool has_changed() const { return has_changed_; }
    void set_processed() { has_changed_ = false; }

    bool check_any_flag(const Flags flags /* cppcheck-suppress passedByValue  */)  const { return (flags_ & flags) != 0; }
    bool check_all_flags(const Flags flags /* cppcheck-suppress passedByValue  */) const { return (flags_ & flags) == flags; }

    bool set_available()
    {
        bool result = false;

        switch(state_)
        {
          case AudioSourceState::UNAVAILABLE:
          case AudioSourceState::DEAD:
          case AudioSourceState::ALIVE_OR_LOCKED:
            if(!check_any_flag(CAN_BE_LOCKED))
                result = set_state(AudioSourceState::ALIVE);
            else
                result = set_state(check_unlocked_fn_(*this));

            break;

          case AudioSourceState::ALIVE:
          case AudioSourceState::LOCKED:
            if(check_any_flag(CAN_BE_LOCKED))
            {
                auto state = check_unlocked_fn_(*this);

                if(state != AudioSourceState::ALIVE_OR_LOCKED)
                    result = set_state(state);
            }

            break;

          case AudioSourceState::ZOMBIE:
            break;
        }

        return result;
    }

    bool update_lock_state()
    {
        bool result = false;

        switch(state_)
        {
          case AudioSourceState::UNAVAILABLE:
          case AudioSourceState::DEAD:
          case AudioSourceState::ZOMBIE:
            break;

          case AudioSourceState::ALIVE:
          case AudioSourceState::LOCKED:
          case AudioSourceState::ALIVE_OR_LOCKED:
            if(check_any_flag(CAN_BE_LOCKED))
                result = set_state(check_unlocked_fn_(*this));

            break;
        }

        return result;
    }

    bool try_summon() const
    {
        if(state_ != AudioSourceState::DEAD)
            return true;

        return invoke_audio_source_fn_ != nullptr
            ? invoke_audio_source_fn_(*this, true)
            : false;
    }

    bool try_kill() const
    {
        if(state_ == AudioSourceState::DEAD)
            return true;

        return invoke_audio_source_fn_ != nullptr
            ? invoke_audio_source_fn_(*this, false)
            : false;
    }

    bool set_name(const char *name)
    {
        bool result = false;

        if(name == nullptr || name[0] == '\0' || default_name_ == name)
        {
            if(!name_override_.empty())
            {
                name_override_.clear();
                result = true;
            }
        }
        else if(name_override_ != name)
        {
            name_override_ = name;
            result = true;
        }

        if(result)
            has_changed_ = true;

        return result;
    }

    const std::string &get_name() const
    {
        return name_override_.empty() ? default_name_ : name_override_;
    }

  private:
    bool set_state(AudioSourceState state)
    {
        if(state == state_)
            return false;

        state_ = state;
        has_changed_ = true;

        return true;
    }
};

struct ServiceStateData
{
    AudioSource &src_;
    Maybe<bool> is_logged_in_;
    Maybe<bool> have_credentials_;

    ServiceStateData(const ServiceStateData &) = delete;
    ServiceStateData(ServiceStateData &&) = default;
    ServiceStateData &operator=(const ServiceStateData &) = delete;

    explicit ServiceStateData(AudioSource &src): src_(src) {}
};

struct ExternalServiceStateLoggedInTraits
{
    static inline const Maybe<bool> &get_state_ref(const ServiceStateData &d)
    {
        return d.is_logged_in_;
    }

    static inline Maybe<bool> &get_state_ref(ServiceStateData &d)
    {
        return d.is_logged_in_;
    }
};

struct ExternalServiceStateCredentialsTraits
{
    static inline const Maybe<bool> &get_state_ref(const ServiceStateData &d)
    {
        return d.have_credentials_;
    }

    static inline Maybe<bool> &get_state_ref(ServiceStateData &d)
    {
        return d.have_credentials_;
    }
};

class ExternalServiceState
{
  public:
    using MapType = std::map<const std::string, ServiceStateData>;

    enum class SetStateServiceUpdateMode
    {
        NO_UPDATE,
        ON_CHANGE,
        FORCED,
    };

  private:
    MapType is_logged_in_;

  public:
    ExternalServiceState(const ExternalServiceState &) = delete;
    ExternalServiceState &operator=(const ExternalServiceState &) = delete;

    explicit ExternalServiceState() {}

    void add_category(const char *const cred_cat, AudioSource &src)
    {
        if(cred_cat != nullptr)
            is_logged_in_.emplace(cred_cat, ServiceStateData(src));
    }

  private:
    template <typename Traits>
    static Maybe<bool> get_state(const MapType &m, const char *const cred_cat)
    {
        if(cred_cat == nullptr)
            return Maybe<bool>();

        const auto it(m.find(cred_cat));

        if(it == m.end())
            return Maybe<bool>();
        else
            return Traits::get_state_ref(it->second);
    }

    template <typename Traits>
    static bool set_state(const MapType &m, MapType::iterator &&it,
                          Maybe<bool> &&state,
                          SetStateServiceUpdateMode update_mode)
    {
        auto &v(Traits::get_state_ref(it->second));
        const bool result = (!state.is_known() || it == m.end())
            ? false
            : !v.is_known() || v != state;

        if(result)
            v = std::move(state);

        switch(update_mode)
        {
          case SetStateServiceUpdateMode::NO_UPDATE:
            break;

          case SetStateServiceUpdateMode::ON_CHANGE:
            if(!result)
                break;

            /* fall-through */

          case SetStateServiceUpdateMode::FORCED:
            it->second.src_.update_lock_state();
            break;
        }

        return result;
    }

  public:
    Maybe<bool> is_logged_in(const char *const cred_cat) const
    {
        return get_state<ExternalServiceStateLoggedInTraits>(is_logged_in_, cred_cat);
    }

    Maybe<bool> have_credentials(const char *const cred_cat) const
    {
        return get_state<ExternalServiceStateCredentialsTraits>(is_logged_in_, cred_cat);
    }

    bool set_login_state(const char *const cred_cat, Maybe<bool> &&state,
                         SetStateServiceUpdateMode update_mode)
    {
        return cred_cat != nullptr
            ? set_login_state(std::move(is_logged_in_.find(cred_cat)),
                              std::move(state), update_mode)
            : false;
    }

    bool set_credentials_state(const char *const cred_cat, Maybe<bool> &&state,
                               SetStateServiceUpdateMode update_mode)
    {
        return cred_cat != nullptr
            ? set_credentials_state(std::move(is_logged_in_.find(cred_cat)),
                                    std::move(state), update_mode)
            : false;
    }

    bool set_login_state(MapType::iterator &&it, Maybe<bool> &&state,
                         SetStateServiceUpdateMode update_mode)
    {
        return set_state<ExternalServiceStateLoggedInTraits>(is_logged_in_,
                                                             std::move(it),
                                                             std::move(state),
                                                             update_mode);
    }

    bool set_credentials_state(MapType::iterator &&it, Maybe<bool> &&state,
                               SetStateServiceUpdateMode update_mode)
    {
        return set_state<ExternalServiceStateCredentialsTraits>(is_logged_in_,
                                                                std::move(it),
                                                                std::move(state),
                                                                update_mode);
    }

    MapType::iterator begin() { return is_logged_in_.begin(); }
    MapType::iterator end() { return is_logged_in_.end(); }
    MapType::const_iterator begin() const { return is_logged_in_.begin(); }
    MapType::const_iterator end() const { return is_logged_in_.end(); }

    static const char *airable_source_id_to_credentials_category(const std::string &source_id)
    {
        static const char strip_prefix[] = "airable.";

        if(source_id.length() < sizeof(strip_prefix))
            return nullptr;

        if(!std::equal(strip_prefix, strip_prefix + sizeof(strip_prefix) - 1, source_id.begin()))
            return nullptr;

        return source_id.c_str() + sizeof(strip_prefix) - 1;
    }
};

class SelectedSource
{
  private:
    mutable LoggedLock::RecMutex lock_;

    SelectionState state_;
    const AudioSource *selected_;
    bool selected_is_half_selected_;
    const AudioSource *pending_;
    GVariantWrapper pending_request_data_;
    GCancellable *cancel_;

  public:
    bool is_test_mode_;

    SelectedSource(const SelectedSource &) = delete;
    SelectedSource &operator=(const SelectedSource &) = delete;

    explicit SelectedSource():
        state_(SelectionState::IDLE),
        selected_(nullptr),
        selected_is_half_selected_(false),
        pending_(nullptr),
        cancel_(nullptr),
        is_test_mode_(false)
    {
        LoggedLock::configure(lock_, "SelectedSource", MESSAGE_LEVEL_DEBUG);
    }

    void reset()
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::RecMutex> l(lock_);
        state_ = SelectionState::IDLE;
        selected_ = nullptr;
        selected_is_half_selected_ = false;
        pending_ = nullptr;
        is_test_mode_ = false;
        log_assert(cancel_ == nullptr);
    }

    void set_unit_test_mode() { is_test_mode_ = true; }

    LoggedLock::UniqueLock<LoggedLock::RecMutex> lock()
    {
        return LoggedLock::UniqueLock<LoggedLock::RecMutex>(lock_);
    }

    const AudioSource *get_half_or_full() const
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::RecMutex> l(lock_);
        return selected_;
    }

    const AudioSource *get(bool &is_half_selected) const
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::RecMutex> l(lock_);
        is_half_selected = selected_is_half_selected_;
        return selected_;
    }

    const SelectionState get_state() const
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::RecMutex> l(lock_);
        return state_;
    }

    bool is_pending(const AudioSource &src) const
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::RecMutex> l(lock_);
        return state_ == SelectionState::PENDING && &src == pending_;
    }

    bool is_selecting(const AudioSource &src) const
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::RecMutex> l(lock_);
        return state_ == SelectionState::SELECTING && &src == pending_;
    }

    GVariantWrapper take_pending_request_data()
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::RecMutex> l(lock_);
        log_assert(pending_request_data_ != nullptr);
        auto result(std::move(pending_request_data_));
        return result;
    }

    void start_request(const AudioSource &src, GVariantWrapper &&request_data,
                       bool try_switch_now)
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::RecMutex> l(lock_);

        switch(state_)
        {
          case SelectionState::IDLE:
            log_assert(pending_ == nullptr);
            log_assert(cancel_ == nullptr);
            break;

          case SelectionState::PENDING:
            log_assert(pending_ != nullptr);
            log_assert(cancel_ == nullptr);
            break;

          case SelectionState::SELECTING:
            log_assert(pending_ != nullptr);
            do_cancel();
            break;

          case SelectionState::SELECTION_REQUEST_FAILED:
          case SelectionState::SELECTION_REQUEST_DONE:
            log_assert(pending_ != nullptr);
            log_assert(cancel_ == nullptr);
            break;
        }

        pending_ = &src;
        pending_request_data_ = std::move(request_data);

        if(try_switch_now)
            do_start_pending();
        else
            state_ = SelectionState::PENDING;
    }

    void start_pending()
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::RecMutex> l(lock_);

        log_assert(state_ == SelectionState::PENDING);
        log_assert(pending_ != nullptr);
        log_assert(cancel_ == nullptr);
        do_start_pending();
    }

    bool selected_notification(const AudioSource &src, bool is_deferred)
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::RecMutex> l(lock_);

        const bool changed = selected_ != &src;

        selected_ = &src;
        selected_is_half_selected_ = is_deferred;

        if(selected_ != pending_)
            return changed;

        switch(state_)
        {
          case SelectionState::IDLE:
            break;

          case SelectionState::SELECTING:
            do_cancel();

            /* fall-through */

          case SelectionState::PENDING:
          case SelectionState::SELECTION_REQUEST_FAILED:
          case SelectionState::SELECTION_REQUEST_DONE:
            state_ = SelectionState::IDLE;
            pending_ = nullptr;
            break;
        }

        return changed;
    }

  private:
    void do_start_pending()
    {
        log_assert(pending_request_data_ != nullptr);

        state_ = SelectionState::SELECTING;
        cancel_ = g_cancellable_new();
        tdbus_aupath_manager_call_request_source(dbus_audiopath_get_manager_iface(),
                                                 pending_->id_.c_str(),
                                                 GVariantWrapper::get(pending_request_data_),
                                                 cancel_,
                                                 request_source_done, this);
        pending_request_data_.release();
    }

    static void request_source_done(GObject *source_object,
                                    GAsyncResult *result, void *user_data)
    {
        auto *const sel = static_cast<SelectedSource *>(user_data);

        tdbusaupathManager *const proxy = sel->is_test_mode_
            ? reinterpret_cast<tdbusaupathManager *>(source_object)
            : TDBUS_AUPATH_MANAGER(source_object);

        gchar *player_id = nullptr;
        gboolean switched;
        GError *error = nullptr;
        (void)tdbus_aupath_manager_call_request_source_finish(proxy, &player_id,
                                                              &switched, result,
                                                              &error);

        if(player_id != nullptr)
            g_free(player_id);

        if(error != nullptr &&
           error->domain == G_IO_ERROR &&
           error->code == G_IO_ERROR_CANCELLED)
        {
            msg_vinfo(MESSAGE_LEVEL_DIAG, "Canceled audio source request");
            g_error_free(error);
            return;
        }

        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::RecMutex> lk(sel->lock_);

        log_assert(sel->state_ == SelectionState::SELECTING);
        log_assert(sel->cancel_ != nullptr);
        g_object_unref(sel->cancel_);
        sel->cancel_ = nullptr;

        if(dbus_common_handle_dbus_error(&error, "Request audio source") == 0)
            sel->state_ = SelectionState::SELECTION_REQUEST_DONE;
        else
            sel->state_ = SelectionState::SELECTION_REQUEST_FAILED;
    }

    void do_cancel()
    {
        log_assert(cancel_ != nullptr);
        g_cancellable_cancel(cancel_);
        g_object_unref(cancel_);
        cancel_ = nullptr;
    }
};

using SlavePushCommandQueue =
    Regs::PushQueue<std::pair<const GetAudioSourcesCommand, const std::string>>;

static void add_to_queue(SlavePushCommandQueue &q,
                         GetAudioSourcesCommand command)
{
    q.add(std::move(std::make_pair(command, std::move(std::string()))));
}

static void add_to_queue(SlavePushCommandQueue &q,
                         GetAudioSourcesCommand command, std::string &&str)
{
    q.add(std::move(std::make_pair(command, std::move(str))));
}

class AudioSourceData
{
  public:
    static constexpr const size_t NUMBER_OF_DEFAULT_SOURCES = 12;

  private:
    LoggedLock::Mutex lock_;

    std::array<AudioSource, NUMBER_OF_DEFAULT_SOURCES> default_sources_;
    std::vector<AudioSource> extra_sources_;

    SelectedSource selected_;

  public:
    AudioSourceData(const AudioSourceData &) = delete;
    AudioSourceData &operator=(const AudioSourceData &) = delete;

    explicit AudioSourceData(std::array<AudioSource, NUMBER_OF_DEFAULT_SOURCES> &&default_sources):
        default_sources_(std::move(default_sources))
    {
        LoggedLock::configure(lock_, "AudioSourceData", MESSAGE_LEVEL_DEBUG);
    }

    void reset(const std::array<const AudioSourceState, NUMBER_OF_DEFAULT_SOURCES> &is_dead)
    {
        for(size_t i = 0; i < is_dead.size(); ++i)
            default_sources_[i].reset(is_dead[i]);

        extra_sources_.clear();
        selected_.reset();
    }

    void set_unit_test_mode() { selected_.set_unit_test_mode(); }

    LoggedLock::UniqueLock<LoggedLock::Mutex> lock()
    {
        return LoggedLock::UniqueLock<LoggedLock::Mutex>(lock_);
    }

  private:
    template <typename T>
    AudioSource *lookup_predefined_impl(const T id)
    {
        const auto it(std::find_if(default_sources_.begin(), default_sources_.end(),
                                   [&id] (const AudioSource &src) { return src.id_ == id; }));
        return it != default_sources_.end() ? it : nullptr;
    }

  public:
    AudioSource *lookup_predefined(const char *id)
    {
        return lookup_predefined_impl(id);
    }

    const AudioSource *lookup_predefined(const char *id) const
    {
        return const_cast<AudioSourceData *>(this)->lookup_predefined_impl(id);
    }

    AudioSource *lookup_predefined(const std::string &id)
    {
        return lookup_predefined_impl(id);
    }

    const AudioSource *lookup_predefined(const std::string &id) const
    {
        return const_cast<AudioSourceData *>(this)->lookup_predefined_impl(id);
    }

    AudioSource *lookup_extra(const char *id)
    {
        auto it(std::find_if(extra_sources_.begin(), extra_sources_.end(),
                             [id] (const AudioSource &src) { return src.id_ == id; }));
        return it != extra_sources_.end() ? &*it : nullptr;
    }

    const AudioSource *lookup_extra(const char *id) const
    {
        return const_cast<AudioSourceData *>(this)->lookup_extra(id);
    }

    AudioSource *lookup(const char *id)
    {
        AudioSource *src = lookup_predefined(id);
        return src != nullptr ? src : lookup_extra(id);
    }

    const AudioSource *lookup(const char *id) const
    {
        return const_cast<AudioSourceData *>(this)->lookup(id);
    }

    AudioSource *insert_extra(const char *id)
    {
        extra_sources_.emplace_back(AudioSource(id));
        return &extra_sources_.back();
    }

    const SelectedSource &get_selected() const { return selected_; }

    void for_each(const std::function<void(const AudioSource &)> &apply) const
    {
        for(const auto &s : default_sources_)
            apply(s);
    }

    void for_each(const std::function<void(AudioSource &)> &apply)
    {
        for(auto &s : default_sources_)
            apply(s);
    }

    void request_audio_source(const AudioSource &src,
                              GVariantWrapper &&request_data,
                              bool try_switch_now)
    {
        LOGGED_LOCK_CONTEXT_HINT;
        auto l(selected_.lock());

        switch(selected_.get_state())
        {
          case SelectionState::IDLE:
          case SelectionState::SELECTION_REQUEST_FAILED:
            break;

          case SelectionState::PENDING:
            if(selected_.get_half_or_full() == &src)
            {
                if(try_switch_now)
                    selected_.start_pending();

                return;
            }

            break;

          case SelectionState::SELECTING:
            if(selected_.is_selecting(src))
                return;

            /* fall-through */

          case SelectionState::SELECTION_REQUEST_DONE:
            if(selected_.get_half_or_full() == &src)
                return;

            break;
        }

        selected_.start_request(src, std::move(request_data), try_switch_now);
    }

    void selected_audio_source_notification(const AudioSource &src, bool is_deferred,
                                            bool notify_register_change = true)
    {
        if(selected_.selected_notification(src, is_deferred) && notify_register_change)
            Regs::get_data().register_changed_notification_fn(81);
    }

    bool audio_source_available_notification(AudioSource &src)
    {
        bool result = src.set_available();

        gchar *source_name = nullptr;
        gchar *player_id = nullptr;
        gchar *dbusname = nullptr;
        gchar *dbuspath = nullptr;
        GError *error = nullptr;

        tdbus_aupath_manager_call_get_source_info_sync(dbus_audiopath_get_manager_iface(),
                                                       src.id_.c_str(),
                                                       &source_name, &player_id,
                                                       &dbusname, &dbuspath,
                                                       nullptr, &error);
        if(dbus_common_handle_dbus_error(&error, "Get audio source information") == 0)
        {
            if(src.set_name(source_name))
                result = true;

            g_free(player_id);
            g_free(dbusname);
            g_free(dbuspath);
            g_free(source_name);
        }

        LOGGED_LOCK_CONTEXT_HINT;
        auto l(selected_.lock());

        if(selected_.is_pending(src))
            request_audio_source(src, std::move(selected_.take_pending_request_data()), true);

        return result;
    }

    static void audio_sources_changed_lock_state_notification(SlavePushCommandQueue &q)
    {
        add_to_queue(q, GetAudioSourcesCommand::SOURCES_CHANGED);
    }
};

static bool try_invoke_roon(const AudioSource &src, bool summon)
{
    if(!summon)
    {
        BUG("Shutting down Roon is not supported yet");
        return false;
    }

    tdbus_systemd_manager_call_start_unit(dbus_get_systemd_manager_iface(),
                                          "taroon.service", "fail",
                                          nullptr, nullptr, nullptr);

    return true;
}

static std::unique_ptr<SlavePushCommandQueue> push_80_command_queue;
static std::unique_ptr<ExternalServiceState> global_external_service_state;
static std::unique_ptr<AudioSourceData> audio_source_data;

static AudioSourceState is_service_unlocked(const AudioSource &src)
{
    const auto logged_in =
        global_external_service_state->is_logged_in(
            ExternalServiceState::airable_source_id_to_credentials_category(src.id_));

    if(logged_in.is_known())
        return logged_in.get() ? AudioSourceState::ALIVE : AudioSourceState::LOCKED;

    if(global_external_service_state->have_credentials(
            ExternalServiceState::airable_source_id_to_credentials_category(src.id_)) == false)
        return AudioSourceState::LOCKED;
    else
        return AudioSourceState::ALIVE_OR_LOCKED;
}


void Regs::AudioSources::init()
{
    push_80_command_queue = std::make_unique<SlavePushCommandQueue>(80, "SlavePushCommandQueue");

    global_external_service_state = std::make_unique<ExternalServiceState>();
    audio_source_data = std::make_unique<AudioSourceData, std::array<AudioSource, AudioSourceData::NUMBER_OF_DEFAULT_SOURCES>>(
    {
        AudioSource("strbo.usb",      "USB devices",             AudioSource::IS_BROWSABLE),
        AudioSource("strbo.upnpcm",   "UPnP media servers",      AudioSource::IS_BROWSABLE | AudioSource::REQUIRES_LAN),
        AudioSource("strbo.plainurl", "TA Control",              AudioSource::REQUIRES_LAN),
        AudioSource("airable",        "Airable",                 AudioSource::IS_BROWSABLE | AudioSource::REQUIRES_INTERNET),
        AudioSource("airable.radios", "Airable Internet Radios", AudioSource::IS_BROWSABLE | AudioSource::REQUIRES_INTERNET),
        AudioSource("airable.feeds",  "Airable Podcasts",        AudioSource::IS_BROWSABLE | AudioSource::REQUIRES_INTERNET),
        AudioSource("airable.tidal",  "TIDAL",
                    AudioSource::IS_BROWSABLE | AudioSource::REQUIRES_INTERNET | AudioSource::CAN_BE_LOCKED,
                    is_service_unlocked),
        AudioSource("airable.deezer", "Deezer",
                    AudioSource::IS_BROWSABLE | AudioSource::REQUIRES_INTERNET | AudioSource::CAN_BE_LOCKED,
                    is_service_unlocked),
        AudioSource("airable.qobuz",  "Qobuz",
                    AudioSource::IS_BROWSABLE | AudioSource::REQUIRES_INTERNET | AudioSource::CAN_BE_LOCKED,
                    is_service_unlocked),
        AudioSource("airable.highresaudio", "HIGHRESAUDIO",
                    AudioSource::IS_BROWSABLE | AudioSource::REQUIRES_INTERNET | AudioSource::CAN_BE_LOCKED,
                    is_service_unlocked),
        AudioSource("roon",           "Roon Ready",              AudioSource::REQUIRES_LAN,
                    nullptr, try_invoke_roon, true),
        AudioSource("",               "Inactive",                0),
    });

    audio_source_data->for_each([] (AudioSource &src)
    {
        if(src.check_any_flag(AudioSource::CAN_BE_LOCKED))
            global_external_service_state->add_category(
                ExternalServiceState::airable_source_id_to_credentials_category(src.id_),
                src);
    });

    /* preselect placeholder audio source for inactive state */
    const auto *inactive_src = audio_source_data->lookup_predefined("");
    if(inactive_src != nullptr)
        audio_source_data->selected_audio_source_notification(*inactive_src,
                                                              false, false);
}

void Regs::AudioSources::deinit()
{
    audio_source_data = nullptr;
    global_external_service_state = nullptr;
    push_80_command_queue = nullptr;
}

static Maybe<bool> have_credentials_stored(const char *category)
{
    if(category == nullptr)
        return Maybe<bool>();

    gchar *username = nullptr;
    gchar *password = nullptr;
    GError *error = nullptr;

    tdbus_credentials_read_call_get_default_credentials_sync(dbus_get_credentials_read_iface(),
                                                             category,
                                                             &username, &password,
                                                             nullptr, &error);

    if(dbus_common_handle_dbus_error(&error, "Check audio source credentials") < 0)
        return Maybe<bool>();

    const Maybe<bool> result(username != nullptr && username[0] != '\0' &&
                             password != nullptr && password[0] != '\0');

    g_free(username);
    g_free(password);

    return result;
}

void Regs::AudioSources::fetch_audio_paths()
{
    GVariant *usable_variant = nullptr;
    GVariant *incomplete_variant = nullptr;
    GError *error = nullptr;

    tdbus_aupath_manager_call_get_paths_sync(dbus_audiopath_get_manager_iface(),
                                             &usable_variant, &incomplete_variant,
                                             nullptr, &error);

    if(dbus_common_handle_dbus_error(&error, "Read out audio paths") < 0)
        return;

    GVariantWrapper usable(usable_variant, GVariantWrapper::Transfer::JUST_MOVE);
    GVariantWrapper incomplete(incomplete_variant, GVariantWrapper::Transfer::JUST_MOVE);

    GVariantIter iter;
    const gchar *source_id;
    const gchar *player_id;

    g_variant_iter_init(&iter, GVariantWrapper::get(usable));

    while(g_variant_iter_next(&iter, "(&s&s)", &source_id, &player_id))
        Regs::AudioSources::source_available(source_id);
}

void Regs::AudioSources::check_external_service_credentials()
{
    bool changed = false;

    for(auto it = global_external_service_state->begin();
        it != global_external_service_state->end();
        ++it)
    {
        if(global_external_service_state->set_credentials_state(
                std::move(ExternalServiceState::MapType::iterator(it)),
                have_credentials_stored(it->first.c_str()),
                ExternalServiceState::SetStateServiceUpdateMode::ON_CHANGE))
            changed = true;
    };

    if(changed)
        audio_source_data->audio_sources_changed_lock_state_notification(*push_80_command_queue);
}

static bool check_network_requirements(const AudioSource &asrc)
{
    if(!asrc.check_any_flag(AudioSource::REQUIRES_LAN |
                            AudioSource::REQUIRES_INTERNET))
        return true;

    const bool is_lan_sufficient(!asrc.check_any_flag(AudioSource::REQUIRES_INTERNET));
    LOGGED_LOCK_CONTEXT_HINT;
    const auto locked_list(Connman::ServiceList::get_singleton_const());

    for(const auto &s : locked_list.first)
    {
        if(s.second == nullptr)
            continue;

        const Maybe<Connman::ServiceState> &state(s.second->get_service_data().state_);

        if(!state.is_known())
            continue;

        switch(state.get())
        {
            case Connman::ServiceState::NOT_AVAILABLE:
            case Connman::ServiceState::UNKNOWN_STATE:
            case Connman::ServiceState::IDLE:
            case Connman::ServiceState::FAILURE:
            case Connman::ServiceState::ASSOCIATION:
            case Connman::ServiceState::CONFIGURATION:
            case Connman::ServiceState::DISCONNECT:
              break;

            case Connman::ServiceState::READY:
              if(is_lan_sufficient)
                  return true;

              break;

            case Connman::ServiceState::ONLINE:
              return true;
        }
    }

    return false;
}

static const uint8_t determine_usable(const AudioSource &asrc)
{
    switch(asrc.get_state())
    {
      case AudioSourceState::ALIVE:
      case AudioSourceState::ALIVE_OR_LOCKED:
        if(check_network_requirements(asrc))
            return asrc.get_state() == AudioSourceState::ALIVE ? 2 : 1;

        break;

      case AudioSourceState::UNAVAILABLE:
      case AudioSourceState::DEAD:
      case AudioSourceState::LOCKED:
      case AudioSourceState::ZOMBIE:
        break;
    }

    return 0;
}

static void write_audio_source_info(RegisterResponseWriter &out,
                                    const AudioSource &asrc,
                                    bool with_human_readable_name,
                                    const std::string *id_override = nullptr)
{
    out.push_back(id_override == nullptr ? asrc.id_ : *id_override);

    if(with_human_readable_name)
        out.push_back(asrc.get_name());

    const uint8_t status_byte =
        uint8_t((asrc.get_state() == AudioSourceState::UNAVAILABLE ||
                 asrc.get_state() == AudioSourceState::DEAD) ? (1 << 7) : 0) |
        uint8_t(asrc.check_any_flag(AudioSource::IS_BROWSABLE) ? (1 << 6) : 0) |
        uint8_t(determine_usable(asrc) << 4) |
        uint8_t(asrc.get_state());

    out.push_back(status_byte);
}

ssize_t Regs::AudioSources::DCP::read_80_get_known_audio_sources(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 80 handler %p %zu", response, length);

    LOGGED_LOCK_CONTEXT_HINT;
    auto lock(audio_source_data->lock());
    const auto queue_item(
        [] () -> std::pair<const GetAudioSourcesCommand, const std::string>
        {
            try
            {
                return push_80_command_queue->take();
            }
            catch(const std::out_of_range &e)
            {
                return std::make_pair(GetAudioSourcesCommand::READ_ALL,
                                      std::move(std::string()));
            }
        }());
    const GetAudioSourcesCommand &command(queue_item.first);

    RegisterResponseWriter out(response, length);

    out.push_back(uint8_t(command));

    switch(command)
    {
      case GetAudioSourcesCommand::READ_ALL:
        out.push_back(uint8_t(audio_source_data->NUMBER_OF_DEFAULT_SOURCES));

        audio_source_data->for_each([&out] (const AudioSource &asrc)
        {
            write_audio_source_info(out, asrc, true);
        });

        break;

      case GetAudioSourcesCommand::READ_ONE:
        {
            const AudioSource *asrc =
                audio_source_data->lookup_predefined(queue_item.second);

            if(asrc != nullptr)
                write_audio_source_info(out, *asrc, true);
            else
            {
                static const AudioSource invalid_audio_source("", "", 0);
                write_audio_source_info(out, invalid_audio_source, true,
                                        &queue_item.second);
            }
        }

        break;

      case GetAudioSourcesCommand::SOURCES_CHANGED:
        size_t number_of_changes = 0;
        audio_source_data->for_each([&number_of_changes] (const AudioSource &asrc)
        {
            if(asrc.has_changed())
                ++number_of_changes;
        });

        if(number_of_changes == 0)
            return 0;

        if(number_of_changes > UINT8_MAX)
            number_of_changes = UINT8_MAX;

        out.push_back(uint8_t(number_of_changes));

        audio_source_data->for_each([&out] (AudioSource &asrc)
        {
            if(asrc.has_changed())
            {
                write_audio_source_info(out, asrc, false);
                asrc.set_processed();
            }
        });

        break;
    }

    if(out.is_overflown())
    {
        msg_error(0, LOG_ERR,
                  "Buffer too small (retrieve audio sources, command 0x%02x)",
                  uint8_t(command));
        return -1;
    }

    return out.get_length();
}

static int queue_read_one_command(const uint8_t *data, size_t length)
{
    const size_t original_length = length;

    if(!Utils::trim_trailing_zero_padding(data, length) ||
       length == original_length)
    {
        msg_error(EINVAL, LOG_ERR, "Non-empty audio source ID expected");
        return -1;
    }

    add_to_queue(*push_80_command_queue,
                 GetAudioSourcesCommand::READ_ONE,
                 std::string(reinterpret_cast<const char *>(data)));

    return 0;
}

int Regs::AudioSources::DCP::write_80_get_known_audio_sources(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 80 handler %p %zu", data, length);

    if(length < 1)
    {
        msg_error(EINVAL, LOG_ERR, "Command code expected");
        return -1;
    }

    int result = -1;

    if(data[0] >= uint8_t(GetAudioSourcesCommand::FIRST_REQUESTABLE_COMMAND) &&
       data[0] <= uint8_t(GetAudioSourcesCommand::LAST_REQUESTABLE_COMMAND))
    {
        const auto command = GetAudioSourcesCommand(data[0]);

        switch(command)
        {
          case GetAudioSourcesCommand::READ_ALL:
            add_to_queue(*push_80_command_queue, GetAudioSourcesCommand(data[0]));
            result = 0;
            break;

          case GetAudioSourcesCommand::READ_ONE:
            result = queue_read_one_command(data + 1, length - 1);
            break;

          case GetAudioSourcesCommand::SOURCES_CHANGED:
            BUG("%s(%d): unreachable", __func__, __LINE__);
            break;
        }
    }
    else
        msg_error(EINVAL, LOG_ERR, "Command 0x%02x out of range", data[0]);

    return result;
}

ssize_t Regs::AudioSources::DCP::read_81_current_audio_source(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 81 handler %p %zu", response, length);

    LOGGED_LOCK_CONTEXT_HINT;
    auto lock(audio_source_data->lock());

    const AudioSource *src =audio_source_data->get_selected().get_half_or_full();

    if(src == nullptr)
        return 0;

    if(length <= src->id_.length())
        return -1;

    src->id_.copy(reinterpret_cast<char *>(response), src->id_.length());
    response[src->id_.length()] = '\0';

    return src->id_.length() + 1;
}

static AudioSourceEnableRequest parse_enable_request(uint8_t request_code)
{
    if(request_code == 0)
        return AudioSourceEnableRequest::DISABLE;
    else if(request_code == 1)
        return AudioSourceEnableRequest::ENABLE;
    else
        return AudioSourceEnableRequest::INVALID;
}

static bool set_request_options(GVariantDict &dict,
                                const char *options, size_t end_of_options)
{
    if(end_of_options == 0)
        return true;

    size_t i = 0;
    bool is_escaping = false;

    while(i < end_of_options)
    {
        std::string key;
        std::string value;
        std::string *dest = &key;

        while(i < end_of_options)
        {
            const char ch = options[i++];

            if(is_escaping)
            {
                dest->push_back(ch);
                is_escaping = false;
                continue;
            }
            else if(ch == '\\')
            {
                is_escaping = true;
                continue;
            }

            if(ch == ',')
                break;

            if(ch != '=' || dest == &value)
                dest->push_back(ch);
            else
                dest = &value;
        }

        if(is_escaping)
            return false;

        if(key.empty())
        {
            if(value.empty())
                continue;

            return false;
        }

        GVariant *const gvalue = (dest == &key)
            ? g_variant_new_boolean(TRUE)
            : g_variant_new_string(value.c_str());

        g_variant_dict_insert_value(&dict, key.c_str(), gvalue);
    }

    return true;
}

int Regs::AudioSources::DCP::write_81_current_audio_source(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 81 handler %p %zu", data, length);

    size_t i;
    size_t options_offset = SIZE_MAX;

    for(i = 0; i < length && data[i] != '\0'; ++i)
    {
        if(options_offset == SIZE_MAX && data[i] == ':')
            options_offset = i + 1;
    }

    if(i >= length)
        return -1;

    const char *audio_source_name = reinterpret_cast<const char *>(data);;
    size_t audio_source_name_length;
    std::string audio_source_name_buffer;
    GVariantDict dict;
    g_variant_dict_init(&dict, nullptr);

    if(options_offset == SIZE_MAX)
        audio_source_name_length = i > 0 ? i - 1 : 0;
    else if(set_request_options(dict, audio_source_name + options_offset, i - options_offset))
    {
        audio_source_name_length = options_offset - 1;

        if(audio_source_name_length > 0)
            audio_source_name_buffer.insert(0, audio_source_name, audio_source_name_length);

        audio_source_name = audio_source_name_buffer.c_str();
    }
    else
        audio_source_name = nullptr;

    auto request_data(GVariantWrapper(g_variant_dict_end(&dict)));

    if(audio_source_name == nullptr)
    {
        msg_error(EINVAL, LOG_NOTICE, "Invalid audio source options");
        return -1;
    }

    if(audio_source_name_length == 0)
    {
        /*
         * There is no explicit audio source that represents
         * inactive/idle/silent state. Instead, the current audio path is
         * deactivated and the player is forced down so that the inactive state
         * corresponds to the state the system is in after a fresh boot, i.e.,
         * without any active audio path. This way, no special case is
         * introduced for inactive state.
         */
        msg_info("Inactive state requested");
        tdbus_aupath_manager_call_release_path(dbus_audiopath_get_manager_iface(),
                                               TRUE, GVariantWrapper::get(request_data),
                                               nullptr, nullptr, nullptr);
        return 0;
    }

    const AudioSourceEnableRequest enable_request(i + 1 == length
                                                  ? AudioSourceEnableRequest::KEEP_AS_IS
                                                  : parse_enable_request(data[i + 1]));

    LOGGED_LOCK_CONTEXT_HINT;
    auto lock(audio_source_data->lock());

    const AudioSource *src =
        audio_source_data->lookup_predefined(audio_source_name);

    if(src == nullptr)
    {
        msg_error(0, LOG_NOTICE, "Audio source \"%s\" not known",
                  audio_source_name);
        return -1;
    }

    switch(enable_request)
    {
      case AudioSourceEnableRequest::KEEP_AS_IS:
        break;

      case AudioSourceEnableRequest::ENABLE:
        if(src->try_summon())
            return 0;

        msg_error(0, LOG_ERR, "Failed enabling audio source \"%s\"",
                  src->id_.c_str());
        return -1;

      case AudioSourceEnableRequest::DISABLE:
        if(src->try_kill())
            return 0;

        msg_error(0, LOG_ERR, "Failed disabling audio source \"%s\"",
                  src->id_.c_str());
        return -1;

      case AudioSourceEnableRequest::INVALID:
        return -1;
    }

    switch(src->get_state())
    {
      case AudioSourceState::ALIVE:
      case AudioSourceState::LOCKED:
      case AudioSourceState::ALIVE_OR_LOCKED:
        audio_source_data->request_audio_source(*src, std::move(request_data), true);
        break;

      case AudioSourceState::UNAVAILABLE:
        audio_source_data->request_audio_source(*src, std::move(request_data), false);
        break;

      case AudioSourceState::DEAD:
      case AudioSourceState::ZOMBIE:
        msg_error(0, LOG_NOTICE, "Audio source \"%s\" is %s",
                  audio_source_name,
                  src->get_state() == AudioSourceState::DEAD ? "dead" : "zombie");
        return -1;
    }

    return 0;
}

void Regs::AudioSources::source_available(const char *source_id)
{
    LOGGED_LOCK_CONTEXT_HINT;
    auto lock(audio_source_data->lock());

    AudioSource *src = audio_source_data->lookup(source_id);

    if(src == nullptr)
        return;

    if(audio_source_data->audio_source_available_notification(*src))
        add_to_queue(*push_80_command_queue, GetAudioSourcesCommand::SOURCES_CHANGED);
}

void Regs::AudioSources::selected_source(const char *source_id,
                                         bool is_deferred)
{
    LOGGED_LOCK_CONTEXT_HINT;
    auto lock(audio_source_data->lock());

    AudioSource *src = audio_source_data->lookup(source_id);

    if(src == nullptr)
        src = audio_source_data->insert_extra(source_id);
    else
    {
        bool is_half_selected;

        if(src == audio_source_data->get_selected().get(is_half_selected))
        {
            if(!is_half_selected)
            {
                BUG("Audio source \"%s\" %s again",
                    source_id, is_deferred ? "deferred" : "selected");
                return;
            }
            else if(is_deferred)
            {
                msg_info("Deferred audio source \"%s\" deferred again", source_id);
                return;
            }
        }
    }

    log_assert(src != nullptr);
    audio_source_data->selected_audio_source_notification(*src, is_deferred);
}

void Regs::AudioSources::set_have_credentials(const char *cred_category,
                                              bool have_credentials)
{
    if(global_external_service_state->set_credentials_state(
            cred_category, Maybe<bool>(have_credentials),
            ExternalServiceState::SetStateServiceUpdateMode::ON_CHANGE))
        audio_source_data->audio_sources_changed_lock_state_notification(*push_80_command_queue);
}

void Regs::AudioSources::set_login_state(const char *cred_category,
                                         bool is_logged_in)
{
    if(global_external_service_state->set_login_state(
            cred_category, Maybe<bool>(is_logged_in),
            ExternalServiceState::SetStateServiceUpdateMode::NO_UPDATE))
    {
        global_external_service_state->set_credentials_state(
            cred_category, have_credentials_stored(cred_category),
            ExternalServiceState::SetStateServiceUpdateMode::FORCED);
        audio_source_data->audio_sources_changed_lock_state_notification(*push_80_command_queue);
    }
}

void Regs::AudioSources::set_unit_test_mode()
{
    audio_source_data->set_unit_test_mode();
}
