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

#include <string>
#include <vector>
#include <array>
#include <map>
#include <algorithm>
#include <mutex>
#include <sstream>

#include "dcpregs_audiosources.h"
#include "connman_service_list.hh"
#include "registers_priv.h"
#include "register_response_writer.hh"
#include "dbus_iface_deep.h"
#include "dbus_common.h"
#include "gvariantwrapper.hh"
#include "maybe.hh"
#include "messages.h"

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
        state_(AudioSourceState::ZOMBIE)
    {}

    explicit AudioSource(std::string &&id, std::string &&default_name,
                         Flags flags,
                         std::function<AudioSourceState(const AudioSource &)> &&check_unlocked_fn = nullptr,
                         std::function<bool(const AudioSource &, bool)> &&invoke_audio_source_fn = nullptr,
                         bool is_dead = false):
        id_(std::move(id)),
        default_name_(std::move(default_name)),
        flags_(flags),
        check_unlocked_fn_(check_unlocked_fn),
        invoke_audio_source_fn_(invoke_audio_source_fn),
        state_(is_dead ? AudioSourceState::DEAD : AudioSourceState::UNAVAILABLE)
    {}

    void reset(AudioSourceState state)
    {
        name_override_.clear();
        state_ = state;
    }

    AudioSourceState get_state() const { return state_; }

    bool check_any_flag(const Flags flags)  const { return (flags_ & flags) != 0; }
    bool check_all_flags(const Flags flags) const { return (flags_ & flags) == flags; }

    void set_available()
    {
        switch(state_)
        {
          case AudioSourceState::UNAVAILABLE:
          case AudioSourceState::DEAD:
          case AudioSourceState::ALIVE_OR_LOCKED:
            if(!check_any_flag(CAN_BE_LOCKED))
                state_ = AudioSourceState::ALIVE;
            else
                state_ = check_unlocked_fn_(*this);

            break;

          case AudioSourceState::ALIVE:
          case AudioSourceState::LOCKED:
            if(check_any_flag(CAN_BE_LOCKED))
            {
                auto state = check_unlocked_fn_(*this);

                if(state != AudioSourceState::ALIVE_OR_LOCKED)
                    state_ = state;
            }

            break;

          case AudioSourceState::ZOMBIE:
            break;
        }
    }

    void update_lock_state()
    {
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
                state_ = check_unlocked_fn_(*this);

            break;
        }
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

    void set_name(const char *name)
    {
        if(name == nullptr || name[0] == '\0' || default_name_ == name)
            name_override_.clear();
        else if(name_override_ != name)
            name_override_ = name;
    }

    const std::string &get_name() const
    {
        return name_override_.empty() ? default_name_ : name_override_;
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
    mutable std::recursive_mutex lock_;

    SelectionState state_;
    const AudioSource *selected_;
    const AudioSource *pending_;
    GCancellable *cancel_;

  public:
    bool is_test_mode_;

    SelectedSource(const SelectedSource &) = delete;
    SelectedSource &operator=(const SelectedSource &) = delete;

    explicit SelectedSource():
        state_(SelectionState::IDLE),
        selected_(nullptr),
        pending_(nullptr),
        cancel_(nullptr),
        is_test_mode_(false)
    {}

    void reset()
    {
        std::lock_guard<std::recursive_mutex> l(lock_);
        state_ = SelectionState::IDLE;
        selected_ = nullptr;
        pending_ = nullptr;
        is_test_mode_ = false;
        log_assert(cancel_ == nullptr);
    }

    void set_unit_test_mode() { is_test_mode_ = true; }

    std::unique_lock<std::recursive_mutex> lock()
    {
        return std::unique_lock<std::recursive_mutex>(lock_);
    }

    const AudioSource *get() const
    {
        std::lock_guard<std::recursive_mutex> l(lock_);
        return selected_;
    }

    const SelectionState get_state() const
    {
        std::lock_guard<std::recursive_mutex> l(lock_);
        return state_;
    }

    bool is_pending(const AudioSource &src) const
    {
        std::lock_guard<std::recursive_mutex> l(lock_);
        return state_ == SelectionState::PENDING && &src == pending_;
    }

    bool is_selecting(const AudioSource &src) const
    {
        std::lock_guard<std::recursive_mutex> l(lock_);
        return state_ == SelectionState::SELECTING && &src == pending_;
    }

    void start_request(const AudioSource &src, bool try_switch_now)
    {
        std::lock_guard<std::recursive_mutex> l(lock_);

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

        if(try_switch_now)
            do_start_pending();
        else
            state_ = SelectionState::PENDING;
    }

    void start_pending()
    {
        std::lock_guard<std::recursive_mutex> l(lock_);

        log_assert(state_ == SelectionState::PENDING);
        log_assert(pending_ != nullptr);
        log_assert(cancel_ == nullptr);
        do_start_pending();
    }

    bool selected_notification(const AudioSource &src)
    {
        std::lock_guard<std::recursive_mutex> l(lock_);

        const bool changed = selected_ != &src;

        selected_ = &src;

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
        state_ = SelectionState::SELECTING;
        cancel_ = g_cancellable_new();
        tdbus_aupath_manager_call_request_source(dbus_audiopath_get_manager_iface(),
                                                 pending_->id_.c_str(), cancel_,
                                                 request_source_done, this);
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

        std::lock_guard<std::recursive_mutex> lock(sel->lock_);

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

class AudioSourceData
{
  public:
    static constexpr const size_t NUMBER_OF_DEFAULT_SOURCES = 10;

  private:
    std::mutex lock_;

    std::array<AudioSource, NUMBER_OF_DEFAULT_SOURCES> default_sources_;
    std::vector<AudioSource> extra_sources_;

    SelectedSource selected_;

  public:
    AudioSourceData(const AudioSourceData &) = delete;
    AudioSourceData &operator=(const AudioSourceData &) = delete;

    explicit AudioSourceData(std::array<AudioSource, NUMBER_OF_DEFAULT_SOURCES> &&default_sources):
        default_sources_(std::move(default_sources))
    {}

    void reset(const std::array<const AudioSourceState, NUMBER_OF_DEFAULT_SOURCES> &is_dead)
    {
        for(size_t i = 0; i < is_dead.size(); ++i)
            default_sources_[i].reset(is_dead[i]);

        extra_sources_.clear();
        selected_.reset();
    }

    void set_unit_test_mode() { selected_.set_unit_test_mode(); }

    std::unique_lock<std::mutex> lock()
    {
        return std::unique_lock<std::mutex>(lock_);
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

    void request_audio_source(const AudioSource &src, bool try_switch_now)
    {
        auto l(selected_.lock());

        switch(selected_.get_state())
        {
          case SelectionState::IDLE:
          case SelectionState::SELECTION_REQUEST_FAILED:
            break;

          case SelectionState::PENDING:
            if(selected_.get() == &src)
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
            if(selected_.get() == &src)
                return;

            break;
        }

        selected_.start_request(src, try_switch_now);
    }

    void selected_audio_source_notification(const AudioSource &src)
    {
        if(selected_.selected_notification(src))
            registers_get_data()->register_changed_notification_fn(81);
    }

    void audio_source_available_notification(AudioSource &src)
    {
        src.set_available();

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
            src.set_name(source_name);

            g_free(player_id);
            g_free(dbusname);
            g_free(dbuspath);
            g_free(source_name);
        }

        auto l(selected_.lock());

        if(selected_.is_pending(src))
            request_audio_source(src, true);
    }

    static void audio_sources_changed_lock_state_notification()
    {
        /* Nothing for now. We may want to notify the slave at this point or
         * something like that. */
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

static ExternalServiceState global_external_service_state;

static AudioSourceState is_service_unlocked(const AudioSource &src)
{
    const auto logged_in =
        global_external_service_state.is_logged_in(
            ExternalServiceState::airable_source_id_to_credentials_category(src.id_));

    if(logged_in.is_known())
        return logged_in.get() ? AudioSourceState::ALIVE : AudioSourceState::LOCKED;

    if(global_external_service_state.have_credentials(
            ExternalServiceState::airable_source_id_to_credentials_category(src.id_)) == false)
        return AudioSourceState::LOCKED;
    else
        return AudioSourceState::ALIVE_OR_LOCKED;
}

static AudioSourceData audio_source_data(
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
    AudioSource("roon",           "Roon Ready",              AudioSource::REQUIRES_LAN,
                nullptr, try_invoke_roon, true),
});

void dcpregs_audiosources_init(void)
{
    audio_source_data.for_each([] (AudioSource &src)
    {
        if(src.check_any_flag(AudioSource::CAN_BE_LOCKED))
            global_external_service_state.add_category(
                ExternalServiceState::airable_source_id_to_credentials_category(src.id_),
                src);
    });
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

void dcpregs_audiosources_fetch_audio_paths(void)
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
        dcpregs_audiosources_source_available(source_id);
}

void dcpregs_audiosources_check_external_service_credentials()
{
    bool changed = false;

    for(auto it = global_external_service_state.begin();
        it != global_external_service_state.end();
        ++it)
    {
        if(global_external_service_state.set_credentials_state(
                std::move(ExternalServiceState::MapType::iterator(it)),
                have_credentials_stored(it->first.c_str()),
                ExternalServiceState::SetStateServiceUpdateMode::ON_CHANGE))
            changed = true;
    };

    if(changed)
        audio_source_data.audio_sources_changed_lock_state_notification();
}

void dcpregs_audiosources_deinit(void)
{
    auto lock(audio_source_data.lock());
    audio_source_data.reset({AudioSourceState::UNAVAILABLE, AudioSourceState::UNAVAILABLE,
                             AudioSourceState::UNAVAILABLE, AudioSourceState::UNAVAILABLE,
                             AudioSourceState::UNAVAILABLE, AudioSourceState::UNAVAILABLE,
                             AudioSourceState::UNAVAILABLE, AudioSourceState::UNAVAILABLE,
                             AudioSourceState::UNAVAILABLE, AudioSourceState::DEAD});
}

static bool check_network_requirements(const AudioSource &asrc)
{
    if(!asrc.check_any_flag(AudioSource::REQUIRES_LAN |
                            AudioSource::REQUIRES_INTERNET))
        return true;

    const bool is_lan_sufficient(!asrc.check_any_flag(AudioSource::REQUIRES_INTERNET));
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

ssize_t dcpregs_read_80_get_known_audio_sources(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 80 handler %p %zu", response, length);

    auto lock(audio_source_data.lock());
    const auto *sel(audio_source_data.get_selected().get());

    RegisterResponseWriter out(response, length);

    out.push_back(uint8_t(GetAudioSourcesCommand::READ_ALL));
    out.push_back(uint8_t(audio_source_data.NUMBER_OF_DEFAULT_SOURCES));

    audio_source_data.for_each([&out, sel] (const AudioSource &asrc)
    {
        out.push_back(asrc.id_);
        out.push_back(asrc.get_name());

        const uint8_t status_byte =
            uint8_t(asrc.check_any_flag(AudioSource::IS_BROWSABLE) ? (1 << 6) : 0) |
            uint8_t(determine_usable(asrc) << 4) |
            uint8_t(asrc.get_state());

        out.push_back(status_byte);
    });

    if(out.is_overflown())
    {
        msg_error(0, LOG_ERR, "Buffer too small for retrieving audio sources");
        return -1;
    }

    return out.get_length();
}

int dcpregs_write_80_get_known_audio_sources(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 80 handler %p %zu", data, length);
    return -1;
}

ssize_t dcpregs_read_81_current_audio_source(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 81 handler %p %zu", response, length);

    auto lock(audio_source_data.lock());

    const AudioSource *src =audio_source_data.get_selected().get();

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

int dcpregs_write_81_current_audio_source(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 81 handler %p %zu", data, length);

    size_t i;

    for(i = 0; i < length && data[i] != '\0'; ++i)
        ;

    if(i >= length)
        return -1;

    if(i == 0)
        return -1;

    const AudioSourceEnableRequest enable_request(i + 1 == length
                                                  ? AudioSourceEnableRequest::KEEP_AS_IS
                                                  : parse_enable_request(data[i + 1]));

    auto lock(audio_source_data.lock());

    const AudioSource *src =
        audio_source_data.lookup_predefined(reinterpret_cast<const char *>(data));

    if(src == nullptr)
    {
        msg_error(0, LOG_NOTICE, "Audio source \"%s\" not known",
                  reinterpret_cast<const char *>(data));
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
        audio_source_data.request_audio_source(*src, true);
        break;

      case AudioSourceState::UNAVAILABLE:
        audio_source_data.request_audio_source(*src, false);
        break;

      case AudioSourceState::DEAD:
      case AudioSourceState::ZOMBIE:
        msg_error(0, LOG_NOTICE, "Audio source \"%s\" is %s",
                  reinterpret_cast<const char *>(data),
                  src->get_state() == AudioSourceState::DEAD ? "dead" : "zombie");
        return -1;
    }

    return 0;
}

void dcpregs_audiosources_source_available(const char *source_id)
{
    auto lock(audio_source_data.lock());

    AudioSource *src = audio_source_data.lookup(source_id);

    if(src != nullptr)
        audio_source_data.audio_source_available_notification(*src);
}

void dcpregs_audiosources_selected_source(const char *source_id)
{
    auto lock(audio_source_data.lock());

    AudioSource *src = audio_source_data.lookup(source_id);

    if(src != nullptr && src == audio_source_data.get_selected().get())
    {
        BUG("Audio source \"%s\" selected again", source_id);
        return;
    }
    else if(src == nullptr)
        src = audio_source_data.insert_extra(source_id);

    log_assert(src != nullptr);
    audio_source_data.selected_audio_source_notification(*src);
}

void dcpregs_audiosources_set_have_credentials(const char *cred_category,
                                               bool have_credentials)
{
    if(global_external_service_state.set_credentials_state(
            cred_category, Maybe<bool>(have_credentials),
            ExternalServiceState::SetStateServiceUpdateMode::ON_CHANGE))
        audio_source_data.audio_sources_changed_lock_state_notification();
}

void dcpregs_audiosources_set_login_state(const char *cred_category,
                                          bool is_logged_in)
{
    if(global_external_service_state.set_login_state(
            cred_category, Maybe<bool>(is_logged_in),
            ExternalServiceState::SetStateServiceUpdateMode::NO_UPDATE))
    {
        global_external_service_state.set_credentials_state(
            cred_category, have_credentials_stored(cred_category),
            ExternalServiceState::SetStateServiceUpdateMode::FORCED);
        audio_source_data.audio_sources_changed_lock_state_notification();
    }
}

void dcpregs_audiosources_set_unit_test_mode(void)
{
    audio_source_data.set_unit_test_mode();
}
