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
#include <algorithm>
#include <mutex>

#include "dcpregs_audiosources.h"
#include "registers_priv.h"
#include "dbus_iface_deep.h"
#include "dbus_common.h"
#include "gvariantwrapper.hh"
#include "messages.h"

enum class AudioSourceState
{
    UNAVAILABLE,
    DEAD,
    ALIVE,
    LOCKED,
    ZOMBIE,
};

enum class SelectionState
{
    IDLE,
    PENDING,
    SELECTING,
    SELECTION_REQUEST_FAILED,
    SELECTION_REQUEST_DONE,
};

class AudioSource
{
  public:
    using Flags = uint16_t;

    /* OR-able flags */
    static constexpr Flags IS_BROWSABLE     = 1U << 0;
    static constexpr Flags REQUIRES_NETWORK = 1U << 1;
    static constexpr Flags CAN_BE_LOCKED    = 1U << 2;

    const std::string id_;

  private:
    const std::string default_name_;
    const Flags flags_;
    const std::function<bool(const AudioSource &)> check_unlocked_fn_;

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
                         std::function<bool(const AudioSource &)> &&check_unlocked_fn = nullptr,
                         bool is_dead = false):
        id_(std::move(id)),
        default_name_(std::move(default_name)),
        flags_(flags),
        check_unlocked_fn_(check_unlocked_fn),
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
            state_ = (check_any_flag(CAN_BE_LOCKED) && !check_unlocked_fn_(*this))
                ? AudioSourceState::LOCKED
                : AudioSourceState::ALIVE;
            break;

          case AudioSourceState::DEAD:
          case AudioSourceState::ALIVE:
          case AudioSourceState::LOCKED:
          case AudioSourceState::ZOMBIE:
            break;
        }
    }

    void set_name(const char *name)
    {
        if(name == nullptr || name[0] == '\0' || default_name_ == name)
            name_override_.clear();
        else if(name_override_ != name)
            name_override_ = name;
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

    AudioSource *lookup_predefined(const char *id)
    {
        const auto it(std::find_if(default_sources_.begin(), default_sources_.end(),
                                   [id] (const AudioSource &src) { return src.id_ == id; }));
        return it != default_sources_.end() ? it : nullptr;
    }

    const AudioSource *lookup_predefined(const char *id) const
    {
        return const_cast<AudioSourceData *>(this)->lookup_predefined(id);
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
};

static bool have_credentials(const AudioSource &src)
{
    BUG("Should check credentials for audio source %s", src.id_.c_str());
    return false;
}

static AudioSourceData audio_source_data(
{
    AudioSource("strbo.usb",      "USB devices",             AudioSource::IS_BROWSABLE),
    AudioSource("strbo.upnpcm",   "UPnP media servers",      AudioSource::IS_BROWSABLE | AudioSource::REQUIRES_NETWORK),
    AudioSource("strbo.plainurl", "TA Control",              AudioSource::REQUIRES_NETWORK),
    AudioSource("airable",        "Airable",                 AudioSource::IS_BROWSABLE | AudioSource::REQUIRES_NETWORK),
    AudioSource("airable.radios", "Airable Internet Radios", AudioSource::IS_BROWSABLE | AudioSource::REQUIRES_NETWORK),
    AudioSource("airable.feeds",  "Airable Podcasts",        AudioSource::IS_BROWSABLE | AudioSource::REQUIRES_NETWORK),
    AudioSource("airable.tidal",  "TIDAL",
                AudioSource::IS_BROWSABLE | AudioSource::REQUIRES_NETWORK | AudioSource::CAN_BE_LOCKED,
                have_credentials),
    AudioSource("airable.deezer", "Deezer",
                AudioSource::IS_BROWSABLE | AudioSource::REQUIRES_NETWORK | AudioSource::CAN_BE_LOCKED,
                have_credentials),
    AudioSource("airable.qobuz",  "Qobuz",
                AudioSource::IS_BROWSABLE | AudioSource::REQUIRES_NETWORK | AudioSource::CAN_BE_LOCKED,
                have_credentials),
    AudioSource("roon",           "Roon Ready",              AudioSource::REQUIRES_NETWORK, nullptr, true),
});

void dcpregs_audiosources_init(void)
{
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

void dcpregs_audiosources_deinit(void)
{
    auto lock(audio_source_data.lock());
    audio_source_data.reset({AudioSourceState::UNAVAILABLE, AudioSourceState::UNAVAILABLE,
                             AudioSourceState::UNAVAILABLE, AudioSourceState::UNAVAILABLE,
                             AudioSourceState::UNAVAILABLE, AudioSourceState::UNAVAILABLE,
                             AudioSourceState::UNAVAILABLE, AudioSourceState::UNAVAILABLE,
                             AudioSourceState::UNAVAILABLE, AudioSourceState::DEAD});
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

int dcpregs_write_81_current_audio_source(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 81 handler %p %zu", data, length);

    size_t i;

    for(i = 0; i < length && data[i] != '\0'; ++i)
        ;

    /* we require a zero-terminated string to allow future extensions to be
     * appended to the source ID */
    if(i >= length)
        return -1;

    if(i == 0)
        return -1;

    auto lock(audio_source_data.lock());

    const AudioSource *src =
        audio_source_data.lookup_predefined(reinterpret_cast<const char *>(data));

    if(src == nullptr)
    {
        msg_error(0, LOG_NOTICE, "Audio source \"%s\" not known",
                  reinterpret_cast<const char *>(data));
        return -1;
    }

    switch(src->get_state())
    {
      case AudioSourceState::ALIVE:
      case AudioSourceState::LOCKED:
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

void dcpregs_audiosources_set_unit_test_mode(void)
{
    audio_source_data.set_unit_test_mode();
}
