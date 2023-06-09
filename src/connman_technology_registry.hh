/*
 * Copyright (C) 2018, 2019, 2022, 2023  T+A elektroakustik GmbH & Co. KG
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

#ifndef CONNMAN_TECHNOLOGY_REGISTRY_HH
#define CONNMAN_TECHNOLOGY_REGISTRY_HH

#include "connman_property_cache.hh"
#include "messages.h"
#include "logged_lock.hh"

#include <vector>
#include <array>
#include <memory>
#include <functional>
#include <algorithm>

/*
 * No, we will *NOT* include stupid GLib headers and litter our global
 * namespace with random junk at this point.
 */
struct _GObject;
struct _GVariant;
struct _GAsyncResult;
struct _GDBusProxy;
struct _tdbusconnmanTechnology;

namespace Connman
{

class TechnologyRegistryError: public std::exception
{
  private:
    const std::string error_message_;

  public:
    explicit TechnologyRegistryError(const char *msg): error_message_(msg) {}
    explicit TechnologyRegistryError(std::string &msg): error_message_(std::move(msg)) {}

    const char *what() const noexcept final override
    {
        return error_message_.c_str();
    }
};

class TechnologyRegistryUnavailableError: public TechnologyRegistryError
{
  public:
    TechnologyRegistryUnavailableError(): TechnologyRegistryError("unavailable") {}
};

class TechnologyPropertiesBase
{
  public:
    enum class StoreResult
    {
        UPDATE_NOTIFICATION,
        COMMITTED_AND_UPDATED,
        COMMITTED_UNCHANGED,
        DBUS_FAILURE,
        UNKNOWN_ERROR,
    };

  protected:
    std::string dbus_object_path_;
    mutable LoggedLock::RecMutex lock_;

    explicit TechnologyPropertiesBase()
    {
        LoggedLock::configure(lock_, "Connman::TechnologyPropertiesBase", MESSAGE_LEVEL_DEBUG);
    }

  public:
    TechnologyPropertiesBase(const TechnologyPropertiesBase &) = delete;
    TechnologyPropertiesBase &operator=(const TechnologyPropertiesBase &) = delete;
    virtual ~TechnologyPropertiesBase() = default;

    virtual void set_dbus_object_path(std::string &&path) = 0;
    virtual bool available() const = 0;

    static void dbus_signal_trampoline(struct _GDBusProxy *proxy,
                                       const char *sender_name,
                                       const char *signal_name,
                                       _GVariant *parameters,
                                       void *user_data)
    {
        auto *const p = static_cast<TechnologyPropertiesBase *>(user_data);
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::RecMutex> lock(p->lock_);
        p->technology_signal(proxy, sender_name, signal_name, parameters);
    }

  protected:
    virtual void technology_signal(struct _GDBusProxy *proxy,
                                   const char *sender_name, const char *signal_name,
                                   _GVariant *parameters) = 0;
};

class TechnologyPropertiesWIFI: public TechnologyPropertiesBase
{
  public:
    enum class Property
    {
        POWERED,
        CONNECTED,
        NAME,
        TYPE,
        TETHERING,
        TETHERING_IDENTIFIER,
        TETHERING_PASSPHRASE,

        LAST_PROPERTY = TETHERING_PASSPHRASE,
    };

  private:
    struct Containers: PropertyContainer<bool>, PropertyContainer<std::string>
    {
        static const std::array<const std::string, static_cast<size_t>(Property::LAST_PROPERTY) + 1> keys;

        void clear() final override
        {
            Connman::PropertyContainer<bool>::reset();
            Connman::PropertyContainer<std::string>::reset();
        }
    };

  public:
    struct Exceptions
    {
        class WriteOnly: public TechnologyRegistryError
        {
          public:
            WriteOnly(): TechnologyRegistryError("write-only property") {}
        };
        class ReadOnly: public TechnologyRegistryError
        {
          public:
            ReadOnly(): TechnologyRegistryError("read-only property") {}
        };
        class PropertyUnknown: public TechnologyRegistryError
        {
          public:
            PropertyUnknown(): TechnologyRegistryError("unknown property") {}
        };
        class NotPending: public TechnologyRegistryError
        {
          public:
            NotPending(): TechnologyRegistryError("no pending property write") {}
        };
    };

    using WatcherFn = std::function<void(Property property, StoreResult, TechnologyPropertiesWIFI &)>;
    using CacheType = PropertyCache<Property, Exceptions, Containers>;

  private:
    CacheType cache_;
    struct _tdbusconnmanTechnology *proxy_;

    LoggedLock::Mutex watchers_lock_;
    std::vector<WatcherFn> watchers_;

  public:
    explicit TechnologyPropertiesWIFI():
        proxy_(nullptr)
    {
        LoggedLock::configure(watchers_lock_,
                              "Connman::TechnologyPropertiesWIFI::watchers_",
                              MESSAGE_LEVEL_DEBUG);
    }

    virtual ~TechnologyPropertiesWIFI();

    void set_dbus_object_path(std::string &&path) final override;

    bool available() const final override
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::RecMutex> lock(lock_);
        return proxy_ != nullptr;
    }

    struct _tdbusconnmanTechnology *get_dbus_proxy();

    void register_property_watcher(WatcherFn &&fn);

    template <Property property, typename traits = CacheType::ValueTraits<property>>
    const typename traits::Type &get() const
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::RecMutex> lock(lock_);
        return cache_.lookup<property>();
    }

    template <Property property, typename traits = CacheType::ValueTraits<property>>
    void set(typename traits::Type &&value)
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::RecMutex> lock(lock_);

        if(!ensure_dbus_proxy())
            throw TechnologyRegistryUnavailableError();

        cache_.set<property>(typename traits::Type(value),
                             PropertyCacheWriteRequest::SPECULATIVE_WRITE);
        send_property_over_dbus<typename traits::Type>(property, value);
    }

    template <typename T>
    void cache_value_by_name(const char *name, T &&value)
    {
        LOGGED_LOCK_CONTEXT_HINT;
        LoggedLock::UniqueLock<LoggedLock::RecMutex> lock(lock_);

        const auto &it(std::find(Containers::keys.begin(), Containers::keys.end(), name));
        if(it == Containers::keys.end())
            throw Exceptions::PropertyUnknown();
        const auto property =
            static_cast<Property>(std::distance(Containers::keys.begin(), it));
        if(cache_.do_set<T>(property, PropertyAccess::READ_ONLY, std::move(value),
                            PropertyCacheWriteRequest::STORE_IN_CACHE))
        {
            LOGGED_LOCK_CONTEXT_HINT;
            lock.unlock();
            notify_watchers(property, TechnologyPropertiesBase::StoreResult::UPDATE_NOTIFICATION);
        }
    }

    template <typename T>
    void handle_send_property_over_dbus_done(Property property, bool is_dbus_failure)
    {
        try
        {
            LOGGED_LOCK_CONTEXT_HINT;
            LoggedLock::UniqueLock<LoggedLock::RecMutex> lock(lock_);

            if(is_dbus_failure)
            {
                cache_.do_rollback<T>(property);
                LOGGED_LOCK_CONTEXT_HINT;
                lock.unlock();
                notify_watchers(property, TechnologyPropertiesBase::StoreResult::DBUS_FAILURE);
            }
            else if(cache_.do_commit<T>(property))
            {
                LOGGED_LOCK_CONTEXT_HINT;
                lock.unlock();
                notify_watchers(property, TechnologyPropertiesBase::StoreResult::COMMITTED_AND_UPDATED);
            }
            else
            {
                LOGGED_LOCK_CONTEXT_HINT;
                lock.unlock();
                notify_watchers(property, TechnologyPropertiesBase::StoreResult::COMMITTED_UNCHANGED);
            }
        }
        catch(const Connman::TechnologyPropertiesWIFI::Exceptions::NotPending &e)
        {
            MSG_BUG("D-Bus call finished, but have no pending property commit");
            notify_watchers(property, TechnologyPropertiesBase::StoreResult::COMMITTED_UNCHANGED);
        }
        catch(...)
        {
            /* we've been called from C, so we *have* to ignore any exceptions */
            MSG_BUG("Got exception while handling end of property sending");
            notify_watchers(property, TechnologyPropertiesBase::StoreResult::UNKNOWN_ERROR);
        }
    }

  private:
    bool ensure_dbus_proxy();

    template <typename T>
    void send_property_over_dbus(Property key, const T &value);

    template <typename T>
    static void send_property_over_dbus_done(struct _GObject *source_object,
                                             struct _GAsyncResult *res, void *user_data);

    /*!
     * Notify all registered watchers about property change.
     *
     * \note
     *     Must be called without holding
     *     #Connman::TechnologyPropertiesBase::lock_.
     */
    void notify_watchers(Property property, StoreResult result);

    void technology_signal(struct _GDBusProxy *proxy,
                           const char *sender_name, const char *signal_name,
                           _GVariant *parameters) final override;
};

#ifdef DOXYGEN
/* it's actually wrong to put the FQNS, but Doxygen doesn't understand the
 * correct syntax */
#define CONNMAN_NS  ::Connman::
#else /* !DOXYGEN */
#define CONNMAN_NS
#endif /* DOXYGEN */

template <> template <>
struct CONNMAN_NS TechnologyPropertiesWIFI::CacheType::ValueTraits<TechnologyPropertiesWIFI::Property::POWERED>
{
    static constexpr auto access = PropertyAccess::READ_WRITE;
    using Type = bool;
};

template <> template <>
struct CONNMAN_NS TechnologyPropertiesWIFI::CacheType::ValueTraits<TechnologyPropertiesWIFI::Property::CONNECTED>
{
    static constexpr auto access = PropertyAccess::READ_ONLY;
    using Type = bool;
};

template <> template <>
struct CONNMAN_NS TechnologyPropertiesWIFI::CacheType::ValueTraits<TechnologyPropertiesWIFI::Property::NAME>
{
    static constexpr auto access = PropertyAccess::READ_ONLY;
    using Type = std::string;
};

template <> template <>
struct CONNMAN_NS TechnologyPropertiesWIFI::CacheType::ValueTraits<TechnologyPropertiesWIFI::Property::TYPE>
{
    static constexpr auto access = PropertyAccess::READ_ONLY;
    using Type = std::string;
};

template <> template <>
struct CONNMAN_NS TechnologyPropertiesWIFI::CacheType::ValueTraits<TechnologyPropertiesWIFI::Property::TETHERING>
{
    static constexpr auto access = PropertyAccess::READ_WRITE;
    using Type = bool;
};

template <> template <>
struct CONNMAN_NS TechnologyPropertiesWIFI::CacheType::ValueTraits<TechnologyPropertiesWIFI::Property::TETHERING_IDENTIFIER>
{
    static constexpr auto access = PropertyAccess::READ_WRITE;
    using Type = std::string;
};

template <> template <>
struct CONNMAN_NS TechnologyPropertiesWIFI::CacheType::ValueTraits<TechnologyPropertiesWIFI::Property::TETHERING_PASSPHRASE>
{
    static constexpr auto access = PropertyAccess::READ_WRITE;
    using Type = std::string;
};

class TechnologyRegistry
{
  private:
    TechnologyPropertiesWIFI wifi_properties_;
    mutable LoggedLock::RecMutex lock_;

  public:
    TechnologyRegistry(const TechnologyRegistry &) = delete;
    TechnologyRegistry &operator=(const TechnologyRegistry &) = delete;

    explicit TechnologyRegistry()
    {
        LoggedLock::configure(lock_, "Connman::TechnologyRegistry", MESSAGE_LEVEL_DEBUG);
    }

    LoggedLock::UniqueLock<LoggedLock::RecMutex> locked() const
    {
        return LoggedLock::UniqueLock<LoggedLock::RecMutex>(lock_);
    }

    void connect_to_connman(const void *data = nullptr);

    const TechnologyPropertiesWIFI &wifi() const
    {
        return const_cast<TechnologyRegistry *>(this)->wifi();
    }

    TechnologyPropertiesWIFI &wifi()
    {
        if(wifi_properties_.available())
            return wifi_properties_;

        throw TechnologyRegistryUnavailableError();
    }

    void register_property_watcher(TechnologyPropertiesWIFI::WatcherFn &&fn)
    {
        wifi_properties_.register_property_watcher(std::move(fn));
    }
};

}

#endif /* !CONNMAN_TECHNOLOGY_REGISTRY_HH */
