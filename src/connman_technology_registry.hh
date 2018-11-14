/*
 * Copyright (C) 2018  T+A elektroakustik GmbH & Co. KG
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

#ifndef CONNMAN_TECHNOLOGY_REGISTRY_HH
#define CONNMAN_TECHNOLOGY_REGISTRY_HH

#include "connman_property_cache.hh"
#include "messages.h"

#include <mutex>
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
    mutable std::recursive_mutex lock_;

    explicit TechnologyPropertiesBase() = default;

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
        std::lock_guard<std::recursive_mutex> lock(p->lock_);
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
    std::vector<WatcherFn> watchers_;

  public:
    explicit TechnologyPropertiesWIFI():
        proxy_(nullptr)
    {}

    virtual ~TechnologyPropertiesWIFI();

    void set_dbus_object_path(std::string &&path) final override;

    bool available() const final override
    {
        std::lock_guard<std::recursive_mutex> lock(lock_);
        return proxy_ != nullptr;
    }

    struct _tdbusconnmanTechnology *get_dbus_proxy();

    void register_property_watcher(WatcherFn &&fn);

    template <Property property, typename traits = CacheType::ValueTraits<property>>
    const typename traits::Type &get() const
    {
        std::lock_guard<std::recursive_mutex> lock(lock_);
        return cache_.lookup<property>();
    }

    template <Property property, typename traits = CacheType::ValueTraits<property>>
    void set(typename traits::Type &&value)
    {
        std::lock_guard<std::recursive_mutex> lock(lock_);

        if(!ensure_dbus_proxy())
            throw TechnologyRegistryUnavailableError();

        cache_.set<property>(typename traits::Type(value),
                             PropertyCacheWriteRequest::SPECULATIVE_WRITE);
        send_property_over_dbus<typename traits::Type>(property, value);
    }

    template <typename T>
    void cache_value_by_name(const char *name, T &&value)
    {
        std::lock_guard<std::recursive_mutex> lock(lock_);

        const auto &it(std::find(Containers::keys.begin(), Containers::keys.end(), name));
        if(it == Containers::keys.end())
            throw Exceptions::PropertyUnknown();
        const auto property =
            static_cast<Property>(std::distance(Containers::keys.begin(), it));
        if(cache_.do_set<T>(property, PropertyAccess::READ_ONLY, std::move(value),
                            PropertyCacheWriteRequest::STORE_IN_CACHE))
            notify_watchers(property, TechnologyPropertiesBase::StoreResult::UPDATE_NOTIFICATION);
    }

    template <typename T>
    void handle_send_property_over_dbus_done(Property property, bool is_dbus_failure)
    {
        try
        {
            std::lock_guard<std::recursive_mutex> lock(lock_);

            if(is_dbus_failure)
            {
                cache_.do_rollback<T>(property);
                notify_watchers(property, TechnologyPropertiesBase::StoreResult::DBUS_FAILURE);
            }
            else if(cache_.do_commit<T>(property))
                notify_watchers(property, TechnologyPropertiesBase::StoreResult::COMMITTED_AND_UPDATED);
            else
                notify_watchers(property, TechnologyPropertiesBase::StoreResult::COMMITTED_UNCHANGED);
        }
        catch(const Connman::TechnologyPropertiesWIFI::Exceptions::NotPending &e)
        {
            BUG("D-Bus call finished, but have no pending property commit");
            notify_watchers(property, TechnologyPropertiesBase::StoreResult::COMMITTED_UNCHANGED);
        }
        catch(...)
        {
            /* we've been called from C, so we *have* to ignore any exceptions */
            BUG("Got exception while handling end of property sending");
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

    void notify_watchers(Property property, StoreResult result)
    {
        for(const auto &fn : watchers_)
            fn(property, result, *this);
    }

    void technology_signal(struct _GDBusProxy *proxy,
                           const char *sender_name, const char *signal_name,
                           _GVariant *parameters) final override;
};

template <> template <>
struct TechnologyPropertiesWIFI::CacheType::ValueTraits<TechnologyPropertiesWIFI::Property::POWERED>
{
    static constexpr auto access = PropertyAccess::READ_WRITE;
    using Type = bool;
};

template <> template <>
struct TechnologyPropertiesWIFI::CacheType::ValueTraits<TechnologyPropertiesWIFI::Property::CONNECTED>
{
    static constexpr auto access = PropertyAccess::READ_ONLY;
    using Type = bool;
};

template <> template <>
struct TechnologyPropertiesWIFI::CacheType::ValueTraits<TechnologyPropertiesWIFI::Property::NAME>
{
    static constexpr auto access = PropertyAccess::READ_ONLY;
    using Type = std::string;
};

template <> template <>
struct TechnologyPropertiesWIFI::CacheType::ValueTraits<TechnologyPropertiesWIFI::Property::TYPE>
{
    static constexpr auto access = PropertyAccess::READ_ONLY;
    using Type = std::string;
};

template <> template <>
struct TechnologyPropertiesWIFI::CacheType::ValueTraits<TechnologyPropertiesWIFI::Property::TETHERING>
{
    static constexpr auto access = PropertyAccess::READ_WRITE;
    using Type = bool;
};

template <> template <>
struct TechnologyPropertiesWIFI::CacheType::ValueTraits<TechnologyPropertiesWIFI::Property::TETHERING_IDENTIFIER>
{
    static constexpr auto access = PropertyAccess::READ_WRITE;
    using Type = std::string;
};

template <> template <>
struct TechnologyPropertiesWIFI::CacheType::ValueTraits<TechnologyPropertiesWIFI::Property::TETHERING_PASSPHRASE>
{
    static constexpr auto access = PropertyAccess::READ_WRITE;
    using Type = std::string;
};

class TechnologyRegistry
{
  private:
    std::unique_ptr<TechnologyPropertiesWIFI> wifi_properties_;

  public:
    TechnologyRegistry(const TechnologyRegistry &) = delete;
    TechnologyRegistry &operator=(const TechnologyRegistry &) = delete;

    explicit TechnologyRegistry():
        wifi_properties_(new TechnologyPropertiesWIFI)
    {}

    void reset()
    {
        wifi_properties_.reset(new TechnologyPropertiesWIFI);
    }

    void connect_to_connman();

    const TechnologyPropertiesWIFI &wifi() const
    {
        return const_cast<TechnologyRegistry *>(this)->wifi();
    }

    TechnologyPropertiesWIFI &wifi()
    {
        if(wifi_properties_ != nullptr && wifi_properties_->available())
            return *wifi_properties_;

        throw TechnologyRegistryUnavailableError();
    }

    void register_property_watcher(TechnologyPropertiesWIFI::WatcherFn &&fn)
    {
        wifi_properties_->register_property_watcher(std::move(fn));
    }

    static void late_init();

    static std::pair<const TechnologyRegistry&, std::unique_lock<std::recursive_mutex>>
    get_singleton_const();

    static std::pair<TechnologyRegistry &, std::unique_lock<std::recursive_mutex>>
    get_singleton_for_update();
};

}

#endif /* !CONNMAN_TECHNOLOGY_REGISTRY_HH */
