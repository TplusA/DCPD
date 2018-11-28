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

#ifndef CONNMAN_PROPERTY_CACHE_HH
#define CONNMAN_PROPERTY_CACHE_HH

#include <map>
#include <string>

namespace Connman
{

enum class PropertyAccess
{
    READ_WRITE,
    READ_ONLY,
    WRITE_ONLY,
};

enum class PropertyCacheWriteRequest
{
    WRITE_THROUGH,
    SPECULATIVE_WRITE,
    STORE_IN_CACHE,
};

template <typename T>
struct PropertyContainer
{
    std::map<std::string, T> values;
    std::map<std::string, T> pending;

    PropertyContainer(const PropertyContainer &) = delete;
    explicit PropertyContainer() = default;
    virtual ~PropertyContainer() = default;

    virtual void clear() = 0;

  protected:
    void reset()
    {
        values.clear();
        pending.clear();
    }
};

template <typename Property, typename ExceptionTypes, typename PropertyContainers>
class PropertyCache
{
  public:
    template <Property P> struct ValueTraits;

  private:
    PropertyContainers store_;
    bool is_valid_;

  public:
    PropertyCache(const PropertyCache &) = delete;
    PropertyCache &operator=(const PropertyCache &) = delete;

    explicit PropertyCache(): is_valid_(false) {}

    void reset() { store_.clear(); }

    template <Property property, typename traits = ValueTraits<property>>
    const typename traits::Type &lookup() const
    {
        return do_lookup<typename traits::Type>(property, traits::access);
    }

    template <Property property, typename traits = ValueTraits<property>>
    typename traits::Type &lookup()
    {
        return do_lookup<typename traits::Type>(property, traits::access);
    }

    template <Property property, typename traits = ValueTraits<property>>
    bool set(typename traits::Type &&value,
             PropertyCacheWriteRequest cwr = PropertyCacheWriteRequest::WRITE_THROUGH)
    {
        return do_set<typename traits::Type>(property, traits::access,
                                             std::move(value), cwr);
    }

    template <typename T>
    bool do_set(Property property, PropertyAccess access, T &&value,
                PropertyCacheWriteRequest cwr = PropertyCacheWriteRequest::WRITE_THROUGH)
    {
        switch(cwr)
        {
          case PropertyCacheWriteRequest::WRITE_THROUGH:
          case PropertyCacheWriteRequest::SPECULATIVE_WRITE:
            switch(access)
            {
              case PropertyAccess::READ_ONLY:
                throw typename ExceptionTypes::ReadOnly();

              case PropertyAccess::READ_WRITE:
              case PropertyAccess::WRITE_ONLY:
                break;
            }

            break;

          case PropertyCacheWriteRequest::STORE_IN_CACHE:
            break;
        }

        PropertyContainer<T> &c(store_);
        const auto &key(PropertyContainers::keys[size_t(property)]);

        switch(cwr)
        {
          case PropertyCacheWriteRequest::WRITE_THROUGH:
          case PropertyCacheWriteRequest::STORE_IN_CACHE:
            if(c.values.find(key) != c.values.end() && c.values[key] == value)
                break;

            c.values[key] = std::move(value);
            return true;

          case PropertyCacheWriteRequest::SPECULATIVE_WRITE:
            c.pending[key] = std::move(value);
            break;
        }

        return false;
    }

  private:
    template <typename T>
    const T &do_lookup(Property property, PropertyAccess access) const
    {
        switch(access)
        {
          case PropertyAccess::READ_ONLY:
          case PropertyAccess::READ_WRITE:
            break;

          case PropertyAccess::WRITE_ONLY:
            throw typename ExceptionTypes::WriteOnly();
        }

        try
        {
            const PropertyContainer<T> &c(store_);
            return c.values.at(PropertyContainers::keys[size_t(property)]);
        }
        catch(const std::out_of_range &e)
        {
            throw typename ExceptionTypes::PropertyUnknown();
        }
    }

    template <typename T>
    T &do_lookup(Property property, PropertyAccess access)
    {
        switch(access)
        {
          case PropertyAccess::READ_ONLY:
          case PropertyAccess::READ_WRITE:
            break;

          case PropertyAccess::WRITE_ONLY:
            throw typename ExceptionTypes::WriteOnly();
        }

        try
        {
            PropertyContainer<T> &c(store_);
            return c.values.at(PropertyContainers::keys[size_t(property)]);
        }
        catch(const std::out_of_range &e)
        {
            throw typename ExceptionTypes::PropertyUnknown();
        }
    }

  public:
    template <Property property, typename traits = ValueTraits<property>>
    bool commit()
    {
        return do_commit<typename traits::Type>(property);
    }

    template <typename T>
    bool do_commit(Property property)
    {
        PropertyContainer<T> &c(store_);
        const auto &key(PropertyContainers::keys[size_t(property)]);
        bool result = false;

        try
        {
            if(c.values.find(key) == c.values.end() ||
               c.values[key] != c.pending.at(key))
            {
                c.values[key] = std::move(c.pending.at(key));
                result = true;
            }

            c.pending.erase(key);
        }
        catch(const std::out_of_range &e)
        {
            throw typename ExceptionTypes::NotPending();
        }

        return result;
    }

    template <Property property, typename traits = ValueTraits<property>>
    void rollback()
    {
        do_rollback<typename traits::Type>(property);
    }

    template <typename T>
    void do_rollback(Property property)
    {
        PropertyContainer<T> &c(store_);

        if(c.pending.find(PropertyContainers::keys[size_t(property)]) != c.pending.end())
            c.pending.erase(PropertyContainers::keys[size_t(property)]);
        else
            throw typename ExceptionTypes::NotPending();
    }
};

}

#endif /* !CONNMAN_PROPERTY_CACHE_HH */
