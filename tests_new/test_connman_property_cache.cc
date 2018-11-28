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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <doctest.h>

#include "connman_property_cache.hh"

#include <iostream>

struct Exceptions
{
    class WriteOnly: public std::exception {};
    class ReadOnly: public std::exception {};
    class PropertyUnknown: public std::exception {};
    class NotPending: public std::exception {};
};

namespace Connman
{

class TestProperties
{
  public:
    enum class Property
    {
        GLOBAL_BOOL_VALUE,
        GLOBAL_STRING_VALUE,
        READONLY_BOOL_VALUE,
        READONLY_STRING_VALUE,
        TRIGGER_SOMETHING_BY_BOOL,
        TRIGGER_SOMETHING_BY_STRING,

        LAST_PROPERTY = TRIGGER_SOMETHING_BY_STRING
    };

  private:
    struct Containers: Connman::PropertyContainer<bool>, Connman::PropertyContainer<std::string>
    {
        static const std::array<const char *const, size_t(Property::LAST_PROPERTY) + 1> keys;

        void clear() final override
        {
            Connman::PropertyContainer<bool>::reset();
            Connman::PropertyContainer<std::string>::reset();
        }
    };

  public:
    using CacheType = Connman::PropertyCache<Property, Exceptions, Containers>;
    CacheType cache_;

  public:
    TestProperties(const TestProperties &) = delete;
    TestProperties &operator=(const TestProperties &) = delete;
    explicit TestProperties() = default;
};

template <> template <>
struct TestProperties::CacheType::ValueTraits<TestProperties::Property::GLOBAL_BOOL_VALUE>
{
    static constexpr auto access = PropertyAccess::READ_WRITE;
    using Type = bool;
};

template <> template <>
struct TestProperties::CacheType::ValueTraits<TestProperties::Property::GLOBAL_STRING_VALUE>
{
    static constexpr auto access = PropertyAccess::READ_WRITE;
    using Type = std::string;
};

template <> template <>
struct TestProperties::CacheType::ValueTraits<TestProperties::Property::READONLY_BOOL_VALUE>
{
    static constexpr auto access = PropertyAccess::READ_ONLY;
    using Type = bool;
};

template <> template <>
struct TestProperties::CacheType::ValueTraits<TestProperties::Property::READONLY_STRING_VALUE>
{
    static constexpr auto access = PropertyAccess::READ_ONLY;
    using Type = std::string;
};

template <> template <>
struct TestProperties::CacheType::ValueTraits<TestProperties::Property::TRIGGER_SOMETHING_BY_BOOL>
{
    static constexpr auto access = PropertyAccess::WRITE_ONLY;
    using Type = bool;
};

template <> template <>
struct TestProperties::CacheType::ValueTraits<TestProperties::Property::TRIGGER_SOMETHING_BY_STRING>
{
    static constexpr auto access = PropertyAccess::WRITE_ONLY;
    using Type = std::string;
};

const std::array<const char *const, size_t(TestProperties::Property::LAST_PROPERTY) + 1> TestProperties::Containers::keys
{
    "yes_or_no", "maybe_true", "ro_bool", "ro_string", "do_it_now", "do_this",
};

}

TEST_SUITE_BEGIN("Connman property cache");

class PropertyCacheTestsFixture
{
  protected:
    Connman::TestProperties props_;
};

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Set boolean r/w value directly")
{
    CHECK(props_.cache_.set<Connman::TestProperties::Property::GLOBAL_BOOL_VALUE>(true));
    CHECK(props_.cache_.lookup<Connman::TestProperties::Property::GLOBAL_BOOL_VALUE>());

    CHECK(props_.cache_.set<Connman::TestProperties::Property::GLOBAL_BOOL_VALUE>(false));
    CHECK_FALSE(props_.cache_.lookup<Connman::TestProperties::Property::GLOBAL_BOOL_VALUE>());
};

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Set string r/w value directly")
{
    CHECK(props_.cache_.set<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>("foo"));
    CHECK(props_.cache_.lookup<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>() == "foo");

    CHECK(props_.cache_.set<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>("bar"));
    CHECK(props_.cache_.lookup<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>() == "bar");
};

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Setting boolean read-only value throws (direct)")
{
    CHECK_THROWS_AS(props_.cache_.set<Connman::TestProperties::Property::READONLY_BOOL_VALUE>(true),
                    Exceptions::ReadOnly);
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Setting boolean read-only value throws (speculative)")
{
    CHECK_THROWS_AS(props_.cache_.set<Connman::TestProperties::Property::READONLY_BOOL_VALUE>(
                            true, Connman::PropertyCacheWriteRequest::SPECULATIVE_WRITE),
                    Exceptions::ReadOnly);
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Setting string read-only value throws (direct)")
{
    CHECK_THROWS_AS(props_.cache_.set<Connman::TestProperties::Property::READONLY_STRING_VALUE>("foo"),
                    Exceptions::ReadOnly);
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Setting string read-only value throws (speculative)")
{
    CHECK_THROWS_AS(props_.cache_.set<Connman::TestProperties::Property::READONLY_STRING_VALUE>(
                            "foo", Connman::PropertyCacheWriteRequest::SPECULATIVE_WRITE),
                    Exceptions::ReadOnly);
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Set boolean write-only value")
{
    CHECK(props_.cache_.set<Connman::TestProperties::Property::TRIGGER_SOMETHING_BY_BOOL>(true));
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Set string write-only value")
{
    CHECK(props_.cache_.set<Connman::TestProperties::Property::TRIGGER_SOMETHING_BY_STRING>("foo"));
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Reading from invalid cache throws")
{
    CHECK_THROWS_AS(props_.cache_.lookup<Connman::TestProperties::Property::GLOBAL_BOOL_VALUE>(),
                    Exceptions::PropertyUnknown);
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Reading from boolean write-only value throws")
{
    CHECK(props_.cache_.set<Connman::TestProperties::Property::TRIGGER_SOMETHING_BY_BOOL>(true));
    CHECK_THROWS_AS(props_.cache_.lookup<Connman::TestProperties::Property::TRIGGER_SOMETHING_BY_BOOL>(),
                    Exceptions::WriteOnly);
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Reading from string write-only value throws")
{
    CHECK(props_.cache_.set<Connman::TestProperties::Property::TRIGGER_SOMETHING_BY_STRING>("foo"));
    CHECK_THROWS_AS(props_.cache_.lookup<Connman::TestProperties::Property::TRIGGER_SOMETHING_BY_STRING>(),
                    Exceptions::WriteOnly);
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Cache boolean read-only value")
{
    CHECK(props_.cache_.set<Connman::TestProperties::Property::READONLY_BOOL_VALUE>(
                true, Connman::PropertyCacheWriteRequest::STORE_IN_CACHE));
    CHECK(props_.cache_.lookup<Connman::TestProperties::Property::READONLY_BOOL_VALUE>());

    CHECK(props_.cache_.set<Connman::TestProperties::Property::READONLY_BOOL_VALUE>(
                false, Connman::PropertyCacheWriteRequest::STORE_IN_CACHE));
    CHECK_FALSE(props_.cache_.lookup<Connman::TestProperties::Property::READONLY_BOOL_VALUE>());
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Cache string read-only value")
{
    CHECK(props_.cache_.set<Connman::TestProperties::Property::READONLY_STRING_VALUE>(
                "foo", Connman::PropertyCacheWriteRequest::STORE_IN_CACHE));
    CHECK(props_.cache_.lookup<Connman::TestProperties::Property::READONLY_STRING_VALUE>() == "foo");

    CHECK(props_.cache_.set<Connman::TestProperties::Property::READONLY_STRING_VALUE>(
                "bar", Connman::PropertyCacheWriteRequest::STORE_IN_CACHE));
    CHECK(props_.cache_.lookup<Connman::TestProperties::Property::READONLY_STRING_VALUE>() == "bar");
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Set same boolean to true twice works only once")
{
    CHECK(props_.cache_.set<Connman::TestProperties::Property::GLOBAL_BOOL_VALUE>(true));
    CHECK_FALSE(props_.cache_.set<Connman::TestProperties::Property::GLOBAL_BOOL_VALUE>(true));
    CHECK(props_.cache_.lookup<Connman::TestProperties::Property::GLOBAL_BOOL_VALUE>());
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Set same boolean to false twice works only once")
{
    CHECK(props_.cache_.set<Connman::TestProperties::Property::GLOBAL_BOOL_VALUE>(false));
    CHECK_FALSE(props_.cache_.set<Connman::TestProperties::Property::GLOBAL_BOOL_VALUE>(false));
    CHECK_FALSE(props_.cache_.lookup<Connman::TestProperties::Property::GLOBAL_BOOL_VALUE>());
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Set same string twice works only once")
{
    CHECK(props_.cache_.set<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>("foo"));
    CHECK_FALSE(props_.cache_.set<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>("foo"));
    CHECK(props_.cache_.lookup<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>() == "foo");

    CHECK(props_.cache_.set<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>("bar"));
    CHECK_FALSE(props_.cache_.set<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>("bar"));
    CHECK(props_.cache_.lookup<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>() == "bar");

    CHECK(props_.cache_.set<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>("foo"));
    CHECK(props_.cache_.lookup<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>() == "foo");
    CHECK(props_.cache_.set<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>("qux"));
    CHECK(props_.cache_.lookup<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>() == "qux");
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Speculative write of boolean followed by commit")
{
    static constexpr auto prop = Connman::TestProperties::Property::GLOBAL_BOOL_VALUE;

    CHECK_FALSE(props_.cache_.set<prop>(true, Connman::PropertyCacheWriteRequest::SPECULATIVE_WRITE));
    CHECK_THROWS_AS(props_.cache_.lookup<prop>(), Exceptions::PropertyUnknown);
    CHECK(props_.cache_.commit<prop>());
    CHECK(props_.cache_.lookup<prop>());

    CHECK_FALSE(props_.cache_.set<prop>(false, Connman::PropertyCacheWriteRequest::SPECULATIVE_WRITE));
    CHECK(props_.cache_.lookup<prop>());
    CHECK(props_.cache_.commit<prop>());
    CHECK_FALSE(props_.cache_.lookup<prop>());
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Speculative write of string followed by commit")
{
    static constexpr auto prop = Connman::TestProperties::Property::GLOBAL_STRING_VALUE;

    CHECK_FALSE(props_.cache_.set<prop>("foo", Connman::PropertyCacheWriteRequest::SPECULATIVE_WRITE));
    CHECK_THROWS_AS(props_.cache_.lookup<prop>(), Exceptions::PropertyUnknown);
    CHECK(props_.cache_.commit<prop>());
    CHECK(props_.cache_.lookup<prop>() == "foo");

    CHECK_FALSE(props_.cache_.set<prop>("bar", Connman::PropertyCacheWriteRequest::SPECULATIVE_WRITE));
    CHECK(props_.cache_.lookup<prop>() == "foo");
    CHECK(props_.cache_.commit<prop>());
    CHECK(props_.cache_.lookup<prop>() == "bar");
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Speculative write of same string keeps old value")
{
    CHECK(props_.cache_.set<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>("foo"));
    CHECK_FALSE(props_.cache_.set<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>(
                "foo", Connman::PropertyCacheWriteRequest::SPECULATIVE_WRITE));
    CHECK_FALSE(props_.cache_.commit<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>());
    CHECK(props_.cache_.lookup<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>() == "foo");
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Speculative write of boolean followed by rollback (first)")
{
    static constexpr auto prop = Connman::TestProperties::Property::GLOBAL_BOOL_VALUE;

    CHECK_FALSE(props_.cache_.set<prop>(true, Connman::PropertyCacheWriteRequest::SPECULATIVE_WRITE));
    CHECK_THROWS_AS(props_.cache_.lookup<prop>(), Exceptions::PropertyUnknown);
    props_.cache_.rollback<prop>();
    CHECK_THROWS_AS(props_.cache_.lookup<prop>(), Exceptions::PropertyUnknown);
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Speculative write of boolean followed by rollback (second)")
{
    static constexpr auto prop = Connman::TestProperties::Property::GLOBAL_BOOL_VALUE;

    CHECK_FALSE(props_.cache_.set<prop>(true, Connman::PropertyCacheWriteRequest::SPECULATIVE_WRITE));
    CHECK_THROWS_AS(props_.cache_.lookup<prop>(), Exceptions::PropertyUnknown);
    CHECK(props_.cache_.commit<prop>());
    CHECK(props_.cache_.lookup<prop>());

    CHECK_FALSE(props_.cache_.set<prop>(false, Connman::PropertyCacheWriteRequest::SPECULATIVE_WRITE));
    CHECK(props_.cache_.lookup<prop>());
    props_.cache_.rollback<prop>();
    CHECK(props_.cache_.lookup<prop>());
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Committing for non-pending write throws")
{
    CHECK_THROWS_AS(props_.cache_.commit<Connman::TestProperties::Property::GLOBAL_BOOL_VALUE>(),
                    Exceptions::NotPending);
    CHECK_THROWS_AS(props_.cache_.commit<Connman::TestProperties::Property::GLOBAL_BOOL_VALUE>(),
                    Exceptions::NotPending);
    CHECK_THROWS_AS(props_.cache_.commit<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>(),
                    Exceptions::NotPending);
    CHECK_THROWS_AS(props_.cache_.commit<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>(),
                    Exceptions::NotPending);
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Rolling back for non-pending write throws")
{
    CHECK_THROWS_AS(props_.cache_.rollback<Connman::TestProperties::Property::GLOBAL_BOOL_VALUE>(),
                    Exceptions::NotPending);
    CHECK_THROWS_AS(props_.cache_.rollback<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>(),
                    Exceptions::NotPending);
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Reset cache removes all values")
{
    auto &c(props_.cache_);

    CHECK(c.set<Connman::TestProperties::Property::GLOBAL_BOOL_VALUE>(true));
    CHECK(c.set<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>("foo"));
    CHECK(c.set<Connman::TestProperties::Property::READONLY_BOOL_VALUE>(true, Connman::PropertyCacheWriteRequest::STORE_IN_CACHE));
    CHECK(c.set<Connman::TestProperties::Property::READONLY_STRING_VALUE>("bar", Connman::PropertyCacheWriteRequest::STORE_IN_CACHE));
    CHECK(c.set<Connman::TestProperties::Property::TRIGGER_SOMETHING_BY_BOOL>(true));
    CHECK(c.set<Connman::TestProperties::Property::TRIGGER_SOMETHING_BY_STRING>("qux"));

    CHECK(c.lookup<Connman::TestProperties::Property::GLOBAL_BOOL_VALUE>());
    CHECK(c.lookup<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>() == "foo");
    CHECK(c.lookup<Connman::TestProperties::Property::READONLY_BOOL_VALUE>());
    CHECK(c.lookup<Connman::TestProperties::Property::READONLY_STRING_VALUE>() == "bar");

    c.reset();

    CHECK_THROWS_AS(c.lookup<Connman::TestProperties::Property::GLOBAL_BOOL_VALUE>(),
                    Exceptions::PropertyUnknown);
    CHECK_THROWS_AS(c.lookup<Connman::TestProperties::Property::GLOBAL_STRING_VALUE>(),
                    Exceptions::PropertyUnknown);
    CHECK_THROWS_AS(c.lookup<Connman::TestProperties::Property::READONLY_BOOL_VALUE>(),
                    Exceptions::PropertyUnknown);
    CHECK_THROWS_AS(c.lookup<Connman::TestProperties::Property::READONLY_STRING_VALUE>(),
                    Exceptions::PropertyUnknown);
}

TEST_CASE_FIXTURE(PropertyCacheTestsFixture, "Reset cache cancels speculative writes")
{
    auto &c(props_.cache_);

    CHECK_FALSE(c.set<Connman::TestProperties::Property::GLOBAL_BOOL_VALUE>(true, Connman::PropertyCacheWriteRequest::SPECULATIVE_WRITE));
    c.reset();
    CHECK_THROWS_AS(c.commit<Connman::TestProperties::Property::GLOBAL_BOOL_VALUE>(),
                    Exceptions::NotPending);
}

TEST_SUITE_END();
