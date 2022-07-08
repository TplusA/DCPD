/*
 * Copyright (C) 2018, 2019, 2022  T+A elektroakustik GmbH & Co. KG
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

#ifndef MOCK_CONNMAN_TECHNOLOGY_REGISTRY_HH
#define MOCK_CONNMAN_TECHNOLOGY_REGISTRY_HH

#include "connman_technology_registry.hh"
#include "mock_expectation.hh"

#include <string>

namespace MockConnmanTechnologyRegistry
{

struct FixtureSetupData
{
    struct _tdbusconnmanTechnology *wifi_tech_proxy;
    bool wifi_properties_are_initialized;
    bool wifi_is_powered;
    bool wifi_is_connected;
    bool wifi_is_tethering;
    std::string wifi_tethering_identifier;
    std::string wifi_tethering_passphrase;

    FixtureSetupData(const FixtureSetupData &) = delete;
    FixtureSetupData(FixtureSetupData &&) = default;
    FixtureSetupData &operator=(const FixtureSetupData &) = delete;
    FixtureSetupData &operator=(FixtureSetupData &&) = default;

    explicit FixtureSetupData():
        wifi_tech_proxy(nullptr),
        wifi_properties_are_initialized(true),
        wifi_is_powered(false),
        wifi_is_connected(false),
        wifi_is_tethering(false)
    {}
};

void setup_fixture(const FixtureSetupData &sd);
void reset_singleton();

namespace Wifi
{

/*! Base class for expectations. */
class Expectation
{
  private:
    std::string name_;
    unsigned int sequence_serial_;

  public:
    Expectation(const Expectation &) = delete;
    Expectation(Expectation &&) = default;
    Expectation &operator=(const Expectation &) = delete;
    Expectation &operator=(Expectation &&) = default;
    Expectation(std::string &&name):
        name_(std::move(name)),
        sequence_serial_(std::numeric_limits<unsigned int>::max())
    {}
    virtual ~Expectation() {}
    const std::string &get_name() const { return name_; }
    void set_sequence_serial(unsigned int ss) { sequence_serial_ = ss; }
    unsigned int get_sequence_serial() const { return sequence_serial_; }
};

class Mock
{
  private:
    Connman::TechnologyRegistry &tech_reg_;
    MockExpectationsTemplate<Expectation> expectations_;

  public:
    Mock(const Mock &) = delete;
    Mock &operator=(const Mock &) = delete;

    explicit Mock(Connman::TechnologyRegistry &tech_reg):
        tech_reg_(tech_reg),
        expectations_("MockConnmanTechnologyRegistry::Wifi")
    {}

    ~Mock() = default;

    void expect(std::unique_ptr<Expectation> expectation)
    {
        expectations_.add(std::move(expectation));
    }

    void expect(Expectation *expectation)
    {
        expectations_.add(std::unique_ptr<Expectation>(expectation));
    }

    template <typename T>
    void ignore(std::unique_ptr<T> default_result)
    {
        expectations_.ignore<T>(std::move(default_result));
    }

    template <typename T>
    void ignore(T *default_result)
    {
        expectations_.ignore<T>(std::unique_ptr<Expectation>(default_result));
    }

    template <typename T>
    void allow() { expectations_.allow<T>(); }

    void done() const { expectations_.done(); }

    template <typename T, typename ... Args>
    auto check_next(Args ... args) -> decltype(std::declval<T>().check(args...))
    {
        return expectations_.check_and_advance<T, decltype(std::declval<T>().check(args...))>(args...);
    }

    template <typename T>
    void simulate_send_property_over_dbus_done(Connman::TechnologyPropertiesWIFI::Property property,
                                               bool is_dbus_failure)
    {
        tech_reg_.wifi().handle_send_property_over_dbus_done<T>(property, is_dbus_failure);
    }

    template <typename T>
    void simulate_property_changed_signal(const char *property_name, T &&value)
    {
        tech_reg_.wifi().cache_value_by_name(property_name, std::move(value));
    }
};


extern Mock *singleton;

template <typename T>
class SendPropertyOverDBus: public Expectation
{
  private:
    const Connman::TechnologyPropertiesWIFI::Property property_;
    const T value_;

  public:
    explicit SendPropertyOverDBus(Connman::TechnologyPropertiesWIFI::Property property, T &&value):
        Expectation("SendPropertyOverDBus"),
        property_(property),
        value_(std::move(value))
    {}

    virtual ~SendPropertyOverDBus() = default;

    void check(Connman::TechnologyPropertiesWIFI::Property property, const T &value) const
    {
        CHECK(int(property) == int(property_));
        CHECK(value == value_);
    }
};

class SetDBusObjectPath: public Expectation
{
  private:
    const std::string path_;
    struct _tdbusconnmanTechnology *const proxy_;

  public:
    explicit SetDBusObjectPath(std::string &&path, struct _tdbusconnmanTechnology *proxy):
        Expectation("SetDBusObjectPath"),
        path_(path),
        proxy_(proxy)
    {}

    virtual ~SetDBusObjectPath() = default;

    struct _tdbusconnmanTechnology *check(const std::string &path) const
    {
        CHECK(path == path_);
        return proxy_;
    }
};

class EnsureDBusProxy: public Expectation
{
  private:
    const bool retval_;
    struct _tdbusconnmanTechnology *const proxy_;

  public:
    explicit EnsureDBusProxy(bool retval, struct _tdbusconnmanTechnology *proxy):
        Expectation("EnsureDBusProxy"),
        retval_(retval),
        proxy_(proxy)
    {}

    virtual ~EnsureDBusProxy() = default;

    std::pair<bool, struct _tdbusconnmanTechnology *> check() const
    {
        return std::make_pair(retval_, proxy_);
    }

    std::pair<bool, struct _tdbusconnmanTechnology *> ignored() const
    {
        return std::make_pair(retval_, proxy_);
    }
};

}

}

#endif /* !MOCK_CONNMAN_TECHNOLOGY_REGISTRY_HH */
