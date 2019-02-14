/*
 * Copyright (C) 2016, 2017, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#include "dbus_handlers_connman_manager.hh"
#include "dbus_iface_deep.h"
#include "dcpregs_networkconfig.hh"
#include "connman_scan.hh"
#include "connman_agent.h"
#include "connman_common.h"
#include "connman_service_list.hh"
#include "network_device_list.hh"
#include "dbus_common.h"

#include <functional>
#include <cinttypes>

/*!
 * Representation of WLAN connection attempts.
 *
 * Each such object keeps track of a single service connect request sent to
 * ConnMan. The objects are not meant to be reused---once constructed, they are
 * useful for a single connection attempt. When the connection attempt is over,
 * a call of #WLANConnection::succeed() or #WLANConnection::fail() is expected,
 * each of which leading the object to its final state and close to its end of
 * life.
 *
 * After a connection has been established or on failure, all objects involved
 * in making a connection are to be destroyed.
 */
class WLANConnection
{
  public:
    enum class State
    {
        NOT_IN_USE,
        RUNNING,
        HAVE_RESULT,
        SUCCEEDED,
        FAILED,
    };

    using CallbackType =
        std::function<void(const std::string &service_name, bool succeeded)>;

  private:
    std::string service_name_;
    tdbusconnmanService *proxy_;
    CallbackType ready_cb_;
    State state_;

  public:
    WLANConnection(const WLANConnection &) = delete;
    WLANConnection(WLANConnection &&) = default;
    WLANConnection &operator=(const WLANConnection &) = delete;

    explicit WLANConnection(std::string &&service_name):
        service_name_(std::move(service_name)),
        proxy_(nullptr),
        state_(State::NOT_IN_USE)
    {}

    ~WLANConnection()
    {
        if(proxy_ != nullptr)
            g_object_unref(proxy_);
    }

    State get_state() const { return state_; }

    const std::string &get_service_name() const { return service_name_; }

    bool is_in_use() const { return state_ != State::NOT_IN_USE; }
    bool has_result() const { return state_ == State::HAVE_RESULT; }
    bool has_failed() const { return state_ == State::FAILED; }

    void do_connect(tdbusconnmanService *proxy, CallbackType &&ready_cb)
    {
        log_assert(state_ == State::NOT_IN_USE);
        log_assert(proxy != nullptr);
        proxy_ = proxy;
        state_ = State::RUNNING;
        ready_cb_ = ready_cb;

        tdbus_connman_service_call_connect(proxy_, nullptr, connected, this);
    }

    void setup_for_failure(CallbackType &&ready_cb)
    {
        log_assert(state_ == State::NOT_IN_USE);
        state_ = State::HAVE_RESULT;
        ready_cb_ = ready_cb;
    }

    bool handle_early_failure_if_failed()
    {
        if(state_ != State::HAVE_RESULT || proxy_ != nullptr)
            return false;

        ready_cb_(service_name_, false);

        return true;
    }

    void succeed()
    {
        log_assert(state_ == State::HAVE_RESULT);
        state_ = State::SUCCEEDED;
    }

    void fail()
    {
        log_assert(state_ == State::HAVE_RESULT);
        state_ = State::FAILED;
    }

  private:
    static void connected(GObject *source_object, GAsyncResult *res,
                          gpointer user_data)
    {
        auto *conn = static_cast<WLANConnection *>(user_data);

        log_assert(conn != nullptr);
        log_assert(TDBUS_CONNMAN_SERVICE(source_object) == conn->proxy_);

        GError *error = nullptr;
        tdbus_connman_service_call_connect_finish(conn->proxy_, res, &error);

        conn->state_ = State::HAVE_RESULT;
        conn->ready_cb_(conn->service_name_,
                        dbus_common_handle_dbus_error(&error, "Connect ConnMan service") == 0);
    }
};

/*!
 * Keep track of network we are trying to connect to.
 *
 * There is at most one #WLANConnection object inside. It is available as long
 * as a connection attempt is in progress.
 */
class WLANConnectionState
{
  public:
    enum class Method
    {
        INVALID,
        KNOWN_CREDENTIALS,
        WPS,
    };

    enum class State
    {
        IDLE,
        WAIT_FOR_REGISTRAR,
        ABOUT_TO_CONNECT,
        CONNECTING,
        DONE,
        FAILED,
        ABORTED,
    };

  private:
    State state_;
    std::unique_ptr<WLANConnection> candidate_;
    Method method_;

    std::chrono::steady_clock::time_point wps_started_at_;
    std::function<bool(const std::string &)> is_network_rejected_for_wps_;
    std::function<void(const std::string &, const Connman::ServiceList &)> found_registrar_;

  public:
    WLANConnectionState(const WLANConnectionState &) = delete;
    WLANConnectionState &operator=(const WLANConnectionState &) = delete;

    explicit WLANConnectionState():
        state_(State::IDLE),
        method_(Method::INVALID)
    {}

    void reset()
    {
        state_ = State::IDLE;
        candidate_.reset();
        method_ = Method::INVALID;
    }

    void abort_wps()
    {
        switch(state_)
        {
          case State::IDLE:
          case State::DONE:
          case State::FAILED:
          case State::ABORTED:
            return;

          case State::WAIT_FOR_REGISTRAR:
          case State::ABOUT_TO_CONNECT:
          case State::CONNECTING:
            switch(method_)
            {
              case Method::INVALID:
              case Method::KNOWN_CREDENTIALS:
                return;

              case Method::WPS:
                break;
            }

            break;
        }

        state_ = State::ABORTED;

        if(candidate_ == nullptr)
            msg_info("Aborted WPS connection while waiting for registrar");
        else
        {
            msg_info("Stopping WPS connection with %s",
                     candidate_->get_service_name().c_str());

            switch(candidate_->get_state())
            {
              case WLANConnection::State::RUNNING:
                connman_common_disconnect_service_by_object_path(candidate_->get_service_name().c_str());
                break;

              case WLANConnection::State::NOT_IN_USE:
              case WLANConnection::State::HAVE_RESULT:
              case WLANConnection::State::SUCCEEDED:
              case WLANConnection::State::FAILED:
                break;
            }
        }
    }

    void start_wps(std::function<bool(const std::string &)> &&is_network_rejected_for_wps,
                   std::function<void(const std::string &, const Connman::ServiceList &)> &&found_registrar)
    {
        log_assert(state_ == State::IDLE);
        log_assert(candidate_ == nullptr);
        log_assert(found_registrar != nullptr);

        msg_info("Starting WPS connection, waiting for registrar");

        state_ = State::WAIT_FOR_REGISTRAR;
        method_ = Method::WPS;
        is_network_rejected_for_wps_ = is_network_rejected_for_wps;
        found_registrar_ = found_registrar;
        wps_started_at_ = std::chrono::steady_clock::now();
    }

    bool has_wps_timeout_expired() const
    {
        log_assert(state_ == State::WAIT_FOR_REGISTRAR);

        const auto now = std::chrono::steady_clock::now();
        const auto t = std::chrono::duration_cast<std::chrono::milliseconds>(now - wps_started_at_);

        return t > std::chrono::minutes(2);
    }

    void about_to_connect_to(const std::string &service_name, Method method)
    {
        log_assert((state_ == State::IDLE && method == Method::KNOWN_CREDENTIALS) ||
                   (state_ == State::WAIT_FOR_REGISTRAR && method == Method::WPS));
        log_assert(candidate_ == nullptr);
        log_assert(!service_name.empty());

        msg_info("About to connect to WLAN \"%s\" %s",
                 service_name.c_str(), connection_method_to_string(method));

        state_ = State::ABOUT_TO_CONNECT;
        method_ = method;
        candidate_.reset(new WLANConnection(std::string(service_name)));
    }

    void start_connecting()
    {
        log_assert(state_ == State::ABOUT_TO_CONNECT);
        log_assert(candidate_ != nullptr);
        state_ = State::CONNECTING;
    }

    void finished_successfully()
    {
        log_assert(candidate_ != nullptr);

        bool be_done = false;

        switch(state_)
        {
          case State::IDLE:
          case State::DONE:
          case State::FAILED:
            break;

          case State::WAIT_FOR_REGISTRAR:
          case State::ABOUT_TO_CONNECT:
            be_done = true;
            break;

          case State::CONNECTING:
            finalize(true);
            state_ = State::DONE;
            return;

          case State::ABORTED:
            state_ = State::DONE;
            return;
        }

        BUG("Successfully connected to \"%s\" in unexpected state %d",
            candidate_->get_service_name().c_str(), static_cast<int>(state_));

        if(be_done)
            state_ = State::DONE;
    }

    bool finished_removed_with_failure(const std::string &object_path)
    {
        if(candidate_ != nullptr &&
           candidate_->get_service_name() == object_path)
        {
            /* we wanted to connect to this service, but it has just been
             * removed from Connman's service list */
            finished_with_failure();
            return true;
        }

        return false;
    }

    void finished_with_failure()
    {
        log_assert(candidate_ != nullptr);

        bool be_a_failure = false;

        switch(state_)
        {
          case State::IDLE:
          case State::DONE:
          case State::FAILED:
            break;

          case State::WAIT_FOR_REGISTRAR:
          case State::ABOUT_TO_CONNECT:
            switch(method_)
            {
              case Method::INVALID:
              case Method::KNOWN_CREDENTIALS:
                be_a_failure = true;
                break;

              case Method::WPS:
                break;
            }

            /* fall-through */

          case State::CONNECTING:
          case State::ABORTED:
            finalize(false);
            state_ = State::FAILED;
            return;
        }

        BUG("Failed connecting to \"%s\" in unexpected state %d",
            candidate_->get_service_name().c_str(), static_cast<int>(state_));

        if(be_a_failure)
            state_ = State::FAILED;
    }

    bool has_failed(const std::string &wlan_name) const
    {
        return candidate_ != nullptr && candidate_->has_failed() &&
               candidate_->get_service_name() == wlan_name;
    }

    State get_state() const { return state_; }

    bool is_wps_mode() const { return method_ == Method::WPS; }

    bool is_ssid_rejected_callback(const std::string &candidate) const
    {
        return is_network_rejected_for_wps_ != nullptr &&
               is_network_rejected_for_wps_(candidate);
    }

    void found_registrar_notification(const std::string &found_ssid,
                                      const Connman::ServiceList &services) const
    {
        log_assert(found_registrar_ != nullptr);
        found_registrar_(found_ssid, services);
    }

    bool try_connect(WLANConnection::CallbackType &&ready_cb)
    {
        log_assert(state_ == State::CONNECTING);
        log_assert(candidate_ != nullptr);

        if(candidate_->is_in_use())
            return false;

        static constexpr int wlan_connect_timeout_seconds = 150;

        auto proxy =
            dbus_new_connman_service_proxy_for_object_path(candidate_->get_service_name().c_str(),
                                                           wlan_connect_timeout_seconds);

        if(proxy == nullptr)
        {
            candidate_->setup_for_failure(std::move(ready_cb));
            candidate_->handle_early_failure_if_failed();
            return false;
        }

        msg_vinfo(MESSAGE_LEVEL_DEBUG, "Connecting to ConnMan service %s",
                  candidate_->get_service_name().c_str());

        candidate_->do_connect(proxy, std::move(ready_cb));

        return true;
    }

  private:
    void finalize(const bool succeeded)
    {
        log_assert(candidate_->has_result());

        static const char succeeded_string[] = "succeeded";
        static const char failed_string[] = "failed";

        if(succeeded)
            candidate_->succeed();
        else
            candidate_->fail();

        msg_info("Connecting service \"%s\" %s (%s)",
                 candidate_->get_service_name().c_str(),
                 succeeded ? succeeded_string : failed_string,
                 connection_method_to_string(method_));
    }

    static const char *connection_method_to_string(Method method)
    {
        switch(method)
        {
          case Method::INVALID:
            return "*INVALID*";

          case Method::KNOWN_CREDENTIALS:
            return "with credentials";

          case Method::WPS:
            return "via WPS";
        }

        return nullptr;
    }
};

class Connman::WLANManager
{
  public:
    LoggedLock::RecMutex lock;

    bool is_disabled;

    std::function<void()> schedule_connect_to_wlan;
    std::function<void()> schedule_refresh_connman_services;

    WLANConnectionState wlan_connection_state;

    Connman::WLANTools *wlan_tools;

    WLANManager(const WLANManager &) = delete;
    WLANManager &operator=(const WLANManager &) = delete;

    explicit WLANManager():
        is_disabled(false),
        schedule_connect_to_wlan(nullptr),
        schedule_refresh_connman_services(nullptr),
        wlan_tools(nullptr)
    {
        LoggedLock::configure(lock, "Connman::WLANManager", MESSAGE_LEVEL_DEBUG);
    }

    void init(std::function<void()> &&schedule_connect_to_wlan_fn,
              std::function<void()> &&schedule_refresh_connman_services_fn,
              Connman::WLANTools *wlan, bool is_enabled)
    {
        is_disabled = !is_enabled;
        schedule_connect_to_wlan = std::move(schedule_connect_to_wlan_fn);
        schedule_refresh_connman_services = std::move(schedule_refresh_connman_services_fn);
        wlan_connection_state.reset();
        wlan_tools = wlan;
        LOGGED_LOCK_CONTEXT_HINT;
        Connman::ServiceList::get_singleton_for_update().first.clear();
    }
};

enum class FindRegistrarResult
{
    NOT_FOUND,
    FOUND,
    TIMEOUT,
};

static bool stop_wps(WLANConnectionState &state, bool emit_warning_if_idle)
{
    bool may_reset_state = false;

    switch(state.get_state())
    {
      case WLANConnectionState::State::WAIT_FOR_REGISTRAR:
        may_reset_state = true;

        /* fall-through */

      case WLANConnectionState::State::ABOUT_TO_CONNECT:
      case WLANConnectionState::State::CONNECTING:
        if(state.is_wps_mode())
            break;

        /* fall-through */

      case WLANConnectionState::State::IDLE:
        if(emit_warning_if_idle)
            msg_info("Cannot stop WPS, not connecting");

        return false;

      case WLANConnectionState::State::DONE:
      case WLANConnectionState::State::FAILED:
      case WLANConnectionState::State::ABORTED:
        return true;
    }

    connman_agent_set_wps_mode(false);
    state.abort_wps();

    if(may_reset_state)
    {
        /* no asynchronous notifications pending */
        state.reset();
    }

    return true;
}

static void service_connected(const std::string &service_name, bool succeeded,
                              Connman::WLANManager &wman)
{
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::RecMutex> lock(wman.lock);

        if(succeeded)
        {
            msg_info("Connected to %s", service_name.c_str());
            wman.wlan_connection_state.finished_successfully();
        }
        else
        {
            msg_info("Failed connecting to %s", service_name.c_str());
            wman.wlan_connection_state.finished_with_failure();
        }
    }

    wman.wlan_connection_state.reset();
    wman.schedule_refresh_connman_services();
}

static void schedule_wlan_connect__unlocked(Connman::WLANManager &wman)
{
    log_assert(
        wman.wlan_connection_state.get_state() == WLANConnectionState::State::WAIT_FOR_REGISTRAR ||
        wman.wlan_connection_state.get_state() == WLANConnectionState::State::ABOUT_TO_CONNECT);

    wman.wlan_tools->power_on();
    wman.schedule_connect_to_wlan();

    msg_vinfo(MESSAGE_LEVEL_DEBUG,
              "***** Scheduled connect to WLAN *****");
}

static inline bool wps_bug_if(bool cond, const char *unknown)
{
    if(cond)
    {
        BUG("Connected via WPS, but %s unknown", unknown);
        return true;
    }
    else
        return false;
}

static void store_wlan_config(const Connman::ServiceBase *service)
{
    if(wps_bug_if(service == nullptr, "service"))
        return;

    const auto &s(static_cast<const Connman::Service<Connman::Technology::WLAN> &>(*service));
    const auto &t(s.get_tech_data());

    if(wps_bug_if(!t.security_.is_known(), "service security"))
        return;

    if(wps_bug_if(!t.network_name_.is_known() && !t.network_ssid_.is_known(), "service SSID"))
        return;

    struct network_prefs *dummy;
    struct network_prefs_handle *handle = network_prefs_open_rw(&dummy, &dummy);

    if(handle == nullptr)
        return;

    network_prefs_remove_prefs(handle, NWPREFSTECH_WLAN);

    struct network_prefs *wlan = network_prefs_add_prefs(handle, NWPREFSTECH_WLAN);

    if(wlan != nullptr)
    {
        network_prefs_put_wlan_config(wlan,
                                      t.network_name_.get().c_str(),
                                      t.network_ssid_.get().c_str(),
                                      t.security_.get().c_str(),
                                      nullptr, nullptr);
        network_prefs_write_to_file(handle);
    }

    network_prefs_close(handle);
}

static void wps_connected(const std::string &service_name, bool succeeded,
                          Connman::WLANManager &wman)
{
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::RecMutex> lock(wman.lock);

        LOGGED_LOCK_CONTEXT_HINT;
        const auto locked_services(Connman::ServiceList::get_singleton_const());
        const auto &services(locked_services.first);

        if(succeeded)
        {
            msg_info("Connected to %s via WPS", service_name.c_str());
            store_wlan_config(services[service_name]);
            wman.wlan_connection_state.finished_successfully();
        }
        else
        {
            msg_info("Failed connecting to %s via WPS", service_name.c_str());
            wman.wlan_connection_state.finished_with_failure();
        }
    }

    wman.wlan_connection_state.reset();
    connman_agent_set_wps_mode(false);

    if(succeeded)
        wman.schedule_refresh_connman_services();
}

static FindRegistrarResult find_wps_registrar(WLANConnectionState &state,
                                              const Connman::ServiceList &services)
{
    Connman::ServiceList::Map::const_iterator strongest_wps_candidate(services.end());
    unsigned int wps_capable_ap_count = 0;

    for(auto it = services.begin(); it != services.end(); ++it)
    {
        /* want WLAN */
        switch(it->second->get_technology())
        {
          case Connman::Technology::UNKNOWN_TECHNOLOGY:
          case Connman::Technology::ETHERNET:
            continue;

          case Connman::Technology::WLAN:
            break;
        }

        const auto &tech_data(static_cast<const Connman::Service<Connman::Technology::WLAN> &>(*it->second).get_tech_data());

        /* want non-hidden networks */
        if(!tech_data.network_name_.is_known() ||
           tech_data.network_name_.get().empty())
            continue;

        /* maybe want services which match a specific name */
        if(state.is_ssid_rejected_callback(tech_data.network_name_.get()))
        {
            msg_vinfo(MESSAGE_LEVEL_DIAG,
                      "Ignoring service with SSID \"%s\" for WPS",
                      tech_data.network_name_.get().c_str());
            continue;
        }

        /* want WPS */
        if(!tech_data.wps_capability_.is_known())
            continue;

        switch(tech_data.wps_capability_.get())
        {
          case Connman::WPSCapability::NONE:
            break;

          case Connman::WPSCapability::POSSIBLE:
            ++wps_capable_ap_count;
            break;

          case Connman::WPSCapability::ACTIVE:
            if(strongest_wps_candidate == services.end() ||
               tech_data.strength_.get() > static_cast<const Connman::Service<Connman::Technology::WLAN> &>(*strongest_wps_candidate->second).get_tech_data().strength_.get())
            {
                strongest_wps_candidate = it;
            }

            break;
        }
    }

    if(strongest_wps_candidate == services.end())
    {
        msg_info("Found %u WPS-capable networks, %sno WPS registrar found",
                 wps_capable_ap_count, wps_capable_ap_count > 0 ? "but " : "");

        if(state.has_wps_timeout_expired())
        {
            msg_error(0, LOG_NOTICE,
                      "Timeout while waiting for WPS registrar, aborting WPS");
            connman_agent_set_wps_mode(false);
            return FindRegistrarResult::TIMEOUT;
        }
        else
            return FindRegistrarResult::NOT_FOUND;
    }

    state.about_to_connect_to(strongest_wps_candidate->first, WLANConnectionState::Method::WPS);
    connman_agent_set_wps_mode(true);

    state.found_registrar_notification(strongest_wps_candidate->first, services);

    return FindRegistrarResult::FOUND;
}

static void scan_for_wps_done(Connman::SiteSurveyResult result);

bool Connman::connect_our_wlan(WLANManager &wman)
{
    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::RecMutex> lock(wman.lock);

    switch(wman.wlan_connection_state.get_state())
    {
      case WLANConnectionState::State::WAIT_FOR_REGISTRAR:
        {
            LOGGED_LOCK_CONTEXT_HINT;
            const auto locked_services(Connman::ServiceList::get_singleton_const());
            const auto &services(locked_services.first);

            switch(find_wps_registrar(wman.wlan_connection_state, services))
            {
              case FindRegistrarResult::NOT_FOUND:
                if(wman.wlan_tools == nullptr)
                {
                    BUG("No WLAN tools");
                    break;
                }

                wman.wlan_tools->start_site_survey(scan_for_wps_done);
                return true;

              case FindRegistrarResult::FOUND:
                return true;

              case FindRegistrarResult::TIMEOUT:
                stop_wps(wman.wlan_connection_state, true);
                break;
            }

            return false;
        }

      case WLANConnectionState::State::ABOUT_TO_CONNECT:
        wman.wlan_connection_state.start_connecting();

        if(wman.wlan_connection_state.is_wps_mode())
            return wman.wlan_connection_state.try_connect(
                [&wman] (const std::string &service_name, bool succeeded)
                {
                    wps_connected(service_name, succeeded, wman);
                });
        else
            return wman.wlan_connection_state.try_connect(
                [&wman] (const std::string &service_name, bool succeeded)
                {
                    service_connected(service_name, succeeded, wman);
                });

      case WLANConnectionState::State::IDLE:
      case WLANConnectionState::State::CONNECTING:
      case WLANConnectionState::State::DONE:
      case WLANConnectionState::State::FAILED:
      case WLANConnectionState::State::ABORTED:
        BUG("Tried to connect to WLAN in state %d",
            static_cast<int>(wman.wlan_connection_state.get_state()));
        break;
    }

    return false;
}

static bool ipv4_settings_are_different(const Maybe<Connman::IPSettings<Connman::AddressType::IPV4>> &maybe_settings,
                                        bool with_dhcp, const char *address,
                                        const char *nm, const char *gw,
                                        Connman::DHCPV4Method &system_dhcp_mode)
{
    if(!maybe_settings.is_known())
    {
        system_dhcp_mode = Connman::DHCPV4Method::UNKNOWN_METHOD;
        return false;
    }

    const auto &settings(maybe_settings.get());
    system_dhcp_mode = settings.get_dhcp_method();

    switch(system_dhcp_mode)
    {
      case Connman::DHCPV4Method::NOT_AVAILABLE:
      case Connman::DHCPV4Method::UNKNOWN_METHOD:
        break;

      case Connman::DHCPV4Method::ON:
      case Connman::DHCPV4Method::OFF:
        if((system_dhcp_mode == Connman::DHCPV4Method::ON && !with_dhcp) ||
           (system_dhcp_mode == Connman::DHCPV4Method::OFF && with_dhcp))
            return true;

        if(address != nullptr || nm != nullptr || gw != nullptr)
            return true;

        break;

      case Connman::DHCPV4Method::MANUAL:
        if(with_dhcp)
            return true;

        if(settings.get_address() != address ||
           settings.get_netmask() != nm ||
           settings.get_gateway() != gw)
            return true;

        break;

      case Connman::DHCPV4Method::FIXED:
        /* special case: cannot change the IPv4 parameters */
        break;
    }

    return false;
}

static bool nameservers_are_different(const Maybe<std::vector<std::string>> &dns_servers,
                                      const Connman::DHCPV4Method dhcp_method,
                                      const char *dns1, const char *dns2)
{
    if(!dns_servers.is_known())
        return false;

    const auto &servers(dns_servers.get());

    if(servers.size() > 0)
    {
        if((dns1 != nullptr && servers[0] != dns1) ||
           (dns1 == nullptr && !servers[0].empty()))
            return true;
    }
    else if(dns1 != nullptr)
        return true;

    if(servers.size() > 1)
    {
        if((dns2 != nullptr && servers[1] != dns2) ||
           (dns2 == nullptr && !servers[1].empty()))
            return true;
    }
    else if(dns2 != nullptr)
        return true;

    return false;
}

static void avoid_service(const Connman::Service<Connman::Technology::ETHERNET> *const service,
                          const std::string &service_name)
{
    log_assert(service != nullptr);
    log_assert(service->is_active());

    connman_common_disconnect_service_by_object_path(service_name.c_str());
}

static void avoid_service(const Connman::Service<Connman::Technology::WLAN> *const service,
                          const std::string &service_name)
{
    log_assert(service != nullptr);
    log_assert(service->is_active());

    connman_common_set_service_property(service_name.c_str(),
                                        "AutoConnect",
                                        g_variant_new_variant(g_variant_new_boolean(false)));
    connman_common_disconnect_service_by_object_path(service_name.c_str());
    connman_common_remove_service_by_object_path(service_name.c_str());
}

static bool avoid_service(const Connman::ServiceBase &service,
                          const std::string &service_name)
{
    switch(service.get_technology())
    {
      case Connman::Technology::UNKNOWN_TECHNOLOGY:
        break;

      case Connman::Technology::ETHERNET:
        avoid_service(dynamic_cast<const Connman::Service<Connman::Technology::ETHERNET> *>(&service),
                      service_name);
        return true;

      case Connman::Technology::WLAN:
        avoid_service(dynamic_cast<const Connman::Service<Connman::Technology::WLAN> *>(&service),
                      service_name);
        return true;
    }

    return false;
}

static bool configure_ipv4_settings(const Connman::ServiceBase &service,
                                    const std::string &service_name,
                                    const struct network_prefs *prefs)
{
    msg_vinfo(MESSAGE_LEVEL_DEBUG,
              "Configure IPv4 parameters for service %s",
              service_name.c_str());

    bool want_dhcp;
    const char *want_address;
    const char *want_netmask;
    const char *want_gateway;
    const char *want_dns1;
    const char *want_dns2;

    if(!network_prefs_get_ipv4_settings(prefs, &want_dhcp, &want_address,
                                        &want_netmask, &want_gateway,
                                        &want_dns1, &want_dns2))
    {
        avoid_service(service, service_name);
        return false;
    }

    Connman::DHCPV4Method system_dhcp_mode;
    const bool different_ipv4_config =
        ipv4_settings_are_different(service.get_service_data().configured_.ipsettings_v4_,
                                    want_dhcp, want_address, want_netmask,
                                    want_gateway, system_dhcp_mode);
    const bool different_nameservers =
        different_ipv4_config
        ? false
        : nameservers_are_different(service.get_service_data().active_.dns_servers_,
                                    system_dhcp_mode,
                                    want_dns1, want_dns2);

    if(!different_ipv4_config && !different_nameservers)
    {
        msg_vinfo(MESSAGE_LEVEL_DEBUG,
                  "Not configuring IPv4 parameters for %s: up to date",
                  service_name.c_str());
        return true;
    }

    GVariant *ipv4_config = NULL;
    GVariant *dns_config = NULL;

    if(different_ipv4_config)
    {
        GVariantBuilder builder;
        g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);

        if(want_dhcp)
            g_variant_builder_add(&builder, "{sv}", "Method", g_variant_new_string("dhcp"));
        else
        {
            g_variant_builder_add(&builder, "{sv}", "Method", g_variant_new_string("manual"));
            g_variant_builder_add(&builder, "{sv}", "Address", g_variant_new_string(want_address));
            g_variant_builder_add(&builder, "{sv}", "Netmask", g_variant_new_string(want_netmask));
            g_variant_builder_add(&builder, "{sv}", "Gateway", g_variant_new_string(want_gateway));
        }

        ipv4_config = g_variant_new_variant(g_variant_builder_end(&builder));
    }

    if(different_nameservers)
    {
        GVariantBuilder builder;
        g_variant_builder_init(&builder, G_VARIANT_TYPE_STRING_ARRAY);

        if(want_dns1 != NULL)
            g_variant_builder_add(&builder, "s", want_dns1);

        if(want_dns2 != NULL)
            g_variant_builder_add(&builder, "s", want_dns1);

        dns_config = g_variant_new_variant(g_variant_builder_end(&builder));
    }

    if(ipv4_config != NULL)
        connman_common_set_service_property(service_name.c_str(),
                                            "IPv4.Configuration", ipv4_config);

    if(dns_config != NULL)
        connman_common_set_service_property(service_name.c_str(),
                                            "Nameservers.Configuration",
                                            dns_config);

    return true;
}

/*!
 * Set network configuration for our WLAN.
 *
 * This function does not connect, it only informs ConnMan about configuration.
 * In case the configuratin is not available in our own configuration file, the
 * service is disconnnected and removed (if possible).
 *
 * \returns
 *     True in case WLAN connection should be established by the caller, false
 *     in case nothing needs to be done.
 */
static bool configure_our_wlan(const Connman::Service<Connman::Technology::WLAN> &service,
                               const std::string &service_name,
                               const struct network_prefs *prefs,
                               WLANConnectionState &wlan_connection_state,
                               bool make_it_favorite, bool immediate_activation,
                               bool force_reconnect)
{
    switch(wlan_connection_state.get_state())
    {
      case WLANConnectionState::State::IDLE:
        break;

      case WLANConnectionState::State::DONE:
      case WLANConnectionState::State::FAILED:
      case WLANConnectionState::State::ABORTED:
        wlan_connection_state.reset();
        break;

      case WLANConnectionState::State::WAIT_FOR_REGISTRAR:
      case WLANConnectionState::State::ABOUT_TO_CONNECT:
      case WLANConnectionState::State::CONNECTING:
        return false;
    }

    if(!configure_ipv4_settings(service, service_name, prefs))
        return false;

    const auto &service_data(service.get_service_data());

    msg_vinfo(MESSAGE_LEVEL_DEBUG,
              "Our WLAN is %sa favorite, auto-connect %s, "
              "make it favorite %d",
              service_data.is_favorite_.pick<const char *>("", "not ", "maybe "),
              service_data.is_auto_connect_.pick<const char *>("yes", "no", "maybe"),
              make_it_favorite);

    if(service_data.is_favorite_ == true)
    {
        if(service_data.is_auto_connect_ == false)
        {
            if(connman_common_set_service_property(service_name.c_str(),
                                                   "AutoConnect",
                                                   g_variant_new_variant(g_variant_new_boolean(true))) &&
               !service.is_active() && immediate_activation)
            {
                wlan_connection_state.about_to_connect_to(service_name,
                                                          WLANConnectionState::Method::KNOWN_CREDENTIALS);
                wlan_connection_state.start_connecting();
            }
        }
        else if(force_reconnect)
            return true;

        /* rely on auto-connect */
        return false;
    }

    if(service_data.is_favorite_ == false && make_it_favorite)
    {
        /* if this function returns true, then the caller will schedule a WLAN
         * connection attempt by calling #schedule_wlan_connect_if_necessary();
         * so we are returning true */
        return true;
    }

    return false;
}

static void dump_removed_services(enum MessageVerboseLevel level,
                                  const std::vector<std::string> &removed)
{
    if(!msg_is_verbose(level))
        return;

    for(const auto &name : removed)
        msg_info("Service removed: \"%s\"", name.c_str());
}

static bool dump_simple_value(const char *prefix,
                              const char *prop, GVariant *value)
{
    if(g_variant_is_of_type(value, G_VARIANT_TYPE_STRING))
        msg_info("%s %s = %s", prefix, prop, g_variant_get_string(value, NULL));
    else if(g_variant_is_of_type(value, G_VARIANT_TYPE_BOOLEAN))
        msg_info("%s %s = %s", prefix, prop, g_variant_get_boolean(value) ? "TRUE" : "FALSE");
    else if(g_variant_is_of_type(value, G_VARIANT_TYPE_BYTE))
        msg_info("%s %s = %" PRIu8, prefix, prop, g_variant_get_byte(value));
    else if(g_variant_is_of_type(value, G_VARIANT_TYPE_INT16))
        msg_info("%s %s = %" PRId16, prefix, prop, g_variant_get_int16(value));
    else if(g_variant_is_of_type(value, G_VARIANT_TYPE_UINT16))
        msg_info("%s %s = %" PRIu16, prefix, prop, g_variant_get_uint16(value));
    else if(g_variant_is_of_type(value, G_VARIANT_TYPE_INT32))
        msg_info("%s %s = %" PRId32, prefix, prop, g_variant_get_int32(value));
    else if(g_variant_is_of_type(value, G_VARIANT_TYPE_UINT32))
        msg_info("%s %s = %" PRIu32, prefix, prop, g_variant_get_uint32(value));
    else if(g_variant_is_of_type(value, G_VARIANT_TYPE_INT64))
        msg_info("%s %s = %" PRId64, prefix, prop, g_variant_get_int64(value));
    else if(g_variant_is_of_type(value, G_VARIANT_TYPE_UINT32))
        msg_info("%s %s = %" PRIu64, prefix, prop, g_variant_get_uint64(value));
    else if(g_variant_is_of_type(value, G_VARIANT_TYPE_DOUBLE))
        msg_info("%s %s = %f", prefix, prop, g_variant_get_double(value));
    else
        return false;

    return true;
}

static void dump_service_changes(enum MessageVerboseLevel level,
                                 const char *name, GVariantIter *props_iter)
{
    if(!msg_is_verbose(level))
        return;

    msg_info((g_variant_iter_n_children(props_iter) > 0)
             ? "Service changed: \"%s\""
             : "Service still available: \"%s\"", name);

    const char *prop = NULL;
    GVariant *value = NULL;
    GVariantIter *iter_copy = g_variant_iter_copy(props_iter);

    while(g_variant_iter_loop(iter_copy, "{&sv}", &prop, &value))
    {
        if(dump_simple_value("-", prop, value))
            continue;
        else if(g_variant_is_of_type(value, G_VARIANT_TYPE_STRING_ARRAY))
        {
            msg_info("- %s", prop);

            GVariantIter array_iter;
            g_variant_iter_init(&array_iter, value);

            const gchar *array_value = NULL;

            while(g_variant_iter_loop(&array_iter, "&s", &array_value))
                msg_info("`-- %s", array_value);
        }
        else if(g_variant_is_of_type(value, G_VARIANT_TYPE_VARDICT))
        {
            msg_info("- %s", prop);

            GVariantIter dict_iter;
            g_variant_iter_init(&dict_iter, value);

            const gchar *dict_key = NULL;
            GVariant *dict_value;

            while(g_variant_iter_loop(&dict_iter, "{&sv}", &dict_key, &dict_value))
            {
                if(dump_simple_value("--", dict_key, dict_value))
                    continue;
                else
                    msg_info("`-- %s (type %s)", dict_key, g_variant_get_type_string(dict_value));
            }
        }
        else
            msg_info("- %s (type %s)", prop, g_variant_get_type_string(value));
    }

    g_variant_iter_free(iter_copy);
}

template <Connman::AddressType IPType>
struct ParseIPSettingsTraits;

template <>
struct ParseIPSettingsTraits<Connman::AddressType::IPV4>
{
    using Settings = Connman::IPSettings<Connman::AddressType::IPV4>;

    static void set_dhcp_method(Settings &settings, const char *method)
    {
        settings.set_dhcp_method(Connman::parse_connman_dhcp_v4_method(method));
    }
};

template <>
struct ParseIPSettingsTraits<Connman::AddressType::IPV6>
{
    using Settings = Connman::IPSettings<Connman::AddressType::IPV6>;

    static void set_dhcp_method(Settings &settings, const char *method)
    {
        settings.set_dhcp_method(Connman::parse_connman_dhcp_v6_method(method));
    }
};

template <Connman::AddressType IPType, typename Traits = ParseIPSettingsTraits<IPType>>
static void parse_ip_settings(GVariant *values,
                              Maybe<Connman::IPSettings<IPType>> &ip_settings)
{
    GVariantIter iter;
    g_variant_iter_init(&iter, values);

    const char *iter_key;
    GVariant *iter_value;

    auto &settings(ip_settings.get_rw());

    while(g_variant_iter_loop(&iter, "{&sv}", &iter_key, &iter_value))
    {
        if(strcmp(iter_key, "Method") == 0)
            Traits::set_dhcp_method(settings, g_variant_get_string(iter_value, NULL));
        else if(strcmp(iter_key, "Address") == 0)
            settings.set_address(g_variant_get_string(iter_value, NULL));
        else if(strcmp(iter_key, "Netmask") == 0)
            settings.set_netmask(g_variant_get_string(iter_value, NULL));
        else if(strcmp(iter_key, "Gateway") == 0)
            settings.set_gateway(g_variant_get_string(iter_value, NULL));
        else if(strcmp(iter_key, "PrefixLength") == 0)
        {
            char temp[4];
            snprintf(temp, sizeof(temp), "%u", g_variant_get_byte(iter_value));
            settings.set_netmask(temp);
        }
    }

    ip_settings.set_known();
}

static void copy_strings_to_vector(GVariant *value,
                                   std::vector<std::string> &dest)
{
    GVariantIter iter;
    g_variant_iter_init(&iter, value);

    const char *iter_string;

    while(g_variant_iter_loop(&iter, "&s", &iter_string))
        dest.push_back(iter_string);
}

static void copy_strings_to_vector(GVariant *value,
                                   Maybe<std::vector<std::string>> &dest)
{
    copy_strings_to_vector(value, dest.get_rw());
    dest.set_known();
}

static void parse_proxy_settings(GVariant *values,
                                 Maybe<Connman::ProxySettings> &proxy_settings)
{
    GVariantIter iter;
    g_variant_iter_init(&iter, values);

    const char *iter_key;
    GVariant *iter_value;

    auto &settings(proxy_settings.get_rw());

    while(g_variant_iter_loop(&iter, "{&sv}", &iter_key, &iter_value))
    {
        if(strcmp(iter_key, "Method") == 0)
            settings.set_method(Connman::parse_connman_proxy_method(
                                    g_variant_get_string(iter_value, NULL)));
        else if(strcmp(iter_key, "URL") == 0)
            settings.set_pac_url(g_variant_get_string(iter_value, NULL));
        else if(strcmp(iter_key, "Servers") == 0)
        {
            std::vector<std::string> v;
            copy_strings_to_vector(iter_value, v);
            settings.set_proxy_servers(std::move(v));
        }
        else if(strcmp(iter_key, "Excludes") == 0)
        {
            std::vector<std::string> v;
            copy_strings_to_vector(iter_value, v);
            settings.set_excluded_hosts(std::move(v));
        }
    }

    proxy_settings.set_known();
}

static bool parse_generic_service_data(const char *prop, GVariant *value,
                                       Connman::ServiceData &service_data,
                                       Connman::Technology &tech,
                                       Connman::Address<Connman::AddressType::MAC> &mac_address)
{
    if(strcmp(prop, "Type") == 0)
        tech = Connman::parse_connman_technology(g_variant_get_string(value, NULL));
    else if(strcmp(prop, "State") == 0)
        service_data.state_ =
            Connman::parse_connman_service_state(g_variant_get_string(value, NULL));
    else if(strcmp(prop, "Favorite") == 0)
        service_data.is_favorite_ = !!g_variant_get_boolean(value);
    else if(strcmp(prop, "AutoConnect") == 0)
        service_data.is_auto_connect_ = !!g_variant_get_boolean(value);
    else if(strcmp(prop, "Immutable") == 0)
        service_data.is_immutable_ = !!g_variant_get_boolean(value);
    else if(strcmp(prop, "Ethernet") == 0)
    {
        GVariantIter iter;
        g_variant_iter_init(&iter, value);

        const char *iter_key;
        GVariant *iter_value;

        while(g_variant_iter_loop(&iter, "{&sv}", &iter_key, &iter_value))
        {
            if(strcmp(iter_key, "Address") != 0)
                continue;

            try
            {
                mac_address.set(g_variant_get_string(iter_value, NULL));
            }
            catch(const std::domain_error &e)
            {
                msg_error(0, LOG_NOTICE,
                          "Ignoring invalid MAC address in service data: \"%s\"",
                          g_variant_get_string(iter_value, NULL));
                continue;
            }

            g_variant_unref(iter_value);
            break;
        }
    }
    else if(strcmp(prop, "Nameservers") == 0)
        copy_strings_to_vector(value, service_data.active_.dns_servers_);
    else if(strcmp(prop, "Nameservers.Configuration") == 0)
        copy_strings_to_vector(value, service_data.configured_.dns_servers_);
    else if(strcmp(prop, "Timeservers") == 0)
        copy_strings_to_vector(value, service_data.active_.time_servers_);
    else if(strcmp(prop, "Timeservers.Configuration") == 0)
        copy_strings_to_vector(value, service_data.configured_.time_servers_);
    else if(strcmp(prop, "Domains") == 0)
        copy_strings_to_vector(value, service_data.active_.domains_);
    else if(strcmp(prop, "Domains.Configuration") == 0)
        copy_strings_to_vector(value, service_data.configured_.domains_);
    else if(strcmp(prop, "IPv4") == 0)
        parse_ip_settings(value, service_data.active_.ipsettings_v4_);
    else if(strcmp(prop, "IPv4.Configuration") == 0)
        parse_ip_settings(value, service_data.configured_.ipsettings_v4_);
    else if(strcmp(prop, "IPv6") == 0)
        parse_ip_settings(value, service_data.active_.ipsettings_v6_);
    else if(strcmp(prop, "IPv6.Configuration") == 0)
        parse_ip_settings(value, service_data.configured_.ipsettings_v6_);
    else if(strcmp(prop, "Proxy") == 0)
        parse_proxy_settings(value, service_data.active_.proxy_);
    else if(strcmp(prop, "Proxy.Configuration") == 0)
        parse_proxy_settings(value, service_data.configured_.proxy_);
    else
        return false;

    return true;
}

static bool parse_ethernet_data(const char *prop, GVariant *value,
                                Connman::Service<Connman::Technology::ETHERNET>::TechDataType &data)
{
    return false;
}

static void process_wlan_security_info(GVariant *security_info,
                                       Maybe<std::string> &security,
                                       Maybe<Connman::WPSCapability> &wps)
{

    const size_t n = g_variant_n_children(security_info);

    if(n == 0)
        security = "";
    else
    {
        GVariant *str = g_variant_get_child_value(security_info, 0);
        security = g_variant_get_string(str, NULL);
        g_variant_unref(str);
    }

    wps = Connman::WPSCapability::NONE;

    if(n <= 1)
        return;

    for(size_t i = 0; i < n; ++i)
    {
        GVariant *str = g_variant_get_child_value(security_info, i);
        const char *const cap = g_variant_get_string(str, NULL);

        if(strcmp(cap, "wps") == 0)
            wps = Connman::WPSCapability::POSSIBLE;
        else if(strcmp(cap, "wps_advertising") == 0)
        {
            wps = Connman::WPSCapability::ACTIVE;
            g_variant_unref(str);
            break;
        }

        g_variant_unref(str);
    }
}

static bool parse_wlan_data(const char *prop, GVariant *value,
                            Connman::Service<Connman::Technology::WLAN>::TechDataType &data)
{
    if(strcmp(prop, "Name") == 0)
        data.network_name_ = g_variant_get_string(value, NULL);
    else if(strcmp(prop, "Security") == 0)
    {
        process_wlan_security_info(value, data.security_, data.wps_capability_);
    }
    else if(strcmp(prop, "Strength") == 0)
        data.strength_ = g_variant_get_byte(value);
    else
        return false;

    return true;
}

static bool parse_service_data(GVariantIter *props_iter,
                               Connman::Technology &tech,
                               Connman::Address<Connman::AddressType::MAC> &mac_address,
                               Connman::ServiceData &service_data,
                               Connman::Service<Connman::Technology::ETHERNET>::TechDataType &ethernet_data,
                               Connman::Service<Connman::Technology::WLAN>::TechDataType &wlan_data)
{
    tech = Connman::Technology::UNKNOWN_TECHNOLOGY;

    bool parsed_any_property = false;
    const char *prop = NULL;
    GVariant *value = NULL;

    while(g_variant_iter_loop(props_iter, "{&sv}", &prop, &value))
    {
        if(parse_generic_service_data(prop, value, service_data, tech, mac_address) ||
           parse_ethernet_data(prop, value, ethernet_data) ||
           parse_wlan_data(prop, value, wlan_data))
        {
            parsed_any_property = true;
        }
    }

    return parsed_any_property;
}

/*!
 * Remove listed services from our list.
 */
static void update_service_list(Connman::ServiceList &known_services,
                                WLANConnectionState &wlan_connection_state,
                                const std::vector<std::string> &removed,
                                bool &have_lost_active_ethernet_device,
                                bool &have_lost_active_wlan_device)
{
    have_lost_active_ethernet_device = false;
    have_lost_active_wlan_device = false;

    if(removed.empty())
        return;

    dump_removed_services(MESSAGE_LEVEL_TRACE, removed);

    for(const auto &name : removed)
    {
        const Connman::ServiceBase *service(known_services[name]);

        if(service == nullptr)
            continue;

        if(service->is_ours() && service->is_active())
        {
            switch(service->get_technology())
            {
              case Connman::Technology::UNKNOWN_TECHNOLOGY:
                BUG("Removed service \"%s\" of unknown technology", name.c_str());
                break;

              case Connman::Technology::ETHERNET:
                have_lost_active_ethernet_device = true;
                break;

              case Connman::Technology::WLAN:
                have_lost_active_wlan_device = true;
                break;
            }
        }

        switch(wlan_connection_state.get_state())
        {
          case WLANConnectionState::State::IDLE:
          case WLANConnectionState::State::WAIT_FOR_REGISTRAR:
          case WLANConnectionState::State::DONE:
          case WLANConnectionState::State::FAILED:
          case WLANConnectionState::State::ABORTED:
            break;

          case WLANConnectionState::State::ABOUT_TO_CONNECT:
          case WLANConnectionState::State::CONNECTING:
            if(wlan_connection_state.finished_removed_with_failure(name))
                wlan_connection_state.reset();

            break;
        }

        known_services.erase(name);
    }
}

static void update_service_list(GVariant *all_services,
                                Connman::ServiceList &known_services,
                                Connman::NetworkDeviceList &network_devices,
                                bool force_refresh_all)
{
    if(all_services == nullptr)
        return;

    /* go through all services */
    GVariantIter iter;
    g_variant_iter_init(&iter, all_services);

    const gchar *name;
    GVariantIter *props_iter;

    while(g_variant_iter_loop(&iter, "(&oa{sv})", &name, &props_iter))
    {
        if(name[0] == '\0')
            continue;

        dump_service_changes(MESSAGE_LEVEL_TRACE, name, props_iter);

        Connman::ServiceData service_data;
        Connman::Service<Connman::Technology::ETHERNET>::TechDataType ethernet_data;
        Connman::Service<Connman::Technology::WLAN>::TechDataType wlan_data;
        Connman::Technology tech;
        Connman::Address<Connman::AddressType::MAC> mac_address;

        if(!parse_service_data(props_iter, tech, mac_address,
                               service_data, ethernet_data, wlan_data))
        {
            BUG("Reported service \"%s\" contains no information", name);
            continue;
        }

        Connman::ServiceBase *service = known_services[name];

        auto dev = network_devices[mac_address];

        if(dev != nullptr)
            service_data.device_ = std::move(dev);
        else
            service_data.device_ = std::move(network_devices.insert(tech, std::move(mac_address)));

        switch(tech)
        {
          case Connman::Technology::UNKNOWN_TECHNOLOGY:
            break;

          case Connman::Technology::ETHERNET:
            if(service == nullptr)
                known_services.insert(name, std::move(service_data), std::move(ethernet_data));
            else
                static_cast<Connman::Service<Connman::Technology::ETHERNET> *>(service)->put_changes(
                        std::move(service_data), std::move(ethernet_data),
                        force_refresh_all);

            break;

          case Connman::Technology::WLAN:
            if(service == nullptr)
                known_services.insert(name, std::move(service_data), std::move(wlan_data));
            else
                static_cast<Connman::Service<Connman::Technology::WLAN> *>(service)->put_changes(
                        std::move(service_data), std::move(wlan_data),
                        force_refresh_all);

            break;
        }
    }
}

/*!
 * Disable use of IPv6 for given service.
 *
 * All we are ever doing about IPv6 is to disable it---sad. :(
 */
static bool disable_ipv6(Connman::ServiceBase &service,
                         const std::string &service_name)
{
    log_assert(service.is_active());

    const auto &data(service.get_service_data());

    if(!data.configured_.ipsettings_v6_.is_known())
        return false;

    switch(data.configured_.ipsettings_v6_.get().get_dhcp_method())
    {
      case Connman::DHCPV6Method::NOT_AVAILABLE:
      case Connman::DHCPV6Method::OFF:
      case Connman::DHCPV6Method::FIXED:
        return false;

      case Connman::DHCPV6Method::ON:
      case Connman::DHCPV6Method::MANUAL:
      case Connman::DHCPV6Method::SIX_TO_FOUR:
      case Connman::DHCPV6Method::UNKNOWN_METHOD:
        break;
    }

    msg_vinfo(MESSAGE_LEVEL_DEBUG,
              "Configure IPv6 parameters for service %s", service_name.c_str());

    GVariantBuilder builder;
    g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);

    g_variant_builder_add(&builder, "{sv}", "Method", g_variant_new_string("off"));

    GVariant *ipv6_config =
        g_variant_new_variant(g_variant_builder_end(&builder));

    if(ipv6_config == NULL)
        return false;

    g_variant_ref_sink(ipv6_config);
    const bool retval =
        connman_common_set_service_property(service_name.c_str(),
                                            "IPv6.Configuration", ipv6_config);
    g_variant_unref(ipv6_config);

    return retval;
}

static void ignore_services_if(Connman::ServiceList &services,
                               std::function<bool(const Connman::ServiceBase &service,
                                                  const std::string &name)> pred)
{
    for(auto &it : services)
    {
        const auto &s(it.second);

        log_assert(s != nullptr);

        if(s->needs_processing())
        {
            if(pred(*s, it.first))
                s->processed();
        }
    }
}

static void ignore_inactive_services_on_wrong_interfaces(Connman::ServiceList &known_services)
{
    ignore_services_if(known_services,
            [] (const Connman::ServiceBase &s, const std::string &name)
            {
                return !s.is_active() && !s.is_ours();
            });
}

static void ignore_wlan_services_on_our_interfaces(Connman::ServiceList &known_services)
{
    if(known_services.number_of_wlan_services() > 0)
        ignore_services_if(known_services,
                [] (const Connman::ServiceBase &s, const std::string &name)
                {
                    return s.is_ours() && s.get_technology() == Connman::Technology::WLAN;
                });
}

static void disconnect_active_services_if(Connman::ServiceList &services,
                                          std::function<bool(const Connman::ServiceBase &service,
                                                             const std::string &name)> pred)
{
    for(auto &it : services)
    {
        const auto &s(it.second);

        log_assert(s != nullptr);

        if(!s->is_active() || !pred(*s, it.first))
            continue;

        if(avoid_service(*s, it.first))
            s->processed();
    }
}

static void disconnect_active_services_on_wrong_interfaces(Connman::ServiceList &known_services)
{
    disconnect_active_services_if(known_services,
            [] (const Connman::ServiceBase &s, const std::string &name)
            {
                return !s.is_ours();
            });
}

static void
disconnect_nonmatching_active_services_on_our_interface(Connman::ServiceList &known_services,
                                                        const std::string &our_ethernet_name,
                                                        const std::string &our_wlan_name)
{
    if(our_ethernet_name.empty() && our_wlan_name.empty())
        return;

    disconnect_active_services_if(known_services,
            [&our_ethernet_name, &our_wlan_name]
            (const Connman::ServiceBase &s, const std::string &name)
            {
                if(!s.is_ours())
                    return false;

                switch(s.get_technology())
                {
                  case Connman::Technology::UNKNOWN_TECHNOLOGY:
                    break;

                  case Connman::Technology::ETHERNET:
                    return !our_ethernet_name.empty() && name != our_ethernet_name;

                  case Connman::Technology::WLAN:
                    return !our_wlan_name.empty() && name != our_wlan_name;
                }

                return false;
            });
}

static bool process_our_ethernet_service(Connman::ServiceBase &service,
                                         const std::string &name,
                                         const struct network_prefs *prefs)
{
    auto &s(static_cast<Connman::Service<Connman::Technology::ETHERNET> &>(service));

    bool consider_wlan_connection = true;

    if(s.needs_processing())
    {
        if(configure_ipv4_settings(s, name, prefs))
            consider_wlan_connection = false;

        if(s.is_active())
            disable_ipv6(s, name);
    }
    else if(s.is_active())
        consider_wlan_connection = false;

    s.processed();

    return consider_wlan_connection;
}

static bool process_our_wlan_service(Connman::ServiceBase &service,
                                     const std::string &name,
                                     bool consider_wlan_connection,
                                     bool have_lost_active_ethernet_device,
                                     WLANConnectionState &wlan_connection_state,
                                     const struct network_prefs *prefs)
{
    auto &s(static_cast<Connman::Service<Connman::Technology::WLAN> &>(service));

    bool want_to_switch_to_wlan = false;

    if(consider_wlan_connection)
    {
        if(s.needs_processing())
        {
            if(configure_our_wlan(s, name, prefs, wlan_connection_state,
                                  false, true, false))
                want_to_switch_to_wlan = true;

            if(s.is_active())
                disable_ipv6(s, name);
        }
        else if(have_lost_active_ethernet_device)
            want_to_switch_to_wlan = true;
    }

    s.processed();

    return want_to_switch_to_wlan;
}

#ifdef NDEBUG
static inline void bug_if_not_processed(const Connman::ServiceList &known_services) {}
#else /* !NDEBUG */
static void bug_if_not_processed(const Connman::ServiceList &known_services)
{
    bool found_bug = false;

    for(auto &it : known_services)
    {
        if(it.second->needs_processing())
        {
            BUG("Service \"%s\" not processed", it.first.c_str());
            found_bug = true;
        }
    }

    log_assert(!found_bug);
}
#endif /* NDEBUG */

static void survey_after_suspend(Connman::SiteSurveyResult result)
{
    msg_vinfo(MESSAGE_LEVEL_DIAG,
              "Site survey result after suspend: %d", int(result));
}

/*!
 * Take care of ConnMan service changes.
 *
 * ConnMan is configured so to connect to Ethernet or WLAN automatically
 * whenever possible. We also prefer Ethernet and have ConnMan switch to
 * that technology as soon as it is available. In case ConnMan does not
 * know a WLAN passphrase, it will ask us via ConnMan agent API. Ideally,
 * this is how all connections are managed and there should be nothing to
 * do in here.
 *
 * There are, however, a few cases that we need to take care about. ConnMan
 * will cache WLAN credentials (in fact, all configuration data for a
 * service) in its own set of configuration files, and it will use them to
 * perform its automatic connection management. Now, if the user decides to
 * use a new or different WLAN, then ConnMan needs to be informed to use
 * it. This, unfortunately, only works if the network is currently visible
 * by ConnMan. While the user is configuring the network connection on the
 * device, the network is usually visible, but for instance due to bad
 * signal quality it may not, and configuration could fail. ConnMan will
 * then resort to the old WLAN it already knows about, leading to
 * confusion, at best. Similar things happen if the credentials entered by
 * the user are wrong, or when moving the device from one house to another,
 * or when configuring Ethernet while no cable is plugged in.
 *
 * The code below tries to sort it all out. It tries to stay connected to
 * the services explicitly configured by the user and to stay away from
 * others. For those services configured by the user, the code tries to
 * enforce use of user settings.
 *
 * Note that the problems described above occur only because our user
 * interface policy enforces a restriction to a single managed WLAN. A more
 * generalized approach that allows multiple configurations would actually
 * simplify things a lot, both for the software and for the end user.
 */
static bool do_process_pending_changes(LoggedLock::UniqueLock<LoggedLock::RecMutex> &&wman_lock,
                                       Connman::ServiceList::LockedSingleton &&locked_services,
                                       bool have_lost_active_ethernet_device,
                                       bool have_lost_active_wlan_device,
                                       WLANConnectionState &wlan_connection_state,
                                       Connman::WLANTools *wlan,
                                       const struct network_prefs *ethernet_prefs,
                                       const struct network_prefs *wlan_prefs)
{
    if(have_lost_active_wlan_device)
        wlan_connection_state.reset();

    ignore_inactive_services_on_wrong_interfaces(locked_services.first);
    disconnect_active_services_on_wrong_interfaces(locked_services.first);

    char configured_ethernet_service_name[NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE];
    char configured_wlan_service_name[NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE];

    /* check what we have in the configuration file */
    const bool have_ethernet_service_prefs =
        network_prefs_generate_service_name(ethernet_prefs,
                                            configured_ethernet_service_name,
                                            sizeof(configured_ethernet_service_name),
                                            true) > 0;
    const bool have_wlan_service_prefs =
        network_prefs_generate_service_name(wlan_prefs,
                                            configured_wlan_service_name,
                                            sizeof(configured_wlan_service_name),
                                            true) > 0;

    /* up to two services known by Connman for which the user also has provided
     * configuration data */
    auto our_ethernet(have_ethernet_service_prefs
                      ? locked_services.first.find(configured_ethernet_service_name)
                      : locked_services.first.end());
    auto our_wlan(have_wlan_service_prefs
                  ? locked_services.first.find(configured_wlan_service_name)
                  : locked_services.first.end());

    if(wlan_connection_state.is_wps_mode())
    {
        if(our_ethernet != locked_services.first.end())
        {
            /* cable was plugged, taking precedence over WLAN */
            stop_wps(wlan_connection_state, true);
        }

        /* do not interfere with Connman */
        configured_wlan_service_name[0] = '\0';
        our_wlan = locked_services.first.end();
    }

    disconnect_nonmatching_active_services_on_our_interface(
            locked_services.first,
            our_ethernet != locked_services.first.end()
            ? our_ethernet->first
            : configured_ethernet_service_name,
            our_wlan != locked_services.first.end()
            ? our_wlan->first
            : configured_wlan_service_name);

    /* either all services have been disconnected above and the function has
     * returned already, or we end up here because there are exactly one or two
     * services left for further configuration */

    const bool consider_wlan_connection =
        our_ethernet != locked_services.first.end()
        ? process_our_ethernet_service(*our_ethernet->second, our_ethernet->first,
                                       ethernet_prefs)
        : true;

    const bool want_to_switch_to_wlan =
        our_wlan != locked_services.first.end()
        ? process_our_wlan_service(*our_wlan->second, our_wlan->first,
                                   consider_wlan_connection,
                                   have_lost_active_ethernet_device,
                                   wlan_connection_state, wlan_prefs)
        : false;

    ignore_wlan_services_on_our_interfaces(locked_services.first);

    bug_if_not_processed(locked_services.first);

    if(!want_to_switch_to_wlan)
    {
        bool revised_decision = false;

        if(consider_wlan_connection && have_wlan_service_prefs)
        {
            /* we didn't want to switch to WLAN in the first place, but we are
             * allowed to because there is no Ethernet connection; also, we
             * have a set of WLAN configuration data */
           if(locked_services.first.number_of_wlan_services() == 0)
           {
               /* there are no known WLANs, maybe because the WLAN adapter
                * is in suspend mode */
               if(wlan != nullptr)
                   wlan->start_site_survey(survey_after_suspend);

               return false;
           }

           /* switch to WLAN if there is a network matching our WLAN
            * configuration */
           revised_decision = our_wlan != locked_services.first.end();
        }

        if(!revised_decision)
            return false;
    }

    /*
     * We have determined that we should switch over to WLAN. If the WLAN is
     * neither connected nor marked as auto-connect, then we need to connect to
     * it by hand.
     */

    log_assert(our_wlan != locked_services.first.end());

    LOGGED_LOCK_CONTEXT_HINT;
    locked_services.second.unlock();

    /* powering on is the least we should do so that ConnMan can find WLAN
     * networks, manual connect may or may not be necessary (see below) */
    if(wlan == nullptr)
        return false;

    wlan->power_on();

    if(our_wlan->second->is_active() == true)
        return false;

    if(our_wlan->second->get_service_data().is_auto_connect_ == true)
        return false;

    switch(wlan_connection_state.get_state())
    {
      case WLANConnectionState::State::DONE:
      case WLANConnectionState::State::FAILED:
      case WLANConnectionState::State::ABORTED:
        msg_info("Minor glitch: WLAN connection state is %d",
                 static_cast<int>(wlan_connection_state.get_state()));

        if(wlan_connection_state.has_failed(our_wlan->first))
        {
            msg_info("Not trying to connect to failed service again");
            wlan_connection_state.reset();
            break;
        }

        wlan_connection_state.reset();

        /* fall-through */

      case WLANConnectionState::State::IDLE:
        wlan_connection_state.about_to_connect_to(our_wlan->first,
                                                  WLANConnectionState::Method::KNOWN_CREDENTIALS);

        /* Click. */
        return true;

      case WLANConnectionState::State::WAIT_FOR_REGISTRAR:
      case WLANConnectionState::State::ABOUT_TO_CONNECT:
      case WLANConnectionState::State::CONNECTING:
        break;
    }

    return false;
}

static void schedule_wlan_connect_if_necessary(bool is_necessary,
                                               Connman::WLANManager &wman)
{
    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::RecMutex> lock(wman.lock);

    if(is_necessary)
        schedule_wlan_connect__unlocked(wman);
}

static bool update_all_services(GVariant *all_services,
                                Connman::ServiceList &services,
                                Connman::NetworkDeviceList &devices,
                                bool force_refresh_all,
                                const char *context)
{
    if(all_services == nullptr)
    {
        BUG("Querying services from ConnMan failed (%s)", context);
        return false;
    }

    update_service_list(all_services, services, devices, force_refresh_all);

    return true;
}

static void process_pending_changes(Connman::WLANManager &wman,
                                    LoggedLock::UniqueLock<LoggedLock::RecMutex> &&wman_lock,
                                    Connman::ServiceList::LockedSingleton &&locked_services,
                                    bool have_lost_active_ethernet_device,
                                    bool have_lost_active_wlan_device)
{
    const struct network_prefs *ethernet_prefs;
    const struct network_prefs *wlan_prefs;
    struct network_prefs_handle *handle =
        network_prefs_open_ro(&ethernet_prefs, &wlan_prefs);

    const bool need_to_schedule_wlan_connection =
        do_process_pending_changes(std::move(wman_lock), std::move(locked_services),
                                   have_lost_active_ethernet_device,
                                   have_lost_active_wlan_device,
                                   wman.wlan_connection_state,
                                   wman.wlan_tools,
                                   ethernet_prefs, wlan_prefs);

    if(handle != NULL)
        network_prefs_close(handle);

    Regs::NetworkConfig::interfaces_changed();

    schedule_wlan_connect_if_necessary(need_to_schedule_wlan_connection, wman);
}

static const std::vector<std::string>
find_removed(const Connman::ServiceList &known_services, GVariant *all_services)
{
    std::vector<std::string> result;
    std::map<const std::string, bool> seen;

    GVariantIter iter;
    g_variant_iter_init(&iter, all_services);

    const gchar *name;
    GVariantIter *props_iter;

    while(g_variant_iter_loop(&iter, "(&oa{sv})", &name, &props_iter))
    {
        if(name[0] != '\0')
            seen[name] = true;
    }

    for(const auto &s : known_services)
    {
        if(seen.find(s.first) == seen.end())
            result.push_back(s.first);
    }

    return result;
}

static void do_refresh_services(Connman::WLANManager &wman, bool force_refresh_all,
                                const char *context)
{
    LOGGED_LOCK_CONTEXT_HINT;
    LoggedLock::UniqueLock<LoggedLock::RecMutex> wman_lock(wman.lock);

    LOGGED_LOCK_CONTEXT_HINT;
    auto locked_services(Connman::ServiceList::get_singleton_for_update());
    auto &services(locked_services.first);

    LOGGED_LOCK_CONTEXT_HINT;
    auto locked_devices(Connman::NetworkDeviceList::get_singleton_for_update());
    auto &devices(locked_devices.first);

    GVariant *all_services =
        connman_common_query_services(dbus_get_connman_manager_iface());

    bool have_lost_active_ethernet_device = false;
    bool have_lost_active_wlan_device = false;

    if(all_services != nullptr)
    {
        const std::vector<std::string> removed(std::move(find_removed(services, all_services)));

        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::RecMutex> lock(wman.lock);

        update_service_list(services, wman.wlan_connection_state,
                            removed,
                            have_lost_active_ethernet_device,
                            have_lost_active_wlan_device);
    }

    if(update_all_services(all_services, services, devices, force_refresh_all,
                           context))
        g_variant_unref(all_services);

    LOGGED_LOCK_CONTEXT_HINT;
    locked_devices.second.unlock();

    process_pending_changes(wman, std::move(wman_lock),
                            std::move(locked_services),
                            have_lost_active_ethernet_device,
                            have_lost_active_wlan_device);
}

void Connman::dbussignal_connman_manager(struct _GDBusProxy *proxy, const char *sender_name,
                                         const char *signal_name, struct _GVariant *parameters,
                                         void *user_data)
{
    auto *wman = static_cast<Connman::WLANManager *>(user_data);

    if(wman != nullptr)
    {
        log_assert(!wman->is_disabled);
        do_refresh_services(*wman, false, signal_name);
    }
    else
        BUG("Got no data in %s()", __func__);
}

static bool is_ssid_rejected(const std::string &ssid,
                             const std::string &wanted_network_name,
                             const std::string &wanted_network_ssid)
{
    log_assert(!ssid.empty());

    if(wanted_network_name.empty() && wanted_network_ssid.empty())
        return false;

    if(ssid == wanted_network_name)
        return false;

    if(ssid == wanted_network_ssid)
        return false;

    return true;
}

static bool start_wps(Connman::WLANManager &wman,
                      const Connman::ServiceList &services,
                      const char *network_name, const char *network_ssid,
                      const char *service_to_be_disabled)
{
    switch(wman.wlan_connection_state.get_state())
    {
      case WLANConnectionState::State::IDLE:
        break;

      case WLANConnectionState::State::DONE:
      case WLANConnectionState::State::FAILED:
      case WLANConnectionState::State::ABORTED:
        wman.wlan_connection_state.reset();
        break;

      case WLANConnectionState::State::WAIT_FOR_REGISTRAR:
      case WLANConnectionState::State::ABOUT_TO_CONNECT:
      case WLANConnectionState::State::CONNECTING:
        msg_info("Cannot connect via WPS, already connecting");
        return false;
    }

    if(services.number_of_wlan_services() == 0)
    {
        msg_info("No WLAN services available, cannot connect via WPS");
        return false;
    }

    const std::string network_name_copy(network_name != nullptr ? network_name : "");
    const std::string network_ssid_copy(network_ssid != nullptr ? network_ssid : "");
    const std::string service_to_be_disabled_copy(
            service_to_be_disabled != nullptr ? service_to_be_disabled : "");

    wman.wlan_connection_state.start_wps(
        [network_name_copy, network_ssid_copy]
        (const std::string &candidate)
        {
            return is_ssid_rejected(candidate, network_name_copy, network_ssid_copy);
        },
        [&wman, service_to_be_disabled_copy]
        (const std::string &found_ssid, const Connman::ServiceList &service_list)
        {
            if(!service_to_be_disabled_copy.empty())
            {
                auto service(service_list.find(service_to_be_disabled_copy));

                if(service != service_list.end() && service->second->is_active())
                    avoid_service(*service->second, service->first);
            }

            schedule_wlan_connect__unlocked(wman);
        });

    return connect_our_wlan(wman);
}

static Connman::WLANManager global_connman_wlan_manager;

Connman::WLANManager *
Connman::init_wlan_manager(std::function<void()> &&schedule_connect_to_wlan_fn,
                           std::function<void()> &&schedule_refresh_connman_services_fn,
                           Connman::WLANTools *wlan_tools, bool is_enabled)
{
    global_connman_wlan_manager.init(std::move(schedule_connect_to_wlan_fn),
                                     std::move(schedule_refresh_connman_services_fn),
                                     wlan_tools, is_enabled);
    return &global_connman_wlan_manager;
}

static void scan_for_wps_done(Connman::SiteSurveyResult result)
{
    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::RecMutex> lock(global_connman_wlan_manager.lock);

    switch(result)
    {
      case Connman::SiteSurveyResult::OK:
        break;

      case Connman::SiteSurveyResult::CONNMAN_ERROR:
      case Connman::SiteSurveyResult::DBUS_ERROR:
      case Connman::SiteSurveyResult::OUT_OF_MEMORY:
      case Connman::SiteSurveyResult::NO_HARDWARE:
        msg_error(0, LOG_ERR,
                  "WLAN scan failed hard (%d), stopping WPS",
                  static_cast<int>(result));
        stop_wps(global_connman_wlan_manager.wlan_connection_state, true);
        return;
    }

    switch(global_connman_wlan_manager.wlan_connection_state.get_state())
    {
      case WLANConnectionState::State::WAIT_FOR_REGISTRAR:
        msg_info("WLAN scan succeeded, now trying to connect to WPS registrar");
        schedule_wlan_connect__unlocked(global_connman_wlan_manager);
        break;

      case WLANConnectionState::State::ABOUT_TO_CONNECT:
      case WLANConnectionState::State::CONNECTING:
        msg_info("WLAN scan succeeded, ignored because WPS connection in progress");
        break;

      case WLANConnectionState::State::IDLE:
      case WLANConnectionState::State::DONE:
      case WLANConnectionState::State::FAILED:
      case WLANConnectionState::State::ABORTED:
        msg_info("WLAN scan succeeded, but WPS stopped already");
        break;
    }
}

void Connman::about_to_connect_dbus_signals()
{
    log_assert(!global_connman_wlan_manager.is_disabled);

    LOGGED_LOCK_CONTEXT_HINT;
    LoggedLock::UniqueLock<LoggedLock::RecMutex> wman_lock(global_connman_wlan_manager.lock);

    LOGGED_LOCK_CONTEXT_HINT;
    auto locked_services(Connman::ServiceList::get_singleton_for_update());
    auto &services(locked_services.first);

    LOGGED_LOCK_CONTEXT_HINT;
    auto locked_devices(Connman::NetworkDeviceList::get_singleton_for_update());
    auto &devices(locked_devices.first);

    GVariant *all_services =
        connman_common_query_services(dbus_get_connman_manager_iface());

    if(update_all_services(all_services, services, devices, true, "startup"))
        g_variant_unref(all_services);

    LOGGED_LOCK_CONTEXT_HINT;
    locked_devices.second.unlock();

    process_pending_changes(global_connman_wlan_manager, std::move(wman_lock),
                            std::move(locked_services), false, false);
}

void Connman::connect_to_service(enum NetworkPrefsTechnology tech,
                                 const char *service_to_be_disabled,
                                 bool immediate_activation, bool force_reconnect)
{
    if(global_connman_wlan_manager.is_disabled)
        return;

    if(tech == NWPREFSTECH_UNKNOWN)
        return;

    const struct network_prefs *ethernet_prefs;
    const struct network_prefs *wlan_prefs;
    struct network_prefs_handle *handle =
        network_prefs_open_ro(&ethernet_prefs, &wlan_prefs);

    if(handle == NULL)
        return;

    LOGGED_LOCK_CONTEXT_HINT;
    LoggedLock::UniqueLock<LoggedLock::RecMutex> lock(global_connman_wlan_manager.lock);

    char service_name[NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE];
    bool need_to_schedule_wlan_connection = false;

    LOGGED_LOCK_CONTEXT_HINT;
    const auto locked_services(Connman::ServiceList::get_singleton_const());
    const auto &services(locked_services.first);

    switch(tech)
    {
      case NWPREFSTECH_UNKNOWN:
        break;

      case NWPREFSTECH_ETHERNET:
        if(network_prefs_generate_service_name(ethernet_prefs, service_name,
                                               sizeof(service_name), true) > 0)
        {
            auto our_service(services.find(service_name));

            if(our_service != services.end())
                configure_ipv4_settings(*our_service->second, our_service->first,
                                        ethernet_prefs);
        }

        break;

      case NWPREFSTECH_WLAN:
        if(network_prefs_generate_service_name(wlan_prefs, service_name,
                                               sizeof(service_name), true) > 0)
        {
            auto our_service(services.find(service_name));

            if(our_service != services.end())
            {
                if(configure_our_wlan(static_cast<const Connman::Service<Connman::Technology::WLAN> &>(*our_service->second),
                                      our_service->first, wlan_prefs,
                                      global_connman_wlan_manager.wlan_connection_state,
                                      true, immediate_activation, force_reconnect) &&
                   immediate_activation)
                {
                    global_connman_wlan_manager.wlan_connection_state.about_to_connect_to(
                        our_service->first, WLANConnectionState::Method::KNOWN_CREDENTIALS);
                    need_to_schedule_wlan_connection = true;
                }
            }
        }

        break;
    }

    network_prefs_close(handle);

    if(service_to_be_disabled != NULL && service_to_be_disabled[0] != '\0')
    {
        auto service(services.find(service_to_be_disabled));

        if(service != services.end() &&
           service->second->is_active())
            avoid_service(*service->second, service->first);
    }

    LOGGED_LOCK_CONTEXT_HINT;
    lock.unlock();

    schedule_wlan_connect_if_necessary(need_to_schedule_wlan_connection,
                                       global_connman_wlan_manager);
}

void Connman::connect_to_wps_service(const char *network_name, const char *network_ssid,
                                     const char *service_to_be_disabled)
{
    if(global_connman_wlan_manager.is_disabled)
        return;

    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::RecMutex> lock(global_connman_wlan_manager.lock);

    LOGGED_LOCK_CONTEXT_HINT;
    const auto locked_services(Connman::ServiceList::get_singleton_const());
    const auto &services(locked_services.first);

    start_wps(global_connman_wlan_manager, services,
              network_name, network_ssid, service_to_be_disabled);
}

void Connman::cancel_wps()
{
    if(global_connman_wlan_manager.is_disabled)
        return;

    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::RecMutex> lock(global_connman_wlan_manager.lock);

    stop_wps(global_connman_wlan_manager.wlan_connection_state, false);
}

static bool get_connecting_status(const Connman::ServiceList::Map::value_type &s,
                                  bool is_wps)
{
    if(!s.second->get_service_data().state_.is_known())
        return false;

    switch(s.second->get_service_data().state_.get())
    {
      case Connman::ServiceState::NOT_AVAILABLE:
      case Connman::ServiceState::UNKNOWN_STATE:
      case Connman::ServiceState::READY:
      case Connman::ServiceState::DISCONNECT:
      case Connman::ServiceState::ONLINE:
        break;

      case Connman::ServiceState::IDLE:
      case Connman::ServiceState::FAILURE:
        if(is_wps)
            return true;

        break;

      case Connman::ServiceState::ASSOCIATION:
      case Connman::ServiceState::CONFIGURATION:
        return true;
    }

    return false;
}

bool Connman::is_connecting(bool *is_wps)
{
    log_assert(!global_connman_wlan_manager.is_disabled);

    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::RecMutex> lock(global_connman_wlan_manager.lock);

    LOGGED_LOCK_CONTEXT_HINT;
    const auto locked_services(Connman::ServiceList::get_singleton_const());
    const auto &services(locked_services.first);

    auto &d(global_connman_wlan_manager);

    *is_wps = d.wlan_connection_state.is_wps_mode();

    switch(d.wlan_connection_state.get_state())
    {
      case WLANConnectionState::State::WAIT_FOR_REGISTRAR:
      case WLANConnectionState::State::ABOUT_TO_CONNECT:
      case WLANConnectionState::State::CONNECTING:
        return true;

      case WLANConnectionState::State::IDLE:
      case WLANConnectionState::State::DONE:
      case WLANConnectionState::State::FAILED:
      case WLANConnectionState::State::ABORTED:
        break;
    }

    for(const auto &s : services)
        if(get_connecting_status(s, false))
            return true;

    return false;
}

void Connman::refresh_services(bool force_refresh_all)
{
    if(!global_connman_wlan_manager.is_disabled)
        do_refresh_services(global_connman_wlan_manager,
                            force_refresh_all, __func__);
}
