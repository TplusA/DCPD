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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "accesspoint.hh"
#include "connman_technology_registry.hh"

#include <exception>

class AccessPointError: public std::runtime_error
{
  public:
    const Network::AccessPoint::Error error_;

    explicit AccessPointError(const std::string &msg, Network::AccessPoint::Error error):
        std::runtime_error(msg),
        error_(error)
    {
        bug_on_no_error(error_);
    }

    explicit AccessPointError(const char *msg, Network::AccessPoint::Error error):
        std::runtime_error(msg),
        error_(error)
    {
        bug_on_no_error(error_);
    }

  private:
    static void bug_on_no_error(Network::AccessPoint::Error error)
    {
        if(error == Network::AccessPoint::Error::OK)
            MSG_BUG("AccessPointError exception without proper error code");
    }
};

Network::AccessPoint::AccessPoint(Connman::TechnologyRegistry &reg):
    tech_reg_(reg),
    started_(false),
    status_(Status::UNKNOWN)
{
    LoggedLock::configure(lock_, "Network::AccessPoint", MESSAGE_LEVEL_DEBUG);

    tech_reg_.register_property_watcher(
        [this]
        (Connman::TechnologyPropertiesWIFI::Property property,
         Connman::TechnologyPropertiesBase::StoreResult result,
         Connman::TechnologyPropertiesWIFI &wifi)
        {
            try
            {
                wifi_property_changed_notification(property, result, wifi);
            }
            catch(...)
            {
                msg_error(0, LOG_ERR,
                          "Failed notifying AP manager about property update");
            }
        });
}

void Network::AccessPoint::start()
{
    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::RecMutex> lock(lock_);

    if(started_)
    {
        MSG_BUG("Access point started again");
        return;
    }

    LOGGED_LOCK_CONTEXT_HINT;
    const auto tech_lock(tech_reg_.locked());

    try
    {
        /* trigger access to properties if not done already */
        const bool is_tethering(tech_reg_.wifi().get<Connman::TechnologyPropertiesWIFI::Property::TETHERING>());
        const auto status(is_tethering ? Status::ACTIVE : Status::DISABLED);
        set_status(status);
        started_ = true;
    }
    catch(const Connman::TechnologyPropertiesWIFI::Exceptions::PropertyUnknown &e)
    {
        /* property not initialized yet (to be expected) */
        started_ = true;
    }
    catch(const Connman::TechnologyRegistryUnavailableError &e)
    {
        /* not connected with D-Bus yet---not OK */
        MSG_BUG("Technology registry unavailable (no D-Bus connection)");
    }
    catch(...)
    {
        /* huh? */
        MSG_BUG("Unexpected exception from WIFI properties registry");
    }
}

void Network::AccessPoint::register_status_watcher(StatusFn &&fn)
{
    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::RecMutex> lock(lock_);
    status_watchers_.emplace_back(fn);
    status_watchers_.back()(tech_reg_, status_, status_);
}

void Network::AccessPoint::set_status(Status status)
{
    const auto old_status = status_;
    status_ = status;

    if(status_ != old_status)
        for(const auto &fn : status_watchers_)
            fn(tech_reg_, old_status, status_);
}

void Network::AccessPoint::request_done(Connman::TechnologyPropertiesBase::StoreResult result,
                                        bool is_tether_status_ok, Status status)
{
    switch(result)
    {
      case Connman::TechnologyPropertiesBase::StoreResult::UPDATE_NOTIFICATION:
        break;

      case Connman::TechnologyPropertiesBase::StoreResult::COMMITTED_AND_UPDATED:
        active_request_->done(is_tether_status_ok ? RequestResult::OK : RequestResult::FAILED,
                              is_tether_status_ok ? Error::OK : Error::UNKNOWN,
                              status);
        active_request_.reset();
        break;

      case Connman::TechnologyPropertiesBase::StoreResult::COMMITTED_UNCHANGED:
        active_request_->done(is_tether_status_ok ? RequestResult::OK : RequestResult::FAILED,
                              is_tether_status_ok ? Error::OK : Error::ALREADY_ACTIVE,
                              status);
        active_request_.reset();
        break;

      case Connman::TechnologyPropertiesBase::StoreResult::DBUS_FAILURE:
        active_request_->done(RequestResult::FAILED, Error::DBUS_FAILURE, status);
        active_request_.reset();
        break;

      case Connman::TechnologyPropertiesBase::StoreResult::UNKNOWN_ERROR:
        active_request_->done(RequestResult::FAILED, Error::UNKNOWN, status);
        active_request_.reset();
        break;
    }
}

void Network::AccessPoint::wifi_property_changed_notification(
        Connman::TechnologyPropertiesWIFI::Property property,
        Connman::TechnologyPropertiesBase::StoreResult result,
        Connman::TechnologyPropertiesWIFI &wifi)
{
    switch(property)
    {
      case Connman::TechnologyPropertiesWIFI::Property::TETHERING:
        {
            const bool is_tethering(wifi.get<Connman::TechnologyPropertiesWIFI::Property::TETHERING>());
            const auto status(is_tethering ? Status::ACTIVE : Status::DISABLED);

            LOGGED_LOCK_CONTEXT_HINT;
            std::lock_guard<LoggedLock::RecMutex> lock(lock_);

            if(dynamic_cast<const SpawnRequest *>(active_request_.get()) != nullptr)
                request_done(result, is_tethering, status);
            else if(dynamic_cast<const ShutdownRequest *>(active_request_.get()) != nullptr)
                request_done(result, !is_tethering, status);

            set_status(status);
        }

        break;

      case Connman::TechnologyPropertiesWIFI::Property::POWERED:
      case Connman::TechnologyPropertiesWIFI::Property::CONNECTED:
      case Connman::TechnologyPropertiesWIFI::Property::NAME:
      case Connman::TechnologyPropertiesWIFI::Property::TYPE:
      case Connman::TechnologyPropertiesWIFI::Property::TETHERING_IDENTIFIER:
      case Connman::TechnologyPropertiesWIFI::Property::TETHERING_PASSPHRASE:
        break;
    }
}

void Network::AccessPoint::spawn(std::unique_ptr<SpawnRequest> request,
                                 LoggedLock::UniqueLock<LoggedLock::RecMutex> &ap_lock)
{
    const auto *const req(request.get());
    active_request_ = std::move(request);

    LOGGED_LOCK_CONTEXT_HINT;
    const auto tech_lock(tech_reg_.locked());
    const char *action = nullptr;

    try
    {
        set_status(Status::ACTIVATING);
        action = "Obtain Connman technology properties";
        auto &wifi(tech_reg_.wifi());

        /* we don't need our lock anymore; also avoids D-Bus deadlock in
         * #Network::AccessPoint::wifi_property_changed_notification() */
        LOGGED_LOCK_CONTEXT_HINT;
        ap_lock.unlock();

        action = "Set AP SSID";
        wifi.set<Connman::TechnologyPropertiesWIFI::Property::TETHERING_IDENTIFIER>(std::string(req->ssid_));
        action = "Set AP passphrase";
        wifi.set<Connman::TechnologyPropertiesWIFI::Property::TETHERING_PASSPHRASE>(std::string(req->passphrase_));
        action = "Enable AP mode";
        wifi.set<Connman::TechnologyPropertiesWIFI::Property::TETHERING>(true);
    }
    catch(...)
    {
        throw AccessPointError(action, Error::DBUS_FAILURE);
    }
}

void Network::AccessPoint::shutdown(std::unique_ptr<ShutdownRequest> request)
{
    active_request_ = std::move(request);

    LOGGED_LOCK_CONTEXT_HINT;
    const auto tech_lock(tech_reg_.locked());
    const char *action = nullptr;

    try
    {
        action = "Obtain Connman technology properties";
        auto &wifi(tech_reg_.wifi());
        action = "Disable AP mode";
        wifi.set<Connman::TechnologyPropertiesWIFI::Property::TETHERING>(false);
        action = "Clear AP passphrase";
        wifi.set<Connman::TechnologyPropertiesWIFI::Property::TETHERING_PASSPHRASE>(std::string(""));
        action = "Clear AP SSID";
        wifi.set<Connman::TechnologyPropertiesWIFI::Property::TETHERING_IDENTIFIER>(std::string(""));
    }
    catch(...)
    {
        throw AccessPointError(action, Error::DBUS_FAILURE);
    }
}

std::unique_ptr<Network::AccessPoint::RequestBase>
Network::AccessPoint::figure_out_current_status(std::unique_ptr<Network::AccessPoint::RequestBase> request,
                                                bool &scheduled)
{
    scheduled = false;
    LOGGED_LOCK_CONTEXT_HINT;
    const auto tech_lock(tech_reg_.locked());

    try
    {
        auto &wifi(tech_reg_.wifi());
        const bool is_tethering(wifi.get<Connman::TechnologyPropertiesWIFI::Property::TETHERING>());
        set_status(is_tethering ? Status::ACTIVE : Status::DISABLED);
        return request;
    }
    catch(const Connman::TechnologyRegistryUnavailableError &e)
    {
        request->done(RequestResult::FAILED, Error::DBUS_FAILURE, status_);
        return nullptr;
    }
    catch(const Connman::TechnologyPropertiesWIFI::Exceptions::ReadOnly &e)
    {
        request->done(RequestResult::BLOCKED_BY_POLICY, Error::DBUS_FAILURE, status_);
        return nullptr;
    }
    catch(const Connman::TechnologyPropertiesWIFI::Exceptions::PropertyUnknown &e)
    {
        /* OK, let's wait for the property update */
    }

    active_request_ = std::move(request);
    scheduled = true;
    set_status(Status::PROBING_STATUS);

    return nullptr;
}

bool Network::AccessPoint::spawn_request(std::string &&ssid, std::string &&passphrase,
                                         DoneFn &&done_notification)
{
    LOGGED_LOCK_CONTEXT_HINT;
    LoggedLock::UniqueLock<LoggedLock::RecMutex> lock(lock_);

    if(!started_)
    {
        MSG_BUG("AP spawn request before start");
        done_notification(RequestResult::FAILED, Error::BUSY, Status::UNKNOWN);
        return false;
    }

    auto request =
        std::make_unique<SpawnRequest>(std::move(ssid), std::move(passphrase),
                                       std::move(done_notification));

    if(status_ == Status::UNKNOWN)
    {
        bool scheduled;
        request.reset(static_cast<SpawnRequest *>(
            figure_out_current_status(std::move(request), scheduled).release()));
        if(request == nullptr)
            return scheduled;
    }

    if(status_ == Status::ACTIVATING)
    {
        request->done(RequestResult::FAILED, Error::ALREADY_ACTIVATING, status_);
        return false;
    }
    else if(status_ == Status::ACTIVE)
    {
        request->done(RequestResult::FAILED, Error::ALREADY_ACTIVE, status_);
        return false;
    }

    if(active_request_ != nullptr)
    {
        request->done(RequestResult::BLOCKED_BUSY, Error::BUSY, status_);
        return false;
    }

    try
    {
        spawn(std::move(request), lock);
        return true;
    }
    catch(const AccessPointError &e)
    {
        msg_error(0, LOG_ERR, "%s", e.what());

        LOGGED_LOCK_CONTEXT_HINT;
        lock.lock();

        auto req(std::move(active_request_));

        if(status_ == Status::PROBING_STATUS)
            set_status(Status::UNKNOWN);

        LOGGED_LOCK_CONTEXT_HINT;
        lock.unlock();

        if(req != nullptr)
            req->done(RequestResult::FAILED, e.error_, status_);
    }

    return false;
}

bool Network::AccessPoint::shutdown_request(DoneFn &&done_notification)
{
    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::RecMutex> lock(lock_);

    if(!started_)
    {
        MSG_BUG("AP shutdown request before start");
        done_notification(RequestResult::FAILED, Error::BUSY, Status::UNKNOWN);
        return false;
    }

    auto request(std::make_unique<ShutdownRequest>(std::move(done_notification)));

    if(status_ == Status::UNKNOWN)
    {
        bool scheduled;
        request.reset(static_cast<ShutdownRequest *>(
            figure_out_current_status(std::move(request), scheduled).release()));
        if(request == nullptr)
            return scheduled;
    }

    if(status_ == Status::DISABLED)
    {
        request->done(RequestResult::FAILED, Error::ALREADY_DISABLED, status_);
        return false;
    }

    if(active_request_ != nullptr)
    {
        request->done(RequestResult::BLOCKED_BUSY, Error::BUSY, status_);
        return false;
    }

    try
    {
        shutdown(std::move(request));
        return true;
    }
    catch(const AccessPointError &e)
    {
        msg_error(0, LOG_ERR, "%s", e.what());

        auto req(std::move(active_request_));

        if(status_ == Status::PROBING_STATUS)
            set_status(Status::UNKNOWN);

        req->done(RequestResult::FAILED, e.error_, status_);
        req = nullptr;
    }

    return false;
}
