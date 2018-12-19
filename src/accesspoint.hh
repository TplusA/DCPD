/*
 * Copyright (C) 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef ACCESSPOINT_HH
#define ACCESSPOINT_HH

#include "connman_address.hh"
#include "connman_technology_registry.hh"

#include <functional>
#include <mutex>
#include <vector>
#include <string>
#include <memory>

namespace Network
{

class AccessPoint
{
  public:
    enum class Status
    {
        UNKNOWN,
        PROBING_STATUS,
        DISABLED,
        ACTIVATING,
        ACTIVE,

        LAST_STATUS = ACTIVE,
    };

    enum class RequestResult
    {
        OK,                 /*!< Succeeded */
        BLOCKED_BY_POLICY,  /*!< AP not allowed by system configuration */
        BLOCKED_BUSY,       /*!< Another request is in progress, try again later */
        FAILED,             /*!< Request failed due to some error */

        LAST_REQUEST_RESULT = FAILED,
    };

    enum class Error
    {
        OK,
        UNKNOWN,
        DBUS_FAILURE,
        BUSY,
        ALREADY_ACTIVATING, /*!< Activation request while activating */
        ALREADY_ACTIVE,     /*!< Activation request while active */
        ALREADY_DISABLED,   /*!< Deactivation request while disabled */

        LAST_ERROR = ALREADY_DISABLED,
    };

    using StatusFn = std::function<void(Connman::TechnologyRegistry &reg,
                                        Status old_status, Status new_status)>;
    using DoneFn = std::function<void(RequestResult result, Error error, Status status)>;

  private:
    class RequestBase
    {
      private:
        const DoneFn done_notification_;
        bool notified_;

      protected:
        explicit RequestBase():
            notified_(false)
        {}

      public:
        RequestBase(const RequestBase &) = delete;
        RequestBase &operator=(const RequestBase &) = delete;

        explicit RequestBase(DoneFn &&done_notification):
            done_notification_(done_notification),
            notified_(false)
        {}

        virtual ~RequestBase()
        {
            if(!notified_)
                BUG("Dropping pending AP request notification");
        }

        void done(RequestResult result, Error error, Status status)
        {
            notified_ = true;
            done_notification_(result, error, status);
        }
    };

    class SpawnRequest: public RequestBase
    {
      public:
        const std::string ssid_;
        const std::string passphrase_;

        explicit SpawnRequest(std::string &&ssid, std::string &&passphrase,
                              DoneFn &&done_notification):
            RequestBase(std::move(done_notification)),
            ssid_(ssid),
            passphrase_(passphrase)
        {}
    };

    class ShutdownRequest: public RequestBase
    {
      public:
        explicit ShutdownRequest(DoneFn &&done_notification):
            RequestBase(std::move(done_notification))
        {}
    };

    std::recursive_mutex lock_;

    Connman::TechnologyRegistry &tech_reg_;
    bool started_;
    Status status_;
    std::vector<StatusFn> status_watchers_;

    std::unique_ptr<RequestBase> active_request_;

  public:
    AccessPoint(const AccessPoint &) = delete;
    AccessPoint &operator=(const AccessPoint &) = delete;

    explicit AccessPoint(Connman::TechnologyRegistry &reg);

    void start();

    void register_status_watcher(StatusFn &&fn);

    bool spawn_request(std::string &&ssid, std::string &&passphrase,
                       DoneFn &&done_notification);
    bool shutdown_request(DoneFn &&done_notification);

  private:
    void wifi_property_changed_notification(Connman::TechnologyPropertiesWIFI::Property property,
                                            Connman::TechnologyPropertiesBase::StoreResult result,
                                            Connman::TechnologyPropertiesWIFI &wifi);

    void set_status(Status status);
    std::unique_ptr<RequestBase>
    figure_out_current_status(std::unique_ptr<RequestBase> request, bool &scheduled);
    void spawn(std::unique_ptr<SpawnRequest> request,
               std::unique_lock<std::recursive_mutex> &ap_lock);
    void shutdown(std::unique_ptr<ShutdownRequest> request);
    void request_done(Connman::TechnologyPropertiesBase::StoreResult result,
                      bool is_tethering, Status status);
};

}

#endif /* !ACCESSPOINT_HH */
