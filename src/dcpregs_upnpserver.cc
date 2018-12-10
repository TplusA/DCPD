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

#include "dcpregs_upnpserver.hh"
#include "gerbera_dbus.h"
#include "dbus_iface_deep.h"
#include "registers_priv.hh"
#include "os.h"
#include "maybe.hh"
#include "messages.h"

#include <cerrno>

class GerberaStatus
{
  private:
    Maybe<bool> is_busy_;

  public:
    GerberaStatus(const GerberaStatus &) = delete;
    GerberaStatus(GerberaStatus &&) = default;
    GerberaStatus &operator=(const GerberaStatus &) = delete;
    GerberaStatus &operator=(GerberaStatus &&) = default;
    explicit GerberaStatus() = default;

    bool disconnected()
    {
        const bool result = is_busy_.is_known();
        is_busy_.set_unknown();
        return result;
    }

    bool set_status(bool busy_state)
    {
        /* do not use operator!= here */
        const bool result = !(is_busy_ == busy_state);
        is_busy_ = busy_state;
        return result;
    }

    Maybe<bool> get() const { return is_busy_; }
};

static GerberaStatus gerbera_status;

void Regs::UPnPServer::connected(bool is_connected)
{
    if(is_connected)
    {
        auto *const iface = dbus_get_gerbera_content_manager_iface();
        set_busy_state(tdbus_gerbera_content_manager_get_busy(iface) == TRUE);
    }
    else
    {
        msg_info("Gerbera status unknown (disconnected)");
        if(gerbera_status.disconnected())
            Regs::get_data().register_changed_notification_fn(89);
    }
}

void Regs::UPnPServer::set_busy_state(bool is_busy)
{
    msg_info("Gerbera is %s", is_busy ? "busy" : "idle");
    if(gerbera_status.set_status(is_busy))
        Regs::get_data().register_changed_notification_fn(89);
}

enum class WriteCommand
{
    /* we don't start at 0x00 because it would be to easy to reset the database
     * by accident */
    RESET_DATABASE = 0x01,

    FIRST_WRITE_COMMAND = RESET_DATABASE,
    LAST_WRITE_COMMAND = RESET_DATABASE,
};

int Regs::UPnPServer::DCP::write_89_upnp_server_command(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 89 handler %p %zu", data, length);

    if(length == 0)
        return -1;

    if(data[0] < uint8_t(WriteCommand::FIRST_WRITE_COMMAND) ||
       data[0] > uint8_t(WriteCommand::LAST_WRITE_COMMAND))
    {
        APPLIANCE_BUG("Invalid UPnP server control subcommand %u", data[0]);
        return -1;
    }

    switch(WriteCommand(data[0]))
    {
      case WriteCommand::RESET_DATABASE:
        os_system(true, "sudo /usr/bin/gerbera-reset-database");
        return 0;
    }

    msg_error(EINVAL, LOG_ERR,
              "UPnP server control command 0x%02x failed", data[0]);

    return -1;
}

bool Regs::UPnPServer::DCP::read_89_upnp_server_status(std::vector<uint8_t> &buffer)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 89 handler");

    const auto &busy_status(gerbera_status.get());

    static constexpr uint8_t STATUS_KNOWN     = 1U << 0;
    static constexpr uint8_t STATUS_BUSY_BIT  = 1U << 1;

    if(busy_status == false)
        buffer.push_back(STATUS_KNOWN);
    else if(busy_status == true)
        buffer.push_back(STATUS_KNOWN | STATUS_BUSY_BIT);
    else
        buffer.push_back(0);

    return true;
}
