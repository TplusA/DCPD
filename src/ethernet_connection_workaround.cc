/*
 * Copyright (C) 2021  T+A elektroakustik GmbH & Co. KG
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

#include "ethernet_connection_workaround.hh"
#include "messages.h"

#include <glib.h>

class PeriodicPHYReset
{
  private:
    constexpr static guint INTERVAL = 5000;

    bool inhibited_;
    bool active_;
    guint source_id_;

  public:
    PeriodicPHYReset(const PeriodicPHYReset &) = delete;
    PeriodicPHYReset(PeriodicPHYReset &&) = default;
    PeriodicPHYReset &operator=(const PeriodicPHYReset &) = delete;
    PeriodicPHYReset &operator=(PeriodicPHYReset &&) = default;

    explicit PeriodicPHYReset():
        inhibited_(true),
        active_(false),
        source_id_(0)
    {}

    void set_inhibited(bool is_inhibited)
    {
        if(is_inhibited == inhibited_)
            return;

        if(is_inhibited)
            stop();

        inhibited_ = is_inhibited;
    }

    void start_background_task()
    {
        if(inhibited_)
            return;

        if(active_)
            return;

        msg_info("Starting periodic Ethernet PHY reset");
        active_ = true;

        if(source_id_ == 0)
            source_id_ = g_timeout_add(INTERVAL, idle_fn, this);
    }

    void stop()
    {
        if(inhibited_)
            return;

        if(active_)
        {
            msg_info("Stopping periodic Ethernet PHY reset");
            active_ = false;
        }
    }

  private:
    static gboolean idle_fn(gpointer user_data)
    {
        auto *me = static_cast<PeriodicPHYReset *>(user_data);
        return me->do_it();
    }

    gboolean do_it()
    {
        if(!active_)
        {
            msg_info("Stopped periodic Ethernet PHY reset");
            source_id_ = 0;
            return FALSE;
        }

        msg_vinfo(MESSAGE_LEVEL_DIAG, "Resetting Ethernet PHY (cable check)");
        os_system(false, "sudo /sbin/mii-tool -R eth0");

        return TRUE;
    }
};

static PeriodicPHYReset phy_reset_;

void EthernetConnectionWorkaround::enable()
{
    phy_reset_.start_background_task();
}

void EthernetConnectionWorkaround::disable()
{
    phy_reset_.stop();
}

void EthernetConnectionWorkaround::required_on_this_kernel(bool is_required)
{
    phy_reset_.set_inhibited(!is_required);
}
