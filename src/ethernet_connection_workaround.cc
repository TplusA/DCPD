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
    constexpr static guint INTERVAL = 15000;

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

    bool start_background_task()
    {
        if(inhibited_)
            return false;

        if(active_)
            return false;

        msg_info("Starting periodic Ethernet PHY reset");
        active_ = true;

        if(source_id_ == 0)
        {
            source_id_ = g_timeout_add(INTERVAL, idle_fn, this);
            return true;
        }

        return false;
    }

    bool stop()
    {
        if(inhibited_)
            return false;

        if(active_)
        {
            msg_info("Stopping periodic Ethernet PHY reset");
            active_ = false;
            return true;
        }

        return false;
    }

    void kickstart() const
    {
        /* don't interfere with periodic reset */
        if(!active_)
            do_reset_now(false);
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

        do_reset_now(true);
        return TRUE;
    }

    static void do_reset_now(bool is_periodic)
    {
        msg_vinfo(MESSAGE_LEVEL_DIAG,
                  "Resetting Ethernet PHY (%s cable check)",
                  is_periodic ? "periodic" : "spontaneous");
        os_system(false, "sudo /sbin/mii-tool -R eth0");
    }
};

static PeriodicPHYReset phy_reset_;

bool EthernetConnectionWorkaround::enable()
{
    return phy_reset_.start_background_task();
}

bool EthernetConnectionWorkaround::disable()
{
    return phy_reset_.stop();
}

void EthernetConnectionWorkaround::kickstart()
{
    phy_reset_.kickstart();
}

void EthernetConnectionWorkaround::required_on_this_kernel(bool is_required)
{
    phy_reset_.set_inhibited(!is_required);
}
