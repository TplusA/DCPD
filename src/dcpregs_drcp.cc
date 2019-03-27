/*
 * Copyright (C) 2015--2019  T+A elektroakustik GmbH & Co. KG
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

#include "dcpregs_drcp.hh"
#include "drcp_command_codes.h"
#include "dcpregs_playstream.hh"
#include "dbus_iface_deep.h"
#include "messages.h"

#include <array>
#include <memory>
#include <functional>
#include <algorithm>

static bool is_length_correct(size_t expected, size_t length)
{
    if(length == expected)
        return true;

    msg_error(EINVAL, LOG_NOTICE,
              "Unexpected data length %zu, expected %zu", length, expected);

    return false;
}

static int handle_goto_view_by_id(tdbusdcpdViews *iface,
                                  const uint8_t *data, size_t length)
{
    if(!is_length_correct(2, length))
        return -1;

    if(data[1] != DRCP_ACCEPT)
        return -1;

    static std::array<const char *const, 3> view_names
    {
        "UPnP",
        "TuneIn",
        "Filesystem",
    };

    if(data[0] >= view_names.size())
    {
        msg_error(EINVAL, LOG_NOTICE, "Unknown view ID 0x%02x", data[0]);
        return -1;
    }

    tdbus_dcpd_views_emit_open(iface, view_names[data[0]]);

    return 0;
}

static bool scroll_many_params_are_valid(const uint8_t *data, size_t length)
{
    if(!is_length_correct(2, length))
        return false;

    if(data[1] != DRCP_ACCEPT)
        return false;

    return (data[0] != 0);
}

class DRCCommand
{
  public:
    const uint8_t code_;

    DRCCommand(const DRCCommand &) = delete;
    DRCCommand(DRCCommand &&) = default;
    DRCCommand &operator=(const DRCCommand &) = delete;
    DRCCommand &operator=(DRCCommand &&) = default;

    explicit DRCCommand(uint8_t code): code_(code) {}
    virtual ~DRCCommand() {};
};

class SimpleCommand: public DRCCommand
{
  public:
    const std::function<void()> fn_;

    explicit SimpleCommand(uint8_t code, std::function<void()> &&fn):
        DRCCommand(code),
        fn_(std::move(fn))
    {}
};

class CommandWithData: public DRCCommand
{
  public:
    const std::function<int(const uint8_t *, size_t)> fn_;

    explicit CommandWithData(uint8_t code,
                             std::function<int(const uint8_t *, size_t)> &&fn):
        DRCCommand(code),
        fn_(std::move(fn))
    {}
};

/*!
 * List of implemented DRCP commands.
 *
 * \note The entries must be sorted by code for binary search.
 */
static const std::array<std::unique_ptr<DRCCommand>, 25> drc_commands
{
    std::make_unique<SimpleCommand>(DRCP_POWER_OFF,
        [] ()
        {
            tdbus_logind_manager_call_power_off_sync(dbus_get_logind_manager_iface(),
                                                     false, nullptr, nullptr);
        }),
    std::make_unique<SimpleCommand>(DRCP_PLAYBACK_PAUSE,
        [] () { tdbus_dcpd_playback_emit_pause(dbus_get_playback_iface()); }),
    std::make_unique<CommandWithData>(DRCP_SCROLL_UP_MANY,
        [] (const uint8_t *data, size_t length)
        {
            if(!scroll_many_params_are_valid(data, length))
                return -1;

            tdbus_dcpd_list_navigation_emit_move_lines(dbus_get_list_navigation_iface(),
                                                       -(gint)data[0]);
            return 0;
        }),
    std::make_unique<CommandWithData>(DRCP_SCROLL_DOWN_MANY,
        [] (const uint8_t *data, size_t length)
        {
            if(!scroll_many_params_are_valid(data, length))
                return -1;

            tdbus_dcpd_list_navigation_emit_move_lines(dbus_get_list_navigation_iface(),
                                                       (gint)data[0]);
            return 0;
        }),
    std::make_unique<SimpleCommand>(DRCP_GO_BACK_ONE_LEVEL,
        [] ()
        {
            tdbus_dcpd_list_navigation_emit_level_up(dbus_get_list_navigation_iface());
        }),
    std::make_unique<SimpleCommand>(DRCP_SCROLL_UP_ONE,
        [] ()
        {
            tdbus_dcpd_list_navigation_emit_move_lines(dbus_get_list_navigation_iface(), -1);
        }),
    std::make_unique<SimpleCommand>(DRCP_SELECT_ITEM,
        [] ()
        {
            tdbus_dcpd_list_navigation_emit_level_down(dbus_get_list_navigation_iface());
        }),
    std::make_unique<SimpleCommand>(DRCP_SCROLL_DOWN_ONE,
        [] ()
        {
            tdbus_dcpd_list_navigation_emit_move_lines(dbus_get_list_navigation_iface(), 1);
        }),
    std::make_unique<SimpleCommand>(DRCP_KEY_OK_ENTER,
        [] ()
        {
            tdbus_dcpd_list_navigation_emit_level_down(dbus_get_list_navigation_iface());
        }),
    std::make_unique<SimpleCommand>(DRCP_FAVORITES_ADD_ITEM,
        [] ()
        {
            tdbus_dcpd_list_item_emit_add_to_list(dbus_get_list_item_iface(),
                                                  "Favorites", 0);
        }),
    std::make_unique<SimpleCommand>(DRCP_FAVORITES_REMOVE_ITEM,
        [] ()
        {
            tdbus_dcpd_list_item_emit_remove_from_list(dbus_get_list_item_iface(),
                                                       "Favorites", 0);
        }),
    std::make_unique<SimpleCommand>(DRCP_SCROLL_PAGE_UP,
        [] ()
        {
            tdbus_dcpd_list_navigation_emit_move_pages(dbus_get_list_navigation_iface(), -1);
        }),
    std::make_unique<SimpleCommand>(DRCP_SCROLL_PAGE_DOWN,
        [] ()
        {
            tdbus_dcpd_list_navigation_emit_move_pages(dbus_get_list_navigation_iface(), 1);
        }),
    std::make_unique<CommandWithData>(DRCP_BROWSE_VIEW_OPEN_SOURCE,
        [] (const uint8_t *data, size_t length)
        {
            return handle_goto_view_by_id(dbus_get_views_iface(), data, length);
        }),
    std::make_unique<SimpleCommand>(DRCP_GOTO_INTERNET_RADIO,
        [] ()
        {
            tdbus_dcpd_views_emit_open(dbus_get_views_iface(), "Internet Radio");
        }),
    std::make_unique<SimpleCommand>(DRCP_GOTO_FAVORITES,
        [] ()
        {
            tdbus_dcpd_views_emit_open(dbus_get_views_iface(), "Favorites");
        }),
    std::make_unique<SimpleCommand>(DRCP_GOTO_HOME,
        [] ()
        {
            tdbus_dcpd_views_emit_open(dbus_get_views_iface(), "Home");
        }),
    std::make_unique<SimpleCommand>(DRCP_PLAYBACK_NEXT,
        [] () { tdbus_dcpd_playback_emit_next(dbus_get_playback_iface()); }),
    std::make_unique<SimpleCommand>(DRCP_PLAYBACK_PREVIOUS,
        [] () { tdbus_dcpd_playback_emit_previous(dbus_get_playback_iface()); }),
    std::make_unique<SimpleCommand>(DRCP_PLAYBACK_STOP,
        [] ()
        {
            if(!Regs::PlayStream::DCP::stop_plain_player())
                tdbus_dcpd_playback_emit_stop(dbus_get_playback_iface());
        }),
    std::make_unique<SimpleCommand>(DRCP_PLAYBACK_START,
        [] () { tdbus_dcpd_playback_emit_start(dbus_get_playback_iface()); }),
    std::make_unique<SimpleCommand>(DRCP_PLAYBACK_TRY_RESUME,
        [] () { tdbus_dcpd_playback_emit_resume(dbus_get_playback_iface()); }),
    std::make_unique<SimpleCommand>(DRCP_BROWSE_PLAY_VIEW_TOGGLE,
        [] ()
        {
            tdbus_dcpd_views_emit_toggle(dbus_get_views_iface(), "Browse", "Play");
        }),
    std::make_unique<SimpleCommand>(DRCP_REPEAT_MODE_TOGGLE,
        [] () { tdbus_dcpd_playback_emit_repeat_mode_toggle(dbus_get_playback_iface()); }),
    std::make_unique<SimpleCommand>(DRCP_SHUFFLE_MODE_TOGGLE,
        [] () { tdbus_dcpd_playback_emit_shuffle_mode_toggle(dbus_get_playback_iface()); }),
};

/*!
 * Write handler for DCP register 72.
 *
 * This function handles the DRC commands sent by the slave.
 */
int Regs::DRCP::DCP::write_drcp_command(const uint8_t *data, size_t length)
{
    log_assert(length >= 1);

    msg_vinfo(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x%02x", data[0]);

    const auto it =
        std::lower_bound(drc_commands.begin(), drc_commands.end(), data[0],
            [] (const std::unique_ptr<DRCCommand> &cmd, uint8_t code)
            {
                return cmd->code_ < code;
            });

    if(it == drc_commands.end() || (*it)->code_ != data[0])
    {
        msg_error(EINVAL, LOG_ERR,
                  "Received unsupported DRC command 0x%02x", data[0]);
        return -1;
    }

    const int ret = [data, length] (const DRCCommand *command)
    {
        if(const auto *sc = dynamic_cast<const SimpleCommand *>(command))
        {
            sc->fn_();
            return 0;
        }

        if(const auto *dc = dynamic_cast<const CommandWithData *>(command))
            return dc->fn_(data + 1, length - 1);

        BUG("Unknown DRCP command type");
        return -1;
    } (it->get());

    if(ret != 0)
        msg_error(0, LOG_ERR, "DRC command 0x%02x failed: %d", data[0], ret);

    return ret;
}
