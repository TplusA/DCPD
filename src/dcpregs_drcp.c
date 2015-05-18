/*
 * Copyright (C) 2015  T+A elektroakustik GmbH & Co. KG
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "dcpregs_drcp.h"
#include "drcp_command_codes.h"
#include "dbus_iface.h"
#include "dbus_iface_deep.h"
#include "dynamic_buffer.h"
#include "messages.h"

static bool is_length_correct(size_t expected, size_t length)
{
    if(length == expected)
        return true;

    msg_error(EINVAL, LOG_NOTICE,
              "Unexpected data length %zu, expected %zu", length, expected);

    return false;
}

static int handle_fast_wind_set_factor(tdbusdcpdPlayback *iface,
                                       const uint8_t *data, size_t length)
{
    if(!is_length_correct(1, length))
        return -1;

    const uint8_t factor_code = data[0];
    if(factor_code < DRCP_KEY_DIGIT_0 || factor_code > DRCP_KEY_DIGIT_9)
        return -1;

    const uint8_t speed_factor = (factor_code - DRCP_KEY_DIGIT_0 + 1) * 3;
    tdbus_dcpd_playback_emit_fast_wind_set_factor(iface, speed_factor);

    return 0;
}

static void handle_goto_internet_radio(tdbusdcpdViews *iface)
{
    tdbus_dcpd_views_emit_open(iface, "Internet Radio");
}

static void handle_goto_favorites(tdbusdcpdViews *iface)
{
    tdbus_dcpd_views_emit_open(iface, "Favorites");
}

static void handle_goto_home(tdbusdcpdViews *iface)
{
    tdbus_dcpd_views_emit_open(iface, "Home");
}

static void handle_toggle_views_browse_play(tdbusdcpdViews *iface)
{
    tdbus_dcpd_views_emit_toggle(iface, "Browse", "Play");
}

static void handle_scroll_one_line_up(tdbusdcpdListNavigation *iface)
{
    tdbus_dcpd_list_navigation_emit_move_lines(iface, -1);
}

static void handle_scroll_one_line_down(tdbusdcpdListNavigation *iface)
{
    tdbus_dcpd_list_navigation_emit_move_lines(iface, 1);
}

static void handle_scroll_one_page_up(tdbusdcpdListNavigation *iface)
{
    tdbus_dcpd_list_navigation_emit_move_pages(iface, -1);
}

static void handle_scroll_one_page_down(tdbusdcpdListNavigation *iface)
{
    tdbus_dcpd_list_navigation_emit_move_pages(iface, 1);
}

static void handle_add_to_favorites(tdbusdcpdListItem *iface)
{
    tdbus_dcpd_list_item_emit_add_to_list(iface, "Favorites", 0);
}

static void handle_remove_from_favorites(tdbusdcpdListItem *iface)
{
    tdbus_dcpd_list_item_emit_remove_from_list(iface, "Favorites", 0);
}

enum dbus_interface_id
{
    DBUSIFACE_PLAYBACK = 1,
    DBUSIFACE_PLAYBACK_WITH_DATA,
    DBUSIFACE_VIEWS,
    DBUSIFACE_VIEWS_WITH_DATA,
    DBUSIFACE_LIST_NAVIGATION,
    DBUSIFACE_LIST_NAVIGATION_WITH_DATA,
    DBUSIFACE_LIST_ITEM,
    DBUSIFACE_LIST_ITEM_WITH_DATA,
};

struct drc_command_t
{
    uint8_t code;

    const enum dbus_interface_id iface_id;

    union
    {
        void (*const playback)(tdbusdcpdPlayback *iface);
        int (*const playback_d)(tdbusdcpdPlayback *iface, const uint8_t *data, size_t length);
        void (*const views)(tdbusdcpdViews *iface);
        int (*const views_d)(tdbusdcpdViews *iface, const uint8_t *data, size_t length);
        void (*const list_navigation)(tdbusdcpdListNavigation *iface);
        int (*const list_navigation_d)(tdbusdcpdListNavigation *iface, const uint8_t *data, size_t length);
        void (*const list_item)(tdbusdcpdListItem *iface);
        int (*const list_item_d)(tdbusdcpdListItem *iface, const uint8_t *data, size_t length);
    }
    dbus_signal;
};

/*!
 * List of implemented DRCP commands.
 *
 * \note The entries must be sorted by code for the binary search.
 */
static const struct drc_command_t drc_commands[] =
{
    {
        .code = DRCP_PLAYBACK_PAUSE,
        .iface_id = DBUSIFACE_PLAYBACK,
        .dbus_signal.playback = tdbus_dcpd_playback_emit_pause,
    },
    {
        .code = DRCP_GO_BACK_ONE_LEVEL,
        .iface_id = DBUSIFACE_LIST_NAVIGATION,
        .dbus_signal.list_navigation = tdbus_dcpd_list_navigation_emit_level_up,
    },
    {
        .code = DRCP_SCROLL_UP_ONE,
        .iface_id = DBUSIFACE_LIST_NAVIGATION,
        .dbus_signal.list_navigation = handle_scroll_one_line_up,
    },
    {
        .code = DRCP_SELECT_ITEM,
        .iface_id = DBUSIFACE_LIST_NAVIGATION,
        .dbus_signal.list_navigation = tdbus_dcpd_list_navigation_emit_level_down,
    },
    {
        .code = DRCP_SCROLL_DOWN_ONE,
        .iface_id = DBUSIFACE_LIST_NAVIGATION,
        .dbus_signal.list_navigation = handle_scroll_one_line_down,
    },
    {
        .code = DRCP_KEY_OK_ENTER,
        .iface_id = DBUSIFACE_LIST_NAVIGATION,
        .dbus_signal.list_navigation = tdbus_dcpd_list_navigation_emit_level_down,
    },
    {
        .code = DRCP_FAVORITES_ADD_ITEM,
        .iface_id = DBUSIFACE_LIST_ITEM,
        .dbus_signal.list_item = handle_add_to_favorites,
    },
    {
        .code = DRCP_FAVORITES_REMOVE_ITEM,
        .iface_id = DBUSIFACE_LIST_ITEM,
        .dbus_signal.list_item = handle_remove_from_favorites,
    },
    {
        .code = DRCP_SCROLL_PAGE_UP,
        .iface_id = DBUSIFACE_LIST_NAVIGATION,
        .dbus_signal.list_navigation = handle_scroll_one_page_up,
    },
    {
        .code = DRCP_SCROLL_PAGE_DOWN,
        .iface_id = DBUSIFACE_LIST_NAVIGATION,
        .dbus_signal.list_navigation = handle_scroll_one_page_down,
    },
    {
        .code = DRCP_GOTO_INTERNET_RADIO,
        .iface_id = DBUSIFACE_VIEWS,
        .dbus_signal.views = handle_goto_internet_radio,
    },
    {
        .code = DRCP_GOTO_FAVORITES,
        .iface_id = DBUSIFACE_VIEWS,
        .dbus_signal.views = handle_goto_favorites,
    },
    {
        .code = DRCP_GOTO_HOME,
        .iface_id = DBUSIFACE_VIEWS,
        .dbus_signal.views = handle_goto_home,
    },
    {
        .code = DRCP_PLAYBACK_NEXT,
        .iface_id = DBUSIFACE_PLAYBACK,
        .dbus_signal.playback = tdbus_dcpd_playback_emit_next,
    },
    {
        .code = DRCP_PLAYBACK_PREVIOUS,
        .iface_id = DBUSIFACE_PLAYBACK,
        .dbus_signal.playback = tdbus_dcpd_playback_emit_previous,
    },
    {
        .code = DRCP_PLAYBACK_STOP,
        .iface_id = DBUSIFACE_PLAYBACK,
        .dbus_signal.playback = tdbus_dcpd_playback_emit_stop,
    },
    {
        .code = DRCP_PLAYBACK_START,
        .iface_id = DBUSIFACE_PLAYBACK,
        .dbus_signal.playback = tdbus_dcpd_playback_emit_start,
    },
    {
        .code = DRCP_BROWSE_PLAY_VIEW_TOGGLE,
        .iface_id = DBUSIFACE_VIEWS,
        .dbus_signal.views = handle_toggle_views_browse_play,
    },
    {
        .code = DRCP_REPEAT_MODE_TOGGLE,
        .iface_id = DBUSIFACE_PLAYBACK,
        .dbus_signal.playback = tdbus_dcpd_playback_emit_repeat_mode_toggle,
    },
    {
        .code = DRCP_FAST_WIND_FORWARD,
        .iface_id = DBUSIFACE_PLAYBACK,
        .dbus_signal.playback = tdbus_dcpd_playback_emit_fast_forward,
    },
    {
        .code = DRCP_FAST_WIND_REVERSE,
        .iface_id = DBUSIFACE_PLAYBACK,
        .dbus_signal.playback = tdbus_dcpd_playback_emit_fast_rewind,
    },
    {
        .code = DRCP_FAST_WIND_STOP,
        .iface_id = DBUSIFACE_PLAYBACK,
        .dbus_signal.playback = tdbus_dcpd_playback_emit_fast_wind_stop,
    },
    {
        .code = DRCP_FAST_WIND_SET_SPEED,
        .iface_id = DBUSIFACE_PLAYBACK_WITH_DATA,
        .dbus_signal.playback_d = handle_fast_wind_set_factor,
    },
    {
        .code = DRCP_SHUFFLE_MODE_TOGGLE,
        .iface_id = DBUSIFACE_PLAYBACK,
        .dbus_signal.playback = tdbus_dcpd_playback_emit_shuffle_mode_toggle,
    },
};

static int compare_command_code(const void *a, const void *b)
{
    return
        (int)((const struct drc_command_t *)a)->code -
        (int)((const struct drc_command_t *)b)->code;
}

/*!
 * Write handler for DCP register 72.
 *
 * This function handles the DRC commands sent by the slave.
 */
int dcpregs_write_drcp_command(const uint8_t *data, size_t length)
{
    log_assert(length >= 1);

    msg_info("DRC: command code 0x%02x", data[0]);

    /* static because we want static initialization; only the code field is
     * ever changed */
    static struct drc_command_t key;

    key.code = data[0];

    struct drc_command_t *command =
        bsearch(&key, drc_commands,
                sizeof(drc_commands) / sizeof(drc_commands[0]),
                sizeof(drc_commands[0]), compare_command_code);

    if(command == NULL)
    {
        msg_error(EINVAL, LOG_ERR,
                  "Received unsupported DRC command 0x%02x", data[0]);
        return -1;
    }

    int ret = 0;

    switch(command->iface_id)
    {
      case DBUSIFACE_PLAYBACK:
        command->dbus_signal.playback(dbus_get_playback_iface());
        break;

      case DBUSIFACE_PLAYBACK_WITH_DATA:
        ret = command->dbus_signal.playback_d(dbus_get_playback_iface(),
                                              data + 1, length - 1);
        break;

      case DBUSIFACE_VIEWS:
        command->dbus_signal.views(dbus_get_views_iface());
        break;

      case DBUSIFACE_VIEWS_WITH_DATA:
        ret = command->dbus_signal.views_d(dbus_get_views_iface(),
                                           data + 1, length - 1);
        break;

      case DBUSIFACE_LIST_NAVIGATION:
        command->dbus_signal.list_navigation(dbus_get_list_navigation_iface());
        break;

      case DBUSIFACE_LIST_NAVIGATION_WITH_DATA:
        ret = command->dbus_signal.list_navigation_d(dbus_get_list_navigation_iface(),
                                                     data + 1, length - 1);
        break;

      case DBUSIFACE_LIST_ITEM:
        command->dbus_signal.list_item(dbus_get_list_item_iface());
        break;

      case DBUSIFACE_LIST_ITEM_WITH_DATA:
        ret = command->dbus_signal.list_item_d(dbus_get_list_item_iface(),
                                               data + 1, length - 1);
        break;
    }

    if(ret != 0)
        msg_error(0, LOG_ERR, "DRC command 0x%02x failed: %d", data[0], ret);

    return ret;
}
