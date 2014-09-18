#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include "dcpregs_drcp.h"
#include "drcp_command_codes.h"
#include "dbus_iface.h"
#include "dbus_iface_deep.h"
#include "dynamic_buffer.h"
#include "messages.h"

enum handle_complex_return_value
{
    CPLXCMD_CONTINUE,
    CPLXCMD_CONTINUE_WITH_ERROR,
    CPLXCMD_END,
    CPLXCMD_END_WITH_ERROR,
};

static enum handle_complex_return_value
handle_fast_wind_set_factor(struct dynamic_buffer *buffer,
                            bool is_start_of_command, bool failed,
                            uint8_t code_1, uint8_t code_2)
{
    static const uint8_t expected_payload_size = 1;

    assert(!is_start_of_command || code_1 == DRCP_FAST_WIND_SET_SPEED);

    if(is_start_of_command)
        return CPLXCMD_CONTINUE;

    if(failed)
        return (code_1 == DRCP_ACCEPT) ? CPLXCMD_END : CPLXCMD_CONTINUE;

    if(code_1 == DRCP_ACCEPT)
    {
        if(buffer->pos != expected_payload_size)
            return CPLXCMD_END_WITH_ERROR;

        const uint8_t factor_code = buffer->data[0];

        if(factor_code < DRCP_KEY_DIGIT_0 || factor_code > DRCP_KEY_DIGIT_9)
            return CPLXCMD_END_WITH_ERROR;

        const uint8_t speed_factor = (factor_code - DRCP_KEY_DIGIT_0 + 1) * 3;

        tdbus_dcpd_playback_emit_fast_wind_set_factor(dbus_get_playback_iface(),
                                                      speed_factor);
        return CPLXCMD_END;
    }

    if(buffer->pos > expected_payload_size - 1U)
        return CPLXCMD_CONTINUE_WITH_ERROR;

    if(!dynamic_buffer_check_space(buffer))
        return CPLXCMD_CONTINUE_WITH_ERROR;

    buffer->data[buffer->pos++] = code_1;

    return CPLXCMD_CONTINUE;
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

typedef enum handle_complex_return_value
    (*custom_handler_t)(struct dynamic_buffer *buffer,
                        bool is_start_of_command, bool failed,
                        uint8_t code_1, uint8_t code_2);

struct complex_command_data
{
    uint8_t code;
    struct dynamic_buffer arguments;
    bool failed;
    custom_handler_t current_handler;
};

enum dbus_interface_id
{
    DBUSIFACE_CUSTOM = 1,
    DBUSIFACE_PLAYBACK,
    DBUSIFACE_VIEWS,
    DBUSIFACE_LIST_NAVIGATION,
    DBUSIFACE_LIST_ITEM,
};

struct drc_command_t
{
    uint8_t code;

    const enum dbus_interface_id iface_id;

    union
    {
        const custom_handler_t custom_handler;
        void (*const playback)(tdbusdcpdPlayback *iface);
        void (*const views)(tdbusdcpdViews *iface);
        void (*const list_navigation)(tdbusdcpdListNavigation *iface);
        void (*const list_item)(tdbusdcpdListItem *iface);
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
        .iface_id = DBUSIFACE_CUSTOM,
        .dbus_signal.custom_handler = handle_fast_wind_set_factor,
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

static int handle_complex_command(struct complex_command_data *command_data,
                                  custom_handler_t handler,
                                  uint8_t code_1, uint8_t code_2)
{
    if(handler != NULL)
    {
        command_data->current_handler = handler;
        command_data->failed = false;
        dynamic_buffer_clear(&command_data->arguments);
    }

    if(command_data->current_handler == NULL)
        return 1;

    enum handle_complex_return_value ret =
        command_data->current_handler(&command_data->arguments,
                                      handler != NULL,
                                      command_data->failed, code_1, code_2);

    const bool is_end_of_command =
        (ret == CPLXCMD_END || ret == CPLXCMD_END_WITH_ERROR);
    const bool have_errors =
        (ret == CPLXCMD_END_WITH_ERROR || ret == CPLXCMD_CONTINUE_WITH_ERROR);

    if(have_errors && !command_data->failed)
    {
        msg_error(0, LOG_ERR, "Handling complex command 0x%02x failed",
                  command_data->code);
        command_data->failed = true;
    }

    if(is_end_of_command)
        command_data->current_handler = NULL;

    return (is_end_of_command && have_errors) ? -1 : 0;
}

/*!
 * Write handler for DCP register 72.
 *
 * This function handles the DRC commands sent by the slave.
 */
int dcpregs_write_drcp_command(const uint8_t *data, size_t length)
{
    assert(length == 2);

    msg_info("DRC: command code 0x%02x, data 0x%02x", data[0], data[1]);

    static struct complex_command_data command_data;

    int ret = handle_complex_command(&command_data, NULL, data[0], data[1]);
    if(ret <= 0)
        return ret;

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

    switch(command->iface_id)
    {
      case DBUSIFACE_CUSTOM:
        ret = handle_complex_command(&command_data,
                                     command->dbus_signal.custom_handler,
                                     data[0], data[1]);
        if(ret <= 0)
            return ret;

        break;

      case DBUSIFACE_PLAYBACK:
        command->dbus_signal.playback(dbus_get_playback_iface());
        break;

      case DBUSIFACE_VIEWS:
        command->dbus_signal.views(dbus_get_views_iface());
        break;

      case DBUSIFACE_LIST_NAVIGATION:
        command->dbus_signal.list_navigation(dbus_get_list_navigation_iface());
        break;

      case DBUSIFACE_LIST_ITEM:
        command->dbus_signal.list_item(dbus_get_list_item_iface());
        break;
    }

    return 0;
}
