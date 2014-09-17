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
};

struct drc_command_t
{
    uint8_t code;

    const enum dbus_interface_id iface_id;

    union
    {
        const custom_handler_t custom_handler;
        void (*const playback)(tdbusdcpdPlayback *iface);
    }
    dbus_signal;
};

static const struct drc_command_t drc_commands[] =
{
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
    }

    return 0;
}
