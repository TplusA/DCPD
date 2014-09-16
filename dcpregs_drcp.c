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
#include "messages.h"

struct drc_command_t
{
    uint8_t code;
    void (*const dbus_signal)(tdbusdcpdPlayback *iface);
};

static const struct drc_command_t drc_commands[] =
{
    {
        .code = DRCP_PLAYBACK_STOP,
        .dbus_signal = tdbus_dcpd_playback_emit_stop,
    },
    {
        .code = DRCP_PLAYBACK_START,
        .dbus_signal = tdbus_dcpd_playback_emit_start,
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
    msg_info("write 72 handler %p %zu", data, length);
    assert(length == 2);

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

    msg_info("DRC: command code 0x%02x, data 0x%02x", data[0], data[1]);

    command->dbus_signal(dbus_get_playback_iface());

    return 0;
}
