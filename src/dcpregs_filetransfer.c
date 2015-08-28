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

#include <string.h>
#include <errno.h>

#include "messages.h"

#include "dcpregs_filetransfer.h"
#include "dcpregs_filetransfer_priv.h"
#include "dbus_iface_deep.h"
#include "registers_priv.h"

#define MAXIMUM_URL_LENGTH 1024U

struct FileTransferData
{
    char url[MAXIMUM_URL_LENGTH + 1];

    struct
    {
        GMutex lock;

        /*! Transfer ID as returned by D-Bus DL, 0 for no transfer. */
        uint32_t xfer_id;

        /*! True after D-Bus DL has been successfully triggered to start. */
        bool is_in_progress;

        /*!
         * Download progress in percent.
         *
         * Note that this value is set to \c UINT8_MAX as long as no progress
         * feedback from D-Bus DL has been received. That is, a value of
         * \c UINT8_MAX should be interpreted as "unknown", therefore 0.
         */
        uint8_t percent;

        /*!
         * Download result as HCR code.
         *
         * This value is valid if #xfer_id is non-zero, #is_in_progress is
         * false, and #percent is equal to 100.
         */
        uint8_t result;
    }
    download_status;
};

static struct FileTransferData filetransfer_data;

static int handle_dbus_error(GError **error)
{
    if(*error == NULL)
        return 0;

    msg_error(0, LOG_EMERG, "%s", (*error)->message);
    g_error_free(*error);
    *error = NULL;

    return -1;
}

/*!
 * Ask D-Bus DL to stop the current transfer, if any.
 *
 * \attention
 *     Must be called with the lock for #FileTransferData::download_status
 *     held.
 */
static void request_cancel_transfer_if_necessary(void)
{
    if(!filetransfer_data.download_status.is_in_progress)
        return;

    GError *error = NULL;

    if(tdbus_file_transfer_call_cancel_sync(dbus_get_file_transfer_iface(),
                                            filetransfer_data.download_status.xfer_id,
                                            NULL, &error))
    {
        filetransfer_data.download_status.xfer_id = 0;
        filetransfer_data.download_status.is_in_progress = false;
    }
    else
    {
        msg_error(0, LOG_ERR, "Failed canceling download %u",
                  filetransfer_data.download_status.xfer_id);
    }

    (void)handle_dbus_error(&error);
}

static void cleanup_transfer(void)
{
    g_mutex_lock(&filetransfer_data.download_status.lock);
    request_cancel_transfer_if_necessary();
    filetransfer_data.download_status.xfer_id = 0;
    filetransfer_data.download_status.is_in_progress = false;
    filetransfer_data.download_status.percent = UINT8_MAX;
    filetransfer_data.download_status.result = HCR_STATUS_DOWNLOAD_OK;
    g_mutex_unlock(&filetransfer_data.download_status.lock);

    filetransfer_data.url[0] = '\0';
}

static bool data_length_is_unexpected(size_t length, size_t expected)
{
    if(length == expected)
        return false;

    msg_error(EINVAL, LOG_ERR,
              "Unexpected data length %zu (expected %zu)", length, expected);

    return true;
}

static bool data_length_is_in_unexpected_range(size_t length,
                                               size_t expected_min,
                                               size_t expected_max)
{
    if(length >= expected_min && length <= expected_max)
        return false;

    msg_error(EINVAL, LOG_ERR,
              "Unexpected data length %zu (expected %zu...%zu)",
              length, expected_min, expected_max);

    return true;
}

int dcpregs_write_40_download_control(const uint8_t *data, size_t length)
{
    static const char unsupported_command_message[] = "Unsupported command";

    msg_info("write 40 handler %p %zu", data, length);

    if(data_length_is_unexpected(length, 2))
        return -1;

    if(data[0] != HCR_COMMAND_CATEGORY_FILE_TRANSFER &&
       data[0] != HCR_COMMAND_CATEGORY_LOAD_TO_DEVICE)
    {
        msg_error(EINVAL, LOG_ERR, unsupported_command_message);
        return -1;
    }

    if(data[0] == HCR_COMMAND_CATEGORY_FILE_TRANSFER)
    {
        msg_error(ENOSYS, LOG_ERR, "XMODEM not implemented yet");
        return -1;
    }

    if(data[1] != HCR_COMMAND_LOAD_TO_DEVICE_DOWNLOAD)
    {
        msg_error(ENOSYS, LOG_ERR, unsupported_command_message);
        return -1;
    }

    if(filetransfer_data.url[0] == '\0')
    {
        msg_error(EINVAL, LOG_NOTICE, "Download URL not configured");
        return -1;
    }

    g_mutex_lock(&filetransfer_data.download_status.lock);
    filetransfer_data.download_status.percent = UINT8_MAX;

    GError *error = NULL;

    /*!
     * FIXME: 100 is not good for small files or very fast connections. 10 is
     *        not good for large files or very slow connections. Comprimising
     *        on 20, but this either needs dynamic adjustment or message rate
     *        limiting.
     */
    if(tdbus_file_transfer_call_download_sync(dbus_get_file_transfer_iface(),
                                              filetransfer_data.url,
                                              20,
                                              &filetransfer_data.download_status.xfer_id,
                                              NULL, &error) &&
       filetransfer_data.download_status.xfer_id != 0)
    {
        msg_info("Download started, transfer ID %u",
                 filetransfer_data.download_status.xfer_id);
        filetransfer_data.download_status.is_in_progress = true;
    }
    else
        filetransfer_data.download_status.is_in_progress = false;

    g_mutex_unlock(&filetransfer_data.download_status.lock);

    return handle_dbus_error(&error);
}

ssize_t dcpregs_read_41_download_status(uint8_t *response, size_t length)
{
    msg_info("read 41 handler %p %zu", response, length);

    if(data_length_is_unexpected(length, 2))
        return -1;

    g_mutex_lock(&filetransfer_data.download_status.lock);

    if(filetransfer_data.download_status.xfer_id != 0)
    {
        if(filetransfer_data.download_status.is_in_progress)
        {
            response[0] = HCR_STATUS_CATEGORY_PROGRESS;
            response[1] =
                (filetransfer_data.download_status.percent < UINT8_MAX)
                ? filetransfer_data.download_status.percent
                : 0;
        }
        else
        {
            response[0] = HCR_STATUS_CATEGORY_DOWNLOAD;
            response[1] = filetransfer_data.download_status.result;
        }
    }
    else
    {
        response[0] = HCR_STATUS_CATEGORY_GENERIC;
        response[1] = HCR_STATUS_GENERIC_OK;
    }

    g_mutex_unlock(&filetransfer_data.download_status.lock);

    return length;
}

int dcpregs_write_209_download_url(const uint8_t *data, size_t length)
{
    msg_info("write 209 handler %p %zu", data, length);

    cleanup_transfer();

    if(length == 0)
    {
        filetransfer_data.url[0] = '\0';
        msg_info("Cleared URL");
        return 0;
    }

    if(data_length_is_in_unexpected_range(length,
                                          8 + 1, 8 + MAXIMUM_URL_LENGTH))
        return -1;

    if(data[0] != HCR_FILE_TRANSFER_CRC_MODE_NONE)
    {
        msg_error(EINVAL, LOG_ERR, "Unsupported CRC mode 0x%02x", data[0]);
        return -1;
    }

    if(data[3] != HCR_FILE_TRANSFER_ENCRYPTION_NONE)
    {
        msg_error(EINVAL, LOG_ERR,
                  "Unsupported encryption mode 0x%02x", data[3]);
        return -1;
    }

    data += 8;
    length -= 8;
    memcpy(filetransfer_data.url, data, length);
    filetransfer_data.url[length] = '\0';

    msg_info("Set URL \"%s\"", filetransfer_data.url);

    return 0;
}

void dcpregs_filetransfer_progress_notification(uint32_t xfer_id,
                                                uint32_t tick,
                                                uint32_t total_ticks)
{
    bool changed = false;
    uint8_t percent = total_ticks > 0
        ? (uint8_t)(100.0 * ((double)tick / (double)total_ticks))
        : 100;

    g_mutex_lock(&filetransfer_data.download_status.lock);

    if(filetransfer_data.download_status.is_in_progress &&
       filetransfer_data.download_status.xfer_id == xfer_id)
    {
        if(filetransfer_data.download_status.percent != percent)
        {
            filetransfer_data.download_status.percent = percent;
            changed = true;
        }
    }

    g_mutex_unlock(&filetransfer_data.download_status.lock);

    if(changed)
        registers_get_data()->register_changed_notification_fn(41);
}

void dcpregs_filetransfer_done_notification(uint32_t xfer_id,
                                            enum DBusListsErrorCode error,
                                            const char *path)
{
    bool changed = false;

    g_mutex_lock(&filetransfer_data.download_status.lock);

    if(filetransfer_data.download_status.is_in_progress &&
       filetransfer_data.download_status.xfer_id == xfer_id)
    {
        filetransfer_data.download_status.is_in_progress = false;
        filetransfer_data.download_status.percent = 100;
        filetransfer_data.download_status.result = HCR_STATUS_DOWNLOAD_OK;

        switch(error)
        {
          case LIST_ERROR_OK:
          case LIST_ERROR_INTERRUPTED:
            break;

          case LIST_ERROR_AUTHENTICATION:
          case LIST_ERROR_PROTOCOL:
            filetransfer_data.download_status.result = HCR_STATUS_DOWNLOAD_CRC_ERROR;
            break;

          case LIST_ERROR_NET_IO:
            filetransfer_data.download_status.result = HCR_STATUS_DOWNLOAD_NETWORK_ERROR;
            break;

          case LIST_ERROR_INVALID_ID:
            filetransfer_data.download_status.result = HCR_STATUS_DOWNLOAD_FILE_NOT_FOUND;
            break;

          case LIST_ERROR_INTERNAL:
          case LIST_ERROR_PHYSICAL_MEDIA_IO:
            filetransfer_data.download_status.result = HCR_STATUS_DOWNLOAD_OUT_OF_MEMORY;
            break;
        }

        changed = true;
    }
    else
    {
        /*
         * Spurious done notifications are possible due to data races, in which
         * case we delete the downloaded file right now.
         *
         * NOTE: This only works under the assumption that we are the only
         * process on the system that uses the D-Bus DL service. If other
         * processes are using it, then this code here causes deletion of all
         * files requested by other processes.
         */
        if(path != NULL)
        {
            msg_info("Delete file \"%s\"", path);
            os_file_delete(path);
        }
    }

    g_mutex_unlock(&filetransfer_data.download_status.lock);

    if(changed)
        registers_get_data()->register_changed_notification_fn(41);
}

void dcpregs_filetransfer_init(void)
{
    memset(&filetransfer_data, 0, sizeof(filetransfer_data));
    g_mutex_init(&filetransfer_data.download_status.lock);
}

void dcpregs_filetransfer_deinit(void)
{
    g_mutex_clear(&filetransfer_data.download_status.lock);
}
