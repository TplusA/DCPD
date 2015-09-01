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

#include "messages.h"

#include "dcpregs_filetransfer.h"
#include "dcpregs_filetransfer_priv.h"
#include "dbus_iface_deep.h"
#include "registers_priv.h"
#include "xmodem.h"

/*! Sane limit on URL length to cap DC traffic. */
#define MAXIMUM_URL_LENGTH 1024U

/*! Limit XMODEM progress reports so that only every N'th report is sent. */
#define XMODEM_PROGRESS_RATE_LIMIT 5

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

    struct
    {
        GMutex lock;

        /*! Full path of the temporary file currently being transferred. */
        char *path;

        /*! Mapped file currently being transferred. */
        struct os_mapped_file_data mapped_file;

        /*! State of XMODEM transfer. */
        struct XModemContext xm_ctx;

        /*!
         * Send progress report only if zero, decreased for each block sent.
         *
         * \see
         *     #XMODEM_PROGRESS_RATE_LIMIT
         */
        int progress_rate_limit;
    }
    xmodem_status;
};

static struct FileTransferData filetransfer_data =
{
    .xmodem_status =
    {
        .mapped_file =
        {
            .fd = -1,
        },
    },
};

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

static inline bool xmodem_transfer_is_in_progress(void)
{
    return filetransfer_data.xmodem_status.mapped_file.fd >= 0;
}

static void reset_xmodem_state(const char *path, bool is_error)
{
    g_mutex_lock(&filetransfer_data.xmodem_status.lock);

    if(xmodem_transfer_is_in_progress())
    {
        log_assert(filetransfer_data.xmodem_status.path != NULL);

        if(is_error)
            msg_error(0, LOG_WARNING, "Aborting XMODEM transfer");
        else
            msg_info("Finished XMODEM transfer");
    }

    if(filetransfer_data.xmodem_status.path != NULL)
    {
        msg_info("Delete file \"%s\"", filetransfer_data.xmodem_status.path);
        os_unmap_file(&filetransfer_data.xmodem_status.mapped_file);
        os_file_delete(filetransfer_data.xmodem_status.path);
        free(filetransfer_data.xmodem_status.path);
    }

    if(path != NULL)
    {
        filetransfer_data.xmodem_status.path = strdup(path);

        if(filetransfer_data.xmodem_status.path == NULL)
            msg_out_of_memory("Path string");
    }
    else
        filetransfer_data.xmodem_status.path = NULL;

    xmodem_init(&filetransfer_data.xmodem_status.xm_ctx, NULL);

    g_mutex_unlock(&filetransfer_data.xmodem_status.lock);
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

static int try_start_download(void)
{
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

static int try_start_xmodem(void)
{
    cleanup_transfer();

    if(xmodem_transfer_is_in_progress())
    {
        msg_info("XMODEM transfer in progress, not restarting");
        return 1;
    }

    int ret;

    g_mutex_lock(&filetransfer_data.xmodem_status.lock);

    if(filetransfer_data.xmodem_status.path != NULL)
    {
        log_assert(filetransfer_data.xmodem_status.xm_ctx.buffer_data.tx_offset == 0);
        ret = os_map_file_to_memory(&filetransfer_data.xmodem_status.mapped_file,
                                    filetransfer_data.xmodem_status.path);

        if(ret == 0)
        {
            xmodem_init(&filetransfer_data.xmodem_status.xm_ctx,
                        &filetransfer_data.xmodem_status.mapped_file);
            msg_info("Ready for XMODEM");
        }
    }
    else
    {
        msg_error(0, LOG_ERR, "No file downloaded for XMODEM");
        ret = -1;
    }

    g_mutex_unlock(&filetransfer_data.xmodem_status.lock);

    return ret;
}

int dcpregs_write_40_download_control(const uint8_t *data, size_t length)
{
    msg_info("write 40 handler %p %zu", data, length);

    if(data_length_is_unexpected(length, 2))
        return -1;

    if(data[0] == HCR_COMMAND_CATEGORY_FILE_TRANSFER &&
       data[1] == HCR_COMMAND_FILE_TRANSFER_DOWNLOAD)
    {
        int ret = try_start_xmodem();

        if(ret == 0)
        {
            /* report 0% progress */
            filetransfer_data.xmodem_status.progress_rate_limit = XMODEM_PROGRESS_RATE_LIMIT;
            registers_get_data()->register_changed_notification_fn(41);
        }
        else if(ret > 0)
            ret = 0;

        return ret;
    }
    else if(data[0] == HCR_COMMAND_CATEGORY_LOAD_TO_DEVICE &&
            data[1] == HCR_COMMAND_LOAD_TO_DEVICE_DOWNLOAD)
    {
        return try_start_download();
    }

    msg_error(ENOSYS, LOG_ERR, "Unsupported command");

    return -1;
}

static void fill_download_status_from_download(uint8_t *response)
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

static void fill_download_status_from_xmodem(uint8_t *response)
{
    if(xmodem_transfer_is_in_progress())
    {
        response[0] = HCR_STATUS_CATEGORY_PROGRESS;
        response[1] = filetransfer_data.xmodem_status.mapped_file.length > 0
            ? (uint8_t)(100.0 *
                        ((double)filetransfer_data.xmodem_status.xm_ctx.buffer_data.tx_offset /
                         (double)filetransfer_data.xmodem_status.mapped_file.length))
            : 100;
    }
    else
    {
        response[0] = HCR_STATUS_CATEGORY_GENERIC;
        response[1] = HCR_STATUS_GENERIC_OK;
    }
}

ssize_t dcpregs_read_41_download_status(uint8_t *response, size_t length)
{
    msg_info("read 41 handler %p %zu", response, length);

    if(data_length_is_unexpected(length, 2))
        return -1;

    g_mutex_lock(&filetransfer_data.download_status.lock);
    g_mutex_lock(&filetransfer_data.xmodem_status.lock);

    if(filetransfer_data.download_status.xfer_id != 0)
        fill_download_status_from_download(response);
    else if(filetransfer_data.xmodem_status.path != NULL)
        fill_download_status_from_xmodem(response);
    else
    {
        response[0] = HCR_STATUS_CATEGORY_GENERIC;
        response[1] = HCR_STATUS_GENERIC_OK;
    }

    g_mutex_unlock(&filetransfer_data.xmodem_status.lock);
    g_mutex_unlock(&filetransfer_data.download_status.lock);

    return length;
}

ssize_t dcpregs_read_44_xmodem_data(uint8_t *response, size_t length)
{
    msg_info("read 44 handler %p %zu", response, length);

    if(data_length_is_in_unexpected_range(length, 1, 3 + 128 + 2))
        return -1;

    g_mutex_lock(&filetransfer_data.xmodem_status.lock);

    bool was_successful = false;

    if(!xmodem_transfer_is_in_progress())
        msg_error(EINVAL, LOG_ERR, "No XMODEM transfer going on");
    else
    {
        const uint8_t *block;
        const ssize_t buffer_size =
            xmodem_get_block(&filetransfer_data.xmodem_status.xm_ctx, &block);

        if(buffer_size <= 0)
            msg_error(EINVAL, LOG_ERR, "No data to send via XMODEM");
        else if((size_t)buffer_size > length)
            msg_error(EINVAL, LOG_ERR, "XMODEM receive buffer too small");
        else
        {
            memcpy(response, block, buffer_size);
            length = buffer_size;
            was_successful = true;

            if(length > 1)
            {
                msg_info("Send %zu bytes of XMODEM data, command 0x%02x, block %u",
                         length, response[0], response[1]);
                if(--filetransfer_data.xmodem_status.progress_rate_limit <= 0)
                {
                    filetransfer_data.xmodem_status.progress_rate_limit = XMODEM_PROGRESS_RATE_LIMIT;
                    registers_get_data()->register_changed_notification_fn(41);
                }
            }
            else
            {
                log_assert(response[0] == XMODEM_COMMAND_EOT);
                msg_info("Send 1 byte of XMODEM data");

                /* report 100% progress */
                filetransfer_data.xmodem_status.progress_rate_limit = 0;
                registers_get_data()->register_changed_notification_fn(41);
            }
        }
    }

    g_mutex_unlock(&filetransfer_data.xmodem_status.lock);

    if(!was_successful)
    {
        reset_xmodem_state(NULL, true);
        response[0] = XMODEM_COMMAND_NACK;
        length = 1;
    }

    return length;
}

int dcpregs_write_45_xmodem_command(const uint8_t *data, size_t length)
{
    msg_info("write 45 handler %p %zu", data, length);

    if(data_length_is_unexpected(length, 1))
        return -1;

    const enum XModemCommand command = xmodem_byte_to_command(data[0]);

    if(command == XMODEM_COMMAND_INVALID)
    {
        msg_error(EINVAL, LOG_ERR, "Invalid XMODEM command 0x%02x", data[0]);
        return -1;
    }

    g_mutex_lock(&filetransfer_data.xmodem_status.lock);

    bool was_successful = false;
    bool is_end_of_transmission = false;

    if(xmodem_transfer_is_in_progress())
    {
        const enum XModemResult result =
            xmodem_process(&filetransfer_data.xmodem_status.xm_ctx, command);

        switch(result)
        {
          case XMODEM_RESULT_OK:
          case XMODEM_RESULT_LAST_BLOCK:
          case XMODEM_RESULT_EOT:
            msg_info("Queuing %s", (result == XMODEM_RESULT_OK
                                    ? "next XMODEM block"
                                    : (result == XMODEM_RESULT_LAST_BLOCK
                                       ? "last XMODEM block"
                                       : "EOT")));
            was_successful = true;
            registers_get_data()->register_changed_notification_fn(44);
            break;

          case XMODEM_RESULT_CLOSED:
            was_successful = true;
            is_end_of_transmission = true;
            break;

          case XMODEM_RESULT_PROTOCOL_VIOLATION:
            msg_error(0, LOG_ERR, "XMODEM protocol violation");
            break;

          case XMODEM_RESULT_TIMEOUT:
            msg_error(0, LOG_ERR, "XMODEM timeout");
            break;
        }
    }
    else
        msg_error(EINVAL, LOG_ERR, "No XMODEM transfer going on");

    g_mutex_unlock(&filetransfer_data.xmodem_status.lock);

    if(!was_successful || is_end_of_transmission)
        reset_xmodem_state(NULL, !was_successful);

    return was_successful ? 0 : -1;
}


int dcpregs_write_209_download_url(const uint8_t *data, size_t length)
{
    msg_info("write 209 handler %p %zu", data, length);

    cleanup_transfer();
    reset_xmodem_state(NULL, true);

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
    const uint8_t percent = total_ticks > 0
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

    reset_xmodem_state(path, true);
}

void dcpregs_filetransfer_init(void)
{
    memset(&filetransfer_data, 0, sizeof(filetransfer_data));
    g_mutex_init(&filetransfer_data.download_status.lock);
    g_mutex_init(&filetransfer_data.xmodem_status.lock);
    filetransfer_data.xmodem_status.mapped_file.fd = -1;
}

void dcpregs_filetransfer_deinit(void)
{
    g_mutex_clear(&filetransfer_data.download_status.lock);
    g_mutex_clear(&filetransfer_data.xmodem_status.lock);

    if(filetransfer_data.xmodem_status.path != NULL)
        free(filetransfer_data.xmodem_status.path);
}
