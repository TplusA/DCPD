/*
 * Copyright (C) 2015--2022  T+A elektroakustik GmbH & Co. KG
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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "dcpregs_filetransfer.hh"
#include "dcpregs_filetransfer_priv.h"
#include "dcpregs_system_update.hh"
#include "coverart.hh"
#include "dbus_iface_deep.h"
#include "registers_priv.hh"
#include "xmodem.h"
#include "inifile.h"
#include "logged_lock.hh"
#include "shutdown_guard.h"
#include "os.hh"

#include <cstring>

/*! Sane limit on URL length to cap DC traffic. */
#define MAXIMUM_URL_LENGTH 1024U

/*! Limit XMODEM progress reports so that only every N'th report is sent. */
#define XMODEM_PROGRESS_RATE_LIMIT 5

enum XModemSource
{
    XMODEM_SOURCE_NONE,
    XMODEM_SOURCE_DBUSDL,
    XMODEM_SOURCE_COVER_ART,
};

class XmodemSourceDBusDLData
{
  public:
    /*! Full path of the temporary file currently being transferred. */
    char *path;

    /*! Mapped file currently being transferred. */
    struct os_mapped_file_data mapped_file;

    XmodemSourceDBusDLData(const XmodemSourceDBusDLData &) = delete;
    XmodemSourceDBusDLData(XmodemSourceDBusDLData &&) = default;
    XmodemSourceDBusDLData &operator=(const XmodemSourceDBusDLData &) = delete;
    XmodemSourceDBusDLData &operator=(XmodemSourceDBusDLData &&) = default;

    explicit XmodemSourceDBusDLData():
        path(nullptr),
        mapped_file{-1, nullptr, 0}
    {}
};

class XModemSourceCoverArtData
{
  public:
    bool in_progress;

    /*! Contains data stored in RAM, type enforced by XMODEM interface */
    struct os_mapped_file_data dummy_file;
    CoverArt::Picture picture;

    XModemSourceCoverArtData(const XModemSourceCoverArtData &) = delete;
    XModemSourceCoverArtData(XModemSourceCoverArtData &&) = default;
    XModemSourceCoverArtData &operator=(const XModemSourceCoverArtData &) = delete;
    XModemSourceCoverArtData &operator=(XModemSourceCoverArtData &&) = default;

    explicit XModemSourceCoverArtData():
        in_progress(false),
        dummy_file{-1, nullptr, 0}
    {}
};

class XModemStatus
{
  public:
    LoggedLock::Mutex lock;

    XModemSource source;

    struct
    {
        XmodemSourceDBusDLData   dbusdl;
        XModemSourceCoverArtData coverart;
    }
    src_data;

    /*! State of XMODEM transfer. */
    struct XModemContext xm_ctx;

    /*!
     * Send progress report only if zero, decreased for each block sent.
     *
     * \see
     *     #XMODEM_PROGRESS_RATE_LIMIT
     */
    int progress_rate_limit;

    XModemStatus(const XModemStatus &) = delete;
    XModemStatus(XModemStatus &&) = default;
    XModemStatus &operator=(const XModemStatus &) = delete;
    XModemStatus &operator=(XModemStatus &&) = default;

    explicit XModemStatus():
        source(XMODEM_SOURCE_NONE),
        xm_ctx({}),
        progress_rate_limit(0)
    {
        LoggedLock::configure(lock, "XModemStatus", MESSAGE_LEVEL_DEBUG);
    }
};

template <XModemSource SRC>
struct XModemStatusTraits;

template <>
struct XModemStatusTraits<XMODEM_SOURCE_NONE>
{
    static bool is_in_progress(const XModemStatus &status) { return false; }
    static void free_resources(XModemStatus &status) {}
    static void reset_state(const XModemStatus &status) {}

    static int try_start(XModemStatus &status)
    {
        msg_error(0, LOG_NOTICE, "No XMODEM source configured");
        return -1;
    }

    static uint8_t get_progress(XModemStatus &status) { return 100; }
};

template <>
struct XModemStatusTraits<XMODEM_SOURCE_DBUSDL>
{
    static bool is_in_progress(const XModemStatus &status)
    {
        return status.src_data.dbusdl.mapped_file.fd >= 0;
    }

    static void free_resources(XModemStatus &status)
    {
        auto &data(status.src_data.dbusdl);

        if(data.path != nullptr)
        {
            free(data.path);
            data.path = nullptr;
        }
    }

    static void reset_state(XModemStatus &status)
    {
        auto &data(status.src_data.dbusdl);

        if(data.path == nullptr)
            return;

        msg_info("Delete file \"%s\"", data.path);
        os_unmap_file(&data.mapped_file);
        os_file_delete(data.path);

        free_resources(status);
    }

    static int try_start(XModemStatus &status)
    {
        auto &data(status.src_data.dbusdl);

        if(data.path == nullptr)
        {
            msg_error(0, LOG_ERR, "No file downloaded for XMODEM");
            return -1;
        }

        int ret = os_map_file_to_memory(&data.mapped_file, data.path);

        if(ret == 0)
            xmodem_init(&status.xm_ctx, &data.mapped_file);

        return ret;
    }

    static uint8_t get_progress(XModemStatus &status)
    {
        const auto &data(status.src_data.dbusdl);

        return data.mapped_file.length > 0
            ? (uint8_t)(100.0 *
                        ((double)status.xm_ctx.buffer_data.tx_offset /
                         (double)data.mapped_file.length))
            : 100;
    }
};

static void dump_picture_hash(const char *const what, const uint8_t *const h)
{
    if(h == nullptr)
        msg_info("Cover art XMODEM: %s, hash EMPTY", what);
    else
        msg_info("Cover art XMODEM: %s, hash: "
                 "%02x%02x%02x%02x%02x%02x%02x%02x"
                 "%02x%02x%02x%02x%02x%02x%02x%02x",
                 what,
                 h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
                 h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]);
}

template <>
struct XModemStatusTraits<XMODEM_SOURCE_COVER_ART>
{
    static bool is_in_progress(const XModemStatus &status)
    {
        return status.src_data.coverart.in_progress;
    }

    static void free_resources(XModemStatus &status)
    {
        auto &data(status.src_data.coverart);

        if(data.picture.is_available())
            msg_info("Cover art XMODEM: Clear session data");

        data.picture.clear();
        data.dummy_file.ptr = nullptr;
        data.dummy_file.length = 0;
    }

    static void reset_state(XModemStatus &status)
    {
        auto &data(status.src_data.coverart);
        data.in_progress = false;

        free_resources(status);
    }

    static int try_start(XModemStatus &status)
    {
        auto &data(status.src_data.coverart);

        if(data.picture.is_available())
        {
            data.dummy_file.ptr = const_cast<uint8_t *>(&*data.picture.begin());
            data.dummy_file.length = std::distance(data.picture.begin(), data.picture.end());
            msg_info("Cover art XMODEM: Setup download of %zu bytes",
                     data.dummy_file.length);
            dump_picture_hash("Setup session", data.picture.get_hash_bytes());
        }
        else
        {
            data.dummy_file.ptr = nullptr;
            data.dummy_file.length = 0;
            msg_info("Cover art XMODEM: Setup download of empty picture");
        }

        xmodem_init(&status.xm_ctx, &data.dummy_file);
        data.in_progress = true;

        return 0;
    }

    static uint8_t get_progress(XModemStatus &status)
    {
        const auto &data(status.src_data.coverart);

        return data.dummy_file.length > 0
            ? (uint8_t)(100.0 *
                        ((double)status.xm_ctx.buffer_data.tx_offset /
                         (double)data.dummy_file.length))
            : 100;
    }
};

class FileTransferData
{
  public:
    struct ShutdownGuard *shutdown_guard;

    char url[MAXIMUM_URL_LENGTH + 1];
    const CoverArt::PictureProviderIface *picture_provider;

    class DownloadStatus
    {
      public:
        LoggedLock::Mutex lock;

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

        DownloadStatus(const DownloadStatus &) = delete;
        DownloadStatus(DownloadStatus &&) = default;
        DownloadStatus &operator=(const DownloadStatus &) = delete;
        DownloadStatus &operator=(DownloadStatus &&) = default;

        explicit DownloadStatus():
            xfer_id(0),
            is_in_progress(false),
            percent(0),
            result(0)
        {
            LoggedLock::configure(lock, "FileTransferData::DownloadStatus",
                                  MESSAGE_LEVEL_DEBUG);
        }
    };

    DownloadStatus download_status;
    XModemStatus xmodem_status;

    FileTransferData(const FileTransferData &) = delete;
    FileTransferData(FileTransferData &&) = default;
    FileTransferData &operator=(const FileTransferData &) = delete;
    FileTransferData &operator=(FileTransferData &&) = default;

    explicit FileTransferData():
        shutdown_guard(shutdown_guard_alloc("filetransfer")),
        url{0},
        picture_provider(nullptr)
    {}

    ~FileTransferData()
    {
        if(shutdown_guard != nullptr)
            shutdown_guard_free(&shutdown_guard);

        XModemStatusTraits<XMODEM_SOURCE_NONE>::free_resources(xmodem_status);
        XModemStatusTraits<XMODEM_SOURCE_DBUSDL>::free_resources(xmodem_status);
        XModemStatusTraits<XMODEM_SOURCE_COVER_ART>::free_resources(xmodem_status);
    }
};

static std::unique_ptr<FileTransferData> filetransfer_data;

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
static void request_cancel_transfer_if_necessary()
{
    if(!filetransfer_data->download_status.is_in_progress)
        return;

    GError *error = NULL;

    if(tdbus_file_transfer_call_cancel_sync(dbus_get_file_transfer_iface(),
                                            filetransfer_data->download_status.xfer_id,
                                            NULL, &error))
    {
        filetransfer_data->download_status.xfer_id = 0;
        filetransfer_data->download_status.is_in_progress = false;
    }
    else
    {
        msg_error(0, LOG_ERR, "Failed canceling download %u",
                  filetransfer_data->download_status.xfer_id);
    }

    (void)handle_dbus_error(&error);
}

static void cleanup_transfer()
{
    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::Mutex> lock(filetransfer_data->download_status.lock);

    request_cancel_transfer_if_necessary();
    filetransfer_data->download_status.xfer_id = 0;
    filetransfer_data->download_status.is_in_progress = false;
    filetransfer_data->download_status.percent = UINT8_MAX;
    filetransfer_data->download_status.result = HCR_STATUS_DOWNLOAD_OK;

    filetransfer_data->url[0] = '\0';
}

static bool is_xmodem_transfer_in_progress(const XModemStatus &status)
{
    switch(status.source)
    {
      case XMODEM_SOURCE_NONE:
        return XModemStatusTraits<XMODEM_SOURCE_NONE>::is_in_progress(status);

      case XMODEM_SOURCE_DBUSDL:
        return XModemStatusTraits<XMODEM_SOURCE_DBUSDL>::is_in_progress(status);

      case XMODEM_SOURCE_COVER_ART:
        return XModemStatusTraits<XMODEM_SOURCE_COVER_ART>::is_in_progress(status);
    }

    return false;
}

static void reset_state(XModemStatus &status, bool is_error)
{
    if(is_xmodem_transfer_in_progress(filetransfer_data->xmodem_status))
    {
        if(is_error)
            msg_error(0, LOG_WARNING, "Aborting XMODEM transfer");
        else
            msg_info("Finished XMODEM transfer");
    }

    switch(filetransfer_data->xmodem_status.source)
    {
      case XMODEM_SOURCE_NONE:
        XModemStatusTraits<XMODEM_SOURCE_NONE>::reset_state(filetransfer_data->xmodem_status);
        break;

      case XMODEM_SOURCE_DBUSDL:
        XModemStatusTraits<XMODEM_SOURCE_DBUSDL>::reset_state(filetransfer_data->xmodem_status);
        break;

      case XMODEM_SOURCE_COVER_ART:
        XModemStatusTraits<XMODEM_SOURCE_COVER_ART>::reset_state(filetransfer_data->xmodem_status);
        break;
    }

    filetransfer_data->xmodem_status.source = XMODEM_SOURCE_NONE;

    xmodem_init(&filetransfer_data->xmodem_status.xm_ctx, NULL);
}

static void reset_xmodem_state_generic(bool is_error)
{
    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::Mutex> lock(filetransfer_data->xmodem_status.lock);
    reset_state(filetransfer_data->xmodem_status, is_error);
}

static void reset_xmodem_state_for_dbusdl(const char *path, bool is_error)
{
    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::Mutex> lock(filetransfer_data->xmodem_status.lock);

    reset_state(filetransfer_data->xmodem_status, is_error);

    if(path == nullptr)
        return;

    auto &data(filetransfer_data->xmodem_status.src_data.dbusdl);

    data.path = strdup(path);

    if(data.path == nullptr)
        msg_out_of_memory("Path string");

    filetransfer_data->xmodem_status.source = XMODEM_SOURCE_DBUSDL;
}

static void reset_xmodem_state_for_cover_art(bool is_error)
{
    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::Mutex> lock(filetransfer_data->xmodem_status.lock);

    reset_state(filetransfer_data->xmodem_status, is_error);

    if(filetransfer_data->picture_provider == nullptr)
    {
        MSG_BUG("No picture provider configured");
        return;
    }

    auto &data(filetransfer_data->xmodem_status.src_data.coverart);

    if(!filetransfer_data->picture_provider->copy_picture(data.picture))
        msg_info("No cover art available");
    else
        dump_picture_hash("Copied from provider", data.picture.get_hash_bytes());

    filetransfer_data->xmodem_status.source = XMODEM_SOURCE_COVER_ART;
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

static int try_start_download_file()
{
    if(filetransfer_data->url[0] == '\0')
    {
        msg_error(EINVAL, LOG_NOTICE, "Download URL not configured");
        return -1;
    }

    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::Mutex> lock(filetransfer_data->download_status.lock);

    filetransfer_data->download_status.percent = UINT8_MAX;

    GError *error = NULL;

    /*!
     * FIXME: 100 is not good for small files or very fast connections. 10 is
     *        not good for large files or very slow connections. Comprimising
     *        on 20, but this either needs dynamic adjustment or message rate
     *        limiting.
     */
    if(tdbus_file_transfer_call_download_sync(dbus_get_file_transfer_iface(),
                                              filetransfer_data->url,
                                              20,
                                              &filetransfer_data->download_status.xfer_id,
                                              NULL, &error) &&
       filetransfer_data->download_status.xfer_id != 0)
    {
        msg_info("Download started, transfer ID %u",
                 filetransfer_data->download_status.xfer_id);
        filetransfer_data->download_status.is_in_progress = true;
    }
    else
        filetransfer_data->download_status.is_in_progress = false;

    return handle_dbus_error(&error);
}

static int try_start_download_cover_art()
{
    msg_info("Download of cover art requested");

    cleanup_transfer();
    reset_xmodem_state_for_cover_art(false);

    return 0;
}

static int try_start_xmodem()
{
    cleanup_transfer();

    if(is_xmodem_transfer_in_progress(filetransfer_data->xmodem_status))
    {
        msg_info("XMODEM transfer in progress, not restarting");
        return 1;
    }

    int ret = -1;

    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::Mutex> lock(filetransfer_data->xmodem_status.lock);

    msg_log_assert(filetransfer_data->xmodem_status.xm_ctx.buffer_data.tx_offset == 0);

    switch(filetransfer_data->xmodem_status.source)
    {
      case XMODEM_SOURCE_NONE:
        ret = XModemStatusTraits<XMODEM_SOURCE_NONE>::try_start(filetransfer_data->xmodem_status);
        break;

      case XMODEM_SOURCE_DBUSDL:
        ret = XModemStatusTraits<XMODEM_SOURCE_DBUSDL>::try_start(filetransfer_data->xmodem_status);
        break;

      case XMODEM_SOURCE_COVER_ART:
        ret = XModemStatusTraits<XMODEM_SOURCE_COVER_ART>::try_start(filetransfer_data->xmodem_status);
        break;
    }

    if(ret == 0)
        msg_info("Ready for XMODEM");

    return ret;
}

int Regs::FileTransfer::hcr_send_shutdown_request(const char *reason)
{
    msg_log_assert(reason != nullptr);
    msg_vinfo(MESSAGE_LEVEL_IMPORTANT, "Shutdown requested: %s", reason);

    GError *error = NULL;
    tdbus_logind_manager_call_reboot_sync(dbus_get_logind_manager_iface(), false, NULL, &error);

    if(error == NULL)
        return 0;

    msg_error(0, LOG_EMERG, "Failed sending reboot command: %s", error->message);
    g_error_free(error);

    return -1;
}

bool Regs::FileTransfer::hcr_is_system_update_in_progress()
{
    OS::SuppressErrorsGuard no_errors;

    switch(os_path_get_type("/var/local/data/system_update_data/system_update.sh"))
    {
      case OS_PATH_TYPE_IO_ERROR:
        return false;

      case OS_PATH_TYPE_FILE:
        msg_info("System update in progress");
        return true;

      case OS_PATH_TYPE_DIRECTORY:
      case OS_PATH_TYPE_OTHER:
        MSG_BUG("Update script exists, but is not a file");
        break;
    }

    return false;
}

/*!
 * Start download from internet or XMODEM transfer from flash.
 *
 * \attention
 *     Must be called with the #ShutdownGuard from #filetransfer_data locked.
 */
static int do_write_download_control(const uint8_t *data)
{
    if(shutdown_guard_is_shutting_down_unlocked(filetransfer_data->shutdown_guard))
    {
        msg_info("Not transferring files during shutdown.");
        return -1;
    }

    if(data[0] == HCR_COMMAND_CATEGORY_FILE_TRANSFER &&
       data[1] == HCR_COMMAND_FILE_TRANSFER_DOWNLOAD)
    {
        int ret = try_start_xmodem();

        if(ret == 0)
        {
            /* report 0% progress */
            filetransfer_data->xmodem_status.progress_rate_limit = XMODEM_PROGRESS_RATE_LIMIT;
            Regs::get_data().register_changed_notification_fn(41);
        }
        else if(ret > 0)
            ret = 0;

        return ret;
    }
    else if(data[0] == HCR_COMMAND_CATEGORY_LOAD_TO_DEVICE)
    {
        if(data[1] == HCR_COMMAND_LOAD_TO_DEVICE_DOWNLOAD)
            return try_start_download_file();
        else if(data[1] == HCR_COMMAND_LOAD_TO_DEVICE_COVER_ART)
            return try_start_download_cover_art();

    }
    else if(data[0] == HCR_COMMAND_CATEGORY_RESET)
    {
        /*
         * Serious question: What kind of stupid idiot has grouped these things
         *                   with file transfer control?
         */
        if(data[1] == HCR_COMMAND_REBOOT_SYSTEM)
        {
            if(Regs::FileTransfer::hcr_is_system_update_in_progress())
            {
                msg_error(0, LOG_ERR,
                          "System reboot request ignored, we are in the middle of an update");
                return 0;
            }
            else
                return Regs::FileTransfer::hcr_send_shutdown_request("DCP command");
        }
        else if(data[1] == HCR_COMMAND_RESTORE_FACTORY_DEFAULTS)
            MSG_BUG("Restore to factory defaults not implemented");
    }
    else if(data[0] == HCR_COMMAND_CATEGORY_UPDATE_FROM_INET)
    {
        if(data[1] == HCR_COMMAND_UPDATE_MAIN_SYSTEM)
        {
            MSG_APPLIANCE_BUG("System update attempted using old interfaces");
            return -1;
        }

        if(data[1] == HCR_COMMAND_UPDATE_STREAMING_BOARD)
        {
            switch(Regs::SystemUpdate::process_update_request())
            {
              case Regs::SystemUpdate::UpdateResult::SUCCESS:
                return 0;

              case Regs::SystemUpdate::UpdateResult::BAD_CLIENT_REQUEST:
                return -1;

              case Regs::SystemUpdate::UpdateResult::FAILURE:
                Regs::FileTransfer::hcr_send_shutdown_request("update failure");
                return -1;
            }
        }
    }

    msg_error(ENOSYS, LOG_ERR, "Unsupported command");

    return -1;
}

int Regs::FileTransfer::DCP::write_40_download_control(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 40 handler %p %zu", data, length);

    if(data_length_is_unexpected(length, 2))
        return -1;

    shutdown_guard_lock(filetransfer_data->shutdown_guard);
    int ret = do_write_download_control(data);
    shutdown_guard_unlock(filetransfer_data->shutdown_guard);

    return ret;
}

static void fill_download_status_from_download(uint8_t *response)
{
    if(filetransfer_data->download_status.is_in_progress)
    {
        response[0] = HCR_STATUS_CATEGORY_PROGRESS;
        response[1] =
            (filetransfer_data->download_status.percent < UINT8_MAX)
            ? filetransfer_data->download_status.percent
            : 0;
    }
    else
    {
        response[0] = HCR_STATUS_CATEGORY_DOWNLOAD;
        response[1] = filetransfer_data->download_status.result;
    }
}

static void fill_download_status_from_xmodem(uint8_t *response)
{
    if(is_xmodem_transfer_in_progress(filetransfer_data->xmodem_status))
    {
        response[0] = HCR_STATUS_CATEGORY_PROGRESS;

        switch(filetransfer_data->xmodem_status.source)
        {
          case XMODEM_SOURCE_NONE:
            response[1] = XModemStatusTraits<XMODEM_SOURCE_NONE>::get_progress(filetransfer_data->xmodem_status);
            break;

          case XMODEM_SOURCE_DBUSDL:
            response[1] = XModemStatusTraits<XMODEM_SOURCE_DBUSDL>::get_progress(filetransfer_data->xmodem_status);
            break;

          case XMODEM_SOURCE_COVER_ART:
            response[1] = XModemStatusTraits<XMODEM_SOURCE_COVER_ART>::get_progress(filetransfer_data->xmodem_status);
            break;
        }
    }
    else
    {
        response[0] = HCR_STATUS_CATEGORY_GENERIC;
        response[1] = HCR_STATUS_GENERIC_OK;
    }
}

ssize_t Regs::FileTransfer::DCP::read_41_download_status(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 41 handler %p %zu", response, length);

    if(data_length_is_unexpected(length, 2))
        return -1;

    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::Mutex> lock_dl(filetransfer_data->download_status.lock);
    LOGGED_LOCK_CONTEXT_HINT;
    std::lock_guard<LoggedLock::Mutex> lock_xm(filetransfer_data->xmodem_status.lock);

    if(filetransfer_data->download_status.xfer_id != 0)
        fill_download_status_from_download(response);
    else if(is_xmodem_transfer_in_progress(filetransfer_data->xmodem_status))
        fill_download_status_from_xmodem(response);
    else
    {
        response[0] = HCR_STATUS_CATEGORY_GENERIC;
        response[1] = HCR_STATUS_GENERIC_OK;
    }

    return length;
}

ssize_t Regs::FileTransfer::DCP::read_44_xmodem_data(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 44 handler %p %zu", response, length);

    if(data_length_is_in_unexpected_range(length, 1, 3 + 128 + 2))
        return -1;

    LOGGED_LOCK_CONTEXT_HINT;
    LoggedLock::UniqueLock<LoggedLock::Mutex> lock(filetransfer_data->xmodem_status.lock);

    bool was_successful = false;

    if(!is_xmodem_transfer_in_progress(filetransfer_data->xmodem_status))
        msg_error(EINVAL, LOG_ERR, "No XMODEM transfer going on");
    else
    {
        const uint8_t *block;
        const ssize_t buffer_size =
            xmodem_get_block(&filetransfer_data->xmodem_status.xm_ctx, &block);

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
                msg_vinfo(MESSAGE_LEVEL_DIAG,
                          "Send %zu bytes of XMODEM data, command 0x%02x, block %u",
                          length, response[0], response[1]);
                if(--filetransfer_data->xmodem_status.progress_rate_limit <= 0)
                {
                    filetransfer_data->xmodem_status.progress_rate_limit = XMODEM_PROGRESS_RATE_LIMIT;
                    Regs::get_data().register_changed_notification_fn(41);
                }
            }
            else
            {
                msg_log_assert(response[0] == XMODEM_COMMAND_EOT);
                msg_vinfo(MESSAGE_LEVEL_DIAG, "Send 1 byte of XMODEM data");

                /* report 100% progress */
                filetransfer_data->xmodem_status.progress_rate_limit = 0;
                Regs::get_data().register_changed_notification_fn(41);
            }
        }
    }

    LOGGED_LOCK_CONTEXT_HINT;
    lock.unlock();

    if(!was_successful)
    {
        reset_xmodem_state_generic(true);
        response[0] = XMODEM_COMMAND_NACK;
        length = 1;
    }

    return length;
}

int Regs::FileTransfer::DCP::write_45_xmodem_command(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 45 handler %p %zu", data, length);

    if(data_length_is_unexpected(length, 1))
        return -1;

    const enum XModemCommand command = xmodem_byte_to_command(data[0]);

    if(command == XMODEM_COMMAND_INVALID)
    {
        msg_error(EINVAL, LOG_ERR, "Invalid XMODEM command 0x%02x", data[0]);
        return -1;
    }

    LOGGED_LOCK_CONTEXT_HINT;
    LoggedLock::UniqueLock<LoggedLock::Mutex> lock(filetransfer_data->xmodem_status.lock);

    bool was_successful = false;
    bool is_end_of_transmission = false;

    if(is_xmodem_transfer_in_progress(filetransfer_data->xmodem_status))
    {
        const enum XModemResult result =
            xmodem_process(&filetransfer_data->xmodem_status.xm_ctx, command);

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
            Regs::get_data().register_changed_notification_fn(44);
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

    LOGGED_LOCK_CONTEXT_HINT;
    lock.unlock();

    if(!was_successful || is_end_of_transmission)
        reset_xmodem_state_generic(!was_successful);

    return was_successful ? 0 : -1;
}

int Regs::FileTransfer::DCP::write_209_download_url(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 209 handler %p %zu", data, length);

    cleanup_transfer();
    reset_xmodem_state_generic(true);

    if(length == 0)
    {
        filetransfer_data->url[0] = '\0';
        msg_vinfo(MESSAGE_LEVEL_DEBUG, "Cleared URL");
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
    memcpy(filetransfer_data->url, data, length);
    filetransfer_data->url[length] = '\0';

    msg_info("Set URL \"%s\"", filetransfer_data->url);

    return 0;
}

void Regs::FileTransfer::progress_notification(uint32_t xfer_id,
                                               uint32_t tick,
                                               uint32_t total_ticks)
{
    bool changed = false;
    const uint8_t percent = total_ticks > 0
        ? (uint8_t)(100.0 * ((double)tick / (double)total_ticks))
        : 100;

    LOGGED_LOCK_CONTEXT_HINT;
    LoggedLock::UniqueLock<LoggedLock::Mutex> lock(filetransfer_data->download_status.lock);

    if(filetransfer_data->download_status.is_in_progress &&
       filetransfer_data->download_status.xfer_id == xfer_id)
    {
        if(filetransfer_data->download_status.percent != percent)
        {
            filetransfer_data->download_status.percent = percent;
            changed = true;
        }
    }

    LOGGED_LOCK_CONTEXT_HINT;
    lock.unlock();

    if(changed)
        Regs::get_data().register_changed_notification_fn(41);
}

void Regs::FileTransfer::done_notification(uint32_t xfer_id,
                                           enum DBusListsErrorCode error,
                                           const char *path)
{
    bool changed = false;

    LOGGED_LOCK_CONTEXT_HINT;
    LoggedLock::UniqueLock<LoggedLock::Mutex> lock(filetransfer_data->download_status.lock);

    if(filetransfer_data->download_status.is_in_progress &&
       filetransfer_data->download_status.xfer_id == xfer_id)
    {
        filetransfer_data->download_status.is_in_progress = false;
        filetransfer_data->download_status.percent = 100;
        filetransfer_data->download_status.result = HCR_STATUS_DOWNLOAD_OK;

        switch(error)
        {
          case LIST_ERROR_OK:
          case LIST_ERROR_INTERRUPTED:
            break;

          case LIST_ERROR_AUTHENTICATION:
          case LIST_ERROR_PROTOCOL:
          case LIST_ERROR_INCONSISTENT:
          case LIST_ERROR_NOT_SUPPORTED:
            filetransfer_data->download_status.result = HCR_STATUS_DOWNLOAD_CRC_ERROR;
            break;

          case LIST_ERROR_NET_IO:
            filetransfer_data->download_status.result = HCR_STATUS_DOWNLOAD_NETWORK_ERROR;
            break;

          case LIST_ERROR_INVALID_ID:
          case LIST_ERROR_INVALID_URI:
          case LIST_ERROR_PERMISSION_DENIED:
          case LIST_ERROR_INVALID_STREAM_URL:
          case LIST_ERROR_INVALID_STRBO_URL:
          case LIST_ERROR_NOT_FOUND:
          case LIST_ERROR_EMPTY:
            filetransfer_data->download_status.result = HCR_STATUS_DOWNLOAD_FILE_NOT_FOUND;
            break;

          case LIST_ERROR_INTERNAL:
            filetransfer_data->download_status.result = HCR_STATUS_DOWNLOAD_OUT_OF_MEMORY;
            break;

          case LIST_ERROR_PHYSICAL_MEDIA_IO:
            filetransfer_data->download_status.result = HCR_STATUS_DOWNLOAD_USB_MEDIA_ERROR;
            break;

          case LIST_ERROR_OUT_OF_RANGE:
          case LIST_ERROR_OVERFLOWN:
          case LIST_ERROR_UNDERFLOWN:
            filetransfer_data->download_status.result = HCR_STATUS_DOWNLOAD_DECRYPTION_ERROR;
            break;

          case LIST_ERROR_BUSY_500:
          case LIST_ERROR_BUSY_1000:
          case LIST_ERROR_BUSY_1500:
          case LIST_ERROR_BUSY_3000:
          case LIST_ERROR_BUSY_5000:
          case LIST_ERROR_BUSY:
            MSG_BUG("List broker is busy, should retry download");
            filetransfer_data->download_status.result = HCR_STATUS_DOWNLOAD_NETWORK_ERROR;
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

    LOGGED_LOCK_CONTEXT_HINT;
    lock.unlock();

    if(changed)
        Regs::get_data().register_changed_notification_fn(41);

    reset_xmodem_state_for_dbusdl(path, true);
}

void Regs::FileTransfer::prepare_for_shutdown()
{
    if(shutdown_guard_down(filetransfer_data->shutdown_guard))
        DCP::write_209_download_url(NULL, 0);
}

void Regs::FileTransfer::init()
{
    filetransfer_data = std::make_unique<FileTransferData>();
}

void Regs::FileTransfer::set_picture_provider(const CoverArt::PictureProviderIface &provider)
{
    filetransfer_data->picture_provider = &provider;
}

void Regs::FileTransfer::deinit()
{
    filetransfer_data = nullptr;
}
