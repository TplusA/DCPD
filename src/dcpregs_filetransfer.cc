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

#include "dcpregs_filetransfer.hh"
#include "dcpregs_filetransfer_priv.h"
#include "coverart.hh"
#include "dbus_iface_deep.h"
#include "registers_priv.hh"
#include "xmodem.h"
#include "inifile.h"
#include "logged_lock.hh"
#include "shutdown_guard.h"

#include <cstring>

/*! Sane limit on URL length to cap DC traffic. */
#define MAXIMUM_URL_LENGTH 1024U

/*! Limit XMODEM progress reports so that only every N'th report is sent. */
#define XMODEM_PROGRESS_RATE_LIMIT 5

static const char feed_config_filename[] = "/var/local/etc/update_feeds.ini";
static const char feed_config_override_filename[] = "/var/local/etc/update_feeds_override.ini";
static const char feed_config_path[] = "/var/local/etc";
static const char feed_config_global_section_name[] = "global";
static const char feed_config_url_key[] = "url";
static const char feed_config_release_key[] = "release";
static const char feed_config_method_key[] = "method";

static const char opkg_configuration_path[] = "/etc/opkg";
static const char opkg_feed_config_suffix[] = "-feed.conf";

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
        BUG("No picture provider configured");
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

    log_assert(filetransfer_data->xmodem_status.xm_ctx.buffer_data.tx_offset == 0);

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

int Regs::FileTransfer::hcr_send_shutdown_request(bool via_dcp_command)
{
    msg_vinfo(MESSAGE_LEVEL_IMPORTANT, "Shutdown requested%s",
              via_dcp_command ? " via DCP command" : "");

    GError *error = NULL;
    tdbus_logind_manager_call_reboot_sync(dbus_get_logind_manager_iface(), false, NULL, &error);

    if(error == NULL)
        return 0;

    msg_error(0, LOG_EMERG, "Failed sending reboot command: %s", error->message);
    g_error_free(error);

    return -1;
}

static size_t get_filename_length_if_is_opkg_feed_file(const char *path)
{
    const size_t path_len = strlen(path);

    if(path_len < sizeof(opkg_feed_config_suffix))
        return 0;

    if(strcmp(&path[path_len - (sizeof(opkg_feed_config_suffix) - 1)],
              opkg_feed_config_suffix) == 0)
        return path_len;
    else
        return 0;
}

static char *generate_opkg_feed_filename(char *buffer, size_t buffer_size,
                                         const char *name, size_t name_len)
{
    log_assert(buffer_size > 0);
    log_assert(name_len > 0);

    const size_t beyond = sizeof(opkg_configuration_path) + name_len;
    log_assert(beyond <= buffer_size);

    memcpy(buffer, opkg_configuration_path, sizeof(opkg_configuration_path) - 1);
    buffer[sizeof(opkg_configuration_path) - 1] = '/';
    memcpy(buffer + sizeof(opkg_configuration_path), name, name_len + 1);

    return &buffer[beyond];
}

static int find_opkg_feed_configuration_file(const char *path,
                                             unsigned char dtype,
                                             void *user_data)
{
    return (get_filename_length_if_is_opkg_feed_file(path) > 0) ? 1 : 0;
}

static bool extract_updatable_objects(const struct ini_file *config,
                                      struct ini_section **section,
                                      const struct ini_key_value_pair **url,
                                      const struct ini_key_value_pair **release)
{
    *section =
        inifile_find_section(config, feed_config_global_section_name,
                             sizeof(feed_config_global_section_name) - 1);

    if(*section != NULL)
    {
        *url = inifile_section_lookup_kv_pair(*section,
                                              feed_config_url_key,
                                              sizeof(feed_config_url_key) - 1);
        *release =
            inifile_section_lookup_kv_pair(*section,
                                           feed_config_release_key,
                                           sizeof(feed_config_release_key) - 1);
    }
    else
    {
        *url = NULL;
        *release = NULL;
    }

    return (*section != NULL && *url != NULL && *release != NULL);
}

static int mk_default_feed_config(struct ini_file *config)
{
    inifile_new(config);

    struct ini_section *section = inifile_new_section(config, "global", 6);
    if(section == NULL)
        goto error_exit;

    if(inifile_section_store_value(section,
                                   "release", 7,
                                   "stable", 6) == NULL)
        goto error_exit;

    if(inifile_section_store_value(section,
                                   "url", 3,
                                   "http://www.ta-hifi.de/fileadmin/auto_download/StrBo", 0) == NULL)
        goto error_exit;

    if(inifile_section_store_value(section,
                                   "method", 6,
                                   "src/gz", 6) == NULL)
        goto error_exit;

    if(inifile_new_section(config, "feed all", 0) == NULL)
        goto error_exit;

    if(inifile_new_section(config, "feed arm1176jzfshf-vfp", 0) == NULL)
        goto error_exit;

    if(inifile_new_section(config, "feed raspberrypi", 0) == NULL)
        goto error_exit;

    return 0;

error_exit:
    inifile_free(config);

    return -1;
}

static int generate_opkg_feed_files_if_necessary()
{
    int have_feeds =
        os_foreach_in_path(opkg_configuration_path,
                           find_opkg_feed_configuration_file, NULL);

    if(have_feeds < 0)
        return -1;
    else if(have_feeds > 0)
        return 0;

    /* no feed configuration files found, need to generate them */
    struct ini_file config;
    if(inifile_parse_from_file(&config, feed_config_override_filename) != 0 &&
       inifile_parse_from_file(&config, feed_config_filename) != 0 &&
       mk_default_feed_config(&config) < 0)
    {
        msg_error(0, LOG_ERR, "Failed reading feed configuration, cannot start update");
        return -1;
    }

    char path_buffer[1024];
    char content_buffer[4096];
    bool failed = false;

    struct ini_section *global_section;
    const struct ini_key_value_pair *url_kv;
    const struct ini_key_value_pair *release_kv;
    const struct ini_key_value_pair *method_kv;

    if(!extract_updatable_objects(&config, &global_section, &url_kv, &release_kv) ||
       (method_kv = inifile_section_lookup_kv_pair(global_section,
                                                   feed_config_method_key,
                                                   sizeof(feed_config_method_key) - 1)) == NULL)
    {
        msg_error(0, LOG_ERR,
                  "Broken or incomplete feed configuration, cannot start update");
        inifile_free(&config);
        return -1;
    }

    for(const struct ini_section *section = config.sections_head;
        section != NULL && !failed;
        section = section->next)
    {
        static const char required_prefix[] = "feed ";

        if(section->name_length < sizeof(required_prefix))
            continue;

        if(memcmp(section->name,
                  required_prefix, sizeof(required_prefix) - 1) != 0)
            continue;

        const char *feed_name = section->name + sizeof(required_prefix) - 1;

        if(strchr(feed_name, ' ') != NULL)
            continue;

        char *beyond_generated =
            generate_opkg_feed_filename(path_buffer, sizeof(path_buffer),
                                        feed_name,
                                        section->name_length - (sizeof(required_prefix) - 1));

        log_assert(*beyond_generated == '\0');

        if(beyond_generated - path_buffer < (ptrdiff_t)sizeof(opkg_feed_config_suffix))
        {
            msg_error(ENOMEM, LOG_ERR,
                      "Path of feed configuration file too long");
            failed = true;
            break;
        }

        strcpy(beyond_generated, opkg_feed_config_suffix);

        const int fd = os_file_new(path_buffer);

        if(fd < 0)
        {
            failed = true;
            break;
        }

        static const char feed_file_format[] =
            "# Generated file, do not edit!\n"
            "%s %s-%s %s/%s/%s\n";

        const int content_size =
            snprintf(content_buffer, sizeof(content_buffer), feed_file_format,
                     method_kv->value, release_kv->value, feed_name,
                     url_kv->value, release_kv->value, feed_name);

        if(content_size <= 0 ||
           os_write_from_buffer(content_buffer, content_size, fd) < 0)
            failed = true;

        os_file_close(fd);
    }

    inifile_free(&config);

    if(failed)
        return -1;

    os_sync_dir(opkg_configuration_path);

    return 0;
}

static const char update_shell_script_file[] = "/tmp/do_update.sh";

bool Regs::FileTransfer::hcr_is_system_update_in_progress()
{
    switch(os_path_get_type(update_shell_script_file))
    {
      case OS_PATH_TYPE_IO_ERROR:
        return false;

      case OS_PATH_TYPE_FILE:
        return true;

      case OS_PATH_TYPE_DIRECTORY:
      case OS_PATH_TYPE_OTHER:
        BUG("Update script exists, but is not a file");
        break;
    }

    return false;
}

static int try_start_system_update()
{
    msg_vinfo(MESSAGE_LEVEL_IMPORTANT, "Attempting to START SYSTEM UPDATE");

    if(generate_opkg_feed_files_if_necessary() < 0)
        return -1;

    int fd = -1;

    if(Regs::FileTransfer::hcr_is_system_update_in_progress())
        msg_info("Update in progress, not starting again");
    else
    {
        /* Good. */
        fd = os_file_new(update_shell_script_file);
    }

    if(fd < 0)
        return -1;

#include "do_update_sh.h"

    const bool success =
        (os_write_from_buffer(shell_script_content,
                              sizeof(shell_script_content) - 1, fd) == 0);

    os_file_close(fd);

    static const char poor_mans_daemonize[] =
        "/bin/sh -c 'exec /bin/sh %s </dev/null >/dev/null 2>/dev/null &'";

    if(success &&
       os_system_formatted(true, poor_mans_daemonize,
                           update_shell_script_file) == EXIT_SUCCESS)
    {
        /* keep file around, used as a lock */
        return 0;
    }

    os_file_delete(update_shell_script_file);

    return -1;
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
                return Regs::FileTransfer::hcr_send_shutdown_request(true);
        }
        else if(data[1] == HCR_COMMAND_RESTORE_FACTORY_DEFAULTS)
            BUG("Restore to factory defaults not implemented");
    }
    else if(data[0] == HCR_COMMAND_CATEGORY_UPDATE_FROM_INET &&
            data[1] == HCR_COMMAND_UPDATE_MAIN_SYSTEM)
    {
        return try_start_system_update();
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
                log_assert(response[0] == XMODEM_COMMAND_EOT);
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

enum UpdateFeedsResult
{
    /*! Bytes in input do not contain feed settings. */
    UPDATE_FEEDS_NOT_A_SPEC,

    /*! Bytes in input look like feed settings, but are not usable. */
    UPDATE_FEEDS_INVALID_SPEC,

    /*! Accepted input as feed settings, but nothing has changed. */
    UPDATE_FEEDS_NOT_CHANGED,

    /*! Accepted input as feed settings and updated them on file system. */
    UPDATE_FEEDS_UPDATED,

    /*! Accepted input as feed settings, but failed to process them. */
    UPDATE_FEEDS_FAILED,
};

static enum UpdateFeedsResult
update_feed_configuration_file(struct ini_file *config,
                               const char *url, size_t url_len,
                               const char *release, size_t release_len,
                               const struct ini_key_value_pair **url_kv,
                               const struct ini_key_value_pair **release_kv)
{
    *url_kv = NULL;
    *release_kv = NULL;

    const int err = inifile_parse_from_file(config, feed_config_filename);

    if(err < 0)
        return UPDATE_FEEDS_FAILED;
    else if(err == 1)
    {
        if(mk_default_feed_config(config) < 0)
            return UPDATE_FEEDS_FAILED;
    }

    struct ini_section *global_section;
    const struct ini_key_value_pair *configured_url;
    const struct ini_key_value_pair *configured_release;

    if(!extract_updatable_objects(config, &global_section,
                                  &configured_url, &configured_release))
    {
        log_assert(err == 0);

        msg_error(0, LOG_NOTICE,
                  "Feed configuration broken, resetting to defaults");

        inifile_free(config);

        if(mk_default_feed_config(config) < 0)
            return UPDATE_FEEDS_FAILED;

        extract_updatable_objects(config, &global_section,
                                  &configured_url, &configured_release);
    }

    log_assert(global_section != NULL);
    log_assert(configured_url != NULL);
    log_assert(configured_release != NULL);

    if(strncmp(configured_url->value, url, url_len) == 0 &&
       configured_url->value[url_len] == '\0' &&
       strncmp(configured_release->value, release, release_len) == 0 &&
       configured_release->value[release_len] == '\0')
    {
        /* nothing has changed */
        return UPDATE_FEEDS_NOT_CHANGED;
    }
    else
    {
        *url_kv =
            inifile_section_store_value(global_section, feed_config_url_key,
                                        sizeof(feed_config_url_key) - 1,
                                        url, url_len);
        *release_kv =
            inifile_section_store_value(global_section,
                                        feed_config_release_key,
                                        sizeof(feed_config_release_key) - 1,
                                        release, release_len);
    }

    if(*url_kv != NULL && *release_kv != NULL)
        return UPDATE_FEEDS_UPDATED;

    inifile_free(config);

    return UPDATE_FEEDS_FAILED;
}

static int delete_opkg_feed_configuration_file(const char *path,
                                               unsigned char dtype,
                                               void *user_data)
{
    const size_t name_len = get_filename_length_if_is_opkg_feed_file(path);

    if(name_len == 0)
        return 0;

    char buffer[sizeof(opkg_configuration_path) + 1 + name_len];

    generate_opkg_feed_filename(buffer, sizeof(buffer), path, name_len);
    os_file_delete(buffer);

    *(bool *)user_data = true;

    return 0;
}

/*!
 * Write repository feed settings to configuration file if necessary, delete
 * opkg feed configuration files if necessary.
 */
static enum UpdateFeedsResult
try_update_repository_feeds(const uint8_t *data, size_t length)
{
    /* chomp trailing zero bytes */
    for(/* nothing */; length > 0; --length)
    {
        if(data[length - 1] != '\0')
            break;
    }

    const uint8_t *separator_pos = NULL;

    for(size_t i = 0; i < length; ++i)
    {
        if(data[i] == ' ')
        {
            if(separator_pos != NULL)
            {
                /* use only the first of the two fields */
                length = i;
                break;
            }

            separator_pos = &data[i];
        }
    }

    if(separator_pos == NULL)
        return UPDATE_FEEDS_NOT_A_SPEC;

    const uint8_t *const release_name = separator_pos + 1;
    const ptrdiff_t url_len = separator_pos - data;
    const ptrdiff_t release_len = &data[length] - release_name;

    if(url_len <= 0 || (size_t)url_len > MAXIMUM_URL_LENGTH)
    {
        msg_error(0, LOG_ERR, "Package feed URL too %s",
                  (url_len <= 0) ? "short" : "long");
        return UPDATE_FEEDS_INVALID_SPEC;
    }

    if(release_len <= 0)
    {
        msg_error(0, LOG_ERR, "Release name in feed specification too short");
        return UPDATE_FEEDS_INVALID_SPEC;
    }

    struct ini_file config;
    const struct ini_key_value_pair *url_kv;
    const struct ini_key_value_pair *release_kv;
    const enum UpdateFeedsResult update_result =
        update_feed_configuration_file(&config, (const char *)data, url_len,
                                       (const char *)release_name, release_len,
                                       &url_kv, &release_kv);

    switch(update_result)
    {
      case UPDATE_FEEDS_NOT_A_SPEC:
      case UPDATE_FEEDS_INVALID_SPEC:
      case UPDATE_FEEDS_FAILED:
        return update_result;

      case UPDATE_FEEDS_NOT_CHANGED:
        inifile_free(&config);
        return update_result;

      case UPDATE_FEEDS_UPDATED:
        break;
    }

    bool modified_directory = false;

    if(os_foreach_in_path(opkg_configuration_path,
                          delete_opkg_feed_configuration_file,
                          &modified_directory) < 0)
    {
        inifile_free(&config);
        return UPDATE_FEEDS_FAILED;
    }

    if(modified_directory)
        os_sync_dir(opkg_configuration_path);

    enum UpdateFeedsResult retval;

    if(inifile_write_to_file(&config, feed_config_filename) == 0)
    {
        os_sync_dir(feed_config_path);
        retval = UPDATE_FEEDS_UPDATED;

        msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                  "Set package update URL \"%s\" for release \"%s\"",
                  url_kv->value, release_kv->value);
    }
    else
        retval = UPDATE_FEEDS_FAILED;

    inifile_free(&config);

    return retval;
}

int Regs::FileTransfer::DCP::write_209_download_url(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 209 handler %p %zu", data, length);

    if(length >= 8)
    {
        /* ignore cruft in first 8 bytes */
        switch(try_update_repository_feeds(data + 8, length - 8))
        {
          case UPDATE_FEEDS_NOT_A_SPEC:
            break;

          case UPDATE_FEEDS_NOT_CHANGED:
          case UPDATE_FEEDS_UPDATED:
            return 0;

          case UPDATE_FEEDS_INVALID_SPEC:
          case UPDATE_FEEDS_FAILED:
            return -1;
        }
    }

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
            BUG("List broker is busy, should retry download");
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
