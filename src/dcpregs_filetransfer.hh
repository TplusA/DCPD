/*
 * Copyright (C) 2017, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCPREGS_FILETRANSFER_HH
#define DCPREGS_FILETRANSFER_HH

#include "de_tahifi_lists_errors.h"

#include <cinttypes>
#include <cstdlib>

namespace CoverArt { class PictureProviderIface; }

/*!
 * \addtogroup registers
 */
/*!@{*/

namespace Regs
{

namespace FileTransfer
{
/*!
 * Function required by unit tests for initializing static data.
 */
void init();

/*!
 * Function required by unit tests for freeing static data.
 */
void deinit();

/*!
 * Check whether or not opkg is in the middle of performing an update.
 */
bool hcr_is_system_update_in_progress();

/*!
 * Shut down (reboot system).
 */
int hcr_send_shutdown_request(bool via_dcp_command);

/*!
 * Report download progress.
 *
 * \attention
 *     Called from D-Bus thread, not main context.
 */
void progress_notification(uint32_t xfer_id,
                           uint32_t tick, uint32_t total_ticks);

/*!
 * Report download finished.
 *
 * \attention
 *     Called from D-Bus thread, not main context.
 */
void done_notification(uint32_t xfer_id, enum DBusListsErrorCode error,
                       const char *path);

/*!
 * Report system shutdown event.
 *
 * This function aborts an ongoing download and flushes all changes to storage.
 * Further attempts to transfer files are blocked after this function has been
 * called.
 *
 * \attention
 *     Called from D-Bus thread, not main context.
 */
void prepare_for_shutdown();

void set_picture_provider(const CoverArt::PictureProviderIface &provider);

namespace DCP
{
int write_40_download_control(const uint8_t *data, size_t length);
ssize_t read_41_download_status(uint8_t *response, size_t length);
ssize_t read_44_xmodem_data(uint8_t *response, size_t length);
int write_45_xmodem_command(const uint8_t *data, size_t length);

/*!
 * Set URL of file to download, or set update package feed configuration.
 *
 * The space character is used to tell regular file URLs from feed
 * configuration:
 * - In case the URL passed in \p data contains no space character, the string
 *   is used as URL of a file to be downloaded (see
 *   #HCR_COMMAND_FILE_TRANSFER_DOWNLOAD).
 * - In case the URL contains a single space character, the string is
 *   interpreted as the base URL of a package feed followed by the name of a
 *   release (see #HCR_COMMAND_UPDATE_MAIN_SYSTEM).
 * - In case the URL contains more than one space character, it is rejected.
 *
 * Package feed updates are written to an internal configuration file owned by
 * \c dcpd. If the feed configuration passed in \p data is actually different
 * from the settings stored in the configuration file, then all \c opkg feed
 * configuration files are deleted from the system configuration, and after
 * that the internal configuration file is updated.
 *
 * When the command for a system update is sent to register 40, the \c opkg
 * configuration files are generated from the internal configuration file if
 * and only if no feed configuration file is found in the system configuration
 * directory. This approach minimizes the amount of write accesses to flash
 * memory.
 */
int write_209_download_url(const uint8_t *data, size_t length);
}

}

}

/*!@}*/

#endif /* !DCPREGS_FILETRANSFER_HH */
