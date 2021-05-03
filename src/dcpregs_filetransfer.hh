/*
 * Copyright (C) 2017, 2018, 2019, 2021  T+A elektroakustik GmbH & Co. KG
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
 * Check whether or not systemd is in the middle of performing an offline
 * update.
 */
bool hcr_is_system_update_in_progress();

/*!
 * Shut down (reboot system).
 */
int hcr_send_shutdown_request(const char *reason);

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
 * Set URL of file to download.
 */
int write_209_download_url(const uint8_t *data, size_t length);
}

}

}

/*!@}*/

#endif /* !DCPREGS_FILETRANSFER_HH */
