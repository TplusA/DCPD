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

#ifndef DCPREGS_FILETRANSFER_H
#define DCPREGS_FILETRANSFER_H

#include <stdint.h>
#include <unistd.h>

#include "de_tahifi_lists_errors.h"

/*!
 * \addtogroup registers
 */
/*!@{*/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Function required by unit tests for initializing static data.
 */
void dcpregs_filetransfer_init(void);

/*!
 * Function required by unit tests for freeing static data.
 */
void dcpregs_filetransfer_deinit(void);

int dcpregs_write_40_download_control(const uint8_t *data, size_t length);
ssize_t dcpregs_read_41_download_status(uint8_t *response, size_t length);
ssize_t dcpregs_read_44_xmodem_data(uint8_t *response, size_t length);
int dcpregs_write_45_xmodem_command(const uint8_t *data, size_t length);
int dcpregs_write_209_download_url(const uint8_t *data, size_t length);

/*!
 * Report download progress.
 *
 * \attention
 *     Called from D-Bus thread, not main context.
 */
void dcpregs_filetransfer_progress_notification(uint32_t xfer_id,
                                                uint32_t tick,
                                                uint32_t total_ticks);

/*!
 * Report download finished.
 *
 * \attention
 *     Called from D-Bus thread, not main context.
 */
void dcpregs_filetransfer_done_notification(uint32_t xfer_id,
                                            enum DBusListsErrorCode error,
                                            const char *path);

#ifdef __cplusplus
}
#endif

/*!@}*/
#endif /* !DCPREGS_FILETRANSFER_H */
