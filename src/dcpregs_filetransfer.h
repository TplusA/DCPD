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

/*!
 * \addtogroup registers
 */
/*!@{*/

#ifdef __cplusplus
extern "C" {
#endif

int dcpregs_write_40_download_control(const uint8_t *data, size_t length);
ssize_t dcpregs_read_41_download_status(uint8_t *response, size_t length);
int dcpregs_write_209_download_url(const uint8_t *data, size_t length);

#ifdef __cplusplus
}
#endif

/*!@}*/
#endif /* !DCPREGS_FILETRANSFER_H */
