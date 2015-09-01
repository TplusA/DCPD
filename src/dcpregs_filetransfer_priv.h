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

#ifndef DCPREGS_FILETRANSFER_PRIV_H
#define DCPREGS_FILETRANSFER_PRIV_H

/*
 * Definitions for HCR register (40)
 */
#define HCR_COMMAND_CATEGORY_FILE_TRANSFER      0x25
#define HCR_COMMAND_FILE_TRANSFER_DOWNLOAD      0x20

#define HCR_COMMAND_CATEGORY_LOAD_TO_DEVICE     0x26
#define HCR_COMMAND_LOAD_TO_DEVICE_DOWNLOAD     0x20

/*
 * Definitions for HCR status register (41)
 */
#define HCR_STATUS_CATEGORY_GENERIC             0x20
#define HCR_STATUS_CATEGORY_DOWNLOAD            0x21
#define HCR_STATUS_CATEGORY_PROGRESS            0x22

#define HCR_STATUS_GENERIC_OK                   0x20

#define HCR_STATUS_DOWNLOAD_OK                  0x20
#define HCR_STATUS_DOWNLOAD_CRC_ERROR           0x21
#define HCR_STATUS_DOWNLOAD_DECRYPTION_ERROR    0x22
#define HCR_STATUS_DOWNLOAD_NETWORK_ERROR       0x23
#define HCR_STATUS_DOWNLOAD_USB_MEDIA_ERROR     0x24
#define HCR_STATUS_DOWNLOAD_FILE_NOT_FOUND      0x25
#define HCR_STATUS_DOWNLOAD_OUT_OF_MEMORY       0x26

/*
 * Definitions for file transfer register (209)
 */
#define HCR_FILE_TRANSFER_CRC_MODE_NONE         0x00
#define HCR_FILE_TRANSFER_ENCRYPTION_NONE       0x20

#endif /* !DCPREGS_FILETRANSFER_PRIV_H */
