/*
 * Copyright (C) 2015, 2017, 2019, 2020  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCPREGS_FILETRANSFER_PRIV_H
#define DCPREGS_FILETRANSFER_PRIV_H

/*
 * Definitions for HCR register (40)
 */
#define HCR_COMMAND_CATEGORY_FILE_TRANSFER      0x25
#define HCR_COMMAND_FILE_TRANSFER_DOWNLOAD      0x20

#define HCR_COMMAND_CATEGORY_LOAD_TO_DEVICE     0x26
#define HCR_COMMAND_LOAD_TO_DEVICE_DOWNLOAD     0x20
#define HCR_COMMAND_LOAD_TO_DEVICE_COVER_ART    0x21

#define HCR_COMMAND_CATEGORY_RESET              0x24
#define HCR_COMMAND_REBOOT_SYSTEM               0x20
#define HCR_COMMAND_RESTORE_FACTORY_DEFAULTS    0x21

#define HCR_COMMAND_CATEGORY_UPDATE_FROM_INET   0x27
#define HCR_COMMAND_UPDATE_MAIN_SYSTEM          0x20
#define HCR_COMMAND_UPDATE_STREAMING_BOARD      0x21

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
