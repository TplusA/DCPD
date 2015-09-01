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

#ifndef XMODEM_H
#define XMODEM_H

#include <stdint.h>
#include <stdbool.h>

#include "os.h"

enum XModemCommand
{
    XMODEM_COMMAND_SOH      = 0x01,
    XMODEM_COMMAND_EOT      = 0x04,
    XMODEM_COMMAND_ACK      = 0x06,
    XMODEM_COMMAND_NACK     = 0x15,
    XMODEM_COMMAND_NACK_CRC = 0x43,

    XMODEM_COMMAND_INVALID  = 0x00,
};

#define XMODEM_EOF              0x1a

/*!
 *  \addtogroup xmodem_protocol XMODEM protocol implementation
 */
/*!@{*/

enum XModemResult
{
    XMODEM_RESULT_OK,
    XMODEM_RESULT_LAST_BLOCK,
    XMODEM_RESULT_EOT,
    XMODEM_RESULT_CLOSED,
    XMODEM_RESULT_TIMEOUT,
    XMODEM_RESULT_PROTOCOL_VIOLATION,
};

struct XModemBufferData
{
    /*! Mapped file currently being transferred. */
    const struct os_mapped_file_data *mapped_file;

    /*! Offset into the file for next XMODEM block. */
    size_t tx_offset;

    /*! Current block number. */
    uint8_t block_number;

    /*! Buffer for XMODEM blocks */
    uint8_t tx_buffer[3U + 128U + 2U];
};

struct XModemContext
{
    struct XModemBufferData buffer_data;

    struct
    {
        int retries_remaining;
        enum XModemResult last_buffer_result;
    }
    flow_data;
};

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Initialize XMODEM protocol context.
 *
 * \param xmodem
 *     Context to be initialized.
 *
 * \param mapped_file
 *     File whose contents should be sent via XMODEM.
 */
void xmodem_init(struct XModemContext *xmodem,
                 const struct os_mapped_file_data *mapped_file);

/*!
 * Cast raw byte to command enumerator.
 *
 * \returns
 *     A valid command on success, #XMODEM_COMMAND_INVALID on error (invalid
 *     command byte).
 */
enum XModemCommand xmodem_byte_to_command(uint8_t byte);

/*!
 * Read raw data from file and encapsulate them into an XMODEM block.
 *
 * \param xmodem
 *     An XMODEM context.
 *
 * \param command
 *     Request sent by the receiver. Use #xmodem_byte_to_command() to convert
 *     raw bytes to XMODEM commands.
 *
 * \retval #XMODEM_RESULT_OK
 *     Buffer has been filled with a XMODEM block, more blocks follow.
 *
 * \retval #XMODEM_RESULT_LAST_BLOCK
 *     Buffer has been filled with a XMODEM block, no more blocks available.
 *
 * \retval #XMODEM_RESULT_EOT
 *     Buffer has been filled with a single EOT byte because the entire file
 *     associated with the XMODEM context has been read.
 *
 * \retval #XMODEM_RESULT_TIMEOUT
 *     Buffer has not been filled because of too many NACKs received from the
 *     receiver, indicating a bad connection.
 *
 * \retval #XMODEM_RESULT_PROTOCOL_VIOLATION
 *     Buffer has not been filled because of XMODEM protocol violation.
 */
enum XModemResult xmodem_process(struct XModemContext *xmodem,
                                 enum XModemCommand command);

/*!
 * Get pointer to current XMODEM block buffer and its size.
 *
 * \returns
 *     A positive value in case there is any data in the buffer; 0 in case of
 *     closed connection; -1 on error (bad state).
 */
ssize_t xmodem_get_block(const struct XModemContext *xmodem,
                         const uint8_t **buffer);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !XMODEM_H */
