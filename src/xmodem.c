/*
 * Copyright (C) 2015, 2018  T+A elektroakustik GmbH & Co. KG
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

#include "xmodem.h"
#include "crc16.h"

#include <string.h>

#define RETRIES 10

void xmodem_init(struct XModemContext *xmodem,
                 const struct os_mapped_file_data *mapped_file)
{
    xmodem->buffer_data.mapped_file = mapped_file;
    xmodem->buffer_data.tx_offset = 0;
    xmodem->buffer_data.block_number = 0;
    xmodem->flow_data.last_buffer_result = XMODEM_RESULT_PROTOCOL_VIOLATION;
    xmodem->flow_data.retries_remaining = RETRIES;
}

enum XModemCommand xmodem_byte_to_command(uint8_t byte)
{
    enum XModemCommand command = byte;

    switch(command)
    {
      case XMODEM_COMMAND_SOH:
      case XMODEM_COMMAND_EOT:
      case XMODEM_COMMAND_ACK:
      case XMODEM_COMMAND_NACK:
      case XMODEM_COMMAND_NACK_CRC:
      case XMODEM_COMMAND_INVALID:
        return command;
    }

    return XMODEM_COMMAND_INVALID;
}

static enum XModemResult fill_buffer_from_file(struct XModemBufferData *data)
{
    ++data->block_number;

    data->tx_buffer[0] = XMODEM_COMMAND_SOH;
    data->tx_buffer[1] = data->block_number;
    data->tx_buffer[2] = ~data->block_number;

    const size_t total_remaining_bytes =
        (data->tx_offset < data->mapped_file->length)
        ? data->mapped_file->length - data->tx_offset
        : 0;
    const size_t block_data_bytes =
        (total_remaining_bytes > 128) ? 128 : total_remaining_bytes;

    if(block_data_bytes > 0)
    {
        /* raw data from file */
        memcpy(data->tx_buffer + 3,
               ((const uint8_t *)data->mapped_file->ptr) + data->tx_offset,
               block_data_bytes);
        data->tx_offset += block_data_bytes;
    }

    enum XModemResult retval;

    if(block_data_bytes < total_remaining_bytes)
        retval = XMODEM_RESULT_OK;
    else
    {
        retval = XMODEM_RESULT_LAST_BLOCK;

        if(block_data_bytes < 128)
        {
            /* fill rest of last block */
            memset(data->tx_buffer + 3 + block_data_bytes, XMODEM_EOF,
                   128 - block_data_bytes);
        }
    }

    const uint16_t crc =
        crc16_compute(data->tx_buffer + 3, sizeof(data->tx_buffer) - 5);

    data->tx_buffer[sizeof(data->tx_buffer) - 2] = crc >> 8;
    data->tx_buffer[sizeof(data->tx_buffer) - 1] = crc & 0xff;

    return retval;
}

enum XModemResult xmodem_process(struct XModemContext *xmodem,
                                 enum XModemCommand command)
{
    switch(command)
    {
      case XMODEM_COMMAND_SOH:
      case XMODEM_COMMAND_EOT:
      case XMODEM_COMMAND_INVALID:
        break;

      case XMODEM_COMMAND_NACK_CRC:
        if(xmodem->flow_data.last_buffer_result != XMODEM_RESULT_PROTOCOL_VIOLATION)
            break;

        xmodem->flow_data.retries_remaining = RETRIES;
        xmodem->flow_data.last_buffer_result =
            fill_buffer_from_file(&xmodem->buffer_data);

        return xmodem->flow_data.last_buffer_result;

      case XMODEM_COMMAND_NACK:
        if(xmodem->flow_data.last_buffer_result == XMODEM_RESULT_PROTOCOL_VIOLATION)
            break;

        if(xmodem->flow_data.retries_remaining > 0)
            --xmodem->flow_data.retries_remaining;
        else
            xmodem->flow_data.last_buffer_result = XMODEM_RESULT_TIMEOUT;

        return xmodem->flow_data.last_buffer_result;

      case XMODEM_COMMAND_ACK:
        xmodem->flow_data.retries_remaining = RETRIES;

        switch(xmodem->flow_data.last_buffer_result)
        {
          case XMODEM_RESULT_OK:
            xmodem->flow_data.last_buffer_result =
                fill_buffer_from_file(&xmodem->buffer_data);
            break;

          case XMODEM_RESULT_LAST_BLOCK:
            xmodem->buffer_data.tx_buffer[0] = XMODEM_COMMAND_EOT;
            xmodem->flow_data.last_buffer_result = XMODEM_RESULT_EOT;
            break;

          case XMODEM_RESULT_EOT:
            xmodem->flow_data.last_buffer_result = XMODEM_RESULT_CLOSED;
            break;

          case XMODEM_RESULT_CLOSED:
          case XMODEM_RESULT_TIMEOUT:
          case XMODEM_RESULT_PROTOCOL_VIOLATION:
            xmodem->flow_data.last_buffer_result = XMODEM_RESULT_PROTOCOL_VIOLATION;
            break;
        }

        return xmodem->flow_data.last_buffer_result;
    }

    xmodem->flow_data.last_buffer_result = XMODEM_RESULT_PROTOCOL_VIOLATION;

    return XMODEM_RESULT_PROTOCOL_VIOLATION;
}

ssize_t xmodem_get_block(const struct XModemContext *xmodem,
                         const uint8_t **buffer)
{
    switch(xmodem->flow_data.last_buffer_result)
    {
      case XMODEM_RESULT_OK:
      case XMODEM_RESULT_LAST_BLOCK:
        *buffer = xmodem->buffer_data.tx_buffer;
        return sizeof(xmodem->buffer_data.tx_buffer);

      case XMODEM_RESULT_EOT:
        *buffer = xmodem->buffer_data.tx_buffer;
        return 1;

      case XMODEM_RESULT_CLOSED:
        *buffer = NULL;
        return 0;

      case XMODEM_RESULT_TIMEOUT:
      case XMODEM_RESULT_PROTOCOL_VIOLATION:
        break;
    }

    return -1;
}
