/*
 * Copyright (C) 2015, 2016  T+A elektroakustik GmbH & Co. KG
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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "transactions.h"
#include "dynamic_buffer.h"
#include "registers.h"
#include "named_pipe.h"
#include "dcpdefs.h"
#include "messages.h"
#include "os.h"

enum transaction_state
{
    TRANSACTION_STATE_ERROR,                /*!< Error state, cannot process */
    TRANSACTION_STATE_SLAVE_PREPARE__INIT,  /*!< Read command from slave */
    TRANSACTION_STATE_PUSH_TO_SLAVE__INIT,  /*!< Prepare answer buffer */
    TRANSACTION_STATE_MASTER_PREPARE__INIT, /*!< Filling command buffer */
    TRANSACTION_STATE_SLAVE_READ_DATA,      /*!< Read data from slave */
    TRANSACTION_STATE_SLAVE_PREPARE_ANSWER, /*!< Fill answer buffer */
    TRANSACTION_STATE_SLAVE_PROCESS_WRITE,  /*!< Process data written by slave */
    TRANSACTION_STATE_SEND_TO_SLAVE,        /*!< Send (any) data to slave */
    TRANSACTION_STATE_SEND_TO_SLAVE_ACKED,  /*!< Data was acknowledged by slave */
    TRANSACTION_STATE_SEND_TO_SLAVE_FAILED, /*!< Final NACK received, abort */
    TRANSACTION_STATE_DCPSYNC_WAIT_FOR_ACK, /*!< Wait for DCPSYNC ack from slave */
};

enum dcpsync_packet_type
{
    DCPSYNC_PACKET_INVALID,
    DCPSYNC_PACKET_IO_ERROR,
    DCPSYNC_PACKET_COMMAND,
    DCPSYNC_PACKET_ACK,
    DCPSYNC_PACKET_NACK,
};

enum read_to_buffer_result
{
    READ_OK,
    READ_INCOMPLETE,
    READ_IO_ERROR,
};

struct dcpsync_header
{
    bool is_enabled;
    uint8_t original_command;
    uint8_t ttl;
    uint16_t serial;
    uint16_t remaining_payload_size;
};

struct transaction
{
    struct transaction *next;
    struct transaction *prev;

    enum transaction_state state;
    bool is_pinned;

    struct dcpsync_header dcpsync;

    uint8_t request_header[DCP_HEADER_SIZE];
    uint8_t command;

    const struct dcp_register_t *reg;

    enum transaction_channel channel;
    struct dynamic_buffer payload;
    size_t current_fragment_offset;
};

static struct
{
    struct transaction tpool[100];
    struct transaction *free_list;

    uint16_t next_dcpsync_serial;
}

global_data;

#define MAX_NUMBER_OF_TRANSACTIONS \
    (sizeof(global_data.tpool) / sizeof(global_data.tpool[0]))

static uint16_t mk_serial(void)
{
    if(global_data.next_dcpsync_serial < DCPSYNC_MASTER_SERIAL_MIN ||
       global_data.next_dcpsync_serial > DCPSYNC_MASTER_SERIAL_MAX)
    {
        global_data.next_dcpsync_serial = DCPSYNC_MASTER_SERIAL_MIN;
    }

    return global_data.next_dcpsync_serial++;
}

void transaction_init_allocator(void)
{
    for(unsigned int i = 1; i < MAX_NUMBER_OF_TRANSACTIONS - 1; ++i)
    {
        global_data.tpool[i].prev = &global_data.tpool[i - 1];
        global_data.tpool[i].next = &global_data.tpool[i + 1];
    }

    struct transaction *t = &global_data.tpool[0];

    t->prev = &global_data.tpool[MAX_NUMBER_OF_TRANSACTIONS - 1];
    t->next = &global_data.tpool[1];

    t = &global_data.tpool[MAX_NUMBER_OF_TRANSACTIONS - 1];
    t->prev = &global_data.tpool[MAX_NUMBER_OF_TRANSACTIONS - 2];
    t->next = &global_data.tpool[0];

    global_data.free_list = &global_data.tpool[0];
    global_data.next_dcpsync_serial = 0;
}

static void transaction_refresh_as_master(struct transaction *t)
{
    if(!t->dcpsync.is_enabled)
        return;

    const uint16_t new_serial = mk_serial();

    /*see also #transaction_init()  */
    t->dcpsync.serial = new_serial;
    t->dcpsync.ttl = UINT8_MAX;
}

static void transaction_init(struct transaction *t,
                             enum transaction_alloc_type alloc_type,
                             enum transaction_channel channel, bool is_pinned)
{
    switch(alloc_type)
    {
      case TRANSACTION_ALLOC_MASTER_FOR_DRCPD_DATA:
        /* plain master transaction initiated by DRCPD */
        t->state = TRANSACTION_STATE_MASTER_PREPARE__INIT;
        break;

      case TRANSACTION_ALLOC_MASTER_FOR_REGISTER:
        /* plain master transaction initiated by us for register data */
        t->state = TRANSACTION_STATE_PUSH_TO_SLAVE__INIT;
        break;

      case TRANSACTION_ALLOC_SLAVE_BY_SLAVE:
        /* plain slave transaction initiated by slave device */
        t->state = TRANSACTION_STATE_SLAVE_PREPARE__INIT;
        break;
    }

    t->is_pinned = is_pinned;

    memset(&t->dcpsync, 0, sizeof(t->dcpsync));

    if(channel == TRANSACTION_CHANNEL_SPI)
    {
        t->dcpsync.is_enabled = true;
        t->dcpsync.ttl = UINT8_MAX;

        switch(alloc_type)
        {
          case TRANSACTION_ALLOC_MASTER_FOR_DRCPD_DATA:
          case TRANSACTION_ALLOC_MASTER_FOR_REGISTER:
            /*see also #transaction_convert_to_master()  */
            t->dcpsync.serial = mk_serial();
            break;

          case TRANSACTION_ALLOC_SLAVE_BY_SLAVE:
            t->dcpsync.serial = DCPSYNC_SLAVE_SERIAL_INVALID;
            break;
        }
    }

    t->reg = NULL;
    t->channel = channel;
    t->current_fragment_offset = 0;
    memset(t->request_header, UINT8_MAX, sizeof(t->request_header));
    dynamic_buffer_init(&t->payload);
}

struct transaction *transaction_alloc(enum transaction_alloc_type alloc_type,
                                      enum transaction_channel channel,
                                      bool is_pinned)
{
    if(global_data.free_list == NULL)
        return NULL;

    struct transaction *t = transaction_queue_remove(&global_data.free_list);

    transaction_init(t, alloc_type, channel, is_pinned);
    return t;
}

void transaction_free(struct transaction **head)
{
    log_assert(head != NULL);
    log_assert(*head != NULL);

    struct transaction *t = *head;

    do
    {
#ifndef NDEBUG
        ptrdiff_t idx = t - global_data.tpool;
#endif /* !NDEBUG */

        log_assert(idx >= 0);
        log_assert((size_t)idx < MAX_NUMBER_OF_TRANSACTIONS);

        dynamic_buffer_free(&t->payload);

        t = t->next;
    }
    while(t != *head);

    transaction_queue_add(&global_data.free_list, *head);
    *head = NULL;
}

void transaction_reset_for_slave(struct transaction *t)
{
    dynamic_buffer_free(&t->payload);
    transaction_init(t, TRANSACTION_ALLOC_SLAVE_BY_SLAVE,
                     t->channel, t->is_pinned);
}

static const struct dcp_register_t *
lookup_register_for_transaction(uint8_t register_address,
                                bool master_not_slave)
{
    const struct dcp_register_t *reg = register_lookup(register_address);

    if(reg == NULL)
        BUG("%s requested register 0x%02x, but is not implemented",
            master_not_slave ? "Master" : "Slave", register_address);

    return reg;
}

/*!
 * Associate transaction with register and command.
 *
 * This function must be called for each transaction before attempting to
 * process them.
 */
static void transaction_bind(struct transaction *t,
                             const struct dcp_register_t *reg, uint8_t command)
{
    log_assert(reg != NULL);
    t->reg = reg;
    t->command = command;
}

void transaction_queue_add(struct transaction **head, struct transaction *t)
{
    log_assert(head != NULL);
    log_assert(t != NULL);

    if(*head != NULL)
    {
        struct transaction *t_last = t->prev;

        t_last->next = *head;
        t->prev = (*head)->prev;

        (*head)->prev->next = t;
        (*head)->prev = t_last;
    }
    else
        *head = t;

    log_assert((*head)->next->prev == *head);
    log_assert((*head)->prev->next == *head);
    log_assert(t->next->prev == t);
    log_assert(t->prev->next == t);
}

bool transaction_is_pinned(const struct transaction *t)
{
    return t->is_pinned;
}

enum transaction_channel transaction_get_channel(const struct transaction *t)
{
    return t->channel;
}

struct transaction *transaction_queue_remove(struct transaction **head)
{
    log_assert(head != NULL);
    log_assert(*head != NULL);

    struct transaction *t = *head;

    *head = t->next;

    if(*head != t)
    {
        t->next->prev = t->prev;
        t->prev->next = t->next;
    }
    else
        *head = NULL;

    t->next = t->prev = t;

    return t;
}

static inline bool is_serial_out_of_range(const uint16_t serial)
{
    return
        !((serial >= DCPSYNC_MASTER_SERIAL_MIN && serial <= DCPSYNC_MASTER_SERIAL_MAX) ||
          (serial >= DCPSYNC_SLAVE_SERIAL_MIN && serial <= DCPSYNC_SLAVE_SERIAL_MAX));
}

struct transaction *transaction_queue_find_by_serial(struct transaction *head,
                                                     uint16_t serial)
{
    if(is_serial_out_of_range(serial))
    {
        BUG("Tried to find transaction with invalid serial 0x%04x", serial);
        return NULL;
    }

    if(head == NULL)
        return NULL;

    struct transaction *t = head;

    do
    {
        if(t->dcpsync.serial == serial)
            return t;

        t = t->next;
    }
    while(t != head);

    return NULL;
}

struct transaction *transaction_queue_cut_element(struct transaction *t)
{
    if(t == NULL)
        return NULL;

    if(t == t->next)
        return t;

    struct transaction *const next = t->next;

    next->prev = t->prev;
    t->prev->next = next;

    t->next = t->prev = t;

    return next;
}

static bool
request_command_matches_register_definition(uint8_t command,
                                            const struct dcp_register_t *reg)
{
    switch(command)
    {
      case DCP_COMMAND_READ_REGISTER:
      case DCP_COMMAND_MULTI_WRITE_REGISTER:
        return true;

      case DCP_COMMAND_WRITE_REGISTER:
      case DCP_COMMAND_MULTI_READ_REGISTER:
        return false;
    }

    return false;
}

static enum read_to_buffer_result read_to_buffer(uint8_t *dest, size_t count,
                                                 int fd, const char *what)
{
    unsigned int retry_counter = 0;

    while(count > 0)
    {
        ssize_t len = os_read(fd, dest, count);

        if(len == 0)
        {
            msg_info("End of data while reading DCP packet from fd %d", fd);
            break;
        }

        if(len < 0)
        {
            if(errno == EAGAIN && retry_counter < 40)
            {
                ++retry_counter;

                /* we retry reading up to 40 times with a delay of 25 ms in
                 * between, so that's at least one second, but not much more */
                static const struct timespec t = { .tv_nsec = 25L * 1000L * 1000L, };
                os_nanosleep(&t);

                continue;
            }

            if(errno == EINTR)
                continue;

            msg_error(errno, LOG_ERR, "Failed reading DCP %s from fd %d", what, fd);

            return READ_IO_ERROR;
        }

        retry_counter = 0;

        dest += len;
        count -= len;
    }

    return count == 0 ? READ_OK : READ_INCOMPLETE;
}

static void skip_transaction_payload(struct transaction *t, const int fd)
{
    uint8_t dummy[64];
    uint16_t skipped_bytes;

    uint16_t count =
        t->dcpsync.is_enabled
        ? t->dcpsync.remaining_payload_size
        : dcp_read_header_data(t->request_header + DCP_HEADER_DATA_OFFSET);

    for(/* nothing */; count > 0; count -= skipped_bytes)
    {
        skipped_bytes = (count >= sizeof(dummy)) ? sizeof(dummy) : count;

        switch(read_to_buffer(dummy, skipped_bytes, fd, "unprocessed payload"))
        {
          case READ_OK:
            break;

          case READ_IO_ERROR:
          case READ_INCOMPLETE:
            count = 0;
            break;
        }
    }

    t->dcpsync.remaining_payload_size = 0;
}

static void fill_dcpsync_header_generic(uint8_t *const dcpsync_header,
                                        const uint8_t command,
                                        const uint8_t ttl,
                                        const uint16_t serial,
                                        const uint16_t dcp_packet_size)
{
    dcpsync_header[0] = command;
    dcpsync_header[1] = ttl;
    dcpsync_header[2] = (serial >> 8) & UINT8_MAX;
    dcpsync_header[3] = (serial >> 0) & UINT8_MAX;
    dcpsync_header[4] = (dcp_packet_size >> 8) & UINT8_MAX;
    dcpsync_header[5] = (dcp_packet_size >> 0) & UINT8_MAX;
}

static uint16_t get_dcpsync_serial(const uint8_t *dcpsync_header)
{
    return (dcpsync_header[0] << 8) | dcpsync_header[1];
}

static uint16_t get_dcpsync_data_size(const uint8_t *dcpsync_header)
{
    return (dcpsync_header[0] << 8) | dcpsync_header[1];
}

static enum dcpsync_packet_type read_dcpsync_header(struct dcpsync_header *dh,
                                                    const int fd)
{
    uint8_t buffer[DCPSYNC_HEADER_SIZE];

    memset(dh, 0, sizeof(*dh));

    if(fd < 0)
        return DCPSYNC_PACKET_COMMAND;

    switch(read_to_buffer(buffer, sizeof(buffer), fd, "sync"))
    {
      case READ_OK:
        break;

      case READ_INCOMPLETE:
        return DCPSYNC_PACKET_INVALID;

      case READ_IO_ERROR:
        return DCPSYNC_PACKET_IO_ERROR;
    }

    dh->is_enabled = true;
    dh->original_command = buffer[0];
    dh->ttl = buffer[1];
    dh->serial = get_dcpsync_serial(buffer + 2);
    dh->remaining_payload_size = get_dcpsync_data_size(buffer + 4);

    static const char unexpected_size_error[] =
        "Skip packet 0x%02x/0x%04x of unexpected size %u";
    static const char unknown_dcpsync_command_error[] =
        "Unknown DCPSYNC command 0x%02x, skipping packet 0x%04x of size %u";

    const char *error_format_string;

    if(dh->original_command == 'c')
    {
        if(dh->remaining_payload_size >= DCP_HEADER_SIZE)
            return DCPSYNC_PACKET_COMMAND;

        if(dh->ttl > 0)
            BUG("Got DCP packet with positive TTL");

        error_format_string = unexpected_size_error;
    }
    else if(dh->original_command == 'a')
    {
        if(dh->remaining_payload_size == 0)
            return DCPSYNC_PACKET_ACK;

        if(dh->ttl > 0)
            BUG("Got ACK with positive TTL");

        error_format_string = unexpected_size_error;
    }
    else if(dh->original_command == 'n')
    {
        if(dh->remaining_payload_size == 0)
            return DCPSYNC_PACKET_NACK;

        error_format_string = unexpected_size_error;
    }
    else
        error_format_string = unknown_dcpsync_command_error;

    msg_error(0, LOG_ERR, error_format_string, dh->original_command,
              dh->serial, dh->remaining_payload_size);

    return DCPSYNC_PACKET_INVALID;
}

static bool fill_request_header(struct transaction *t, const int fd)
{
    switch(read_to_buffer(t->request_header, sizeof(t->request_header), fd, "header"))
    {
      case READ_OK:
        if(t->dcpsync.is_enabled)
            t->dcpsync.remaining_payload_size -= sizeof(t->request_header);

        break;

      case READ_INCOMPLETE:
      case READ_IO_ERROR:
        return false;
    }

    const bool is_header_valid = ((t->request_header[0] & 0xf0) == 0);

    if(!is_header_valid)
    {
        if(t->dcpsync.is_enabled)
            skip_transaction_payload(t, fd);

        goto error_invalid_header;
    }

    const struct dcp_register_t *reg = lookup_register_for_transaction(t->request_header[1], false);

    if(reg == NULL)
    {
        skip_transaction_payload(t, fd);
        return false;
    }

    transaction_bind(t, reg, t->request_header[0] & 0x0f);

    switch(t->command)
    {
      case DCP_COMMAND_READ_REGISTER:
        if(t->request_header[DCP_HEADER_DATA_OFFSET] != 0 ||
           t->request_header[DCP_HEADER_DATA_OFFSET + 1] != 0)
            break;

        /* fall-through */

      case DCP_COMMAND_MULTI_WRITE_REGISTER:
        if(!request_command_matches_register_definition(t->command, t->reg))
        {
            msg_error(EINVAL, LOG_ERR,
                      "Register 0x%02x requested using wrong command",
                      t->request_header[1]);
            skip_transaction_payload(t, fd);
            break;
        }

        return true;

      case DCP_COMMAND_MULTI_READ_REGISTER:
        msg_error(EINVAL, LOG_ERR, "Multiple read command not supported");
        return false;

      case DCP_COMMAND_WRITE_REGISTER:
        msg_error(EINVAL, LOG_ERR, "Simple write command not supported");
        return false;
    }

error_invalid_header:
    msg_error(EINVAL, LOG_ERR,
              "Invalid DCP header 0x%02x 0x%02x 0x%02x 0x%02x",
              t->request_header[0], t->request_header[1],
              t->request_header[2], t->request_header[3]);
    return false;
}

static bool fill_payload_buffer(struct transaction *t, const int fd)
{
    uint16_t size =
        dcp_read_header_data(t->request_header + DCP_HEADER_DATA_OFFSET);

    log_assert(t->command == DCP_COMMAND_MULTI_WRITE_REGISTER);
    log_assert(dynamic_buffer_is_empty(&t->payload));

    if(size == 0)
        return true;

    if(t->dcpsync.is_enabled)
    {
        if(size < t->dcpsync.remaining_payload_size)
            msg_error(0, LOG_WARNING, "DCP packet size %u smaller than "
                      "DCPSYNC remaining payload size %u (ignored)",
                      size, t->dcpsync.remaining_payload_size);
        else if(size > t->dcpsync.remaining_payload_size)
        {
            msg_error(EINVAL, LOG_ERR, "DCP packet size %u too large to fit "
                      "into remaining DCPSYNC payload of size %u",
                      size, t->dcpsync.remaining_payload_size);
            goto error_exit;
        }
    }

    if(!dynamic_buffer_is_allocated(&t->payload) &&
       !dynamic_buffer_resize(&t->payload, size))
    {
        goto error_exit;
    }

    if(t->payload.size < size)
    {
        msg_error(EINVAL, LOG_ERR,
                  "DCP payload too large for register %u, "
                  "expecting no more than %zu bytes of data",
                  t->reg->address, t->payload.size);
        goto error_exit;
    }

    switch(read_to_buffer(t->payload.data, size, fd, "payload"))
    {
      case READ_OK:
        break;

      case READ_INCOMPLETE:
      case READ_IO_ERROR:
        return false;
    }

    t->payload.pos = size;

    if(t->dcpsync.is_enabled)
    {
        t->dcpsync.remaining_payload_size -= size;
        skip_transaction_payload(t, fd);
    }

    return true;

error_exit:
    skip_transaction_payload(t, fd);
    return false;
}

static bool allocate_payload_buffer(struct transaction *t)
{
    if(register_is_static_size(t->reg))
        return dynamic_buffer_resize(&t->payload, t->reg->max_data_size);

    dynamic_buffer_clear(&t->payload);

    return true;
}

static bool do_read_register(struct transaction *t)
{
    if(register_is_static_size(t->reg))
    {
        if(t->reg->read_handler == NULL)
        {
            msg_error(ENOSYS, LOG_ERR,
                      "No read handler defined for register %u",
                      t->reg->address);
            return false;
        }

        const ssize_t read_result =
            t->reg->read_handler(t->payload.data, t->payload.size);

        if(read_result < 0)
        {
            msg_error(0, LOG_ERR, "RegIO R: FAILED READING %d (%zd)",
                      t->reg->address, read_result);
            return false;
        }

        if(t->reg->address != 120 || msg_is_verbose(MESSAGE_LEVEL_DEBUG))
            msg_vinfo(MESSAGE_LEVEL_DIAG,
                      "RegIO R: %d, %zu bytes", t->reg->address, read_result);

        t->payload.pos = read_result;

        return true;
    }
    else
    {
        if(t->reg->read_handler_dynamic == NULL)
        {
            msg_error(ENOSYS, LOG_ERR,
                      "No dynamic read handler defined for register %u",
                      t->reg->address);
            return false;
        }

        if(!t->reg->read_handler_dynamic(&t->payload))
        {
            msg_error(0, LOG_ERR, "RegIO R: FAILED READING %d",
                      t->reg->address);
            return false;
        }

        msg_vinfo(MESSAGE_LEVEL_DIAG,
                  "RegIO R: %d, %zu bytes", t->reg->address, t->payload.pos);

        return true;
    }
}

static inline size_t get_remaining_fragment_size(const struct transaction *t)
{
    return t->payload.pos - t->current_fragment_offset;
}

static size_t get_current_fragment_size(const struct transaction *t)
{
    log_assert((t->current_fragment_offset < t->payload.pos) ||
               (t->current_fragment_offset == 0 && t->payload.pos == 0));

    const size_t temp = get_remaining_fragment_size(t);

    if(temp <= DCP_PACKET_MAX_PAYLOAD_SIZE)
        return temp;
    else
        return DCP_PACKET_MAX_PAYLOAD_SIZE;
}

static bool is_last_fragment(struct transaction *t)
{
    return get_remaining_fragment_size(t) <= DCP_PACKET_MAX_PAYLOAD_SIZE;
}

static void set_collision_exception(struct transaction_exception *e,
                                    struct transaction *t)
{
    e->exception_code = TRANSACTION_EXCEPTION_COLLISION;
    e->d.collision.t = t;
}

static void set_ooo_ack_exception(struct transaction_exception *e,
                                  uint16_t serial)
{
    e->exception_code = TRANSACTION_EXCEPTION_OUT_OF_ORDER_ACK;
    e->d.ack.serial = serial;
}

static void set_ooo_nack_exception(struct transaction_exception *e,
                                   uint16_t serial, uint8_t ttl)
{
    e->exception_code = TRANSACTION_EXCEPTION_OUT_OF_ORDER_NACK;
    e->d.nack.ttl = ttl;
    e->d.nack.serial = serial;
}

static bool process_ack(struct transaction *t, uint16_t serial)
{
    if(serial != t->dcpsync.serial)
        return false;

    t->state = TRANSACTION_STATE_SEND_TO_SLAVE_ACKED;

    return true;
}

static bool process_nack(struct transaction *t, uint16_t serial, uint8_t ttl)
{
    if(serial != t->dcpsync.serial)
    {
        msg_vinfo(MESSAGE_LEVEL_TRACE,
                  "Got NACK[%u] for 0x%04x while waiting for 0x%04x ACK",
                  ttl, serial, t->dcpsync.serial);
        return false;
    }

    t->dcpsync.ttl = ttl;

    if(ttl > 0)
    {
        t->state = TRANSACTION_STATE_SEND_TO_SLAVE;
        t->dcpsync.serial = mk_serial();

        msg_vinfo(MESSAGE_LEVEL_TRACE,
                  "Got NACK[%u] for 0x%04x, resending packet as 0x%04x",
                  ttl, serial, t->dcpsync.serial);
    }
    else
    {
        t->state = TRANSACTION_STATE_SEND_TO_SLAVE_FAILED;

        msg_vinfo(MESSAGE_LEVEL_TRACE,
                  "Got final NACK for 0x%04x, aborting transaction", serial);
    }

    return true;
}

enum transaction_process_status transaction_process(struct transaction *t,
                                                    int from_slave_fd,
                                                    int to_slave_fd,
                                                    struct transaction_exception *e)
{
    log_assert(t != NULL);
    log_assert(e != NULL);

    switch(t->state)
    {
      case TRANSACTION_STATE_ERROR:
        break;

      case TRANSACTION_STATE_SLAVE_PREPARE__INIT:
        {
            bool failed = false;

            switch(read_dcpsync_header(&t->dcpsync,
                                       t->channel == TRANSACTION_CHANNEL_SPI ? from_slave_fd : -1))
            {
              case DCPSYNC_PACKET_INVALID:
                skip_transaction_payload(t, from_slave_fd);

                /* fall-through */

              case DCPSYNC_PACKET_IO_ERROR:
                failed = true;
                break;

              case DCPSYNC_PACKET_COMMAND:
                failed = !fill_request_header(t, from_slave_fd);
                break;

              case DCPSYNC_PACKET_ACK:
                msg_vinfo(MESSAGE_LEVEL_TRACE,
                          "Got ACK for 0x%04x while waiting for new command packet",
                          t->dcpsync.serial);

                set_ooo_ack_exception(e, t->dcpsync.serial);

                t->dcpsync.original_command = 0x00;
                t->dcpsync.serial = DCPSYNC_SLAVE_SERIAL_INVALID;

                return TRANSACTION_EXCEPTION;

              case DCPSYNC_PACKET_NACK:
                msg_vinfo(MESSAGE_LEVEL_TRACE,
                          "Got NACK[%u] for 0x%04x while waiting for new "
                          "command packet", t->dcpsync.ttl, t->dcpsync.serial);

                set_ooo_nack_exception(e, t->dcpsync.serial, t->dcpsync.ttl);

                t->dcpsync.original_command = 0x00;
                t->dcpsync.serial = DCPSYNC_SLAVE_SERIAL_INVALID;

                return TRANSACTION_EXCEPTION;
            }

            if(failed)
                break;
            else
                t->state = TRANSACTION_STATE_SLAVE_READ_DATA;
        }

        /* fall-through */

      case TRANSACTION_STATE_SLAVE_READ_DATA:
        if(!allocate_payload_buffer(t))
            break;

        log_assert(t->command == DCP_COMMAND_MULTI_WRITE_REGISTER ||
                   t->command == DCP_COMMAND_READ_REGISTER);

        if(t->command == DCP_COMMAND_MULTI_WRITE_REGISTER)
        {
            if(!fill_payload_buffer(t, from_slave_fd))
                break;

            t->state = TRANSACTION_STATE_SLAVE_PROCESS_WRITE;

            return TRANSACTION_IN_PROGRESS;
        }
        else
        {
            transaction_refresh_as_master(t);
            t->state = TRANSACTION_STATE_SLAVE_PREPARE_ANSWER;

            return TRANSACTION_PUSH_BACK;
        }

      case TRANSACTION_STATE_PUSH_TO_SLAVE__INIT:
        if(!allocate_payload_buffer(t))
            break;

        log_assert(t->command == DCP_COMMAND_MULTI_WRITE_REGISTER);

        t->state = TRANSACTION_STATE_SLAVE_PREPARE_ANSWER;

        /* fall-through */

      case TRANSACTION_STATE_SLAVE_PREPARE_ANSWER:
        if(!do_read_register(t))
            break;

        if(t->command == DCP_COMMAND_READ_REGISTER)
            t->request_header[0] = DCP_COMMAND_MULTI_READ_REGISTER;

        t->state = TRANSACTION_STATE_SEND_TO_SLAVE;

        return TRANSACTION_IN_PROGRESS;

      case TRANSACTION_STATE_SLAVE_PROCESS_WRITE:
        if(t->reg->write_handler == NULL)
        {
            msg_error(ENOSYS, LOG_ERR,
                      "No write handler defined for register %u",
                      t->reg->address);
            break;
        }

        const int write_result =
            (t->command == DCP_COMMAND_WRITE_REGISTER
             ? t->reg->write_handler(t->request_header + DCP_HEADER_DATA_OFFSET, 2)
             : t->reg->write_handler(t->payload.data, t->payload.pos));

        if(write_result < 0)
        {
            msg_error(0, LOG_ERR,
                      "RegIO W: FAILED WRITING %zu bytes to %d (%d)",
                      t->command == DCP_COMMAND_WRITE_REGISTER ? 2 : t->payload.pos,
                      t->reg->address, write_result);
            break;
        }

        if(t->reg->address != 121 || msg_is_verbose(MESSAGE_LEVEL_DEBUG))
            msg_vinfo(MESSAGE_LEVEL_DIAG, "RegIO W: %d, %zu bytes",
                      t->reg->address,
                      t->command == DCP_COMMAND_WRITE_REGISTER ? 2 : t->payload.pos);

        return TRANSACTION_FINISHED;

      case TRANSACTION_STATE_MASTER_PREPARE__INIT:
        if(t->command != DCP_COMMAND_MULTI_WRITE_REGISTER)
        {
            log_assert(t->command == DCP_COMMAND_READ_REGISTER);
            log_assert(t->payload.data == NULL);
        }

        t->state = TRANSACTION_STATE_SEND_TO_SLAVE;

        /* fall-through */

      case TRANSACTION_STATE_SEND_TO_SLAVE:
        {
            const size_t fragsize = get_current_fragment_size(t);
            uint8_t sync_header[DCPSYNC_HEADER_SIZE];

            if(t->dcpsync.is_enabled)
                fill_dcpsync_header_generic(sync_header, 'c',
                                            t->dcpsync.ttl, t->dcpsync.serial,
                                            fragsize + DCP_HEADER_SIZE);

            dcp_put_header_data(t->request_header + DCP_HEADER_DATA_OFFSET,
                                fragsize);

            if((t->dcpsync.is_enabled &&
                os_write_from_buffer(sync_header, sizeof(sync_header),
                                     to_slave_fd) < 0) ||
               os_write_from_buffer(t->request_header, sizeof(t->request_header),
                                    to_slave_fd) < 0 ||
               os_write_from_buffer(t->payload.data + t->current_fragment_offset,
                                    fragsize, to_slave_fd) < 0)
                break;
        }

        if(t->dcpsync.is_enabled)
        {
            t->state = TRANSACTION_STATE_DCPSYNC_WAIT_FOR_ACK;
            return TRANSACTION_IN_PROGRESS;
        }
        else
            t->state = TRANSACTION_STATE_SEND_TO_SLAVE_ACKED;

        /* fall-through */

      case TRANSACTION_STATE_SEND_TO_SLAVE_ACKED:
        if(is_last_fragment(t))
            return TRANSACTION_FINISHED;

        t->current_fragment_offset += DCP_PACKET_MAX_PAYLOAD_SIZE;
        log_assert(t->current_fragment_offset < t->payload.pos);

        transaction_refresh_as_master(t);
        t->state = TRANSACTION_STATE_SEND_TO_SLAVE;

        return TRANSACTION_PUSH_BACK;

      case TRANSACTION_STATE_SEND_TO_SLAVE_FAILED:
        t->state = TRANSACTION_STATE_ERROR;

        return TRANSACTION_ERROR;

      case TRANSACTION_STATE_DCPSYNC_WAIT_FOR_ACK:
        log_assert(t->dcpsync.is_enabled);

        {
            struct dcpsync_header dh;

            switch(read_dcpsync_header(&dh, from_slave_fd))
            {
              case DCPSYNC_PACKET_IO_ERROR:
                break;

              case DCPSYNC_PACKET_INVALID:
                skip_transaction_payload(t, from_slave_fd);

                return TRANSACTION_IN_PROGRESS;

              case DCPSYNC_PACKET_COMMAND:
                msg_vinfo(MESSAGE_LEVEL_DEBUG,
                          "Collision: New packet 0x%04x while waiting for 0x%04x ACK",
                          dh.serial, t->dcpsync.serial);

                set_collision_exception(e,
                                        transaction_alloc(TRANSACTION_ALLOC_SLAVE_BY_SLAVE,
                                                          t->channel, false));

                bool failed;

                if(e->d.collision.t == NULL)
                {
                    msg_out_of_memory("interrupting slave transaction");
                    msg_error(ENOMEM, LOG_CRIT,
                              "Received packet 0x%04x while processing "
                              "packet 0x%04x, but cannot handle it",
                              dh.serial, t->dcpsync.serial);
                    failed = true;
                }
                else
                {
                    e->d.collision.t->dcpsync = dh;
                    failed = !fill_request_header(e->d.collision.t, from_slave_fd);
                }

                if(failed)
                {
                    if(e->d.collision.t != NULL)
                        transaction_free(&e->d.collision.t);

                    /* skipping this transaction is all we can do under these
                     * conditions... */
                    skip_transaction_payload(t, from_slave_fd);
                    return TRANSACTION_IN_PROGRESS;
                }
                else
                {
                    e->d.collision.t->state = TRANSACTION_STATE_SLAVE_READ_DATA;
                    return TRANSACTION_EXCEPTION;
                }

              case DCPSYNC_PACKET_ACK:
                if(process_ack(t, dh.serial))
                    return TRANSACTION_IN_PROGRESS;

                set_ooo_ack_exception(e, dh.serial);

                return TRANSACTION_EXCEPTION;

              case DCPSYNC_PACKET_NACK:
                if(process_nack(t, dh.serial, dh.ttl))
                    return TRANSACTION_IN_PROGRESS;

                set_ooo_nack_exception(e, dh.serial, dh.ttl);

                return TRANSACTION_EXCEPTION;
            }
        }

        break;
    }

    msg_error(0, LOG_ERR, "Transaction %p failed in state %d", t, t->state);
    t->state = TRANSACTION_STATE_ERROR;

    return TRANSACTION_ERROR;
}

enum transaction_process_status
transaction_process_out_of_order_ack(struct transaction *t,
                                     const struct transaction_exception_ack_data *d)
{
    log_assert(t != NULL);
    log_assert(t->dcpsync.is_enabled);
    log_assert(d != NULL);

    if(d->serial != t->dcpsync.serial)
    {
        BUG("Serial for out-of-order ACK wrong (0x%04x, expected 0x%04x)",
            d->serial, t->dcpsync.serial);
        return TRANSACTION_EXCEPTION;
    }

    switch(t->state)
    {
      case TRANSACTION_STATE_ERROR:
        return TRANSACTION_ERROR;

      case TRANSACTION_STATE_SLAVE_PREPARE__INIT:
      case TRANSACTION_STATE_PUSH_TO_SLAVE__INIT:
      case TRANSACTION_STATE_MASTER_PREPARE__INIT:
      case TRANSACTION_STATE_SLAVE_READ_DATA:
      case TRANSACTION_STATE_SLAVE_PREPARE_ANSWER:
      case TRANSACTION_STATE_SLAVE_PROCESS_WRITE:
      case TRANSACTION_STATE_SEND_TO_SLAVE:
      case TRANSACTION_STATE_SEND_TO_SLAVE_ACKED:
      case TRANSACTION_STATE_SEND_TO_SLAVE_FAILED:
        BUG("Ignoring out-of-order ACK for 0x%04x in state %d",
            t->dcpsync.serial, t->state);
        break;

      case TRANSACTION_STATE_DCPSYNC_WAIT_FOR_ACK:
        if(process_ack(t, d->serial))
            return TRANSACTION_IN_PROGRESS;

        BUG("Double out-of-order ACK exception");

        break;
    }

    return TRANSACTION_EXCEPTION;
}

enum transaction_process_status
transaction_process_out_of_order_nack(struct transaction *t,
                                      const struct transaction_exception_nack_data *d)
{
    log_assert(t != NULL);
    log_assert(t->dcpsync.is_enabled);
    log_assert(d != NULL);

    if(d->serial != t->dcpsync.serial)
    {
        BUG("Serial for out-of-order NACK[%u] wrong (0x%04x, expected 0x%04x)",
            d->ttl, d->serial, t->dcpsync.serial);
        return TRANSACTION_EXCEPTION;
    }

    switch(t->state)
    {
      case TRANSACTION_STATE_ERROR:
        return TRANSACTION_ERROR;

      case TRANSACTION_STATE_SLAVE_PREPARE__INIT:
      case TRANSACTION_STATE_PUSH_TO_SLAVE__INIT:
      case TRANSACTION_STATE_MASTER_PREPARE__INIT:
      case TRANSACTION_STATE_SLAVE_READ_DATA:
      case TRANSACTION_STATE_SLAVE_PREPARE_ANSWER:
      case TRANSACTION_STATE_SLAVE_PROCESS_WRITE:
      case TRANSACTION_STATE_SEND_TO_SLAVE:
      case TRANSACTION_STATE_SEND_TO_SLAVE_ACKED:
      case TRANSACTION_STATE_SEND_TO_SLAVE_FAILED:
        BUG("Ignoring out-of-order NACK[%u] for 0x%04x in state %d",
            d->ttl, t->dcpsync.serial, t->state);
        break;

      case TRANSACTION_STATE_DCPSYNC_WAIT_FOR_ACK:
        if(process_nack(t, d->serial, d->ttl))
            return TRANSACTION_IN_PROGRESS;

        BUG("Double out-of-order NACK[%u] exception", d->ttl);

        break;
    }

    return TRANSACTION_EXCEPTION;
}

bool transaction_is_input_required(const struct transaction *t)
{
    if(t == NULL)
        return true;

    switch(t->state)
    {
      case TRANSACTION_STATE_SLAVE_PREPARE__INIT:
      case TRANSACTION_STATE_SLAVE_READ_DATA:
      case TRANSACTION_STATE_DCPSYNC_WAIT_FOR_ACK:
        return true;

      case TRANSACTION_STATE_PUSH_TO_SLAVE__INIT:
      case TRANSACTION_STATE_MASTER_PREPARE__INIT:
      case TRANSACTION_STATE_SLAVE_PREPARE_ANSWER:
      case TRANSACTION_STATE_SLAVE_PROCESS_WRITE:
      case TRANSACTION_STATE_SEND_TO_SLAVE:
      case TRANSACTION_STATE_SEND_TO_SLAVE_ACKED:
      case TRANSACTION_STATE_SEND_TO_SLAVE_FAILED:
      case TRANSACTION_STATE_ERROR:
        break;
    }

    return false;
}

uint16_t transaction_get_max_data_size(const struct transaction *t)
{
    log_assert(t != NULL);
    log_assert(t->reg);
    log_assert(t->reg->max_data_size > 0);

    return t->reg->max_data_size;
}

/*!
 * Prepare transaction header according to address.
 *
 * This function sets the DCP register address for master transactions.
 * The size, if any, is inserted later.
 */
static void set_address_for_master(struct transaction *t,
                                   const struct dcp_register_t *reg)
{
    transaction_bind(t, reg, DCP_COMMAND_MULTI_WRITE_REGISTER);

    t->request_header[0] = t->command;
    t->request_header[1] = reg->address;
    dcp_put_header_data(t->request_header + DCP_HEADER_DATA_OFFSET, 0);
}

static struct transaction *mk_push_transaction(struct transaction **head,
                                               const struct dcp_register_t *reg,
                                               bool is_register_push,
                                               enum transaction_channel channel)
{
    log_assert(reg != NULL);

    const enum transaction_alloc_type alloc_type = is_register_push
        ? TRANSACTION_ALLOC_MASTER_FOR_REGISTER
        : TRANSACTION_ALLOC_MASTER_FOR_DRCPD_DATA;
    struct transaction *t = transaction_alloc(alloc_type, channel, false);

    if(t == NULL)
    {
        msg_error(ENOMEM, LOG_CRIT, "DCP congestion: no free transaction slot");
        return NULL;
    }

    /* fill in request header */
    set_address_for_master(t, reg);

    t->dcpsync.original_command = 'c';

    transaction_queue_add(head, t);

    return t;
}

static bool transaction_set_payload(struct transaction *t,
                                    const uint8_t *src, size_t length)
{
    log_assert(t != NULL);
    log_assert(t->payload.data == NULL);
    log_assert(src != NULL);

    if(!dynamic_buffer_resize(&t->payload, length))
        return false;

    memcpy(t->payload.data, src, length);
    t->payload.pos = length;

    return true;
}

struct transaction *
transaction_fragments_from_data(const uint8_t *const data, const size_t length,
                                uint8_t register_address,
                                enum transaction_channel channel)
{
    log_assert(data != NULL);
    log_assert(length > 0);

    const struct dcp_register_t *reg =
        lookup_register_for_transaction(register_address, true);

    if(reg == NULL)
        return NULL;

    struct transaction *head = NULL;
    size_t i = 0;

    while(i < length)
    {
        struct transaction *t =
            mk_push_transaction(&head, reg, false, channel);

        if(t == NULL)
            break;

        uint16_t size = transaction_get_max_data_size(t);

        if(i + size >= length)
            size = length - i;

        log_assert(size > 0);

        if(!transaction_set_payload(t, data + i, size))
            break;

        i += size;
    }

    if(i < length && head != NULL)
        transaction_free(&head);

    return head;
}

bool transaction_push_register_to_slave(struct transaction **head,
                                        uint8_t register_address,
                                        enum transaction_channel channel)
{
    const struct dcp_register_t *reg =
        lookup_register_for_transaction(register_address, true);

    if(reg == NULL)
        return false;

    return mk_push_transaction(head, reg, true, channel) != NULL;
}
