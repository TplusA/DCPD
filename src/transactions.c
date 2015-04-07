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
    TRANSACTION_STATE_SLAVE_READ_COMMAND,   /*!< Read command + data from slave */
    TRANSACTION_STATE_PUSH_TO_SLAVE,        /*!< Prepare answer buffer */
    TRANSACTION_STATE_SLAVE_PREPARE_ANSWER, /*!< Fill answer buffer */
    TRANSACTION_STATE_SLAVE_PROCESS_WRITE,  /*!< Process data written by slave */
    TRANSACTION_STATE_MASTER_PREPARE,       /*!< Filling command buffer */
    TRANSACTION_STATE_SEND_TO_SLAVE,        /*!< Send (any) data to slave */
};

struct transaction
{
    struct transaction *next;
    struct transaction *prev;

    enum transaction_state state;
    bool is_pinned;

    uint8_t request_header[DCP_HEADER_SIZE];
    uint8_t command;

    const struct dcp_register_t *reg;

    enum transaction_channel channel;
    struct dynamic_buffer payload;
};

static struct transaction transactions_container[100];

#define MAX_NUMBER_OF_TRANSACTIONS \
    (sizeof(transactions_container) / sizeof(transactions_container[0]))

static struct transaction *free_list;

void transaction_init_allocator(void)
{
    for(unsigned int i = 1; i < MAX_NUMBER_OF_TRANSACTIONS - 1; ++i)
    {
        transactions_container[i].prev = &transactions_container[i - 1];
        transactions_container[i].next = &transactions_container[i + 1];
    }

    struct transaction *t = &transactions_container[0];

    t->prev = &transactions_container[MAX_NUMBER_OF_TRANSACTIONS - 1];
    t->next = &transactions_container[1];

    t = &transactions_container[MAX_NUMBER_OF_TRANSACTIONS - 1];
    t->prev = &transactions_container[MAX_NUMBER_OF_TRANSACTIONS - 2];
    t->next = &transactions_container[0];

    free_list = &transactions_container[0];
}

static void transaction_init(struct transaction *t, bool is_slave_request,
                             enum transaction_channel channel, bool is_pinned)
{
    t->state = (is_slave_request
                ? TRANSACTION_STATE_SLAVE_READ_COMMAND
                : TRANSACTION_STATE_MASTER_PREPARE);
    t->is_pinned = is_pinned;
    t->reg = NULL;
    t->channel = channel;
    memset(t->request_header, UINT8_MAX, sizeof(t->request_header));
    dynamic_buffer_init(&t->payload);
}

struct transaction *transaction_alloc(bool is_slave_request,
                                      enum transaction_channel channel,
                                      bool is_pinned)
{
    if(free_list == NULL)
        return NULL;

    struct transaction *t = transaction_queue_remove(&free_list);

    transaction_init(t, is_slave_request, channel, is_pinned);
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
        ptrdiff_t idx = t - transactions_container;
#endif /* !NDEBUG */

        log_assert(idx >= 0);
        log_assert((size_t)idx < MAX_NUMBER_OF_TRANSACTIONS);

        dynamic_buffer_free(&t->payload);

        t = t->next;
    }
    while(t != *head);

    transaction_queue_add(&free_list, *head);
    *head = NULL;
}

void transaction_reset_for_slave(struct transaction *t)
{
    dynamic_buffer_free(&t->payload);
    transaction_init(t, true, t->channel, t->is_pinned);
}

/*!
 * Look up register by address, associate transaction with it.
 *
 * This function must be called for each transaction before attempting to
 * process them.
 */
static bool transaction_set_register_struct(struct transaction *t,
                                            uint8_t register_address,
                                            bool master_not_slave)
{
    const struct dcp_register_t *reg = register_lookup(register_address);

    if(reg == NULL)
    {
        msg_error(0, LOG_NOTICE,
                  "%s requested unsupported register 0x%02x",
                  master_not_slave ? "Master" : "Slave", register_address);
        return false;
    }

    log_assert(reg->address == register_address);

    t->reg = reg;

    return true;
}

/*!
 * Prepare transaction header according to address.
 *
 * The size, if any, is inserted later.
 */
bool transaction_set_address_for_master(struct transaction *t,
                                        uint8_t register_address)
{
    if(!transaction_set_register_struct(t, register_address, true))
        return false;

    t->command = DCP_COMMAND_MULTI_READ_REGISTER;

    t->request_header[0] = t->command;
    t->request_header[1] = register_address;
    dcp_put_header_data(t->request_header + DCP_HEADER_DATA_OFFSET, 0);

    return true;
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

static int read_to_buffer(uint8_t *dest, size_t count, int fd)
{
    while(count > 0)
    {
        ssize_t len = os_read(fd, dest, count);

        if(len == 0)
        {
            msg_info("End of data while reading DCP packet from fd %d", fd);
            return -1;
        }

        if(len < 0)
        {
            msg_error(errno, LOG_ERR, "Failed reading from fd %d", fd);
            return -1;
        }

        dest += len;
        count -= len;
    }

    return 0;
}

static bool fill_request_header(struct transaction *t, const int fd)
{
    if(read_to_buffer(t->request_header, sizeof(t->request_header), fd) < 0)
        return false;

    if((t->request_header[0] & 0xf0) != 0)
        goto error_invalid_header;

    t->command = t->request_header[0] & 0x0f;

    if(!transaction_set_register_struct(t, t->request_header[1], false))
        return false;

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

    if(!dynamic_buffer_is_allocated(&t->payload))
        return false;

    if(t->payload.size < size)
    {
        msg_error(EINVAL, LOG_ERR,
                  "DCP payload too large for register %u, "
                  "expecting no more than %zu bytes of data",
                  t->reg->address, t->payload.size);
        return false;
    }

    if(read_to_buffer(t->payload.data, size, fd) < 0)
        return false;

    t->payload.pos = size;

    return true;
}

static bool allocate_payload_buffer(struct transaction *t)
{
    log_assert(t->reg->max_data_size > 0);

    return dynamic_buffer_resize(&t->payload, t->reg->max_data_size);
}

enum transaction_process_status transaction_process(struct transaction *t,
                                                    int from_slave_fd,
                                                    int to_slave_fd)
{
    log_assert(t != NULL);

    switch(t->state)
    {
      case TRANSACTION_STATE_ERROR:
        break;

      case TRANSACTION_STATE_SLAVE_READ_COMMAND:
        if(!fill_request_header(t, from_slave_fd))
            break;

        /* fall-through */

      case TRANSACTION_STATE_PUSH_TO_SLAVE:
        if(!allocate_payload_buffer(t))
            break;

        if(t->command == DCP_COMMAND_WRITE_REGISTER ||
           t->command == DCP_COMMAND_MULTI_WRITE_REGISTER)
        {
            if(t->command == DCP_COMMAND_MULTI_WRITE_REGISTER &&
               !fill_payload_buffer(t, from_slave_fd))
                break;

            t->state = TRANSACTION_STATE_SLAVE_PROCESS_WRITE;
        }
        else
            t->state = TRANSACTION_STATE_SLAVE_PREPARE_ANSWER;

        return TRANSACTION_IN_PROGRESS;

      case TRANSACTION_STATE_SLAVE_PREPARE_ANSWER:
        if(t->reg->read_handler == NULL)
        {
            msg_error(ENOSYS, LOG_ERR,
                      "No read handler defined for register %u",
                      t->reg->address);
            break;
        }

        const ssize_t read_result = t->reg->read_handler(t->payload.data,
                                                         t->payload.size);

        if(read_result < 0)
            break;

        if(t->command == DCP_COMMAND_READ_REGISTER)
            t->request_header[0] = DCP_COMMAND_MULTI_READ_REGISTER;

        t->payload.pos = read_result;
        dcp_put_header_data(t->request_header + DCP_HEADER_DATA_OFFSET,
                            t->payload.pos);

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
            break;

        return TRANSACTION_FINISHED;

      case TRANSACTION_STATE_MASTER_PREPARE:
        if(t->command == DCP_COMMAND_MULTI_READ_REGISTER)
            dcp_put_header_data(t->request_header + DCP_HEADER_DATA_OFFSET,
                                t->payload.pos);
        else
        {
            log_assert(t->command == DCP_COMMAND_READ_REGISTER);
            log_assert(t->payload.data == NULL);
        }

        t->state = TRANSACTION_STATE_SEND_TO_SLAVE;

        return TRANSACTION_IN_PROGRESS;

      case TRANSACTION_STATE_SEND_TO_SLAVE:
        if(os_write_from_buffer(t->request_header, sizeof(t->request_header),
                                to_slave_fd) < 0 ||
           os_write_from_buffer(t->payload.data, t->payload.pos,
                                to_slave_fd) < 0)
            break;

        return TRANSACTION_FINISHED;
    }

    msg_error(EIO, LOG_NOTICE, "Transaction %p failed in state %d", t, t->state);
    t->state = TRANSACTION_STATE_ERROR;

    return TRANSACTION_ERROR;
}

bool transaction_is_input_required(const struct transaction *t)
{
    if(t == NULL)
        return true;

    switch(t->state)
    {
      case TRANSACTION_STATE_SLAVE_READ_COMMAND:
        return true;

      case TRANSACTION_STATE_PUSH_TO_SLAVE:
      case TRANSACTION_STATE_SLAVE_PREPARE_ANSWER:
      case TRANSACTION_STATE_SLAVE_PROCESS_WRITE:
      case TRANSACTION_STATE_MASTER_PREPARE:
      case TRANSACTION_STATE_SEND_TO_SLAVE:
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

bool transaction_set_payload(struct transaction *t,
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

static struct transaction *mk_push_transaction(struct transaction **head,
                                               uint8_t register_address,
                                               bool is_pure_push,
                                               enum transaction_channel channel)
{
    struct transaction *t = transaction_alloc(is_pure_push, channel, false);

    if(t == NULL)
    {
        msg_error(ENOMEM, LOG_CRIT, "DCP congestion: no free transaction slot");
        return NULL;
    }

    /* fill in request header */
    if(transaction_set_address_for_master(t, register_address))
    {
        if(is_pure_push)
        {
            /* simulate slave request, bypass reading command from slave fd */
            t->state = TRANSACTION_STATE_PUSH_TO_SLAVE;
        }

        transaction_queue_add(head, t);
    }
    else
        transaction_free(&t);

    return t;
}

static struct transaction *mk_master_transaction(struct transaction **head,
                                                 uint8_t register_address,
                                                 enum transaction_channel channel)
{
    return mk_push_transaction(head, register_address, false, channel);
}

struct transaction *
transaction_fragments_from_data(const uint8_t *const data, const size_t length,
                                uint8_t register_address,
                                enum transaction_channel channel)
{
    log_assert(data != NULL);
    log_assert(length > 0);

    struct transaction *head = NULL;
    size_t i = 0;

    while(i < length)
    {
        struct transaction *t =
            mk_master_transaction(&head, register_address, channel);

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
    return (mk_push_transaction(head, register_address, true, channel) != NULL);
}
