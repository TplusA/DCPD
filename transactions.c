#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
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
    assert(head != NULL);
    assert(*head != NULL);

    struct transaction *t = *head;

    do
    {
#ifndef NDEBUG
        ptrdiff_t idx = t - transactions_container;
#endif /* !NDEBUG */

        assert(idx >= 0);
        assert((size_t)idx < MAX_NUMBER_OF_TRANSACTIONS);

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

    assert(reg->address == register_address);

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

    if((t->reg->flags & DCP_REGISTER_FLAG_IS_VARIABLE_LENGTH) != 0)
        t->command = DCP_COMMAND_MULTI_READ_REGISTER;
    else
        t->command = DCP_COMMAND_READ_REGISTER;

    t->request_header[0] = t->command;
    t->request_header[1] = register_address;
    dcp_put_header_data(t->request_header + DCP_HEADER_DATA_OFFSET, 0);

    return true;
}

void transaction_queue_add(struct transaction **head, struct transaction *t)
{
    assert(head != NULL);
    assert(t != NULL);

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

    assert((*head)->next->prev == *head);
    assert((*head)->prev->next == *head);
    assert(t->next->prev == t);
    assert(t->prev->next == t);
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
    assert(head != NULL);
    assert(*head != NULL);

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
      case DCP_COMMAND_WRITE_REGISTER:
        return !(reg->flags & DCP_REGISTER_FLAG_IS_VARIABLE_LENGTH);

      case DCP_COMMAND_MULTI_READ_REGISTER:
      case DCP_COMMAND_MULTI_WRITE_REGISTER:
        return !!(reg->flags & DCP_REGISTER_FLAG_IS_VARIABLE_LENGTH);
    }

    return false;
}

static int read_to_buffer(uint8_t *dest, size_t count, int fd)
{
    while(count > 0)
    {
        ssize_t len = os_read(fd, dest, count);

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
      case DCP_COMMAND_MULTI_READ_REGISTER:
        if(t->request_header[DCP_HEADER_DATA_OFFSET] != 0 ||
           t->request_header[DCP_HEADER_DATA_OFFSET + 1] != 0)
            break;

        /* fall-through */

      case DCP_COMMAND_WRITE_REGISTER:
      case DCP_COMMAND_MULTI_WRITE_REGISTER:
        if(!request_command_matches_register_definition(t->command, t->reg))
        {
            msg_error(0, LOG_ERR,
                      "Register 0x%02x requested using wrong command",
                      t->request_header[1]);
            break;
        }

        return true;
    }

error_invalid_header:
    msg_error(0, LOG_ERR,
              "Invalid DCP header 0x%02x 0x%02x 0x%02x 0x%02x",
              t->request_header[0], t->request_header[1],
              t->request_header[2], t->request_header[3]);
    return false;
}

static bool fill_payload_buffer(struct transaction *t, const int fd)
{
    uint16_t size =
        dcp_read_header_data(t->request_header + DCP_HEADER_DATA_OFFSET);

    assert(t->command == DCP_COMMAND_MULTI_WRITE_REGISTER);
    assert(dynamic_buffer_is_empty(&t->payload));

    if(size == 0)
        return true;

    if(!dynamic_buffer_is_allocated(&t->payload))
        return false;

    assert(t->payload.size == size);

    if(read_to_buffer(t->payload.data, size, fd) < 0)
        return false;

    t->payload.pos = size;

    return true;
}

static bool allocate_payload_buffer(struct transaction *t)
{
    if(t->command != DCP_COMMAND_MULTI_READ_REGISTER &&
       t->command != DCP_COMMAND_MULTI_WRITE_REGISTER)
    {
        assert(t->payload.data == NULL);
        return true;
    }

    const uint16_t size =
        (t->command == DCP_COMMAND_MULTI_READ_REGISTER
         ? t->reg->max_data_size
         : dcp_read_header_data(t->request_header + DCP_HEADER_DATA_OFFSET));

    if(size == 0)
        return true;

    return dynamic_buffer_resize(&t->payload, size);
}

enum transaction_process_status transaction_process(struct transaction *t,
                                                    int from_slave_fd,
                                                    int to_slave_fd)
{
    assert(t != NULL);

    switch(t->state)
    {
      case TRANSACTION_STATE_ERROR:
        break;

      case TRANSACTION_STATE_SLAVE_READ_COMMAND:
        if(!fill_request_header(t, from_slave_fd))
            break;

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

        const ssize_t read_result =
            (t->command == DCP_COMMAND_READ_REGISTER
             ? t->reg->read_handler(t->request_header + DCP_HEADER_DATA_OFFSET, 2)
             : t->reg->read_handler(t->payload.data, t->payload.size));

        if(read_result < 0)
            break;

        if(t->command == DCP_COMMAND_MULTI_READ_REGISTER)
        {
            t->payload.pos = read_result;
            dcp_put_header_data(t->request_header + DCP_HEADER_DATA_OFFSET,
                                t->payload.pos);
        }

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
            assert(t->command == DCP_COMMAND_READ_REGISTER);
            assert(t->payload.data == NULL);
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
    assert(t != NULL);
    assert(t->reg);

    return ((t->reg->flags & DCP_REGISTER_FLAG_IS_VARIABLE_LENGTH)
            ? t->reg->max_data_size
            : 2);
}

bool transaction_set_payload(struct transaction *t,
                             const uint8_t *src, size_t length)
{
    assert(t != NULL);
    assert(t->payload.data == NULL);
    assert(src != NULL);

    if(!dynamic_buffer_resize(&t->payload, length))
        return false;

    memcpy(t->payload.data, src, length);
    t->payload.pos = length;

    return true;
}

static struct transaction *mk_master_transaction(struct transaction **head,
                                                 uint8_t register_address,
                                                 enum transaction_channel channel)
{
    struct transaction *t = transaction_alloc(false, channel, false);

    if(t == NULL)
    {
        msg_error(ENOMEM, LOG_CRIT, "DCP congestion: no free transaction slot");
        return NULL;
    }

    if(transaction_set_address_for_master(t, register_address))
        transaction_queue_add(head, t);
    else
        transaction_free(&t);

    return t;
}

struct transaction *
transaction_fragments_from_data(const uint8_t *const data, const size_t length,
                                uint8_t register_address,
                                enum transaction_channel channel)
{
    assert(data != NULL);
    assert(length > 0);

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

        assert(size > 0);

        if(!transaction_set_payload(t, data + i, size))
            break;

        i += size;
    }

    if(i < length && head != NULL)
        transaction_free(&head);

    return head;
}
