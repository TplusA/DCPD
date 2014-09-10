#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include "transactions.h"
#include "registers.h"
#include "dcpdefs.h"
#include "messages.h"

enum transaction_state
{
    TRANSACTION_STATE_ERROR,                /*!< Error state, cannot process */
    TRANSACTION_STATE_SLAVE_READ_COMMAND,   /*!< Read command + data from slave */
    TRANSACTION_STATE_SLAVE_PREPARE_ANSWER, /*!< Fill answer buffer */
    TRANSACTION_STATE_SLAVE_SEND_ANSWER,    /*!< Send answer to slave */
    TRANSACTION_STATE_SLAVE_PROCESS_WRITE,  /*!< Process data written by slave */
    TRANSACTION_STATE_MASTER_PREPARE,       /*!< Filling command buffer */
    TRANSACTION_STATE_MASTER_SEND_COMMAND,  /*!< Sending command to slave */
    TRANSACTION_STATE_MASTER_READ_ANSWER,   /*!< Reading answer from slave */
};

struct transaction
{
    struct transaction *next;
    struct transaction *prev;

    enum transaction_state state;

    uint8_t request_header[DCP_HEADER_SIZE];
    uint8_t command;

    const struct register_t *reg;

    struct transaction_payload payload;
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

static void transaction_init(struct transaction *t, bool is_slave_request)
{
    t->state = (is_slave_request
                ? TRANSACTION_STATE_SLAVE_READ_COMMAND
                : TRANSACTION_STATE_MASTER_PREPARE);
    t->reg = NULL;
    memset(t->request_header, UINT8_MAX, sizeof(t->request_header));

    t->payload.data = NULL;
    t->payload.buffer_size = 0;
    t->payload.pos = 0;
}

struct transaction *transaction_alloc(bool is_slave_request)
{
    if(free_list == NULL)
        return NULL;

    struct transaction *t = transaction_queue_remove(&free_list);

    transaction_init(t, is_slave_request);
    return t;
}

void transaction_free(struct transaction **t)
{
    assert(t != NULL);
    assert(*t != NULL);

#ifndef NDEBUG
    ptrdiff_t idx = *t - transactions_container;
#endif /* !NDEBUG */

    assert(idx >= 0);
    assert((size_t)idx < MAX_NUMBER_OF_TRANSACTIONS);

    if((*t)->payload.data != NULL)
        free((*t)->payload.data);

    transaction_queue_add_one(&free_list, *t);

    *t = NULL;
}

void transaction_reset_for_slave(struct transaction *t)
{
    if(t->payload.data != NULL)
        free(t->payload.data);

    transaction_init(t, true);
}

/*!
 * Put register data into transaction.
 *
 * This function inspects the register definition and sets up the buffering
 * accordingly. This function must be called for each transaction before
 * attempting to process them.
 */
static void transaction_set_register(struct transaction *t,
                                     const struct register_t *reg)
{
    assert(t != NULL);
    assert(reg != NULL);

    t->reg = reg;

    if((reg->flags & DCP_REGISTER_FLAG_IS_VARIABLE_LENGTH) == 0)
    {
    }
}

static bool transaction_set_address(struct transaction *t,
                                    uint8_t register_address,
                                    bool master_not_slave)
{
    const struct register_t *reg = register_lookup(register_address);

    if(reg == NULL)
    {
        msg_error(0, LOG_NOTICE,
                  "%s requested unsupported register 0x%02x",
                  master_not_slave ? "Master" : "Slave", register_address);
        return false;
    }

    assert(reg->address == register_address);
    transaction_set_register(t, reg);

    return true;
}

/*!
 * FIXME: Need to generate header from register description.
 *
 * \bug Not properly implemented
 */
bool transaction_set_address_for_master(struct transaction *t,
                                        uint8_t register_address)
{
    return transaction_set_address(t, register_address, true);
}

void transaction_queue_add_one(struct transaction **head, struct transaction *t)
{
    assert(head != NULL);
    assert(t != NULL);
    assert(t->next == t);
    assert(t->prev == t);

    if(*head != NULL)
    {
        t->next = *head;
        t->prev = (*head)->prev;

        (*head)->prev->next = t;
        (*head)->prev = t;
    }
    else
        *head = t;
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
                                            const struct register_t *reg)
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
        ssize_t len = read(fd, dest, count);

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

static int write_from_buffer(const uint8_t *src, size_t count, int fd)
{
    while(count > 0)
    {
        ssize_t len = write(fd, src, count);

        if(len < 0)
        {
            msg_error(errno, LOG_ERR, "Failed writing to fd %d", fd);
            return -1;
        }

        src += len;
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

    if(!transaction_set_address(t, t->request_header[1], false))
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

        msg_info("Slave access register 0x%02x, command 0x%02x",
                 t->reg->address, t->command);

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
    assert(t->payload.pos == 0);

    if(size == 0)
        return true;

    if(t->payload.data == NULL)
        return false;

    assert(t->payload.buffer_size == size);

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

    return transaction_payload_resize(&t->payload, size);
}

enum transaction_process_status transaction_process(struct transaction *t,
                                                    int from_slave_fd,
                                                    int to_slave_fd)
{
    assert(t != NULL);

    msg_info("Process transaction %p, state %d, reg %p, command %u, "
             "payload %p %zu %zu",
             t, t->state, t->reg, t->command,
             t->payload.data, t->payload.buffer_size, t->payload.pos);

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
             : t->reg->read_handler(t->payload.data, t->payload.buffer_size));

        if(read_result < 0)
            break;

        if(t->command == DCP_COMMAND_MULTI_READ_REGISTER)
        {
            t->payload.pos = read_result;
            dcp_put_header_data(t->request_header + DCP_HEADER_DATA_OFFSET,
                                t->payload.pos);
        }

        t->state = TRANSACTION_STATE_SLAVE_SEND_ANSWER;

        return TRANSACTION_IN_PROGRESS;

      case TRANSACTION_STATE_SLAVE_SEND_ANSWER:
        msg_info("Sending %u bytes to slave", DCP_HEADER_SIZE + t->payload.pos);
        if(write_from_buffer(t->request_header, sizeof(t->request_header),
                             to_slave_fd) < 0 ||
           write_from_buffer(t->payload.data, t->payload.pos, to_slave_fd) < 0)
            break;

        return TRANSACTION_FINISHED;

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
      case TRANSACTION_STATE_MASTER_SEND_COMMAND:
      case TRANSACTION_STATE_MASTER_READ_ANSWER:
        msg_error(0, LOG_EMERG, "state %d not implemented yet", t->state);
        break;
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
      case TRANSACTION_STATE_MASTER_READ_ANSWER:
        return true;

      case TRANSACTION_STATE_SLAVE_PREPARE_ANSWER:
      case TRANSACTION_STATE_SLAVE_SEND_ANSWER:
      case TRANSACTION_STATE_SLAVE_PROCESS_WRITE:
      case TRANSACTION_STATE_MASTER_PREPARE:
      case TRANSACTION_STATE_MASTER_SEND_COMMAND:
      case TRANSACTION_STATE_ERROR:
        break;
    }

    return false;
}

struct transaction_payload *transaction_get_payload(struct transaction *t)
{
    assert(t != NULL);
    return &t->payload;
}

bool transaction_payload_resize(struct transaction_payload *p, size_t size)
{
    assert(p != NULL);
    assert(size > 0);

    void *temp = realloc(p->data, size);

    if(temp == NULL)
    {
        msg_error(errno, LOG_CRIT,
                  "Failed resizing payload buffer from %zu to %zu bytes",
                  p->buffer_size, size);
        return false;
    }

    p->data = temp;
    p->buffer_size = size;

    return true;
}
