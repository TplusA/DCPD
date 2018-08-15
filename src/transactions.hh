/*
 * Copyright (C) 2015, 2016, 2018  T+A elektroakustik GmbH & Co. KG
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

#ifndef TRANSACTIONS_H
#define TRANSACTIONS_H

#include <stdbool.h>

/*!
 * \addtogroup dcp_transaction DCP transactions
 */
/*!@{*/

enum transaction_alloc_type
{
    TRANSACTION_ALLOC_MASTER_FOR_DRCPD_DATA,
    TRANSACTION_ALLOC_MASTER_FOR_REGISTER,
    TRANSACTION_ALLOC_SLAVE_BY_SLAVE,
};

enum transaction_process_status
{
    TRANSACTION_IN_PROGRESS,
    TRANSACTION_PUSH_BACK,
    TRANSACTION_FINISHED,
    TRANSACTION_ERROR,
    TRANSACTION_EXCEPTION,
};

enum transaction_exception_code
{
    TRANSACTION_EXCEPTION_COLLISION,
    TRANSACTION_EXCEPTION_OUT_OF_ORDER_ACK,
    TRANSACTION_EXCEPTION_OUT_OF_ORDER_NACK,
};

enum transaction_channel
{
    TRANSACTION_CHANNEL_SPI,
    TRANSACTION_CHANNEL_INET,
};

#define TRANSACTION_DUMP_SENT_MASK          (7U << 0)
#define TRANSACTION_DUMP_SENT_DCPSYNC       (1U << 0)
#define TRANSACTION_DUMP_SENT_DCP_HEADER    (1U << 1)
#define TRANSACTION_DUMP_SENT_DCP_PAYLOAD   (1U << 2)
#define TRANSACTION_DUMP_SENT_NONE          0U

#define TRANSACTION_DUMP_SENT_MERGE_MASK    (3U << 4)
#define TRANSACTION_DUMP_SENT_MERGE_NONE    (0U << 4)
#define TRANSACTION_DUMP_SENT_MERGE_DCP     (1U << 4)
#define TRANSACTION_DUMP_SENT_MERGE_ALL     (2U << 4)

/*!
 * Opaque transaction structure.
 */
struct transaction;

struct transaction_exception_collision_data
{
    struct transaction *t;
};

struct transaction_exception_ack_data
{
    uint16_t serial;
};

struct transaction_exception_nack_data
{
    uint8_t ttl;
    uint16_t serial;
};

/*!
 * Pseudo exception for exceptional situations in transaction processing.
 */
struct transaction_exception
{
    enum transaction_exception_code exception_code;

    union
    {
        struct transaction_exception_collision_data collision;
        struct transaction_exception_ack_data ack;
        struct transaction_exception_nack_data nack;
    }
    d;
};

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Initialize transaction container.
 *
 * Must be called once before calling any other functions declared in this
 * header file.
 */
void transaction_init_allocator(void);

/*!
 * Allocate a new transaction object.
 *
 * \returns A pointer to a transaction, or NULL on error.
 */
struct transaction *transaction_alloc(enum transaction_alloc_type alloc_type,
                                      enum transaction_channel channel,
                                      bool is_pinned);

/*!
 * Free a transaction queue.
 *
 * \param head Pointer to pointer of transaction queue to free. The pointer
 *     that is pointed to will be set to NULL.
 */
void transaction_free(struct transaction **head);

/*!
 * Free payload and reinitialize structure.
 */
void transaction_reset_for_slave(struct transaction *t);

/*!
 * Add queue \p t to end of given queue.
 *
 * \param head Pointer to a pointer of the first element of a queue. If it
 *     points to a NULL pointer, it will be changed to point to \p t, otherwise
 *     it will remain untouched.
 * \param t The queue to add to the queue.
 */
void transaction_queue_add(struct transaction **head, struct transaction *t);

/*!
 * Remove first element from queue.
 *
 * \param head Pointer to a pointer of the first element of a queue. The head
 *     pointer will be moved to the next element in the queue, if any; if there
 *     is only one element in the queue, then the head pointer is set to NULL.
 *
 * \returns Pointer that \p head was pointing to.
 */
struct transaction *transaction_queue_remove(struct transaction **head);

/*!
 * Find transaction given a DCPSYNC serial.
 */
struct transaction *transaction_queue_find_by_serial(struct transaction *head,
                                                     uint16_t serial);

/*!
 * Remove transaction from queue, making it a queue of its own.
 *
 * \returns
 *     The element that followed \p t before it was removed from its queue.
 */
struct transaction *transaction_queue_cut_element(struct transaction *t);

/*!
 * Return communication channel used by the given transaction.
 */
enum transaction_channel transaction_get_channel(const struct transaction *t);

/*!
 * Whether or not to free the transaction object.
 *
 * This flag is only advisory and used by client code. Calling
 * #transaction_free() for a pinned transaction still frees the object and
 * returns it to the pool of unused transaction objects.
 */
bool transaction_is_pinned(const struct transaction *t);

/*!
 * Process the transaction.
 *
 * \param[in] t
 *     Transaction to process.
 * \param[in] from_slave_fd
 *     Where to read data sent by slave from.
 * \param[in] to_slave_fd
 *     Where to write data to be sent to slave to.
 * \param[in] dump_sent_data_flags
 *     Whether or not to log DCP data sent to slave, and how.
 *     See \c TRANSACTION_DUMP_SENT_ flag definitions.
 * \param[out] e
 *     New transaction that was created while processing \p t as a result of a
 *     collision. This new transaction takes priority over \p tc and must be
 *     processed next, processing of \p t must be deferred until after \p tc
 *     has finished.
 *
 * \retval #TRANSACTION_IN_PROGRESS
 *     The transaction needs more processing, #transaction_process() must be
 *     called again. Check result of #transaction_is_input_required() before
 *     actually doing it.
 * \retval #TRANSACTION_PUSH_BACK
 *     The transaction has been recycled (ACK received, answer to read command
 *     should be sent) and should be reinserted at the end of the queue.
 * \retval #TRANSACTION_FINISHED
 *     The transaction has been processed without any errors and may be freed.
 * \retval #TRANSACTION_ERROR
 *     The transaction has finished with an error and may be freed.
 * \retval #TRANSACTION_EXCEPTION
 *     There was an exception (see #transaction_exception_code) which must be
 *     handled by the caller. This mechnism is required because this function
 *     only operates on a single transaction, not a queue of transactions.
 */
enum transaction_process_status transaction_process(struct transaction *t,
                                                    int from_slave_fd,
                                                    int to_slave_fd,
                                                    unsigned int dump_sent_data_flags,
                                                    struct transaction_exception *e);

/*!
 * Inject ACK into transaction.
 *
 * For out-of-order ACK handling.
 */
enum transaction_process_status
transaction_process_out_of_order_ack(struct transaction *t,
                                     const struct transaction_exception_ack_data *d);

/*!
 * Inject NACK into transaction.
 *
 * For out-of-order NACK handling.
 */
enum transaction_process_status
transaction_process_out_of_order_nack(struct transaction *t,
                                      const struct transaction_exception_nack_data *d);

bool transaction_is_input_required(const struct transaction *t);

uint16_t transaction_get_max_data_size(const struct transaction *t);

struct transaction *
transaction_fragments_from_data(const uint8_t *data, size_t length,
                                uint8_t register_address,
                                enum transaction_channel channel);

bool transaction_push_register_to_slave(struct transaction **head,
                                        uint8_t register_address,
                                        enum transaction_channel channel);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !TRANSACTIONS_H */
