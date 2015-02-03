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

#ifndef TRANSACTIONS_H
#define TRANSACTIONS_H

#include <stdbool.h>

/*!
 * \addtogroup dcp_transaction DCP transactions
 */
/*!@{*/

enum transaction_process_status
{
    TRANSACTION_IN_PROGRESS,
    TRANSACTION_FINISHED,
    TRANSACTION_ERROR,
};

enum transaction_channel
{
    TRANSACTION_CHANNEL_SPI,
    TRANSACTION_CHANNEL_INET,
};

/*!
 * Opaque transaction structure.
 */
struct transaction;

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
struct transaction *transaction_alloc(bool is_slave_request,
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
 * Set DCP register address for master transaction.
 */
bool transaction_set_address_for_master(struct transaction *t,
                                        uint8_t register_address);

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
 */
enum transaction_process_status transaction_process(struct transaction *t,
                                                    int from_slave_fd,
                                                    int to_slave_fd);

bool transaction_is_input_required(const struct transaction *t);

uint16_t transaction_get_max_data_size(const struct transaction *t);

bool transaction_set_payload(struct transaction *t,
                             const uint8_t *src, size_t length);

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
