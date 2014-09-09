#ifndef TRANSACTIONS_H
#define TRANSACTIONS_H

#include <stdbool.h>

enum transaction_process_status
{
    TRANSACTION_IN_PROGRESS,
    TRANSACTION_FINISHED,
    TRANSACTION_ERROR,
};

/*!
 * Opaque transaction structure.
 */
struct transaction;

struct transaction_payload
{
    uint8_t *data;
    size_t buffer_size;
    size_t pos;
};

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
struct transaction *transaction_alloc(bool is_slave_request);

/*!
 * Free a transaction.
 *
 * \param t Pointer to pointer of transaction structure to free. Note that the
 *     transaction must not be in any queue. The pointer that is pointed to
 *     will be set to NULL.
 */
void transaction_free(struct transaction **t);

void transaction_reset_for_slave(struct transaction *t);

/*!
 * Set DCP register address for master transaction.
 */
bool transaction_set_address_for_master(struct transaction *t,
                                        uint8_t register_address);

/*!
 * Add single element to end of given queue.
 *
 * \param head Pointer to a pointer of the first element of a queue. If it
 *     points to a NULL pointer, it will be changed to point to \p t, otherwise
 *     it will remain untouched.
 * \param t The element to add to the queue.
 */
void transaction_queue_add_one(struct transaction **head, struct transaction *t);

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
 * Process the transaction.
 */
enum transaction_process_status transaction_process(struct transaction *t,
                                                    int from_slave_fd,
                                                    int to_slave_fd);

bool transaction_is_input_required(const struct transaction *t);

struct transaction_payload *transaction_get_payload(struct transaction *t);

bool transaction_payload_resize(struct transaction_payload *p, size_t size);

bool transaction_payload_add_space(struct transaction_payload *p, size_t size);

#endif /* !TRANSACTIONS_H */
