/*
 * Copyright (C) 2015, 2016, 2018, 2019, 2021  T+A elektroakustik GmbH & Co. KG
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

#ifndef TRANSACTIONS_H
#define TRANSACTIONS_H

#include "dcpdefs.h"
#include "registers.hh"

#include <memory>
#include <queue>
#include <functional>
#include <stdexcept>
#include <cinttypes>
#include <cstdlib>

/*!
 * \addtogroup dcp_transaction DCP transactions
 */
/*!@{*/

namespace TransactionQueue
{

/*!
 * What kind of transaction to construct.
 */
enum class InitialType
{
    MASTER_FOR_DRCPD_DATA,
    MASTER_FOR_REGISTER,
    SLAVE_BY_SLAVE,
};

/*!
 * Result of a transaction processing step.
 */
enum class ProcessResult
{
    IN_PROGRESS,
    PUSH_BACK,
    FINISHED,
    ERROR,
};

/*!
 * Communication channel identifier.
 */
enum class Channel
{
    SPI,
    INET,
};

using DumpFlags = unsigned int;

static constexpr DumpFlags DUMP_SENT_MASK        = (7U << 0);
static constexpr DumpFlags DUMP_SENT_DCPSYNC     = (1U << 0);
static constexpr DumpFlags DUMP_SENT_DCP_HEADER  = (1U << 1);
static constexpr DumpFlags DUMP_SENT_DCP_PAYLOAD = (1U << 2);
static constexpr DumpFlags DUMP_SENT_NONE =         0U;

static constexpr DumpFlags DUMP_SENT_MERGE_MASK  = (3U << 4);
static constexpr DumpFlags DUMP_SENT_MERGE_NONE  = (0U << 4);
static constexpr DumpFlags DUMP_SENT_MERGE_DCP   = (1U << 4);
static constexpr DumpFlags DUMP_SENT_MERGE_ALL   = (2U << 4);

class Queue;
class Transaction;

/*!
 * Synchronization data for DCPSYNC encapsulation.
 */
class TXSync
{
  private:
    bool is_enabled_;
    uint8_t original_command_;
    uint8_t ttl_;
    uint16_t serial_;
    uint16_t remaining_payload_size_;

  public:
    TXSync(const TXSync &) = delete;
    TXSync &operator=(const TXSync &) = delete;
    TXSync &operator=(TXSync &&) = default;

    explicit TXSync() { disable(); }
    explicit TXSync(Queue &queue, InitialType init_type, uint8_t command, Channel channel);

    bool is_enabled() const { return is_enabled_; }
    uint8_t get_command() const { return original_command_; }
    uint8_t get_ttl() const { return ttl_; }
    uint16_t get_serial() const { return serial_; }
    uint16_t get_remaining_payload_size() const { return remaining_payload_size_; }
    bool consumed_payload(size_t n);
    void drop_payload() { remaining_payload_size_ = 0; }
    void process_nack();
    void process_nack(uint16_t serial, uint8_t ttl);

    enum class SizeCheckResult
    {
        NOT_ENABLED,
        MATCH,
        TRAILING_JUNK,
        TRUNCATED,
    };

    SizeCheckResult does_dcp_packet_size_match(uint16_t n) const;

    void disable();
    void enable(uint8_t ttl, uint16_t serial);
    void enable(uint8_t command, uint8_t ttl, uint16_t serial, uint16_t payload_size);
    void refresh(uint16_t serial);
    void enter_exception();
};

/*!
 * Base class for exceptions thrown for exceptional situations in transaction
 * processing.
 */
class ProtocolException: public std::runtime_error
{
  protected:
    explicit ProtocolException(const char *m): std::runtime_error(m) {}

  public:
    virtual ~ProtocolException() {}
};

/*!
 * Exception: Packet collision.
 */
class CollisionException: public ProtocolException
{
  public:
    std::unique_ptr<Transaction> transaction_;

    explicit CollisionException(std::unique_ptr<Transaction> t):
        ProtocolException("DCP collision"),
        transaction_(std::move(t))
    {}
};

/*!
 * Exception: Out-ouf-order ACK processing.
 */
class OOOAckException: public ProtocolException
{
  public:
    const uint16_t serial_;

    explicit OOOAckException(uint16_t serial):
        ProtocolException("out-of-order ACK"),
        serial_(serial)
    {}
};

/*!
 * Exception: Out-ouf-order NACK processing.
 */
class OOONackException: public ProtocolException
{
  public:
    const uint8_t ttl_;
    const uint16_t serial_;

    explicit OOONackException(uint16_t serial, uint8_t ttl):
        ProtocolException("out-of-order NACK"),
        ttl_(ttl),
        serial_(serial)
    {}
};

/*!
 * A single DCP transaction.
 */
class Transaction
{
  public:
    enum class Pinned
    {
        NOT_PINNED,
        INTENDED_AS_PREALLOCATED,
    };

  private:
    enum class State
    {
        ERROR,                /*!< Error state, cannot process */
        SLAVE_PREPARE__INIT,  /*!< Read command from slave */
        PUSH_TO_SLAVE__INIT,  /*!< Prepare answer buffer */
        MASTER_PREPARE__INIT, /*!< Filling command buffer */
        SLAVE_READ_DATA,      /*!< Read data from slave */
        SLAVE_PREPARE_APPEND, /*!< Read next fragment */
        SLAVE_READ_APPEND,    /*!< Read more data from slave (big
                               *   chunk in multiple packets) */
        SLAVE_PREPARE_ANSWER, /*!< Fill answer buffer */
        SLAVE_PROCESS_WRITE,  /*!< Process data written by slave */
        SEND_TO_SLAVE,        /*!< Send (any) data to slave */
        SEND_TO_SLAVE_ACKED,  /*!< Data was acknowledged by slave */
        SEND_TO_SLAVE_FAILED, /*!< Final NACK received, abort */
        DCPSYNC_WAIT_FOR_ACK, /*!< Wait for DCPSYNC ack from slave */
    };

    enum class LogWrite
    {
        SINGLE,
        INCOMPLETE,
        CONTINUED,
        COMPLETED,
    };

    const Pinned is_pinned_;
    const Channel channel_;

    State state_;

    TXSync tx_sync_;

    std::array<uint8_t, DCP_HEADER_SIZE> request_header_;
    uint8_t command_;

    const Regs::Register *reg_;

    std::vector<uint8_t> payload_;
    size_t current_fragment_offset_;

    Queue &queue_;

  public:
    Transaction(const Transaction &) = delete;
    Transaction &operator=(const Transaction &) = delete;

  private:
    explicit Transaction(Queue &queue, InitialType init_type,
                         const Regs::Register *const reg,
                         Channel channel, Pinned mark_as_pinned);

  public:
    static std::unique_ptr<Transaction>
    new_for_queue(Queue &queue, InitialType init_type, Channel channel,
                  Pinned mark_as_pinned)
    {
        /* no std::make_unique because the ctor is private */
        return std::unique_ptr<Transaction>(
                            new Transaction(queue, init_type, nullptr,
                                            channel, mark_as_pinned));
    }

    static std::unique_ptr<Transaction>
    new_for_queue(Queue &queue, InitialType init_type,
                  const Regs::Register &reg, Channel channel)
    {
        /* no std::make_unique because the ctor is private */
        return std::unique_ptr<Transaction>(
                            new Transaction(queue, init_type, &reg,
                                            channel, Pinned::NOT_PINNED));
    }

    /*!
     * Free payload and reinitialize structure.
     */
    void reset_for_slave();

    /*!
     * Whether or not to free the transaction object.
     *
     * This flag is only advisory and is used by client code for managing
     * pre-allocated objects.
     */
    bool is_pinned() const { return is_pinned_ != Pinned::NOT_PINNED; }

    /*!
     * Return communication channel used by this transaction.
     */
    Channel get_channel() const { return channel_; }

    /*!
     * Return DCPSYNC serial number for this transaction.
     */
    uint16_t get_dcpsync_serial() const { return tx_sync_.get_serial(); }

    /*!
     * Process the transaction.
     *
     * This function can throw exceptions of type
     * #TransactionQueue::ProtocolException, which must be handled by the
     * caller. This mechnism is required because this function only operates on
     * a single transaction, not a queue of transactions.
     *
     * In case of a collision, a new transaction will have been created and
     * passed as data with the exception object. That new transaction takes
     * priority over the current transaction and must be processed next;
     * processing of this transaction must be deferred until after the new
     * transaction has finished.
     *
     * \param from_slave_fd
     *     Where to read data sent by slave from.
     * \param to_slave_fd
     *     Where to write data to be sent to slave to.
     * \param dump_sent_data_flags
     *     Whether or not to log DCP data sent to slave, and how.
     *     See \c TransactionQueue::DUMP_SENT_ flag definitions (e.g.,
     *     #TransactionQueue::DUMP_SENT_DCP_HEADER).
     *
     * \retval #TransactionQueue::ProcessResult::IN_PROGRESS
     *     The transaction needs more processing,
     *     #TransactionQueue::Transaction::process() must be called again.
     *     Check the result of
     *     #TransactionQueue::Transaction::is_input_required() before actually
     *     doing this.
     * \retval #TransactionQueue::ProcessResult::PUSH_BACK
     *     The transaction has been recycled (ACK received, answer to read
     *     command should be sent) and should be reinserted at the end of the
     *     queue.
     * \retval #TransactionQueue::ProcessResult::FINISHED
     *     The transaction has been processed without any errors and may be
     *     freed.
     * \retval #TransactionQueue::ProcessResult::ERROR
     *     The transaction has finished with an error and may be freed.
     * \throw CollisionException
     *     Collision detected.
     * \throw OOOAckException
     *     Out-of-order ACK received.
     * \throw OOONackException
     *     Out-of-order NACK received.
     */
    ProcessResult process(int from_slave_fd, int to_slave_fd, DumpFlags dump_sent_data_flags);

    /*!
     * Inject ACK into transaction.
     *
     * For out-of-order ACK handling.
     */
    ProcessResult process_out_of_order_ack(const OOOAckException &e);

    /*!
     * Inject NACK into transaction.
     *
     * For out-of-order NACK handling.
     */
    ProcessResult process_out_of_order_nack(const OOONackException &e);

    /*!
     * Whether or not further input is required, depending on current state.
     */
    bool is_input_required() const;

    /*!\internal
     * \brief
     * Return maximum size of data for the register bound to this transaction.
     *
     * Note that it is a programming error to call this function if there is no
     * register bound yet or if the register has unbounded, dynamic size.
     *
     * \note
     *     Used internally by TransactionQueue::fragments_from_data().
     */
    uint16_t get_max_data_size() const;

    /*!\internal
     * \brief
     * Copy given data to this transaction's payload buffer.
     *
     * \note
     *     Used internally by TransactionQueue::fragments_from_data().
     */
    void set_payload(const uint8_t *src, size_t length);

  private:
    void init(InitialType init_type, const Regs::Register *reg, bool is_reinit);
    void bind_to_register(const Regs::Register &reg, uint8_t command);
    void refresh_as_master_transaction();
    void allocate_payload_buffer();
    bool fill_request_header(const int fd);
    bool fill_payload_buffer(const int fd, bool append);
    bool do_read_register();
    size_t get_current_fragment_size() const;
    size_t get_remaining_fragment_size() const { return payload_.size() - current_fragment_offset_; }
    bool is_last_fragment() const { return get_remaining_fragment_size() <= DCP_PACKET_MAX_PAYLOAD_SIZE; }
    void skip_transaction_payload(const int fd);

    bool process_ack(uint16_t serial);
    bool process_nack(uint16_t serial, uint8_t ttl);

    void log_register_write(LogWrite what) const;
    void log_dcp_data(DumpFlags flags, const uint8_t *sync_header, const size_t fragsize) const;
};

/*!
 * A queue of #TransactionQueue::Transaction objects.
 */
class Queue
{
  private:
    std::deque<std::unique_ptr<Transaction>> transactions_;
    uint16_t next_dcpsync_serial_;

  public:
    Queue(const Queue &) = delete;
    Queue &operator=(const Queue &) = delete;

    explicit Queue():
        next_dcpsync_serial_(0)
    {}

    uint16_t mk_dcpsync_serial();

    bool empty() const { return transactions_.empty(); }

    bool append(std::unique_ptr<Transaction> t);
    bool append(std::deque<std::unique_ptr<Transaction>> &&ts);
    bool prepend(std::unique_ptr<Transaction> t);

    /*!
     * Remove first element from queue.
     */
    std::unique_ptr<Transaction> pop();

    /*!
     * Apply function to transaction matching the given DCPSYNC serial.
     */
    ProcessResult apply_to_dcpsync_serial(uint16_t serial,
                                          const std::function<ProcessResult(Transaction &)> &fn);
};

std::deque<std::unique_ptr<Transaction>>
fragments_from_data(Queue &queue, const uint8_t *data, size_t length,
                    uint8_t register_address, Channel channel);

bool push_register_to_slave(Queue &queue, uint8_t register_address,
                            Channel channel);

}

/*!@}*/

#endif /* !TRANSACTIONS_H */
