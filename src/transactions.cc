/*
 * Copyright (C) 2015, 2016, 2018--2021  T+A elektroakustik GmbH & Co. KG
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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "transactions.hh"
#include "registers.hh"
#include "dcpdefs.h"
#include "messages.h"
#include "hexdump.h"

#include <algorithm>

enum class DCPSYNCPacketType
{
    INVALID,
    IO_ERROR,
    COMMAND,
    ACK,
    NACK,
};

enum class ReadToBufferResult
{
    OK,
    INCOMPLETE,
    IO_ERROR,
};

#define REGISTER_FORMAT_STRING  "%d [%s]"

void TransactionQueue::Transaction::log_register_write(LogWrite what) const
{
    if(reg_->address_ == 121 && !msg_is_verbose(MESSAGE_LEVEL_DEBUG))
        return;

    const char *suffix = "";

    switch(what)
    {
      case LogWrite::SINGLE:
        break;

      case LogWrite::INCOMPLETE:
        suffix = " (incomplete)";
        break;

      case LogWrite::CONTINUED:
        suffix = " (continued)";
        break;

      case LogWrite::COMPLETED:
        suffix = " (complete)";
        break;
    }

    msg_vinfo(MESSAGE_LEVEL_DIAG,
              "RegIO W: " REGISTER_FORMAT_STRING ", %zu bytes%s",
              reg_->address_, reg_->name_.c_str(),
              command_ == DCP_COMMAND_WRITE_REGISTER ? 2 : payload_.size(),
              suffix);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
uint16_t TransactionQueue::Queue::mk_dcpsync_serial()
{
    if(next_dcpsync_serial_ < DCPSYNC_MASTER_SERIAL_MIN ||
       next_dcpsync_serial_ > DCPSYNC_MASTER_SERIAL_MAX)
    {
        next_dcpsync_serial_ = DCPSYNC_MASTER_SERIAL_MIN;
    }

    return next_dcpsync_serial_++;
}
#pragma GCC diagnostic pop

TransactionQueue::TXSync::TXSync(Queue &queue, InitialType init_type,
                                 uint8_t command, Channel channel)
{
    switch(channel)
    {
      case TransactionQueue::Channel::SPI:
        switch(init_type)
        {
          case TransactionQueue::InitialType::MASTER_FOR_DRCPD_DATA:
          case TransactionQueue::InitialType::MASTER_FOR_REGISTER:
            enable(UINT8_MAX, queue.mk_dcpsync_serial());
            break;

          case TransactionQueue::InitialType::SLAVE_BY_SLAVE:
            enable(command, UINT8_MAX, DCPSYNC_SLAVE_SERIAL_INVALID, 0);
            break;
        }

        break;

      case TransactionQueue::Channel::INET:
        disable();
        break;
    }
}

void TransactionQueue::TXSync::disable()
{
    is_enabled_ = false;
    original_command_ = 0;
    ttl_ = 0;
    serial_ = 0;
    remaining_payload_size_ = 0;
}

void TransactionQueue::TXSync::enable(uint8_t ttl, uint16_t serial)
{
    is_enabled_ = true;
    original_command_ = 0;
    ttl_ = ttl;
    serial_ = serial;
    remaining_payload_size_ = 0;
}

void TransactionQueue::TXSync::enable(uint8_t command, uint8_t ttl,
                                      uint16_t serial, uint16_t payload_size)
{
    is_enabled_ = true;
    original_command_ = command;
    ttl_ = ttl;
    serial_ = serial;
    remaining_payload_size_ = payload_size;
}

void TransactionQueue::TXSync::refresh(uint16_t serial)
{
    serial_ = serial;
    ttl_ = UINT8_MAX;
}

void TransactionQueue::TXSync::enter_exception()
{
    original_command_ = 0x00;
    serial_ = DCPSYNC_SLAVE_SERIAL_INVALID;
}

void TransactionQueue::Transaction::refresh_as_master_transaction()
{
    if(tx_sync_.is_enabled())
        tx_sync_.refresh(queue_.mk_dcpsync_serial());
}

void TransactionQueue::Transaction::init(InitialType init_type,
                                         const Regs::Register *reg,
                                         bool is_reinit)
{
    switch(init_type)
    {
      case TransactionQueue::InitialType::MASTER_FOR_DRCPD_DATA:
        /* plain master transaction initiated by DRCPD */
        state_ = State::MASTER_PREPARE__INIT;
        break;

      case TransactionQueue::InitialType::MASTER_FOR_REGISTER:
        /* plain master transaction initiated by us for register data */
        state_ = State::PUSH_TO_SLAVE__INIT;
        break;

      case TransactionQueue::InitialType::SLAVE_BY_SLAVE:
        /* plain slave transaction initiated by slave device */
        state_ = State::SLAVE_PREPARE__INIT;
        break;
    }

    if(is_reinit)
    {
        if(channel_ == TransactionQueue::Channel::SPI)
        {
            switch(init_type)
            {
              case TransactionQueue::InitialType::MASTER_FOR_DRCPD_DATA:
              case TransactionQueue::InitialType::MASTER_FOR_REGISTER:
                /*see also #transaction_convert_to_master()  */
                tx_sync_.enable(UINT8_MAX, queue_.mk_dcpsync_serial());
                break;

              case TransactionQueue::InitialType::SLAVE_BY_SLAVE:
                tx_sync_.enable(UINT8_MAX, DCPSYNC_SLAVE_SERIAL_INVALID);
                break;
            }
        }
        else
            tx_sync_.disable();
    }

    request_header_.fill(UINT8_MAX);
    command_ = DCP_COMMAND_WRITE_REGISTER;
    reg_ = reg;
    current_fragment_offset_ = 0;

    if(is_reinit)
    {
        payload_.clear();
        payload_.shrink_to_fit();
    }
}

TransactionQueue::Transaction::Transaction(Queue &queue, InitialType init_type,
                                           const Regs::Register *const reg,
                                           Channel channel, Pinned mark_as_pinned):
    is_pinned_(mark_as_pinned),
    channel_(channel),
    tx_sync_(queue, init_type, 'c', channel),
    queue_(queue)
{
    init(init_type, reg, false);

    if(reg != nullptr)
    {
        bind_to_register(*reg, DCP_COMMAND_MULTI_WRITE_REGISTER);

        /* fill in request header */
        request_header_[0] = command_;
        request_header_[1] = reg->address_;
        dcp_put_header_data(&request_header_[DCP_HEADER_DATA_OFFSET], 0);
    }
}

void TransactionQueue::Transaction::reset_for_slave()
{
    init(TransactionQueue::InitialType::SLAVE_BY_SLAVE, nullptr, true);
}

static const Regs::Register *
lookup_register_for_transaction(uint8_t register_address,
                                bool master_not_slave)
{
    const auto *reg = Regs::lookup(register_address);

    if(reg == nullptr)
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
void TransactionQueue::Transaction::bind_to_register(const Regs::Register &reg,
                                                     uint8_t command)
{
    reg_ = &reg;
    command_ = command;
}

bool TransactionQueue::Queue::append(std::unique_ptr<Transaction> t)
{
    if(t == nullptr)
        return false;

    transactions_.emplace_back(std::move(t));
    return true;
}

bool TransactionQueue::Queue::prepend(std::unique_ptr<Transaction> t)
{
    if(t == nullptr)
        return false;

    transactions_.emplace_front(std::move(t));
    return true;
}

bool TransactionQueue::Queue::append(std::deque<std::unique_ptr<Transaction>> &&ts)
{
    if(ts.empty())
        return false;

    while(!ts.empty())
    {
        transactions_.emplace_back(std::move(ts.front()));
        ts.pop_front();
    }

    return true;
}

std::unique_ptr<TransactionQueue::Transaction> TransactionQueue::Queue::pop()
{
    if(transactions_.empty())
        return nullptr;

    auto result = std::move(transactions_.front());
    transactions_.pop_front();
    return result;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
static inline bool is_serial_out_of_range(const uint16_t serial)
{
    return
        !((serial >= DCPSYNC_MASTER_SERIAL_MIN && serial <= DCPSYNC_MASTER_SERIAL_MAX) ||
          (serial >= DCPSYNC_SLAVE_SERIAL_MIN && serial <= DCPSYNC_SLAVE_SERIAL_MAX));
}
#pragma GCC diagnostic pop

TransactionQueue::ProcessResult
TransactionQueue::Queue::apply_to_dcpsync_serial(uint16_t serial,
                                                 const std::function<ProcessResult(Transaction &)> &fn)
{
    if(is_serial_out_of_range(serial))
    {
        BUG("Tried to find transaction with invalid serial 0x%04x", serial);
        return ProcessResult::ERROR;
    }

    const auto it =
        std::find_if(transactions_.begin(), transactions_.end(),
                [serial] (const std::unique_ptr<Transaction> &t)
                {
                    return t->get_dcpsync_serial() == serial;
                });

    if(it == transactions_.end())
        return ProcessResult::ERROR;

    log_assert(*it != nullptr);

    return fn(**it);
}

static ReadToBufferResult read_to_buffer(uint8_t *dest, size_t count,
                                         int fd, const char *what)
{
    unsigned int retry_counter = 0;

    while(count > 0)
    {
        ssize_t len = os_read(fd, dest, count);

        if(len == 0)
        {
            msg_info("End of data while reading DCP packet for %s from fd %d, "
                     "missing %zu bytes", what, fd, count);
            break;
        }

        if(len < 0)
        {
            if(errno == EAGAIN && retry_counter < 40)
            {
                ++retry_counter;

                /* we retry reading up to 40 times with a delay of 25 ms in
                 * between, so that's at least one second, but not much more */
                static const struct timespec t = {0, 25L * 1000L * 1000L};
                os_nanosleep(&t);

                continue;
            }

            if(errno == EINTR)
                continue;

            msg_error(errno, LOG_ERR, "Failed reading DCP %s from fd %d", what, fd);

            return ReadToBufferResult::IO_ERROR;
        }

        retry_counter = 0;

        dest += len;
        count -= len;
    }

    return count == 0 ? ReadToBufferResult::OK : ReadToBufferResult::INCOMPLETE;
}

void TransactionQueue::Transaction::skip_transaction_payload(const int fd)
{
    std::array<uint8_t, 64> dummy;
    uint16_t skipped_bytes;

    uint16_t count =
        tx_sync_.is_enabled()
        ? tx_sync_.get_remaining_payload_size()
        : dcp_read_header_data(&request_header_[DCP_HEADER_DATA_OFFSET]);

    for(/* nothing */; count > 0; count -= skipped_bytes)
    {
        skipped_bytes = (count >= dummy.size()) ? dummy.size() : count;

        switch(read_to_buffer(dummy.data(), skipped_bytes, fd,
                              "unprocessed payload"))
        {
          case ReadToBufferResult::OK:
            break;

          case ReadToBufferResult::IO_ERROR:
          case ReadToBufferResult::INCOMPLETE:
            count = 0;
            break;
        }
    }

    tx_sync_.drop_payload();
}

static void fill_dcpsync_header_generic(std::array<uint8_t, DCPSYNC_HEADER_SIZE> &dcpsync_header,
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

static uint16_t extract_dcpsync_serial(const std::array<uint8_t, DCPSYNC_HEADER_SIZE> &dcpsync_header)
{
    return (dcpsync_header[2] << 8) | dcpsync_header[3];
}

static uint16_t extract_dcpsync_data_size(const std::array<uint8_t, DCPSYNC_HEADER_SIZE> &dcpsync_header)
{
    return (dcpsync_header[4] << 8) | dcpsync_header[5];
}

static DCPSYNCPacketType read_dcpsync_header(TransactionQueue::TXSync &ts,
                                             const int fd)
{
    std::array<uint8_t, DCPSYNC_HEADER_SIZE> buffer {};

    if(fd < 0)
    {
        ts.disable();
        return DCPSYNCPacketType::COMMAND;
    }

    switch(read_to_buffer(buffer.data(), buffer.size(), fd, "sync"))
    {
      case ReadToBufferResult::OK:
        break;

      case ReadToBufferResult::INCOMPLETE:
        ts.disable();
        return DCPSYNCPacketType::INVALID;

      case ReadToBufferResult::IO_ERROR:
        ts.disable();
        return DCPSYNCPacketType::IO_ERROR;
    }

    ts.enable(buffer[0], buffer[1], extract_dcpsync_serial(buffer),
              extract_dcpsync_data_size(buffer));

    static const char unexpected_size_error[] =
        "Skip packet 0x%02x/0x%04x of unexpected size %u";
    static const char unknown_dcpsync_command_error[] =
        "Unknown DCPSYNC command 0x%02x, skipping packet 0x%04x of size %u";

    const char *error_format_string;

    if(ts.get_command() == 'c')
    {
        if(ts.get_remaining_payload_size() >= DCP_HEADER_SIZE)
            return DCPSYNCPacketType::COMMAND;

        if(ts.get_ttl() > 0)
            BUG("Got DCP packet with positive TTL");

        error_format_string = unexpected_size_error;
    }
    else if(ts.get_command() == 'a')
    {
        if(ts.get_remaining_payload_size() == 0)
            return DCPSYNCPacketType::ACK;

        if(ts.get_ttl() > 0)
            BUG("Got ACK with positive TTL");

        error_format_string = unexpected_size_error;
    }
    else if(ts.get_command() == 'n')
    {
        if(ts.get_remaining_payload_size() == 0)
            return DCPSYNCPacketType::NACK;

        error_format_string = unexpected_size_error;
    }
    else
        error_format_string = unknown_dcpsync_command_error;

    msg_error(0, LOG_ERR, error_format_string, ts.get_command(),
              ts.get_serial(), ts.get_remaining_payload_size());

    return DCPSYNCPacketType::INVALID;
}

bool TransactionQueue::TXSync::consumed_payload(size_t n)
{
    if(!is_enabled_)
        return false;

    remaining_payload_size_ -= n;
    return true;
}

bool TransactionQueue::Transaction::fill_request_header(const int fd)
{
    switch(read_to_buffer(request_header_.data(), request_header_.size(), fd, "header"))
    {
      case ReadToBufferResult::OK:
        tx_sync_.consumed_payload(request_header_.size());
        break;

      case ReadToBufferResult::INCOMPLETE:
      case ReadToBufferResult::IO_ERROR:
        return false;
    }

    const bool is_header_valid = ((request_header_[0] & 0xf0) == 0);
    const Regs::Register *reg;

    if(!is_header_valid)
    {
        if(tx_sync_.is_enabled())
            skip_transaction_payload(fd);

        goto error_invalid_header;
    }

    reg = lookup_register_for_transaction(request_header_[1], false);

    if(reg == nullptr)
    {
        skip_transaction_payload(fd);
        return false;
    }

    bind_to_register(*reg, request_header_[0] & 0x0f);

    switch(command_)
    {
      case DCP_COMMAND_READ_REGISTER:
        if(request_header_[DCP_HEADER_DATA_OFFSET] != 0 ||
           request_header_[DCP_HEADER_DATA_OFFSET + 1] != 0)
            break;

        /* fall-through */

      case DCP_COMMAND_MULTI_WRITE_REGISTER:
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
              request_header_[0], request_header_[1],
              request_header_[2], request_header_[3]);
    return false;
}

TransactionQueue::TXSync::SizeCheckResult
TransactionQueue::TXSync::does_dcp_packet_size_match(uint16_t n) const
{
    if(!is_enabled_)
        return SizeCheckResult::NOT_ENABLED;

    if(n == remaining_payload_size_)
        return SizeCheckResult::MATCH;

    return (n < remaining_payload_size_)
        ? SizeCheckResult::TRAILING_JUNK
        : SizeCheckResult::TRUNCATED;
}

bool TransactionQueue::Transaction::fill_payload_buffer(const int fd, bool append)
{
    const uint16_t size =
        dcp_read_header_data(&request_header_[DCP_HEADER_DATA_OFFSET]);

    log_assert(command_ == DCP_COMMAND_MULTI_WRITE_REGISTER);

    if(size == 0)
        return true;

    const size_t offset = append ? payload_.size() : 0;

    switch(tx_sync_.does_dcp_packet_size_match(size))
    {
      case TXSync::SizeCheckResult::NOT_ENABLED:
      case TXSync::SizeCheckResult::MATCH:
        break;

      case TXSync::SizeCheckResult::TRAILING_JUNK:
        msg_error(0, LOG_WARNING, "DCP packet size %u smaller than "
                  "DCPSYNC remaining payload size %u (ignored)",
                  size, tx_sync_.get_remaining_payload_size());
        break;

      case TXSync::SizeCheckResult::TRUNCATED:
        msg_error(EINVAL, LOG_ERR, "DCP packet size %u too large to fit "
                  "into remaining DCPSYNC payload of size %u",
                  size, tx_sync_.get_remaining_payload_size());
        skip_transaction_payload(fd);
        return false;
    }

    if(append)
        log_assert(!payload_.empty());
    else
    {
        log_assert(payload_.empty());

        if(offset > 0)
            msg_error(0, LOG_ERR,
                      "Expecting at most %u bytes payload for register %u, "
                      "received %zu bytes",
                      size, reg_->address_, offset + size);
    }

    const auto old_size = payload_.size();
    payload_.resize(old_size + size);

    switch(read_to_buffer(payload_.data() + old_size, size, fd, "payload"))
    {
      case ReadToBufferResult::OK:
        break;

      case ReadToBufferResult::INCOMPLETE:
      case ReadToBufferResult::IO_ERROR:
        payload_.resize(old_size);
        return false;
    }

    if(tx_sync_.consumed_payload(size))
        skip_transaction_payload(fd);

    return true;
}

void TransactionQueue::Transaction::allocate_payload_buffer()
{
    if(reg_->is_static_size())
        payload_.reserve(reg_->max_data_size_);
    else
        payload_.clear();
}

bool TransactionQueue::Transaction::do_read_register()
{
    if(reg_->is_static_size())
    {
        size_t n;
        const auto old_size = payload_.size();

        try
        {
            payload_.resize(reg_->max_data_size_);
            n = reg_->read(payload_.data(), payload_.size());
        }
        catch(const Regs::no_handler &e)
        {
            msg_error(ENOSYS, LOG_ERR,
                      "No read handler defined for register "
                      REGISTER_FORMAT_STRING,
                      reg_->address_, reg_->name_.c_str());
            payload_.resize(old_size);
            return false;
        }
        catch(const Regs::io_error &e)
        {
            msg_error(0, LOG_ERR,
                      "RegIO R: FAILED READING " REGISTER_FORMAT_STRING " (%zd)",
                      reg_->address_, reg_->name_.c_str(), e.result());
            payload_.resize(old_size);
            return false;
        }

        if(reg_->address_ != 120 || msg_is_verbose(MESSAGE_LEVEL_DEBUG))
            msg_vinfo(MESSAGE_LEVEL_DIAG,
                      "RegIO R: " REGISTER_FORMAT_STRING ", %zu bytes",
                      reg_->address_, reg_->name_.c_str(), n);

        payload_.resize(n);
        return true;
    }
    else
    {
        try
        {
            reg_->read(payload_);
        }
        catch(const Regs::no_handler &e)
        {
            msg_error(ENOSYS, LOG_ERR,
                      "No dynamic read handler defined for register "
                      REGISTER_FORMAT_STRING,
                      reg_->address_, reg_->name_.c_str());
            return false;
        }
        catch(const Regs::io_error &e)
        {
            msg_error(0, LOG_ERR,
                      "RegIO R: FAILED READING " REGISTER_FORMAT_STRING,
                      reg_->address_, reg_->name_.c_str());
            return false;
        }

        msg_vinfo(MESSAGE_LEVEL_DIAG,
                  "RegIO R: " REGISTER_FORMAT_STRING ", %zu bytes",
                  reg_->address_, reg_->name_.c_str(), payload_.size());

        return true;
    }
}

size_t TransactionQueue::Transaction::get_current_fragment_size() const
{
    log_assert((current_fragment_offset_ < payload_.size()) ||
               (current_fragment_offset_ == 0 && payload_.size() == 0));

    const size_t temp = get_remaining_fragment_size();

    if(temp <= DCP_PACKET_MAX_PAYLOAD_SIZE)
        return temp;
    else
        return DCP_PACKET_MAX_PAYLOAD_SIZE;
}

bool TransactionQueue::Transaction::process_ack(uint16_t serial)
{
    if(serial != tx_sync_.get_serial())
        return false;

    state_ = State::SEND_TO_SLAVE_ACKED;

    return true;
}

void TransactionQueue::TXSync::process_nack()
{
    ttl_ = 0;
}

void TransactionQueue::TXSync::process_nack(uint16_t serial, uint8_t ttl)
{
    ttl_ = ttl;
    serial_ = serial;
}

bool TransactionQueue::Transaction::process_nack(uint16_t serial, uint8_t ttl)
{
    if(serial != tx_sync_.get_serial())
    {
        msg_vinfo(MESSAGE_LEVEL_TRACE,
                  "Got NACK[%u] for 0x%04x while waiting for 0x%04x ACK",
                  ttl, serial, tx_sync_.get_serial());
        return false;
    }

    if(ttl > 0)
    {
        tx_sync_.process_nack(queue_.mk_dcpsync_serial(), ttl);
        state_ = State::SEND_TO_SLAVE;

        msg_vinfo(MESSAGE_LEVEL_TRACE,
                  "Got NACK[%u] for 0x%04x, resending packet as 0x%04x",
                  ttl, serial, tx_sync_.get_serial());
    }
    else
    {
        tx_sync_.process_nack();
        state_ = State::SEND_TO_SLAVE_FAILED;

        msg_vinfo(MESSAGE_LEVEL_TRACE,
                  "Got final NACK for 0x%04x, aborting transaction", serial);
    }

    return true;
}

//
// Uncomment for white-listing registers in log_dcp_data().
//
// #include <set>

void TransactionQueue::Transaction::log_dcp_data(DumpFlags flags,
                                                 const uint8_t *sync_header,
                                                 const size_t fragsize) const
{
    if((flags & TransactionQueue::DUMP_SENT_MASK) == TransactionQueue::DUMP_SENT_NONE)
        return;

    //
    // Uncomment and edit for white-listing registers.
    //
    /*
    static const std::set<uint8_t> white_list { 71, 75, 76 };
    if(white_list.find(reg_->address_) == white_list.end())
        return;
    */

    if((flags & TransactionQueue::DUMP_SENT_MERGE_MASK) == TransactionQueue::DUMP_SENT_MERGE_NONE)
    {
        if(tx_sync_.is_enabled() && (flags & TransactionQueue::DUMP_SENT_DCPSYNC) != 0)
            hexdump_to_log(MESSAGE_LEVEL_IMPORTANT,
                           sync_header, DCPSYNC_HEADER_SIZE,
                           "DCPSYNC header");

        if((flags & TransactionQueue::DUMP_SENT_DCP_HEADER) != 0)
            hexdump_to_log(MESSAGE_LEVEL_IMPORTANT,
                           request_header_.data(), request_header_.size(),
                           "DCP header");

        if((flags & TransactionQueue::DUMP_SENT_DCP_PAYLOAD) != 0)
            hexdump_to_log(MESSAGE_LEVEL_IMPORTANT,
                           &payload_.data()[current_fragment_offset_],
                           fragsize, "DCP payload");
    }
    else
    {
        std::vector<uint8_t> merged_buffer;
        merged_buffer.reserve(DCPSYNC_HEADER_SIZE + request_header_.size() + fragsize);

        if(tx_sync_.is_enabled() && (flags & TransactionQueue::DUMP_SENT_DCPSYNC) != 0)
        {
            if((flags & TransactionQueue::DUMP_SENT_MERGE_MASK) == TransactionQueue::DUMP_SENT_MERGE_ALL)
                std::copy(sync_header, sync_header + DCPSYNC_HEADER_SIZE,
                          std::back_inserter(merged_buffer));
            else
            {
                /* separate dump of DCPSYNC header requested and possible */
                hexdump_to_log(MESSAGE_LEVEL_IMPORTANT,
                               sync_header, DCPSYNC_HEADER_SIZE,
                               "DCPSYNC header");
            }
        }

        if((flags & TransactionQueue::DUMP_SENT_DCP_HEADER) != 0)
            std::copy(request_header_.begin(), request_header_.end(),
                      std::back_inserter(merged_buffer));

        if((flags & TransactionQueue::DUMP_SENT_DCP_PAYLOAD) != 0)
        {
            const auto from(std::next(payload_.begin(), current_fragment_offset_));
            std::copy(from, std::next(from, fragsize), std::back_inserter(merged_buffer));
        }

        std::string header("Sent register ");
        header += std::to_string(int(reg_->address_));
        header += " (";
        header += reg_->name_;
        header += ") to DCP peer";

        hexdump_to_log(MESSAGE_LEVEL_IMPORTANT,
                       merged_buffer.data(), merged_buffer.size(),
                       header.c_str());
    }
}

TransactionQueue::ProcessResult
TransactionQueue::Transaction::process(int from_slave_fd, int to_slave_fd,
                                       DumpFlags dump_sent_data_flags)
{
    switch(state_)
    {
      case State::ERROR:
        break;

      case State::SLAVE_PREPARE__INIT:
      case State::SLAVE_PREPARE_APPEND:
        {
            bool failed = false;

            switch(read_dcpsync_header(tx_sync_,
                                       channel_ == Channel::SPI ? from_slave_fd : -1))
            {
              case DCPSYNCPacketType::INVALID:
                skip_transaction_payload(from_slave_fd);

                /* fall-through */

              case DCPSYNCPacketType::IO_ERROR:
                failed = true;
                break;

              case DCPSYNCPacketType::COMMAND:
                failed = !fill_request_header(from_slave_fd);
                break;

              case DCPSYNCPacketType::ACK:
                {
                    msg_vinfo(MESSAGE_LEVEL_TRACE,
                              "Got ACK for 0x%04x while waiting for new command packet",
                              tx_sync_.get_serial());

                    const auto serial(tx_sync_.get_serial());

                    tx_sync_.enter_exception();

                    throw OOOAckException(serial);
                }

              case DCPSYNCPacketType::NACK:
                {
                    msg_vinfo(MESSAGE_LEVEL_TRACE,
                              "Got NACK[%u] for 0x%04x while waiting for new "
                              "command packet",
                              tx_sync_.get_ttl(), tx_sync_.get_serial());

                    const auto serial(tx_sync_.get_serial());
                    const auto ttl(tx_sync_.get_ttl());

                    tx_sync_.enter_exception();

                    throw OOONackException(serial, ttl);
                }
            }

            if(!failed && state_ == State::SLAVE_PREPARE_APPEND)
            {
                state_ =
                    (command_ == DCP_COMMAND_MULTI_WRITE_REGISTER &&
                     request_header_[DCP_HEADER_DATA_OFFSET + 0] == 0 &&
                     request_header_[DCP_HEADER_DATA_OFFSET + 1] == 0)
                    ? State::SLAVE_PROCESS_WRITE
                    : State::SLAVE_READ_APPEND;

                return ProcessResult::IN_PROGRESS;
            }

            if(failed)
                break;
            else
                state_ = State::SLAVE_READ_DATA;
        }

        /* fall-through */

      case State::SLAVE_READ_DATA:
        allocate_payload_buffer();

        log_assert(command_ == DCP_COMMAND_MULTI_WRITE_REGISTER ||
                   command_ == DCP_COMMAND_READ_REGISTER);

        if(command_ == DCP_COMMAND_MULTI_WRITE_REGISTER)
        {
            if(!fill_payload_buffer(from_slave_fd, false))
                break;

            state_ = payload_.size() < DCP_PACKET_MAX_PAYLOAD_SIZE
                ? State::SLAVE_PROCESS_WRITE
                : State::SLAVE_PREPARE_APPEND;

            if(state_ == State::SLAVE_PREPARE_APPEND)
                log_register_write(LogWrite::INCOMPLETE);

            return ProcessResult::IN_PROGRESS;
        }
        else
        {
            refresh_as_master_transaction();
            state_ = State::SLAVE_PREPARE_ANSWER;

            return ProcessResult::PUSH_BACK;
        }

      case State::SLAVE_READ_APPEND:
        {
            log_assert(command_ == DCP_COMMAND_MULTI_WRITE_REGISTER);
            log_assert(!payload_.empty());

            const size_t previous_pos = payload_.size();

            if(!fill_payload_buffer(from_slave_fd, true))
                break;

            state_ =
                (payload_.size() - previous_pos) < DCP_PACKET_MAX_PAYLOAD_SIZE
                ? State::SLAVE_PROCESS_WRITE
                : State::SLAVE_PREPARE_APPEND;

            if(state_ == State::SLAVE_PREPARE_APPEND)
                log_register_write(LogWrite::CONTINUED);

            return ProcessResult::IN_PROGRESS;
        }

      case State::PUSH_TO_SLAVE__INIT:
        allocate_payload_buffer();

        log_assert(command_ == DCP_COMMAND_MULTI_WRITE_REGISTER);

        state_ = State::SLAVE_PREPARE_ANSWER;

        /* fall-through */

      case State::SLAVE_PREPARE_ANSWER:
        if(!do_read_register())
            break;

        if(command_ == DCP_COMMAND_READ_REGISTER)
            request_header_[0] = DCP_COMMAND_MULTI_READ_REGISTER;

        state_ = State::SEND_TO_SLAVE;

        return ProcessResult::IN_PROGRESS;

      case State::SLAVE_PROCESS_WRITE:
        try
        {
            if(command_ == DCP_COMMAND_WRITE_REGISTER)
                reg_->write(&request_header_[DCP_HEADER_DATA_OFFSET], 2);
            else
                reg_->write(payload_.data(), payload_.size());
        }
        catch(const Regs::no_handler &ex)
        {
            msg_error(ENOSYS, LOG_ERR,
                      "No write handler defined for register "
                      REGISTER_FORMAT_STRING,
                      reg_->address_, reg_->name_.c_str());
            break;
        }
        catch(const Regs::io_error &ex)
        {
            msg_error(0, LOG_ERR,
                      "RegIO W: FAILED WRITING %zu bytes to "
                      REGISTER_FORMAT_STRING " (%zd)",
                      command_ == DCP_COMMAND_WRITE_REGISTER ? 2 : payload_.size(),
                      reg_->address_, reg_->name_.c_str(), ex.result());
            break;
        }

        log_register_write(payload_.size() < DCP_PACKET_MAX_PAYLOAD_SIZE
                           ? LogWrite::SINGLE
                           : LogWrite::COMPLETED);

        return ProcessResult::FINISHED;

      case State::MASTER_PREPARE__INIT:
        if(command_ != DCP_COMMAND_MULTI_WRITE_REGISTER)
        {
            log_assert(command_ == DCP_COMMAND_READ_REGISTER);
            log_assert(payload_.empty());
        }

        state_ = State::SEND_TO_SLAVE;

        /* fall-through */

      case State::SEND_TO_SLAVE:
        {
            const size_t fragsize = get_current_fragment_size();
            std::array<uint8_t, DCPSYNC_HEADER_SIZE> sync_header;

            if(tx_sync_.is_enabled())
                fill_dcpsync_header_generic(sync_header, 'c',
                                            tx_sync_.get_ttl(), tx_sync_.get_serial(),
                                            fragsize + DCP_HEADER_SIZE);

            dcp_put_header_data(&request_header_[DCP_HEADER_DATA_OFFSET],
                                fragsize);

            log_dcp_data(dump_sent_data_flags, sync_header.data(), fragsize);

            if((tx_sync_.is_enabled() &&
                os_write_from_buffer(sync_header.data(), sync_header.size(),
                                     to_slave_fd) < 0) ||
               os_write_from_buffer(request_header_.data(), request_header_.size(),
                                    to_slave_fd) < 0 ||
               os_write_from_buffer(&payload_.data()[current_fragment_offset_],
                                    fragsize, to_slave_fd) < 0)
                break;
        }

        if(tx_sync_.is_enabled())
        {
            state_ = State::DCPSYNC_WAIT_FOR_ACK;
            return ProcessResult::IN_PROGRESS;
        }
        else
            state_ = State::SEND_TO_SLAVE_ACKED;

        /* fall-through */

      case State::SEND_TO_SLAVE_ACKED:
        if(is_last_fragment())
            return ProcessResult::FINISHED;

        current_fragment_offset_ += DCP_PACKET_MAX_PAYLOAD_SIZE;
        log_assert(current_fragment_offset_ < payload_.size());

        refresh_as_master_transaction();
        state_ = State::SEND_TO_SLAVE;

        return ProcessResult::IN_PROGRESS;

      case State::SEND_TO_SLAVE_FAILED:
        state_ = State::ERROR;

        return ProcessResult::ERROR;

      case State::DCPSYNC_WAIT_FOR_ACK:
        log_assert(tx_sync_.is_enabled());

        {
            TXSync ts;

            switch(read_dcpsync_header(ts, from_slave_fd))
            {
              case DCPSYNCPacketType::IO_ERROR:
                break;

              case DCPSYNCPacketType::INVALID:
                skip_transaction_payload(from_slave_fd);

                return ProcessResult::IN_PROGRESS;

              case DCPSYNCPacketType::COMMAND:
                msg_vinfo(MESSAGE_LEVEL_DEBUG,
                          "Collision: New packet 0x%04x while waiting for 0x%04x ACK",
                          ts.get_serial(), tx_sync_.get_serial());

                {
                    auto temp = new_for_queue(queue_,
                                              TransactionQueue::InitialType::SLAVE_BY_SLAVE,
                                              channel_, Pinned::NOT_PINNED);
                    bool failed;

                    if(temp == nullptr)
                    {
                        msg_out_of_memory("interrupting slave transaction");
                        msg_error(ENOMEM, LOG_CRIT,
                                  "Received packet 0x%04x while processing "
                                  "packet 0x%04x, but cannot handle it",
                                  ts.get_serial(), tx_sync_.get_serial());
                        failed = true;
                    }
                    else
                    {
                        temp->tx_sync_ = std::move(ts);
                        failed = !temp->fill_request_header(from_slave_fd);
                    }

                    if(failed)
                    {
                        /* skipping this transaction is all we can do under these
                         * conditions... */
                        temp->skip_transaction_payload(from_slave_fd);
                        return ProcessResult::IN_PROGRESS;
                    }
                    else
                    {
                        temp->state_ = State::SLAVE_READ_DATA;
                        throw CollisionException(std::move(temp));
                    }
                }

              case DCPSYNCPacketType::ACK:
                if(process_ack(ts.get_serial()))
                    return ProcessResult::IN_PROGRESS;

                throw OOOAckException(ts.get_serial());

              case DCPSYNCPacketType::NACK:
                if(process_nack(ts.get_serial(), ts.get_ttl()))
                    return ProcessResult::IN_PROGRESS;

                throw OOONackException(ts.get_serial(), ts.get_ttl());
            }
        }

        break;
    }

    msg_error(0, LOG_ERR, "Transaction %p failed in state %d",
              static_cast<const void *>(this), int(state_));
    state_ = State::ERROR;

    return ProcessResult::ERROR;
}

TransactionQueue::ProcessResult
TransactionQueue::Transaction::process_out_of_order_ack(const OOOAckException &e)
{
    log_assert(tx_sync_.is_enabled());

    if(e.serial_ != tx_sync_.get_serial())
    {
        BUG("Serial for out-of-order ACK wrong (0x%04x, expected 0x%04x)",
            e.serial_, tx_sync_.get_serial());
        return ProcessResult::ERROR;
    }

    switch(state_)
    {
      case State::ERROR:
        return ProcessResult::ERROR;

      case State::SLAVE_PREPARE__INIT:
      case State::PUSH_TO_SLAVE__INIT:
      case State::MASTER_PREPARE__INIT:
      case State::SLAVE_READ_DATA:
      case State::SLAVE_PREPARE_APPEND:
      case State::SLAVE_READ_APPEND:
      case State::SLAVE_PREPARE_ANSWER:
      case State::SLAVE_PROCESS_WRITE:
      case State::SEND_TO_SLAVE:
      case State::SEND_TO_SLAVE_ACKED:
      case State::SEND_TO_SLAVE_FAILED:
        BUG("Ignoring out-of-order ACK for 0x%04x in state %d",
            tx_sync_.get_serial(), int(state_));
        break;

      case State::DCPSYNC_WAIT_FOR_ACK:
        if(process_ack(e.serial_))
            return ProcessResult::IN_PROGRESS;

        BUG("Double out-of-order ACK exception");

        break;
    }

    return ProcessResult::ERROR;
}

TransactionQueue::ProcessResult
TransactionQueue::Transaction::process_out_of_order_nack(const OOONackException &e)
{
    log_assert(tx_sync_.is_enabled());

    if(e.serial_ != tx_sync_.get_serial())
    {
        BUG("Serial for out-of-order NACK[%u] wrong (0x%04x, expected 0x%04x)",
            e.ttl_, e.serial_, tx_sync_.get_serial());
        return ProcessResult::ERROR;
    }

    switch(state_)
    {
      case State::ERROR:
        return ProcessResult::ERROR;

      case State::SLAVE_PREPARE__INIT:
      case State::PUSH_TO_SLAVE__INIT:
      case State::MASTER_PREPARE__INIT:
      case State::SLAVE_READ_DATA:
      case State::SLAVE_PREPARE_APPEND:
      case State::SLAVE_READ_APPEND:
      case State::SLAVE_PREPARE_ANSWER:
      case State::SLAVE_PROCESS_WRITE:
      case State::SEND_TO_SLAVE:
      case State::SEND_TO_SLAVE_ACKED:
      case State::SEND_TO_SLAVE_FAILED:
        BUG("Ignoring out-of-order NACK[%u] for 0x%04x in state %d",
            e.ttl_, tx_sync_.get_serial(), int(state_));
        break;

      case State::DCPSYNC_WAIT_FOR_ACK:
        if(process_nack(e.serial_, e.ttl_))
            return ProcessResult::IN_PROGRESS;

        BUG("Double out-of-order NACK[%u] exception", e.ttl_);

        break;
    }

    return ProcessResult::ERROR;
}

bool TransactionQueue::Transaction::is_input_required() const
{
    switch(state_)
    {
      case State::SLAVE_PREPARE__INIT:
      case State::SLAVE_READ_DATA:
      case State::SLAVE_PREPARE_APPEND:
      case State::SLAVE_READ_APPEND:
      case State::DCPSYNC_WAIT_FOR_ACK:
        return true;

      case State::PUSH_TO_SLAVE__INIT:
      case State::MASTER_PREPARE__INIT:
      case State::SLAVE_PREPARE_ANSWER:
      case State::SLAVE_PROCESS_WRITE:
      case State::SEND_TO_SLAVE:
      case State::SEND_TO_SLAVE_ACKED:
      case State::SEND_TO_SLAVE_FAILED:
      case State::ERROR:
        break;
    }

    return false;
}

uint16_t TransactionQueue::Transaction::get_max_data_size() const
{
    log_assert(reg_ != nullptr);
    log_assert(reg_->max_data_size_ > 0);

    return reg_->max_data_size_;
}

void TransactionQueue::Transaction::set_payload(const uint8_t *src, size_t length)
{
    log_assert(payload_.empty());
    log_assert(src != nullptr);

    payload_.reserve(length);
    std::copy(src, src + length, std::back_inserter(payload_));
}

std::deque<std::unique_ptr<TransactionQueue::Transaction>>
TransactionQueue::fragments_from_data(Queue &queue, const uint8_t *data,
                                      size_t length, uint8_t register_address,
                                      Channel channel)
{
    log_assert(data != nullptr);
    log_assert(length > 0);

    std::deque<std::unique_ptr<Transaction>> result;

    const auto *reg = lookup_register_for_transaction(register_address, true);

    if(reg == nullptr)
        return result;

    size_t i = 0;

    while(i < length)
    {
        auto t = Transaction::new_for_queue(queue,
                                            InitialType::MASTER_FOR_DRCPD_DATA,
                                            *reg, channel);

        if(t == nullptr)
            break;

        uint16_t size = t->get_max_data_size();

        if(i + size >= length)
            size = length - i;

        log_assert(size > 0);
        t->set_payload(data + i, size);

        result.emplace_back(std::move(t));

        i += size;
    }

    if(i < length)
        result.clear();
    else if((length % DCP_PACKET_MAX_PAYLOAD_SIZE) == 0)
    {
        auto t = Transaction::new_for_queue(queue,
                                            InitialType::MASTER_FOR_DRCPD_DATA,
                                            *reg, channel);

        if(t != nullptr)
            result.emplace_back(std::move(t));
        else
            result.clear();
    }

    return result;
}

bool TransactionQueue::push_register_to_slave(Queue &queue,
                                              uint8_t register_address,
                                              Channel channel)
{
    const auto *reg = lookup_register_for_transaction(register_address, true);

    return (reg != nullptr)
        ? queue.append(Transaction::new_for_queue(
                            queue,
                            TransactionQueue::InitialType::MASTER_FOR_REGISTER,
                            *reg, channel))
        : false;
}
