/*
 * Copyright (C) 2015--2020  T+A elektroakustik GmbH & Co. KG
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

#include <cppcutter.h>
#include <array>
#include <algorithm>
#include <sstream>
#include <glib.h>

#include "transactions.hh"
#include "registers.hh"
#include "networkprefs.h"
#include "connman_service_list.hh"
#include "network_device_list.hh"
#include "configproxy.h"
#include "configuration_dcpd.h"
#include "dcpregs_networkconfig.hh"
#include "dcpdefs.h"
#include "mainloop.hh"

#include "mock_messages.hh"
#include "mock_backtrace.hh"
#include "mock_os.hh"

#if LOGGED_LOCKS_ENABLED && LOGGED_LOCKS_THREAD_CONTEXTS
thread_local LoggedLock::Context LoggedLock::context;
#endif

MainLoop::Queue MainLoop::detail::queued_work;

ssize_t (*os_read)(int fd, void *dest, size_t count) = nullptr;
ssize_t (*os_write)(int fd, const void *buf, size_t count) = nullptr;

#if !LOGGED_LOCKS_ENABLED

/*!
 * \addtogroup dcp_transaction_tests Unit tests
 * \ingroup dcp_transaction
 *
 * DCP transaction unit tests.
 */
/*!@{*/

class read_data_partial_t
{
  public:
    read_data_partial_t(const read_data_partial_t &) = delete;
    read_data_partial_t &operator=(const read_data_partial_t &) = delete;

    read_data_partial_t(read_data_partial_t &&) = default;

    const std::vector<uint8_t> data_;
    const int errno_value_;
    const ssize_t return_value_;

    explicit read_data_partial_t(const std::vector<uint8_t> data,
                                 int err, ssize_t ret):
        data_(data),
        errno_value_(err),
        return_value_(ret)
    {}
};

class read_data_t
{
  public:
    read_data_t(const read_data_t &) = delete;
    read_data_t &operator=(const read_data_t &) = delete;

    size_t fragment_;
    std::vector<read_data_partial_t> partial_;

    explicit read_data_t(): fragment_(0) {}

    template <size_t N>
    void set(const uint8_t (&data)[N])
    {
        set(data, N, 0, N);
    }

    template <size_t N>
    void set(const std::array<uint8_t, N> &data)
    {
        set(data.data(), N, 0, N);
    }

    void set(const uint8_t *data, size_t data_size, int err = 0)
    {
        set(data, data_size, err, data_size);
    }

    void set(const uint8_t *data, size_t data_size, int err, ssize_t ret)
    {
        partial_.push_back(read_data_partial_t(std::vector<uint8_t>(data, data + data_size), err, ret));
    }
};

GVariant *configuration_get_key(const char *key)
{
    cppcut_assert_equal("appliance:appliance:id", key);
    return g_variant_new_string("strbo");
}

namespace dcp_transaction_tests_queue
{

static TransactionQueue::Queue *queue;

static MockMessages *mock_messages;
static MockBacktrace *mock_backtrace;

void cut_setup()
{
    os_read = nullptr;
    os_write = nullptr;

    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_backtrace = new MockBacktrace;
    cppcut_assert_not_null(mock_backtrace);
    mock_backtrace->init();
    mock_backtrace_singleton = mock_backtrace;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    queue = new TransactionQueue::Queue;
    cppcut_assert_not_null(queue);

    Connman::ServiceList::get_singleton_for_update().first.clear();
    Connman::NetworkDeviceList::get_singleton_for_update().first.clear();

    Regs::register_zero_for_unit_tests = nullptr;
}

void cut_teardown()
{
    Connman::ServiceList::get_singleton_for_update().first.clear();
    Connman::NetworkDeviceList::get_singleton_for_update().first.clear();

    delete queue;
    queue = nullptr;

    mock_messages->check();
    mock_backtrace->check();

    mock_messages_singleton = nullptr;
    mock_backtrace_singleton = nullptr;

    delete mock_messages;
    delete mock_backtrace;

    mock_messages = nullptr;
    mock_backtrace = nullptr;
}

/*!\test
 * Single transactions can be allocated and deallocated for SPI channel.
 */
void test_allocation_and_deallocation_of_single_transaction_object_spi()
{
    auto t = TransactionQueue::Transaction::new_for_queue(
                *queue,
                TransactionQueue::InitialType::MASTER_FOR_DRCPD_DATA,
                TransactionQueue::Channel::SPI, false);
    cppcut_assert_not_null(t.get());
    cut_assert(TransactionQueue::Channel::SPI == t->get_channel());
    cut_assert_false(t->is_pinned());

    t.reset();
}

/*!\test
 * Transactions can be pinned in memory.
 */
void test_pinned_transaction_object()
{
    auto t = TransactionQueue::Transaction::new_for_queue(
                *queue,
                TransactionQueue::InitialType::MASTER_FOR_DRCPD_DATA,
                TransactionQueue::Channel::SPI, true);
    cppcut_assert_not_null(t.get());
    cut_assert_true(t->is_pinned());
}

/*!\test
 * Single transactions can be allocated and deallocated for IP channel.
 */
void test_allocation_and_deallocation_of_single_transaction_object_inet()
{
    auto t = TransactionQueue::Transaction::new_for_queue(
                *queue,
                TransactionQueue::InitialType::MASTER_FOR_DRCPD_DATA,
                TransactionQueue::Channel::INET, false);
    cppcut_assert_not_null(t.get());
    cut_assert(TransactionQueue::Channel::INET == t->get_channel());

    t.reset();
}

/*!\test
 * Deallocation of transaction frees the internal payload buffer.
 *
 * This test relies on Valgrind's memcheck. We actually should mock away
 * dynamic_buffer_free(), but since Valgrind is run anyway, this half-assed
 * test is all we need to stay on the green side.
 */
void test_deallocation_frees_payload_buffer()
{
    static const uint8_t payload_data[] = "test payload data";

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    Regs::init(nullptr, nullptr);

    auto frags(TransactionQueue::fragments_from_data(*queue,
                                                     payload_data, sizeof(payload_data),
                                                     71, TransactionQueue::Channel::SPI));
    cut_assert_false(frags.empty());
    frags.clear();

    Regs::deinit();
}

/*!\test
 * Dequeue single element from list.
 */
void test_dequeue_from_list_of_length_one()
{
    auto t = TransactionQueue::Transaction::new_for_queue(
                    *queue,
                    TransactionQueue::InitialType::MASTER_FOR_DRCPD_DATA,
                    TransactionQueue::Channel::SPI, false);
    cppcut_assert_not_null(t.get());
    auto *const raw_ptr = t.get();

    cut_assert_true(queue->empty());
    cut_assert_true(queue->append(std::move(t)));
    cut_assert_false(queue->empty());

    auto p(queue->pop());

    cppcut_assert_not_null(p.get());
    cppcut_assert_equal(raw_ptr, p.get());
    cut_assert_true(queue->empty());
}

static void make_short_queue(TransactionQueue::Queue &q,
                             std::vector<TransactionQueue::Transaction *> &raw_pointers,
                             const size_t count)
{
    for(size_t i = 0; i < count; ++i)
    {
        auto t = TransactionQueue::Transaction::new_for_queue(
                        q,
                        TransactionQueue::InitialType::MASTER_FOR_DRCPD_DATA,
                        TransactionQueue::Channel::SPI, false);
        cppcut_assert_not_null(t.get());
        raw_pointers.push_back(t.get());
        q.append(std::move(t));
    }

    cut_assert_false(q.empty());
}

void test_find_transaction_by_existing_serial()
{
    static constexpr size_t count = 4;
    std::vector<TransactionQueue::Transaction *> objects;

    make_short_queue(*queue, objects, count);

    for(size_t i = 0; i < count; ++i)
    {
        bool found = false;
        auto result =
            queue->apply_to_dcpsync_serial(DCPSYNC_MASTER_SERIAL_MIN + i,
                        [&found, &objects, i]
                        (const TransactionQueue::Transaction &t)
                        {
                            found = true;
                            cppcut_assert_equal(objects[i], &t);
                            return TransactionQueue::ProcessResult::FINISHED;
                        });
        cut_assert(TransactionQueue::ProcessResult::FINISHED == result);
    }
}

void test_find_transaction_by_nonexistent_serial()
{
    static constexpr size_t count = 4;
    std::vector<TransactionQueue::Transaction *> objects;

    make_short_queue(*queue, objects, count);

    const auto fn =
        []
        (const TransactionQueue::Transaction &t) -> TransactionQueue::ProcessResult
        {
            return TransactionQueue::ProcessResult::FINISHED;
        };

    cut_assert(TransactionQueue::ProcessResult::ERROR ==
               queue->apply_to_dcpsync_serial(DCPSYNC_MASTER_SERIAL_MIN + count, fn));
    cut_assert(TransactionQueue::ProcessResult::ERROR ==
               queue->apply_to_dcpsync_serial(DCPSYNC_MASTER_SERIAL_MAX, fn));
    cut_assert(TransactionQueue::ProcessResult::ERROR ==
               queue->apply_to_dcpsync_serial(DCPSYNC_MASTER_SERIAL_MAX - 1, fn));
    cut_assert(TransactionQueue::ProcessResult::ERROR ==
               queue->apply_to_dcpsync_serial(DCPSYNC_SLAVE_SERIAL_MIN, fn));
    cut_assert(TransactionQueue::ProcessResult::ERROR ==
               queue->apply_to_dcpsync_serial(DCPSYNC_SLAVE_SERIAL_MAX, fn));
    cut_assert(TransactionQueue::ProcessResult::ERROR ==
               queue->apply_to_dcpsync_serial(DCPSYNC_SLAVE_SERIAL_MIN + 1, fn));
    cut_assert(TransactionQueue::ProcessResult::ERROR ==
               queue->apply_to_dcpsync_serial(DCPSYNC_SLAVE_SERIAL_MAX - 1, fn));

    mock_messages->expect_msg_error_formatted(0, LOG_CRIT,
        "BUG: Tried to find transaction with invalid serial 0x8000");
    cut_assert(TransactionQueue::ProcessResult::ERROR ==
               queue->apply_to_dcpsync_serial(DCPSYNC_MASTER_SERIAL_INVALID, fn));
    mock_messages->expect_msg_error_formatted(0, LOG_CRIT,
        "BUG: Tried to find transaction with invalid serial 0x0000");
    cut_assert(TransactionQueue::ProcessResult::ERROR ==
               queue->apply_to_dcpsync_serial(DCPSYNC_SLAVE_SERIAL_INVALID, fn));
}

}

namespace dcp_transaction_tests_with_specific_register_config
{

static constexpr int expected_from_slave_fd = 80;
static constexpr int expected_to_slave_fd = 90;

static read_data_t *read_data;

static ssize_t test_os_read(int fd, void *dest, size_t count)
{
    cppcut_assert_equal(expected_from_slave_fd, fd);
    cppcut_assert_operator(read_data->fragment_, <, read_data->partial_.size());

    const read_data_partial_t &partial(read_data->partial_[read_data->fragment_++]);

    cppcut_assert_equal(partial.data_.size(), count);
    std::copy_n(partial.data_.begin(), partial.data_.size(),
                static_cast<uint8_t *>(dest));

    errno = partial.errno_value_;

    return partial.return_value_;
}

static ssize_t test_os_write(int fd, const void *buf, size_t count)
{
    cppcut_assert_equal(expected_to_slave_fd, fd);
    cut_fail("write");
    return -1;
}

static TransactionQueue::Queue *queue;

static MockMessages *mock_messages;
static MockOs *mock_os;

static std::vector<uint8_t> *answer_written_to_fifo;

static int read_answer(const void *src, size_t count, int fd)
{
    std::copy_n(static_cast<const uint8_t *>(src), count,
                std::back_inserter(*answer_written_to_fifo));
    return 0;
}

void cut_setup()
{
    os_read = test_os_read;
    os_write = test_os_write;

    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_os = new MockOs;
    cppcut_assert_not_null(mock_os);
    mock_os->init();
    mock_os_singleton = mock_os;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    Regs::register_zero_for_unit_tests = nullptr;

    read_data = new read_data_t;
    cppcut_assert_not_null(read_data);

    answer_written_to_fifo = new std::vector<uint8_t>;

    queue = new TransactionQueue::Queue;
    cppcut_assert_not_null(queue);

    Connman::ServiceList::get_singleton_for_update().first.clear();
    Connman::NetworkDeviceList::get_singleton_for_update().first.clear();
}

void cut_teardown()
{
    delete queue;
    queue = nullptr;

    mock_messages->check();
    mock_os->check();

    mock_messages_singleton = nullptr;
    mock_os_singleton = nullptr;

    delete mock_messages;
    delete mock_os;

    mock_messages = nullptr;
    mock_os = nullptr;

    delete read_data;
    read_data = nullptr;

    delete answer_written_to_fifo;
    answer_written_to_fifo = nullptr;
}

static std::unique_ptr<TransactionQueue::Transaction>
send_dcpsync_ack(uint16_t serial, std::unique_ptr<TransactionQueue::Transaction> t,
                 TransactionQueue::ProcessResult last_status = TransactionQueue::ProcessResult::FINISHED,
                 bool process_only_once = false)
{
    const std::array<uint8_t, DCPSYNC_HEADER_SIZE> dcpsync_ack =
    {
        'a', 0x00,
        uint8_t(serial >> 8), uint8_t(serial & UINT8_MAX),
        0x00, 0x00,
    };

    read_data->set(dcpsync_ack.data(), dcpsync_ack.size());

    if(!process_only_once)
        cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
                   t->process(expected_from_slave_fd, expected_to_slave_fd,
                              TransactionQueue::DUMP_SENT_NONE));

    cut_assert(last_status ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    cut_assert_false(t->is_input_required());

    if(last_status == TransactionQueue::ProcessResult::FINISHED)
        t.reset();

    return t;
}

/*!\test
 * A whole simple register read transaction initiated by the slave device, one
 * byte of payload.
 */
void test_register_read_request_size_1_transaction()
{
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    network_prefs_init("/somewhere", "/somewhere/cfg.rc");
    Regs::init(nullptr, nullptr);

    auto t = TransactionQueue::Transaction::new_for_queue(
                *queue,
                TransactionQueue::InitialType::SLAVE_BY_SLAVE,
                TransactionQueue::Channel::SPI, false);
    cppcut_assert_not_null(t.get());

    static const uint8_t dcpsync_header[] =
    {
        'c', 0x00, 0x51, 0xfe, 0x00, DCP_HEADER_SIZE,
    };
    static const uint8_t read_reg_55_read_dhcp_mode[] =
    {
        DCP_COMMAND_READ_REGISTER, 0x37, 0x00, 0x00,
    };

    read_data->set(dcpsync_header);
    read_data->set(read_reg_55_read_dhcp_mode);

    cut_assert(TransactionQueue::ProcessResult::PUSH_BACK ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG, "RegIO R: 55 [DHCP control], 1 bytes");

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    static const uint8_t expected_answer[] =
    {
        /* DCPSYNC answer */
        'c', UINT8_MAX, 0x80, 0x01, 0x00, DCP_HEADER_SIZE + 0x01,

        /* command header, payload size is 1 byte */
        DCP_COMMAND_MULTI_READ_REGISTER, 0x37, 0x01, 0x00,

        /* DHCP is not enabled */
        0x00
    };
    cut_assert_equal_memory(expected_answer, sizeof(expected_answer),
                            answer_written_to_fifo->data(), answer_written_to_fifo->size());

    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN, std::move(t));

    Regs::deinit();
    network_prefs_deinit();
}

static void setup_network_config(const char *mac)
{
    Connman::Address<Connman::AddressType::MAC> addr(mac);
    Connman::NetworkDeviceList::get_singleton_for_update().first.set_auto_select_mac_address(
            Connman::Technology::ETHERNET, addr);
    Connman::NetworkDeviceList::get_singleton_for_update().first.insert(
            Connman::Technology::ETHERNET, Connman::Address<Connman::AddressType::MAC>(addr));
    cppcut_assert_not_null(Connman::NetworkDeviceList::get_singleton_const().first[addr].get());

    Connman::ServiceData data;
    Connman::IPSettings<Connman::AddressType::IPV4> ipv4_data;
    ipv4_data.set_address("111.222.255.100");
    ipv4_data.set_netmask("255.255.255.0");
    ipv4_data.set_gateway("111.222.255.1");
    data.device_ = Connman::NetworkDeviceList::get_singleton_const().first[addr];
    data.is_favorite_ = true;
    data.is_auto_connect_ = true;
    data.is_immutable_ = false;
    data.state_ = Connman::ServiceState::ONLINE;
    data.active_.ipsettings_v4_ = std::move(ipv4_data);
    Connman::ServiceList::get_singleton_for_update().first.insert(
            "/some/service", std::move(data),
            std::move(Connman::TechData<Connman::Technology::ETHERNET>()));
}

/*!\test
 * A whole simple register read transaction initiated by the slave device,
 * several bytes of payload.
 */
void test_register_read_request_size_16_transaction()
{
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    network_prefs_init("/somewhere", "/somewhere/cfg.rc");
    Regs::init(nullptr, nullptr);
    setup_network_config("11:23:34:45:56:67");

    auto t = TransactionQueue::Transaction::new_for_queue(
                *queue,
                TransactionQueue::InitialType::SLAVE_BY_SLAVE,
                TransactionQueue::Channel::SPI, false);
    cppcut_assert_not_null(t.get());

    static const uint8_t dcpsync_header[] =
    {
        'c', 0x00, 0x2a, 0x2b, 0x00, DCP_HEADER_SIZE,
    };
    static const uint8_t read_reg_56_read_ipv4_address[] =
    {
        DCP_COMMAND_READ_REGISTER, 0x38, 0x00, 0x00,
    };

    read_data->set(dcpsync_header);
    read_data->set(read_reg_56_read_ipv4_address);

    cut_assert(TransactionQueue::ProcessResult::PUSH_BACK ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG, "RegIO R: 56 [IPv4 address], 16 bytes");

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    static const uint8_t expected_answer[] =
    {
        /* DCPSYNC answer */
        'c', UINT8_MAX, 0x80, 0x01, 0x00, DCP_HEADER_SIZE + 0x10,

        /* command header, payload size is 16 bytes */
        DCP_COMMAND_MULTI_READ_REGISTER, 0x38, 0x10, 0x00,

        /* zero-terminated string "111.222.255.100" */
        0x31, 0x31, 0x31, 0x2e, 0x32, 0x32, 0x32, 0x2e,
        0x32, 0x35, 0x35, 0x2e, 0x31, 0x30, 0x30, 0x00
    };
    cut_assert_equal_memory(expected_answer, sizeof(expected_answer),
                            answer_written_to_fifo->data(), answer_written_to_fifo->size());

    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN, std::move(t));

    Regs::deinit();
    network_prefs_deinit();
}

/*!\test
 * A whole multi-step register read transaction initiated by the slave device.
 */
void test_register_multi_step_read_request_transaction()
{
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    network_prefs_init("/somewhere", "/somewhere/cfg.rc");
    Regs::init(nullptr, nullptr);
    setup_network_config("11:34:56:78:9A:BC");

    auto t = TransactionQueue::Transaction::new_for_queue(
                *queue,
                TransactionQueue::InitialType::SLAVE_BY_SLAVE,
                TransactionQueue::Channel::SPI, false);
    cppcut_assert_not_null(t.get());

    static const uint8_t dcpsync_header[] =
    {
        'c', 0x00, 0x1a, 0x1b, 0x00, DCP_HEADER_SIZE,
    };
    static const uint8_t read_reg_51_mac_address[] =
    {
        DCP_COMMAND_READ_REGISTER, 0x33, 0x00, 0x00,
    };

    read_data->set(dcpsync_header);
    read_data->set(read_reg_51_mac_address);

    cut_assert(TransactionQueue::ProcessResult::PUSH_BACK ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG, "RegIO R: 51 [MAC address], 18 bytes");

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    static const uint8_t expected_answer[] =
    {
        /* DCPSYNC answer */
        'c', UINT8_MAX, 0x80, 0x01, 0x00, DCP_HEADER_SIZE + 0x12,

        /* command header, payload size is 18 bytes */
        DCP_COMMAND_MULTI_READ_REGISTER, 0x33, 0x12, 0x00,

        /* MAC address 11:34:56:78:9A:BC */
        0x31, 0x31, 0x3a, 0x33, 0x34, 0x3a, 0x35, 0x36,
        0x3a, 0x37, 0x38, 0x3a, 0x39, 0x41, 0x3a, 0x42,
        0x43, 0x00
    };
    cut_assert_equal_memory(expected_answer, sizeof(expected_answer),
                            answer_written_to_fifo->data(), answer_written_to_fifo->size());

    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN, std::move(t));

    Regs::deinit();
    network_prefs_deinit();
}

static constexpr const uint8_t big_data[] =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

static bool return_big_data(std::vector<uint8_t> &buffer)
{
    cut_assert(buffer.empty());
    buffer.reserve(sizeof(big_data));
    std::copy(big_data, big_data + sizeof(big_data), std::back_inserter(buffer));
    return true;
}

/*!\test
 * Reading a dynamically-size, big register by slave results in fragments being
 * generated on-the-fly.
 */
void test_big_data_is_sent_to_slave_in_fragments()
{
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    network_prefs_init("/somewhere", "/somewhere/cfg.rc");
    Regs::init(nullptr, nullptr);

    auto t = TransactionQueue::Transaction::new_for_queue(
                *queue,
                TransactionQueue::InitialType::SLAVE_BY_SLAVE,
                TransactionQueue::Channel::SPI, false);
    cppcut_assert_not_null(t.get());
    cut_assert_true(queue->append(std::move(t)));

    /* append another transaction to the end to check if the fragmentation code
     * accidently cuts off the end of the queue */
    t = TransactionQueue::Transaction::new_for_queue(
                *queue,
                TransactionQueue::InitialType::MASTER_FOR_DRCPD_DATA,
                TransactionQueue::Channel::SPI, false);
    cppcut_assert_not_null(t.get());
    cut_assert_true(queue->append(std::move(t)));

    static const Regs::Register big_register("big register (unit tests)", 0,
                                             REGISTER_MK_VERSION(1, 0, 0),
                                             REGISTER_MK_VERSION(UINT8_MAX, UINT8_MAX, UINT8_MAX),
                                             return_big_data, nullptr);

    Regs::register_zero_for_unit_tests = &big_register;

    static const uint8_t dcpsync_header[] =
    {
        'c', 0x00, 0x49, 0xc3, 0x00, DCP_HEADER_SIZE,
    };
    static const uint8_t read_test_register[] =
    {
        DCP_COMMAND_READ_REGISTER, 0x00, 0x00, 0x00,
    };

    read_data->set(dcpsync_header);
    read_data->set(read_test_register);

    t = queue->pop();
    cppcut_assert_not_null(t.get());
    cut_assert_false(queue->empty());

    cut_assert(TransactionQueue::ProcessResult::PUSH_BACK ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    /* this is our \c #big_register defined above */
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG, "RegIO R: 0 [big register (unit tests)], 683 bytes");

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    uint16_t master_serial = DCPSYNC_MASTER_SERIAL_MIN + 1;
    size_t bytes_left = sizeof(big_data);
    cppcut_assert_operator(size_t(DCP_PACKET_MAX_PAYLOAD_SIZE), <, bytes_left);

    while(bytes_left > 0)
    {
        answer_written_to_fifo->clear();
        mock_os->expect_os_write_from_buffer_callback(0, read_answer);
        mock_os->expect_os_write_from_buffer_callback(0, read_answer);
        mock_os->expect_os_write_from_buffer_callback(0, read_answer);

        const auto status = t->process(expected_from_slave_fd, expected_to_slave_fd,
                                       TransactionQueue::DUMP_SENT_NONE);
        cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS == status);

        const size_t expected_data_size = (bytes_left <= DCP_PACKET_MAX_PAYLOAD_SIZE
                                           ? bytes_left
                                           : DCP_PACKET_MAX_PAYLOAD_SIZE);
        const uint8_t expected_header[] =
        {
            /* DCPSYNC header */
            'c', UINT8_MAX,
            static_cast<uint8_t>((master_serial) >> 8),
            static_cast<uint8_t>((master_serial) & 0xff),
            static_cast<uint8_t>((DCP_HEADER_SIZE + expected_data_size) >> 8),
            static_cast<uint8_t>((DCP_HEADER_SIZE + expected_data_size) & 0xff),

            /* DCP header */
            DCP_COMMAND_MULTI_READ_REGISTER, 0x00,
            static_cast<uint8_t>(expected_data_size & 0xff),
            static_cast<uint8_t>(expected_data_size >> 8)
        };

        cppcut_assert_operator(sizeof(expected_header), <=, answer_written_to_fifo->size());
        cut_assert_equal_memory(expected_header, sizeof(expected_header),
                                answer_written_to_fifo->data(), sizeof(expected_header));

        cut_assert_equal_memory(big_data + (sizeof(big_data) - bytes_left),
                                expected_data_size,
                                answer_written_to_fifo->data() + sizeof(expected_header),
                                answer_written_to_fifo->size() - sizeof(expected_header));

        if(expected_data_size < DCP_PACKET_MAX_PAYLOAD_SIZE)
        {
            send_dcpsync_ack(master_serial, std::move(t));
            cppcut_assert_equal(expected_data_size, bytes_left);
        }
        else
        {
            t = send_dcpsync_ack(master_serial, std::move(t),
                                 TransactionQueue::ProcessResult::IN_PROGRESS);
            cppcut_assert_not_null(t.get());
        }

        bytes_left -= expected_data_size;
        ++master_serial;
    }

    t = queue->pop();
    cppcut_assert_not_null(t.get());
    cut_assert_true(queue->empty());

    Regs::deinit();
    network_prefs_deinit();
}

}

namespace dcp_transaction_tests
{

static constexpr int expected_from_slave_fd = 23;
static constexpr int expected_to_slave_fd = 42;

static read_data_t *read_data;

static ssize_t test_os_read(int fd, void *dest, size_t count)
{
    cppcut_assert_equal(expected_from_slave_fd, fd);
    cppcut_assert_operator(read_data->fragment_, <, read_data->partial_.size());

    const read_data_partial_t &partial(read_data->partial_[read_data->fragment_++]);

    cppcut_assert_equal(partial.data_.size(), count);
    std::copy_n(partial.data_.begin(), partial.data_.size(),
                static_cast<uint8_t *>(dest));

    errno = partial.errno_value_;

    return partial.return_value_;
}

static ssize_t test_os_write(int fd, const void *buf, size_t count)
{
    cppcut_assert_equal(expected_to_slave_fd, fd);
    cut_fail("write");
    return -1;
}

static TransactionQueue::Queue *queue;

static MockMessages *mock_messages;
static MockBacktrace *mock_backtrace;
static MockOs *mock_os;

static std::vector<uint8_t> *answer_written_to_fifo;

static int read_answer(const void *src, size_t count, int fd)
{
    std::copy_n(static_cast<const uint8_t *>(src), count,
                std::back_inserter(*answer_written_to_fifo));
    return 0;
}

void cut_setup()
{
    os_read = test_os_read;
    os_write = test_os_write;

    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_backtrace = new MockBacktrace;
    cppcut_assert_not_null(mock_backtrace);
    mock_backtrace->init();
    mock_backtrace_singleton = mock_backtrace;

    mock_os = new MockOs;
    cppcut_assert_not_null(mock_os);
    mock_os->init();
    mock_os_singleton = mock_os;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    Regs::register_zero_for_unit_tests = nullptr;

    read_data = new read_data_t;
    cppcut_assert_not_null(read_data);

    answer_written_to_fifo = new std::vector<uint8_t>;

    queue = new TransactionQueue::Queue;
    cppcut_assert_not_null(queue);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    Connman::ServiceList::get_singleton_for_update().first.clear();
    Connman::NetworkDeviceList::get_singleton_for_update().first.clear();

    network_prefs_init(nullptr, nullptr);
    Regs::init(nullptr, nullptr);
}

void cut_teardown()
{
    Regs::deinit();
    network_prefs_deinit();

    Connman::ServiceList::get_singleton_for_update().first.clear();
    Connman::NetworkDeviceList::get_singleton_for_update().first.clear();

    delete queue;
    queue = nullptr;

    mock_messages->check();
    mock_backtrace->check();
    mock_os->check();

    mock_messages_singleton = nullptr;
    mock_backtrace_singleton = nullptr;
    mock_os_singleton = nullptr;

    delete mock_messages;
    delete mock_backtrace;
    delete mock_os;

    mock_messages = nullptr;
    mock_backtrace = nullptr;
    mock_os = nullptr;

    delete read_data;
    read_data = nullptr;

    delete answer_written_to_fifo;
    answer_written_to_fifo = nullptr;
}

static void send_dcpsync_ack(uint16_t serial, std::unique_ptr<TransactionQueue::Transaction> t,
                             TransactionQueue::ProcessResult last_status = TransactionQueue::ProcessResult::FINISHED,
                             bool process_only_once = false)
{
    const std::array<uint8_t, DCPSYNC_HEADER_SIZE> dcpsync_ack =
    {
        'a', 0x00,
        uint8_t(serial >> 8), uint8_t(serial & UINT8_MAX),
        0x00, 0x00,
    };

    read_data->set(dcpsync_ack.data(), dcpsync_ack.size());

    if(!process_only_once)
        cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
                   t->process(expected_from_slave_fd, expected_to_slave_fd,
                              TransactionQueue::DUMP_SENT_NONE));

    cut_assert(last_status ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));
}

static void send_dcpsync_nack(uint16_t serial, uint8_t ttl, TransactionQueue::Transaction &t,
                              TransactionQueue::ProcessResult expected_status = TransactionQueue::ProcessResult::IN_PROGRESS)
{
    const std::array<uint8_t, DCPSYNC_HEADER_SIZE> dcpsync_nack =
    {
        'n', ttl,
        uint8_t(serial >> 8), uint8_t(serial & UINT8_MAX),
        0x00, 0x00,
    };

    read_data->set(dcpsync_nack.data(), dcpsync_nack.size());

    cut_assert(expected_status ==
               t.process(expected_from_slave_fd, expected_to_slave_fd,
                         TransactionQueue::DUMP_SENT_NONE));
}

/*!\test
 * A whole (former) simple register write transaction initiated by the slave
 * device.
 */
void test_register_write_request_transaction()
{
    auto t = TransactionQueue::Transaction::new_for_queue(
                *queue,
                TransactionQueue::InitialType::SLAVE_BY_SLAVE,
                TransactionQueue::Channel::SPI, false);
    cppcut_assert_not_null(t.get());

    static const uint8_t dcpsync_header[] =
    {
        'c', UINT8_MAX, 0x7e, 0x04, 0x00, DCP_HEADER_SIZE + 0x01,
    };
    static const uint8_t write_reg_54_selected_ip_profile[] =
    {
        DCP_COMMAND_MULTI_WRITE_REGISTER, 0x36, 0x01, 0x00, 0x00,
    };

    read_data->set(dcpsync_header);
    read_data->set(write_reg_54_selected_ip_profile, DCP_HEADER_SIZE);
    read_data->set(write_reg_54_selected_ip_profile + DCP_HEADER_SIZE,
                   sizeof(write_reg_54_selected_ip_profile) - DCP_HEADER_SIZE);

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    Regs::NetworkConfig::set_primary_technology(Connman::Technology::ETHERNET);
    mock_messages->expect_msg_info("Could not determine active network technology, trying fallback");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "Modify Ethernet configuration");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG, "RegIO W: 54 [start network configuration], 1 bytes");

    cut_assert_false(t->is_input_required());

    cut_assert(TransactionQueue::ProcessResult::FINISHED ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    cut_assert_false(t->is_input_required());
}

/*!\test
 * Simple register write transactions are not supported anymore.
 *
 * This was done to keep the implementation a bit simpler.
 */
void test_register_simple_write_not_supported()
{
    auto t = TransactionQueue::Transaction::new_for_queue(
                *queue,
                TransactionQueue::InitialType::SLAVE_BY_SLAVE,
                TransactionQueue::Channel::SPI, false);
    cppcut_assert_not_null(t.get());

    static const uint8_t dcpsync_header[] =
    {
        'c', 0x00, 0x08, 0xcc, 0x00, DCP_HEADER_SIZE,
    };
    static const uint8_t oldstyle_write_reg_55_enable_dhcp[] =
    {
        DCP_COMMAND_WRITE_REGISTER, 0x37, 0x01, 0x00,
    };

    read_data->set(dcpsync_header);
    read_data->set(oldstyle_write_reg_55_enable_dhcp);

    mock_messages->expect_msg_error(EINVAL, LOG_ERR, "Simple write command not supported");
    mock_messages->expect_msg_error(0, LOG_ERR, "Transaction %p failed in state %d");

    cut_assert(TransactionQueue::ProcessResult::ERROR ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));
}

/*!\test
 * Multi-step register read commands are not supported anymore.
 *
 * This was done to keep the implementation a bit simpler.
 */
void test_register_multi_read_not_supported()
{
    auto t = TransactionQueue::Transaction::new_for_queue(
                *queue,
                TransactionQueue::InitialType::SLAVE_BY_SLAVE,
                TransactionQueue::Channel::SPI, false);
    cppcut_assert_not_null(t.get());

    static const uint8_t dcpsync_header[] =
    {
        'c', 0x00, 0x08, 0xdd, 0x00, DCP_HEADER_SIZE,
    };
    static const uint8_t oldstyle_read_reg_51_mac_address[] =
    {
        DCP_COMMAND_MULTI_READ_REGISTER, 0x33, 0x00, 0x00,
    };

    read_data->set(dcpsync_header);
    read_data->set(oldstyle_read_reg_51_mac_address);

    mock_messages->expect_msg_error(EINVAL, LOG_ERR, "Multiple read command not supported");
    mock_messages->expect_msg_error(0, LOG_ERR, "Transaction %p failed in state %d");

    cut_assert(TransactionQueue::ProcessResult::ERROR ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));
}

/*!\test
 * The SPI slave may send junk bytes, which we are ignoring.
 */
void test_junk_bytes_are_ignored()
{
    auto t = TransactionQueue::Transaction::new_for_queue(
                *queue,
                TransactionQueue::InitialType::SLAVE_BY_SLAVE,
                TransactionQueue::Channel::SPI, false);
    cppcut_assert_not_null(t.get());

    static const uint8_t dcpsync_header[] = { 'c', 0x00, 0x66, 0x08, 0x00, DCP_HEADER_SIZE, };
    static const uint8_t junk_bytes[] = { 0x67, 0xac, 0x00, 0x20, };

    read_data->set(dcpsync_header);
    read_data->set(junk_bytes);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Invalid DCP header 0x67 0xac 0x00 0x20 (Invalid argument)");
    mock_messages->expect_msg_error(0, LOG_ERR, "Transaction %p failed in state %d");

    cut_assert(TransactionQueue::ProcessResult::ERROR ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));
}

/*!\test
 * A small, atomic write transaction initiated by the master device.
 *
 * This is a special case (albeit frequent) scenario where the payload entirely
 * fits into a DCP packet. For bigger data, the transaction has to be split
 * into multiple transactions as demonstrated in the more generic test
 * #test_big_master_transaction().
 */
void test_small_master_transaction()
{
    static const uint8_t xml_data[] =
        "<view name=\"welcome\"><icon id=\"welcome\" text=\"Profile 1\">welcome</icon></view>";
    auto frags(TransactionQueue::fragments_from_data(*queue,
                                                     xml_data, sizeof(xml_data) - 1U,
                                                     71, TransactionQueue::Channel::SPI));
    cut_assert_false(frags.empty());

    const size_t max_data_size = frags.front()->get_max_data_size();
    cppcut_assert_operator(sizeof(xml_data) - 1U, <, max_data_size);

    cut_assert_true(queue->append(std::move(frags)));

    auto t = queue->pop();
    cut_assert_true(queue->empty());
    cppcut_assert_not_null(t.get());

    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    cut_assert_true(t->is_input_required());

    /* check emitted DCP data */
    static const uint8_t expected_headers[] =
    {
        /* DCPSYNC header */
        'c', UINT8_MAX,
        static_cast<uint8_t>(DCPSYNC_MASTER_SERIAL_MIN >> 8),
        static_cast<uint8_t>(DCPSYNC_MASTER_SERIAL_MIN & 0xff),
        static_cast<uint8_t>((DCP_HEADER_SIZE + sizeof(xml_data) - 1) >> 8),
        static_cast<uint8_t>((DCP_HEADER_SIZE + sizeof(xml_data) - 1) & 0xff),

        /* DCP header */
        DCP_COMMAND_MULTI_WRITE_REGISTER, 71,
        sizeof(xml_data) - 1U,
        0x00,
    };

    cut_assert(sizeof(expected_headers) + sizeof(xml_data) - 1U ==
               answer_written_to_fifo->size());

    cut_assert_equal_memory(expected_headers, sizeof(expected_headers),
                            answer_written_to_fifo->data(), sizeof(expected_headers));
    cut_assert_equal_memory(xml_data, sizeof(xml_data) - 1U,
                            answer_written_to_fifo->data() + sizeof(expected_headers),
                            sizeof(xml_data) - 1U);

    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN, std::move(t));
}

/*!\test
 * We try to repeat rejected master transactions.
 */
void test_master_transaction_retry_on_nack()
{
    mock_messages->ignore_messages_above(MESSAGE_LEVEL_MAX);

    static const uint8_t xml_data[] =
        "<view name=\"welcome\"><icon id=\"welcome\" text=\"Profile 1\">welcome</icon></view>";
    auto frags(TransactionQueue::fragments_from_data(*queue,
                                                     xml_data, sizeof(xml_data) - 1U,
                                                     71, TransactionQueue::Channel::SPI));
    cut_assert_false(frags.empty());

    const size_t max_data_size = frags.front()->get_max_data_size();
    cppcut_assert_operator(sizeof(xml_data) - 1U, <, max_data_size);

    cut_assert_true(queue->append(std::move(frags)));

    auto t = queue->pop();
    cut_assert_true(queue->empty());
    cppcut_assert_not_null(t.get());

    /* first try */
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    cut_assert_true(t->is_input_required());

    /* data for first try */
    static const uint8_t expected_headers_first[] =
    {
        /* DCPSYNC header */
        'c', UINT8_MAX,
        static_cast<uint8_t>(DCPSYNC_MASTER_SERIAL_MIN >> 8),
        static_cast<uint8_t>(DCPSYNC_MASTER_SERIAL_MIN & 0xff),
        static_cast<uint8_t>((DCP_HEADER_SIZE + sizeof(xml_data) - 1) >> 8),
        static_cast<uint8_t>((DCP_HEADER_SIZE + sizeof(xml_data) - 1) & 0xff),

        /* DCP header */
        DCP_COMMAND_MULTI_WRITE_REGISTER, 71,
        sizeof(xml_data) - 1U,
        0x00,
    };

    cut_assert(sizeof(expected_headers_first) + sizeof(xml_data) - 1U ==
               answer_written_to_fifo->size());

    cut_assert_equal_memory(expected_headers_first, sizeof(expected_headers_first),
                            answer_written_to_fifo->data(), sizeof(expected_headers_first));
    cut_assert_equal_memory(xml_data, sizeof(xml_data) - 1U,
                            answer_written_to_fifo->data() + sizeof(expected_headers_first),
                            sizeof(xml_data) - 1U);

    answer_written_to_fifo->clear();

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_TRACE,
        "Got NACK[9] for 0x8001, resending packet as 0x8002");

    send_dcpsync_nack(DCPSYNC_MASTER_SERIAL_MIN, 9, *t);

    cut_assert_false(t->is_input_required());

    /* second try */
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    cut_assert_true(t->is_input_required());

    /* data for second try */
    static const uint8_t expected_headers_second[] =
    {
        /* DCPSYNC header */
        'c', 0x09,
        static_cast<uint8_t>((DCPSYNC_MASTER_SERIAL_MIN + 1) >> 8),
        static_cast<uint8_t>((DCPSYNC_MASTER_SERIAL_MIN + 1) & 0xff),
        static_cast<uint8_t>((DCP_HEADER_SIZE + sizeof(xml_data) - 1) >> 8),
        static_cast<uint8_t>((DCP_HEADER_SIZE + sizeof(xml_data) - 1) & 0xff),

        /* DCP header */
        DCP_COMMAND_MULTI_WRITE_REGISTER, 71,
        sizeof(xml_data) - 1U,
        0x00,
    };

    cut_assert(sizeof(expected_headers_second) + sizeof(xml_data) - 1U ==
               answer_written_to_fifo->size());

    cut_assert_equal_memory(expected_headers_second, sizeof(expected_headers_second),
                            answer_written_to_fifo->data(), sizeof(expected_headers_second));
    cut_assert_equal_memory(xml_data, sizeof(xml_data) - 1U,
                            answer_written_to_fifo->data() + sizeof(expected_headers_second),
                            sizeof(xml_data) - 1U);

    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN + 1, std::move(t));
}

static void do_big_master_transaction(const uint8_t *const xml_data,
                                      const size_t xml_size,
                                      const size_t max_data_size,
                                      const unsigned int expected_number_of_transactions)
{
    cut_assert_false(queue->empty());
    cppcut_assert_operator(1U, <, expected_number_of_transactions);

    const uint8_t *xml_data_ptr = xml_data;
    size_t bytes_left = xml_size;
    unsigned int number_of_transactions = 0;
    uint16_t expected_serial = DCPSYNC_MASTER_SERIAL_MIN;

    do
    {
        /* take next transaction of fragmented DRCP packet */
        auto t = queue->pop();
        cppcut_assert_not_null(t.get());

        mock_os->expect_os_write_from_buffer_callback(0, read_answer);
        mock_os->expect_os_write_from_buffer_callback(0, read_answer);
        mock_os->expect_os_write_from_buffer_callback(0, read_answer);

        answer_written_to_fifo->clear();

        cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
                   t->process(expected_from_slave_fd, expected_to_slave_fd,
                              TransactionQueue::DUMP_SENT_NONE));

        /* check emitted DCP data */
        const size_t expected_data_size = std::min(bytes_left, max_data_size);
        const uint8_t expected_headers[] =
        {
            /* DCPSYNC header */
            'c', UINT8_MAX,
            static_cast<uint8_t>(expected_serial >> 8),
            static_cast<uint8_t>(expected_serial & 0xff),
            static_cast<uint8_t>((DCP_HEADER_SIZE + expected_data_size) >> 8),
            static_cast<uint8_t>((DCP_HEADER_SIZE + expected_data_size) & 0xff),

            /* DCP header */
            DCP_COMMAND_MULTI_WRITE_REGISTER, 71,
            static_cast<uint8_t>(expected_data_size & 0xff),
            static_cast<uint8_t>(expected_data_size >> 8)
        };

        if(queue->empty() && (xml_size % DCP_PACKET_MAX_PAYLOAD_SIZE) == 0)
        {
            /* this particular last packet must be empty */
            cppcut_assert_equal(size_t(DCPSYNC_HEADER_SIZE + DCP_HEADER_SIZE),
                                answer_written_to_fifo->size());
            cppcut_assert_equal(size_t(0), bytes_left);
            cppcut_assert_equal(size_t(0), expected_data_size);
        }

        cppcut_assert_equal(sizeof(expected_headers) + expected_data_size,
                            answer_written_to_fifo->size());

        cut_assert_equal_memory(expected_headers, sizeof(expected_headers),
                                answer_written_to_fifo->data(), sizeof(expected_headers));
        cut_assert_equal_memory(xml_data_ptr, expected_data_size,
                                answer_written_to_fifo->data() + sizeof(expected_headers),
                                expected_data_size);

        send_dcpsync_ack(expected_serial, std::move(t));

        bytes_left -= expected_data_size;
        xml_data_ptr += expected_data_size;
        ++number_of_transactions;
        ++expected_serial;
    }
    while(!queue->empty() && number_of_transactions < expected_number_of_transactions);

    cppcut_assert_equal(expected_number_of_transactions, number_of_transactions);
}

/*!\test
 * A big, fragmented write transaction initiated by the master device.
 */
void test_big_master_transaction()
{
    static const uint8_t xml_data[] =
        "<view name=\"play\">\n"
        "    <text id=\"albart\">yes</text>\n"
        "    <text id=\"scrid\">109</text>\n"
        "    <text id=\"artist\">U2</text>\n"
        "    <text id=\"track\">One</text>\n"
        "    <text id=\"album\">Achtung baby</text>\n"
        "    <text id=\"mimtype\">Wma</text>\n"
        "    <text id=\"drm\">no</text>\n"
        "    <text id=\"livstrm\">no</text>\n"
        "    <text id=\"bitrate\">64</text>\n"
        "    <icon id=\"wicon\">infra</icon>\n"
        "    <value id=\"timep\" min=\"0\" max=\"65535\">43</value>\n"
        "    <value id=\"timet\" min=\"0\" max=\"65535\">327</value>\n"
        "    <value id=\"timec\" min=\"0\" max=\"99999\">65400</value>\n"
        "    <value id=\"date\" min=\"0\" max=\"99999999\">20040907</value>\n"
        "    <value id=\"buflvl\" min=\"0\" max=\"100\">70</value>\n"
        "    <value id=\"wilvl\" min=\"0\" max=\"100\">100</value>\n"
        "</view>\n";

    static const size_t xfer_size = sizeof(xml_data) - 1;

    cppcut_assert_not_equal(size_t(0), xfer_size % DCP_PACKET_MAX_PAYLOAD_SIZE);

    auto frags(TransactionQueue::fragments_from_data(*queue,
                                                     xml_data, xfer_size, 71,
                                                     TransactionQueue::Channel::SPI));
    cut_assert_false(frags.empty());

    cut_assert_true(queue->empty());
    const size_t max_data_size = frags.front()->get_max_data_size();
    cut_assert_true(queue->append(std::move(frags)));

    do_big_master_transaction(xml_data, xfer_size, max_data_size, 3);

    cut_assert_true(queue->empty());
}

/*!\test
 * Big chunk sent in fragments with a last fragment of size 256 is followed by
 * a terminating empty fragment of size 0.
 */
void test_big_master_transaction_with_size_of_multiple_of_256()
{
    static const uint8_t xml_data[] =
        "<view name=\"play\">\n"
        "    <text id=\"scrid\">109</text>\n"
        "    <text id=\"artist\">U2</text>\n"
        "    <text id=\"track\">One</text>\n"
        "    <text id=\"album\">Achtung baby</text>\n"
        "    <text id=\"mimtype\">FLAC</text>\n"
        "    <text id=\"drm\">no</text>\n"
        "    <text id=\"bitrate\">1056</text>\n"
        "    <icon id=\"wicon\">infra</icon>\n"
        "    <value id=\"timep\" min=\"0\" max=\"65535\">43</value>\n"
        "    <value id=\"timet\" min=\"0\" max=\"65535\">327</value>\n"
        "    <value id=\"timec\" min=\"0\" max=\"99999\">65400</value>\n"
        "    <value id=\"buflvl\" min=\"0\" max=\"100\">70</value>\n"
        "</view>\n";

    static const size_t xfer_size = sizeof(xml_data) - 1;

    cppcut_assert_equal(size_t(0), xfer_size % DCP_PACKET_MAX_PAYLOAD_SIZE);

    auto frags(TransactionQueue::fragments_from_data(*queue,
                                                     xml_data, xfer_size, 71,
                                                     TransactionQueue::Channel::SPI));
    cut_assert_false(frags.empty());

    cut_assert_true(queue->empty());
    const size_t max_data_size = frags.front()->get_max_data_size();
    cut_assert_true(queue->append(std::move(frags)));

    do_big_master_transaction(xml_data, xfer_size, max_data_size, 3);

    cut_assert_true(queue->empty());
}

static size_t big_write_calls_count;
static size_t big_write_calls_expected;
static std::vector<uint8_t> big_write_data;

/*
 * Dummy implementation.
 */
static int big_write_handler(const uint8_t *data, size_t length)
{
    ++big_write_calls_count;
    cppcut_assert_operator(big_write_calls_expected, >=, big_write_calls_count);
    std::copy(data, data + length, std::back_inserter(big_write_data));
    return 0;
}

/*!\test
 * A big, fragmented write transaction initiated by the slave.
 *
 * The fragments are collected and reassembled into a big chunk before
 * forwarding the packet to whom it concerns.
 */
void test_big_slave_transaction()
{
    static const Regs::Register big_write("big write (unit tests)", 0,
                                          REGISTER_MK_VERSION(1, 0, 0),
                                          REGISTER_MK_VERSION(UINT8_MAX, UINT8_MAX, UINT8_MAX),
                                          1024, nullptr, big_write_handler);

    big_write_calls_expected = 0;
    big_write_calls_count = 0;
    Regs::register_zero_for_unit_tests = &big_write;

    std::vector<uint8_t> expected_data;

    auto t = TransactionQueue::Transaction::new_for_queue(
                *queue,
                TransactionQueue::InitialType::SLAVE_BY_SLAVE,
                TransactionQueue::Channel::SPI, false);
    cppcut_assert_not_null(t.get());

    std::array<uint8_t, DCPSYNC_HEADER_SIZE> dcpsync_header { 'c', UINT8_MAX, 0x31, 0xc5, };
    std::array<uint8_t, DCP_HEADER_SIZE + DCP_PACKET_MAX_PAYLOAD_SIZE> reg_0_fragment;
    std::fill(reg_0_fragment.begin(), reg_0_fragment.end(), 0x55);

    /* first fragment */
    dcpsync_header[4] = 0x01;
    dcpsync_header[5] = DCP_HEADER_SIZE;
    reg_0_fragment[0] = DCP_COMMAND_MULTI_WRITE_REGISTER;
    reg_0_fragment[1] = 0;
    reg_0_fragment[2] = 0x00;
    reg_0_fragment[3] = 0x01;
    reg_0_fragment[4] = 0xc1;
    reg_0_fragment.back() = 0xc2;

    read_data->set(dcpsync_header);
    read_data->set(reg_0_fragment.data(), DCP_HEADER_SIZE);
    read_data->set(reg_0_fragment.data() + DCP_HEADER_SIZE,
                   reg_0_fragment.size() - DCP_HEADER_SIZE);
    std::copy(reg_0_fragment.data() + DCP_HEADER_SIZE,
              reg_0_fragment.data() + reg_0_fragment.size(),
              std::back_inserter(expected_data));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "RegIO W: 0 [big write (unit tests)], 256 bytes (incomplete)");

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    cut_assert_true(t->is_input_required());
    mock_messages->check();

    /* second fragment */
    reg_0_fragment[4] = 0xd1;
    reg_0_fragment.back() = 0xd2;
    ++dcpsync_header[3];

    read_data->set(dcpsync_header);
    read_data->set(reg_0_fragment.data(), DCP_HEADER_SIZE);

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    cut_assert_true(t->is_input_required());

    read_data->set(reg_0_fragment.data() + DCP_HEADER_SIZE,
                   reg_0_fragment.size() - DCP_HEADER_SIZE);
    std::copy(reg_0_fragment.data() + DCP_HEADER_SIZE,
              reg_0_fragment.data() + reg_0_fragment.size(),
              std::back_inserter(expected_data));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "RegIO W: 0 [big write (unit tests)], 512 bytes (continued)");

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    cut_assert_true(t->is_input_required());
    mock_messages->check();

    /* third and last fragment, much smaller */
    reg_0_fragment[2] = 0x06;
    reg_0_fragment[3] = 0x00;
    reg_0_fragment[4] = 0xe1;
    reg_0_fragment[9] = 0xe2;
    ++dcpsync_header[3];
    dcpsync_header[4] = 0x00;
    dcpsync_header[5] = DCP_HEADER_SIZE + reg_0_fragment[2];;

    read_data->set(dcpsync_header);
    read_data->set(reg_0_fragment.data(), DCP_HEADER_SIZE);

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    cut_assert_true(t->is_input_required());

    read_data->set(reg_0_fragment.data() + DCP_HEADER_SIZE, reg_0_fragment[2]);
    std::copy(reg_0_fragment.data() + DCP_HEADER_SIZE,
              reg_0_fragment.data() + DCP_HEADER_SIZE + reg_0_fragment[2],
              std::back_inserter(expected_data));

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    cut_assert_false(t->is_input_required());
    mock_messages->check();

    /* and we are done */
    big_write_calls_expected = 1;
    big_write_calls_count = 0;
    big_write_data.clear();

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "RegIO W: 0 [big write (unit tests)], 518 bytes (complete)");

    cut_assert(TransactionQueue::ProcessResult::FINISHED ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    cut_assert_false(t->is_input_required());
    cppcut_assert_equal(big_write_calls_expected, big_write_calls_count);
    cut_assert_equal_memory(expected_data.data(), expected_data.size(),
                            big_write_data.data(), big_write_data.size());

    big_write_data.clear();
}

/*!\test
 * Big chunk received in fragments with a last fragment of size 256 is followed
 * by a terminating empty fragment of size 0.
 */
void test_big_slave_transaction_with_size_of_multiple_of_256()
{
    static const Regs::Register big_write("big write (unit tests)", 0,
                                          REGISTER_MK_VERSION(1, 0, 0),
                                          REGISTER_MK_VERSION(UINT8_MAX, UINT8_MAX, UINT8_MAX),
                                          1024, nullptr, big_write_handler);

    big_write_calls_expected = 0;
    big_write_calls_count = 0;
    Regs::register_zero_for_unit_tests = &big_write;

    std::vector<uint8_t> expected_data;

    auto t = TransactionQueue::Transaction::new_for_queue(
                *queue,
                TransactionQueue::InitialType::SLAVE_BY_SLAVE,
                TransactionQueue::Channel::SPI, false);
    cppcut_assert_not_null(t.get());

    std::array<uint8_t, DCPSYNC_HEADER_SIZE> dcpsync_header { 'c', UINT8_MAX, 0x31, 0xc5, };
    std::array<uint8_t, DCP_HEADER_SIZE + DCP_PACKET_MAX_PAYLOAD_SIZE> reg_0_fragment;
    std::fill(reg_0_fragment.begin(), reg_0_fragment.end(), 0x55);

    /* first fragment */
    dcpsync_header[4] = 0x01;
    dcpsync_header[5] = DCP_HEADER_SIZE;
    reg_0_fragment[0] = DCP_COMMAND_MULTI_WRITE_REGISTER;
    reg_0_fragment[1] = 0;
    reg_0_fragment[2] = 0x00;
    reg_0_fragment[3] = 0x01;
    reg_0_fragment[4] = 0xc1;
    reg_0_fragment.back() = 0xc2;

    read_data->set(dcpsync_header);
    read_data->set(reg_0_fragment.data(), DCP_HEADER_SIZE);
    read_data->set(reg_0_fragment.data() + DCP_HEADER_SIZE,
                   reg_0_fragment.size() - DCP_HEADER_SIZE);
    std::copy(reg_0_fragment.data() + DCP_HEADER_SIZE,
              reg_0_fragment.data() + reg_0_fragment.size(),
              std::back_inserter(expected_data));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "RegIO W: 0 [big write (unit tests)], 256 bytes (incomplete)");

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    cut_assert_true(t->is_input_required());
    mock_messages->check();

    /* second fragment */
    reg_0_fragment[4] = 0xd1;
    reg_0_fragment.back() = 0xd2;
    ++dcpsync_header[3];

    read_data->set(dcpsync_header);
    read_data->set(reg_0_fragment.data(), DCP_HEADER_SIZE);

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    cut_assert_true(t->is_input_required());

    read_data->set(reg_0_fragment.data() + DCP_HEADER_SIZE,
                   reg_0_fragment.size() - DCP_HEADER_SIZE);
    std::copy(reg_0_fragment.data() + DCP_HEADER_SIZE,
              reg_0_fragment.data() + reg_0_fragment.size(),
              std::back_inserter(expected_data));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "RegIO W: 0 [big write (unit tests)], 512 bytes (continued)");

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    cut_assert_true(t->is_input_required());
    mock_messages->check();

    /* third and last fragment, empty */
    reg_0_fragment[2] = 0x00;
    reg_0_fragment[3] = 0x00;
    reg_0_fragment[4] = 0xe1;
    reg_0_fragment[9] = 0xe2;
    ++dcpsync_header[3];
    dcpsync_header[4] = 0x00;
    dcpsync_header[5] = DCP_HEADER_SIZE + reg_0_fragment[2];;

    read_data->set(dcpsync_header);
    read_data->set(reg_0_fragment.data(), DCP_HEADER_SIZE);

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    cut_assert_false(t->is_input_required());
    mock_messages->check();

    /* and we are done */
    big_write_calls_expected = 1;
    big_write_calls_count = 0;
    big_write_data.clear();

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "RegIO W: 0 [big write (unit tests)], 512 bytes (complete)");

    cut_assert(TransactionQueue::ProcessResult::FINISHED ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    cut_assert_false(t->is_input_required());
    cppcut_assert_equal(big_write_calls_expected, big_write_calls_count);
    cut_assert_equal_memory(expected_data.data(), expected_data.size(),
                            big_write_data.data(), big_write_data.size());

    big_write_data.clear();
}

/*!\test
 * In case the slave sends a write command for an unsupported register, the
 * command is ignored and skipped.
 */
void test_bad_register_addresses_are_handled_in_slave_write_transactions()
{
    auto t = TransactionQueue::Transaction::new_for_queue(
                *queue,
                TransactionQueue::InitialType::SLAVE_BY_SLAVE,
                TransactionQueue::Channel::SPI, false);
    cppcut_assert_not_null(t.get());

    static const uint8_t write_unknown_data[] =
    {
        0x90, 0x10, 0xab, 0x7f, 0x00, 0x00, 0xff, 0xff,
        0x50, 0xcf, 0xaa, 0x8e, 0x41, 0x77, 0x18, 0x2e,
        0x91, 0x10, 0xab, 0x7f, 0x01, 0x00, 0xff, 0xff,
        0x51, 0xcf, 0xaa, 0x8e, 0x42, 0x77, 0x18, 0x2e,
        0x92, 0x10, 0xab, 0x7f, 0x02, 0x00, 0xff, 0xff,
        0x52, 0xcf, 0xaa, 0x8e, 0x43, 0x77, 0x18, 0x2e,
        0x93, 0x10, 0xab, 0x7f, 0x03, 0x00, 0xff, 0xff,
        0x53, 0xcf, 0xaa, 0x8e, 0x44, 0x77, 0x18, 0x2e,
        0x94, 0x10, 0xab, 0x7f, 0x04, 0x00, 0xff, 0xff,
        0x54, 0xcf, 0xaa, 0x8e, 0x45, 0x77, 0x18, 0x2e,
        0x95, 0x10, 0xab, 0x7f, 0x05, 0x00, 0xff, 0xff,
        0x55, 0xcf, 0xaa, 0x8e,
    };
    static const uint8_t dcpsync_header_unsupported[] =
    {
        'c', 0x00, 0x4b, 0xd3, 0x00, DCP_HEADER_SIZE + sizeof(write_unknown_data),
    };
    static const uint8_t write_unsupported_register[] =
    {
        DCP_COMMAND_MULTI_WRITE_REGISTER, 0x0a,
        sizeof(write_unknown_data), 0x00,
    };
    static constexpr const size_t internal_skip_command_size = 64;

    read_data->set(dcpsync_header_unsupported);
    read_data->set(write_unsupported_register);
    mock_messages->expect_msg_error_formatted(0, LOG_CRIT,
                                              "BUG: Slave requested register 0x0a, but is not implemented");
    mock_messages->expect_msg_error(0, LOG_ERR, "Transaction %p failed in state %d");
    read_data->set(write_unknown_data, internal_skip_command_size);
    read_data->set(write_unknown_data, sizeof(write_unknown_data) - internal_skip_command_size);

    cut_assert(TransactionQueue::ProcessResult::ERROR ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    /* next transaction from slave is processed, indicating that the data from
     * the previously rejected command has indeed been skipped */
    t->reset_for_slave();

    static const uint8_t dcpsync_header[] = { 'c', 0x00, 0x4b, 0xd4, 0x00, DCP_HEADER_SIZE, };
    static const uint8_t read_device_status[] = { DCP_COMMAND_READ_REGISTER, 0x11, 0x00, 0x00, };

    read_data->set(dcpsync_header);
    read_data->set(read_device_status);

    cut_assert(TransactionQueue::ProcessResult::PUSH_BACK ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG, "RegIO R: 17 [device status], 2 bytes");

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    static const uint8_t expected_answer[] =
    {
        /* DCPSYNC answer */
        'c', UINT8_MAX, 0x80, 0x01, 0x00, DCP_HEADER_SIZE + 0x02,

        /* command header, payload size is 2 bytes */
        DCP_COMMAND_MULTI_READ_REGISTER, 0x11, 0x02, 0x00,

        /* device status all zero */
        0x00, 0x00,
    };
    cut_assert_equal_memory(expected_answer, sizeof(expected_answer),
                            answer_written_to_fifo->data(), answer_written_to_fifo->size());

    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN, std::move(t));
}

/*!\test
 * Register changes are pushed to slave by sending write commands.
 */
void test_register_push_transaction()
{
    cut_assert_true(TransactionQueue::push_register_to_slave(*queue, 17,
                                                             TransactionQueue::Channel::SPI));
    cut_assert_false(queue->empty());

    auto t = queue->pop();
    cppcut_assert_not_null(t.get());
    cut_assert_true(queue->empty());

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG, "RegIO R: 17 [device status], 2 bytes");

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    cut_assert_false(t->is_input_required());

    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    cut_assert_true(t->is_input_required());

    static const uint8_t expected_answer[] =
    {
        /* DCPSYNC command */
        'c', UINT8_MAX, 0x80, 0x01, 0x00, DCP_HEADER_SIZE + 0x02,

        /* command header, payload size is 2 bytes */
        DCP_COMMAND_MULTI_WRITE_REGISTER, 0x11, 0x02, 0x00,

        /* device status all zero */
        0x00, 0x00,
    };
    cut_assert_equal_memory(expected_answer, sizeof(expected_answer),
                            answer_written_to_fifo->data(), answer_written_to_fifo->size());

    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN, std::move(t));
}

static std::unique_ptr<TransactionQueue::Transaction>
create_master_transaction_that_waits_for_ack(std::unique_ptr<TransactionQueue::Transaction> t,
                                             uint16_t expected_serial, uint8_t expected_ttl)
{
    if(t == nullptr)
    {
        cut_assert_true(TransactionQueue::push_register_to_slave(*queue, 17,
                                                                 TransactionQueue::Channel::SPI));
        cut_assert_false(queue->empty());

        t = queue->pop();
        cppcut_assert_not_null(t.get());

        mock_messages->expect_msg_vinfo_if_not_ignored(MESSAGE_LEVEL_TRACE,
                                                       "read 17 handler %p %zu");
        mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG, "RegIO R: 17 [device status], 2 bytes");

        cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
                   t->process(expected_from_slave_fd, expected_to_slave_fd,
                              TransactionQueue::DUMP_SENT_NONE));
    }
    else
    {
        /* as part of NACK handling, send data for \p t again below */
    }

    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    mock_os->check();

    const uint8_t expected_register_answer[] =
    {
        /* DCPSYNC command */
        'c', expected_ttl,
        uint8_t(expected_serial >> 8),
        uint8_t(expected_serial & UINT8_MAX),
        0x00, DCP_HEADER_SIZE + 0x02,

        /* command header, payload size is 2 bytes */
        DCP_COMMAND_MULTI_WRITE_REGISTER, 0x11, 0x02, 0x00,

        /* device status all zero */
        0x00, 0x00,
    };
    cut_assert_equal_memory(expected_register_answer, sizeof(expected_register_answer),
                            answer_written_to_fifo->data(), answer_written_to_fifo->size());

    answer_written_to_fifo->clear();

    return t;
}

/*!\test
 * Register changes require ACK from receiver, but NACK is allowed and handled
 * correctly as well.
 */
void test_register_push_transaction_can_be_rejected()
{
    mock_messages->ignore_messages_above(MESSAGE_LEVEL_MAX);

    /* first try fails */
    auto t =
        create_master_transaction_that_waits_for_ack(nullptr, DCPSYNC_MASTER_SERIAL_MIN, UINT8_MAX);
    cppcut_assert_not_null(t.get());
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_TRACE,
        "Got NACK[9] for 0x8001, resending packet as 0x8002");

    send_dcpsync_nack(DCPSYNC_MASTER_SERIAL_MIN, 9, *t);

    /* second try fails */
    t = create_master_transaction_that_waits_for_ack(std::move(t), DCPSYNC_MASTER_SERIAL_MIN + 1, 9);
    cppcut_assert_not_null(t.get());
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_TRACE,
        "Got NACK[8] for 0x8002, resending packet as 0x8003");

    send_dcpsync_nack(DCPSYNC_MASTER_SERIAL_MIN + 1, 8, *t);

    /* third try succeeds */
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t->process(expected_from_slave_fd, expected_to_slave_fd,
                          TransactionQueue::DUMP_SENT_NONE));

    static const uint8_t expected_answer_second[] =
    {
        /* DCPSYNC command */
        'c', 0x08, 0x80, 0x03, 0x00, DCP_HEADER_SIZE + 0x02,

        /* command header, payload size is 2 bytes */
        DCP_COMMAND_MULTI_WRITE_REGISTER, 0x11, 0x02, 0x00,

        /* device status all zero */
        0x00, 0x00,
    };
    cut_assert_equal_memory(expected_answer_second, sizeof(expected_answer_second),
                            answer_written_to_fifo->data(), answer_written_to_fifo->size());

    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN + 2, std::move(t));
}

/*!\test
 * Accesses to unsupported registers are intercepted when pushing registers to
 * slave.
 */
void test_bad_register_addresses_are_handled_in_push_transactions()
{
    mock_messages->expect_msg_error_formatted(0, LOG_CRIT,
                                              "BUG: Master requested register 0x2a, but is not implemented");

    cut_assert_false(TransactionQueue::push_register_to_slave(*queue, 42,
                                                              TransactionQueue::Channel::SPI));
    cut_assert_true(queue->empty());
}

/*!\test
 * Accesses to unsupported registers are intercepted in fragmented
 * transactions.
 */
void test_bad_register_addresses_are_handled_in_fragmented_transactions()
{
    mock_messages->expect_msg_error_formatted(0, LOG_CRIT,
                                              "BUG: Master requested register 0x2a, but is not implemented");

    static const uint8_t dummy = 23U;
    auto frags(TransactionQueue::fragments_from_data(*queue,
                                                     &dummy, sizeof(dummy),
                                                     42, TransactionQueue::Channel::SPI));
    cut_assert_true(frags.empty());
}

/*!\test
 * While waiting for a new command, the slave sends an ACK packet.
 *
 * Caller must handle this situation and call
 * #TransactionQueue::Transaction::process_out_of_order_ack() for the
 * transaction.
 */
void test_waiting_for_command_interrupted_by_ack()
{
    mock_messages->ignore_messages_above(MESSAGE_LEVEL_MAX);

    auto to_be_acked =
        create_master_transaction_that_waits_for_ack(nullptr, DCPSYNC_MASTER_SERIAL_MIN, UINT8_MAX);
    auto t = TransactionQueue::Transaction::new_for_queue(
                *queue,
                TransactionQueue::InitialType::SLAVE_BY_SLAVE,
                TransactionQueue::Channel::SPI, false);
    cppcut_assert_not_null(t.get());

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_TRACE,
        "Got ACK for 0x8001 while waiting for new command packet");

    try
    {
        send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN, std::move(t),
                         TransactionQueue::ProcessResult::ERROR, true);
        cut_fail("Missing exception");
    }
    catch(const TransactionQueue::OOOAckException &e)
    {
        cppcut_assert_equal(uint16_t(DCPSYNC_MASTER_SERIAL_MIN), e.serial_);

        /* caller must handle this ACK by finding the transaction for the given
         * serial and processing it */
        cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
                   to_be_acked->process_out_of_order_ack(e));
    }
    catch(...)
    {
        cut_fail("Wrong exception");
    }

    cut_assert(TransactionQueue::ProcessResult::FINISHED ==
               to_be_acked->process(expected_from_slave_fd,
                                    expected_to_slave_fd,
                                    TransactionQueue::DUMP_SENT_NONE));

    /* now we could go on processing the interrupted transaction */
}

/*!\test
 * While waiting for a new command, the slave sends an NACK packet.
 *
 * Caller must handle this situation and call
 * #TransactionQueue::Transaction::process_out_of_order_nack() for the
 * transaction.
 */
void test_waiting_for_command_interrupted_by_nack()
{
    mock_messages->ignore_messages_above(MESSAGE_LEVEL_MAX);

    auto to_be_acked =
        create_master_transaction_that_waits_for_ack(nullptr, DCPSYNC_MASTER_SERIAL_MIN, UINT8_MAX);
    auto t = TransactionQueue::Transaction::new_for_queue(
                *queue,
                TransactionQueue::InitialType::SLAVE_BY_SLAVE,
                TransactionQueue::Channel::SPI, false);
    cppcut_assert_not_null(t.get());

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_TRACE,
        "Got NACK[9] for 0x8001 while waiting for new command packet");

    try
    {
        send_dcpsync_nack(DCPSYNC_MASTER_SERIAL_MIN, 9,
                          *t, TransactionQueue::ProcessResult::ERROR);
        cut_fail("Missing exception");
    }
    catch(const TransactionQueue::OOONackException &e)
    {
        cppcut_assert_equal(uint16_t(DCPSYNC_MASTER_SERIAL_MIN), e.serial_);
        cppcut_assert_equal(uint8_t(9), e.ttl_);

        /* caller must handle this NACK by finding the transaction for the given
         * serial and processing it */
        mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_TRACE,
                                                  "Got NACK[9] for 0x8001, resending packet as 0x8002");
        cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
                   to_be_acked->process_out_of_order_nack(e));

    }
    catch(...)
    {
        cut_fail("Wrong exception");
    }

    /* resend and succeed by receiving the ACK */
    to_be_acked =
        create_master_transaction_that_waits_for_ack(std::move(to_be_acked),
                                                     DCPSYNC_MASTER_SERIAL_MIN + 1, 9);
    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN + 1, std::move(to_be_acked));

    /* now we could go on processing the interrupted transaction */
}

/*!\test
 * While waiting for an ACK, the slave sends an ACK packet for a different
 * transaction.
 *
 * Caller must handle this situation and call
 * #TransactionQueue::Transaction::process_out_of_order_ack() for the
 * transaction.
 */
void test_waiting_for_master_ack_interrupted_by_ack_for_other_transaction()
{
    auto to_be_acked =
        create_master_transaction_that_waits_for_ack(nullptr, DCPSYNC_MASTER_SERIAL_MIN, UINT8_MAX);
    auto t =
        create_master_transaction_that_waits_for_ack(nullptr, DCPSYNC_MASTER_SERIAL_MIN + 1, UINT8_MAX);

    try
    {
        send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN, std::move(t),
                         TransactionQueue::ProcessResult::ERROR, true);
        cut_fail("Missing exception");
    }
    catch(const TransactionQueue::OOOAckException &e)
    {
        cppcut_assert_equal(uint16_t(DCPSYNC_MASTER_SERIAL_MIN), e.serial_);

        /* caller must handle this ACK by finding the transaction for the given
         * serial and processing it */
        cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
                   to_be_acked->process_out_of_order_ack(e));
    }
    catch(...)
    {
        cut_fail("Wrong exception");
    }

    cut_assert(TransactionQueue::ProcessResult::FINISHED ==
               to_be_acked->process(expected_from_slave_fd,
                                    expected_to_slave_fd,
                                    TransactionQueue::DUMP_SENT_NONE));

    /* now we could go on processing the interrupted transaction */
}

/*!\test
 * While waiting for an ACK, the slave sends a NACK packet for a different
 * transaction.
 *
 * Caller must handle this situation and call
 * #TransactionQueue::Transaction::process_out_of_order_nack() for the
 * transaction.
 */
void test_waiting_for_master_ack_interrupted_by_nack_for_other_transaction()
{
    mock_messages->ignore_messages_above(MESSAGE_LEVEL_MAX);

    auto to_be_acked =
        create_master_transaction_that_waits_for_ack(nullptr, DCPSYNC_MASTER_SERIAL_MIN, UINT8_MAX);
    auto t =
        create_master_transaction_that_waits_for_ack(nullptr, DCPSYNC_MASTER_SERIAL_MIN + 1, UINT8_MAX);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_TRACE,
        "Got NACK[9] for 0x8001 while waiting for 0x8002 ACK");

    try
    {
        send_dcpsync_nack(DCPSYNC_MASTER_SERIAL_MIN, 9, *t, TransactionQueue::ProcessResult::ERROR);
        cut_fail("Missing exception");
    }
    catch(const TransactionQueue::OOONackException &e)
    {
        cppcut_assert_equal(uint16_t(DCPSYNC_MASTER_SERIAL_MIN), e.serial_);
        cppcut_assert_equal(uint8_t(9), e.ttl_);

        /* caller must handle this NACK by finding the transaction for the given
         * serial and processing it */
        mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_TRACE,
                                                  "Got NACK[9] for 0x8001, resending packet as 0x8003");
        cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
                   to_be_acked->process_out_of_order_nack(e));
    }
    catch(...)
    {
        cut_fail("Wrong exception");
    }

    /* resend and succeed by receiving the ACK */
    to_be_acked =
        create_master_transaction_that_waits_for_ack(std::move(to_be_acked),
                                                     DCPSYNC_MASTER_SERIAL_MIN + 2, 9);
    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN + 2, std::move(to_be_acked));

    /* now we could go on processing the interrupted transaction */
}

/*!\test
 * While waiting for an ACK/NACK, the slave may start a new transaction instead.
 *
 * This situation arises if our transaction has not made it all the way down to
 * the hardware level. The SPI slave may have started a transaction in the
 * meantime because it doesn't know anything about our transaction yet. We need
 * to suspend our own transfer and move it back to our queue if this happens.
 */
void test_waiting_for_master_ack_interrupted_by_slave_read_transaction()
{
    auto keys(static_cast<char **>(g_malloc_n(2, sizeof(char *))));
    keys[0] = g_strdup("appliance:appliance:id");
    keys[1] = nullptr;
    configproxy_init();
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG,
                                              "Registered local key \"@dcpd:appliance:appliance:id\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Registered 1 local key for \"dcpd\"");
    configproxy_register_local_configuration_owner("dcpd", keys);

    auto t_push =
        create_master_transaction_that_waits_for_ack(nullptr, DCPSYNC_MASTER_SERIAL_MIN, UINT8_MAX);

    /* colliding slave read transaction */
    static const uint8_t dcpsync_header[] = { 'c', UINT8_MAX, 0x60, 0xc7, 0x00, DCP_HEADER_SIZE, };
    static const uint8_t read_reg_87_appliance_id[] = { DCP_COMMAND_READ_REGISTER, 0x57, 0x00, 0x00, };

    read_data->set(dcpsync_header);
    read_data->set(read_reg_87_appliance_id);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG,
        "Collision: New packet 0x60c7 while waiting for 0x8001 ACK");

    std::unique_ptr<TransactionQueue::Transaction> t_slave;

    try
    {
        t_push->process(expected_from_slave_fd, expected_to_slave_fd,
                        TransactionQueue::DUMP_SENT_NONE);
        cut_fail("Missing exception");
    }
    catch(TransactionQueue::CollisionException &e)
    {
        t_slave = std::move(e.transaction_);
    }
    catch(...)
    {
        cut_fail("Wrong exception");
    }

    cppcut_assert_not_null(t_slave.get());

    /* the push transaction is moved to some other place for deferred
     * processing, a new transaction has been allocated for the newly detected
     * slave transaction; now continue processing that one */
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG, "RegIO R: 87 [appliance ID], 5 bytes");

    cut_assert(TransactionQueue::ProcessResult::PUSH_BACK ==
               t_slave->process(expected_from_slave_fd, expected_to_slave_fd,
                                         TransactionQueue::DUMP_SENT_NONE));
    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t_slave->process(expected_from_slave_fd, expected_to_slave_fd,
                                TransactionQueue::DUMP_SENT_NONE));

    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);
    mock_os->expect_os_write_from_buffer_callback(0, read_answer);

    cut_assert(TransactionQueue::ProcessResult::IN_PROGRESS ==
               t_slave->process(expected_from_slave_fd, expected_to_slave_fd,
                                TransactionQueue::DUMP_SENT_NONE));

    mock_os->check();

    static const uint8_t expected_answer_to_collision[] =
    {
        /* DCPSYNC answer */
        'c', UINT8_MAX, 0x80, 0x02, 0x00, DCP_HEADER_SIZE + 0x05,

        /* command header, payload size is 5 bytes */
        DCP_COMMAND_MULTI_READ_REGISTER, 0x57, 0x05, 0x00,

        /* string: "strbo" */
        0x73, 0x74, 0x72, 0x62, 0x6f,
    };
    cut_assert_equal_memory(expected_answer_to_collision,
                            sizeof(expected_answer_to_collision),
                            answer_written_to_fifo->data(), answer_written_to_fifo->size());

    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN + 1, std::move(t_slave));

    /* continue with our push transaction, no resend because there was no NACK,
     * just an interspersed communication; this time we get the ACK and no
     * interruption occurs */
    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN, std::move(t_push));

    configproxy_deinit();
}

}

/*!@}*/

#endif /* !LOGGED_LOCKS_ENABLED  */
