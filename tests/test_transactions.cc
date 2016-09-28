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

#include <cppcutter.h>
#include <array>
#include <algorithm>

#include "transactions.h"
#include "registers.h"
#include "dcpdefs.h"

#include "mock_dcpd_dbus.hh"
#include "mock_connman.hh"
#include "mock_messages.hh"
#include "mock_os.hh"

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

    void set(const uint8_t *data, size_t data_size, int err = 0)
    {
        set(data, data_size, err, data_size);
    }

    void set(const uint8_t *data, size_t data_size, int err, ssize_t ret)
    {
        partial_.push_back(read_data_partial_t(std::vector<uint8_t>(data, data + data_size), err, ret));
    }
};

ssize_t (*os_read)(int fd, void *dest, size_t count) = NULL;
ssize_t (*os_write)(int fd, const void *buf, size_t count) = NULL;

namespace dcp_transaction_tests_queue
{

static MockMessages *mock_messages;

void cut_setup()
{
    os_read = NULL;
    os_write = NULL;

    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    register_zero_for_unit_tests = NULL;
    transaction_init_allocator();
}

void cut_teardown()
{
    mock_messages->check();
    mock_messages_singleton = nullptr;
    delete mock_messages;
    mock_messages = nullptr;
}

/*!\test
 * Single transactions can be allocated and deallocated for SPI channel.
 */
void test_allocation_and_deallocation_of_single_transaction_object_spi()
{
    struct transaction *t = transaction_alloc(TRANSACTION_ALLOC_MASTER_FOR_DRCPD_DATA,
                                              TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);
    cppcut_assert_equal(TRANSACTION_CHANNEL_SPI, transaction_get_channel(t));
    cut_assert_false(transaction_is_pinned(t));

    transaction_free(&t);
    cppcut_assert_null(t);
}

/*!\test
 * Transactions can be pinned in memory.
 */
void test_pinned_transaction_object()
{
    struct transaction *t = transaction_alloc(TRANSACTION_ALLOC_MASTER_FOR_DRCPD_DATA,
                                              TRANSACTION_CHANNEL_SPI, true);
    cppcut_assert_not_null(t);
    cut_assert_true(transaction_is_pinned(t));
}

/*!\test
 * Single transactions can be allocated and deallocated for IP channel.
 */
void test_allocation_and_deallocation_of_single_transaction_object_inet()
{
    struct transaction *t = transaction_alloc(TRANSACTION_ALLOC_MASTER_FOR_DRCPD_DATA,
                                              TRANSACTION_CHANNEL_INET, false);
    cppcut_assert_not_null(t);
    cppcut_assert_equal(TRANSACTION_CHANNEL_INET, transaction_get_channel(t));

    transaction_free(&t);
    cppcut_assert_null(t);
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

    struct transaction *t =
        transaction_fragments_from_data(payload_data, sizeof(payload_data),
                                        71, TRANSACTION_CHANNEL_SPI);
    cppcut_assert_not_null(t);

    transaction_free(&t);
    cppcut_assert_null(t);
}

/*!
 * Protect ourselves against infinite loop in case of broken SUT code.
 */
static constexpr size_t max_allocs = 1000;

/*!
 * Use up all transaction objects.
 */
static size_t allocate_all_transactions(std::array<struct transaction *, max_allocs> &dest)
{
    size_t count = 0;

    for(size_t i = 0; i < dest.size(); ++i)
    {
        dest[i] = transaction_alloc(TRANSACTION_ALLOC_MASTER_FOR_DRCPD_DATA,
                                    TRANSACTION_CHANNEL_SPI, false);

        if(dest[i] == NULL)
            break;

        ++count;
    }

    cppcut_assert_operator(size_t(0), <, count);
    cppcut_assert_operator(max_allocs, >, count);

    return count;
}

/*!
 * Queue up first \p count transactions in passed array.
 */
static struct transaction *
queue_up_all_transactions(std::array<struct transaction *, max_allocs> &objects,
                          size_t count)
{
    struct transaction *head = NULL;

    for(size_t i = 0; i < count; ++i)
    {
        cppcut_assert_not_null(objects[i]);
        transaction_queue_add(&head, objects[i]);
        cppcut_assert_equal(objects[0], head);
    }

    return head;
}

/*!\test
 * Allocate all transaction objects, free them, allocate them again.
 */
void test_allocation_and_deallocation_of_all_transaction_objects()
{
    std::array<struct transaction *, max_allocs> objects;
    const size_t count = allocate_all_transactions(objects);

    for(size_t i = 0; i < count; ++i)
    {
        cppcut_assert_not_null(objects[i]);
        transaction_free(&objects[i]);
    }

    const size_t count_second_time = allocate_all_transactions(objects);
    cppcut_assert_equal(count, count_second_time);
}


/*!\test
 * Allocate all transaction objects, free one in the middle, allocate it again.
 */
void test_allocation_of_all_transaction_objects_reallocate_one()
{
    std::array<struct transaction *, max_allocs> objects;
    const size_t count = allocate_all_transactions(objects);

    const size_t reused_index = count / 4;
    struct transaction *const reused = objects[reused_index];
    cppcut_assert_not_null(reused);
    transaction_free(&objects[reused_index]);

    cppcut_assert_equal(reused, transaction_alloc(TRANSACTION_ALLOC_MASTER_FOR_DRCPD_DATA,
                                                  TRANSACTION_CHANNEL_SPI, false));
    cppcut_assert_null(transaction_alloc(TRANSACTION_ALLOC_MASTER_FOR_DRCPD_DATA,
                                         TRANSACTION_CHANNEL_SPI, false));
}

/*!\test
 * Allocate all transaction objects, queue them up, deallocate by freeing head.
 */
void test_deallocation_of_linked_list()
{
    std::array<struct transaction *, max_allocs> objects;
    const size_t count = allocate_all_transactions(objects);
    struct transaction *head = queue_up_all_transactions(objects, count);

    transaction_free(&head);
    cppcut_assert_null(head);

    const size_t count_second_time = allocate_all_transactions(objects);
    cppcut_assert_equal(count, count_second_time);
}

/*!\test
 * Allocate all transaction objects, queue them up, dequeue one in the middle.
 */
void test_dequeue_from_middle_of_linked_list()
{
    std::array<struct transaction *, max_allocs> objects;
    const size_t count = allocate_all_transactions(objects);
    struct transaction *head = queue_up_all_transactions(objects, count);

    const size_t removed_index = count / 3;
    struct transaction *const removed = objects[removed_index];
    cppcut_assert_not_null(removed);

    cppcut_assert_equal(removed, transaction_queue_remove(&objects[removed_index]));
    cppcut_assert_equal(objects[removed_index + 1], objects[removed_index]);

    transaction_free(&head);

    const size_t count_second_time = allocate_all_transactions(objects);
    cppcut_assert_equal(count - 1, count_second_time);
}

/*!\test
 * Dequeue single element from list.
 */
void test_dequeue_from_list_of_length_one()
{
    struct transaction *const head = transaction_alloc(TRANSACTION_ALLOC_MASTER_FOR_DRCPD_DATA,
                                                       TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(head);

    struct transaction *head_ptr = head;
    cppcut_assert_equal(head, transaction_queue_remove(&head_ptr));
    cppcut_assert_null(head_ptr);
}

static struct transaction *
make_short_queue(std::array<struct transaction *, max_allocs> &objects,
                 const size_t count)
{
    for(size_t i = 0; i < count; ++i)
    {
        objects[i] = transaction_alloc(TRANSACTION_ALLOC_MASTER_FOR_DRCPD_DATA,
                                       TRANSACTION_CHANNEL_SPI, false);
        cppcut_assert_not_null(objects[i]);
    }

    struct transaction *const head = queue_up_all_transactions(objects, count);
    cppcut_assert_not_null(head);

    return head;
}

void test_find_transaction_by_existing_serial()
{
    static constexpr size_t count = 4;
    std::array<struct transaction *, max_allocs> objects;
    struct transaction *head = make_short_queue(objects, count);

    for(size_t i = 0; i < count; ++i)
        cppcut_assert_equal(objects[i],
                            transaction_queue_find_by_serial(head, DCPSYNC_MASTER_SERIAL_MIN + i));

    transaction_free(&head);
    cppcut_assert_null(head);
}

void test_find_transaction_by_nonexistent_serial()
{
    static constexpr size_t count = 4;
    std::array<struct transaction *, max_allocs> objects;
    struct transaction *head = make_short_queue(objects, count);

    cppcut_assert_null(transaction_queue_find_by_serial(head, DCPSYNC_MASTER_SERIAL_MIN + count));
    cppcut_assert_null(transaction_queue_find_by_serial(head, DCPSYNC_MASTER_SERIAL_MAX));
    cppcut_assert_null(transaction_queue_find_by_serial(head, DCPSYNC_MASTER_SERIAL_MAX - 1));
    cppcut_assert_null(transaction_queue_find_by_serial(head, DCPSYNC_SLAVE_SERIAL_MIN));
    cppcut_assert_null(transaction_queue_find_by_serial(head, DCPSYNC_SLAVE_SERIAL_MAX));
    cppcut_assert_null(transaction_queue_find_by_serial(head, DCPSYNC_SLAVE_SERIAL_MIN + 1));
    cppcut_assert_null(transaction_queue_find_by_serial(head, DCPSYNC_SLAVE_SERIAL_MAX - 1));

    mock_messages->expect_msg_error_formatted(0, LOG_CRIT,
        "BUG: Tried to find transaction with invalid serial 0x8000");
    cppcut_assert_null(transaction_queue_find_by_serial(head, DCPSYNC_MASTER_SERIAL_INVALID));
    mock_messages->expect_msg_error_formatted(0, LOG_CRIT,
        "BUG: Tried to find transaction with invalid serial 0x0000");
    cppcut_assert_null(transaction_queue_find_by_serial(head, DCPSYNC_SLAVE_SERIAL_INVALID));

    transaction_free(&head);
    cppcut_assert_null(head);
}

static void run_cut_transaction_from_queue_test(const size_t count, const size_t removed)
{
    cppcut_assert_operator(count, >, size_t(1));
    cppcut_assert_operator(count, >, removed);

    std::array<struct transaction *, max_allocs> objects;
    struct transaction *head = make_short_queue(objects, count);

    struct transaction *next = transaction_queue_cut_element(objects[removed]);
    cppcut_assert_not_null(next);

    if(removed < count - 1)
        cppcut_assert_equal(objects[removed + 1], next);
    else
        cppcut_assert_equal(objects[0], next);

    /* need to fix up head pointer if head was cut */
    if(removed == 0)
        head = next;

    for(size_t i = 0; i < count; ++i)
    {
        const uint16_t serial = DCPSYNC_MASTER_SERIAL_MIN + i;

        if(i != removed)
        {
            cppcut_assert_equal(objects[i],
                                transaction_queue_find_by_serial(head, serial));
            cppcut_assert_null(transaction_queue_find_by_serial(objects[removed], serial));
        }
        else
        {
            cppcut_assert_null(transaction_queue_find_by_serial(head, serial));
            cppcut_assert_equal(objects[i],
                                transaction_queue_find_by_serial(objects[removed], serial));
        }
    }

    transaction_free(&objects[removed]);
    transaction_free(&head);
    cppcut_assert_null(head);
}

void test_cut_transaction_from_queue()
{
    run_cut_transaction_from_queue_test(5, 2);
}

void test_cut_head_from_queue()
{
    run_cut_transaction_from_queue_test(5, 0);
}

void test_cut_tail_from_queue()
{
    run_cut_transaction_from_queue_test(5, 4);
}

void test_cut_transaction_from_itself()
{
    struct transaction *head =
        transaction_alloc(TRANSACTION_ALLOC_MASTER_FOR_DRCPD_DATA,
                          TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(head);

    struct transaction *next = transaction_queue_cut_element(head);
    cppcut_assert_equal(head, next);

    cppcut_assert_equal(next,
                        transaction_queue_find_by_serial(next, DCPSYNC_MASTER_SERIAL_MIN));

    transaction_free(&head);
    cppcut_assert_null(head);
}

};

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

static MockMessages *mock_messages;
static MockOs *mock_os;
static MockConnman *mock_connman;

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

    mock_connman = new MockConnman();
    cppcut_assert_not_null(mock_connman);
    mock_connman->init();
    mock_connman_singleton = mock_connman;

    register_zero_for_unit_tests = NULL;

    read_data = new read_data_t;
    cppcut_assert_not_null(read_data);

    answer_written_to_fifo = new std::vector<uint8_t>;

    transaction_init_allocator();
}

void cut_teardown()
{
    mock_messages->check();
    mock_os->check();
    mock_connman->check();

    mock_messages_singleton = nullptr;
    mock_os_singleton = nullptr;
    mock_connman_singleton = nullptr;

    delete mock_messages;
    delete mock_os;
    delete mock_connman;

    mock_messages = nullptr;
    mock_os = nullptr;
    mock_connman = nullptr;

    delete read_data;
    read_data = nullptr;

    delete answer_written_to_fifo;
    answer_written_to_fifo = nullptr;
}

static void send_dcpsync_ack(uint16_t serial, struct transaction *t,
                             enum transaction_process_status last_status = TRANSACTION_FINISHED,
                             bool process_only_once = false,
                             struct transaction_exception *exception = nullptr)
{
    cppcut_assert_not_null(t);

    const uint8_t dcpsync_ack[DCPSYNC_HEADER_SIZE] =
    {
        'a', 0x00,
        uint8_t(serial >> 8), uint8_t(serial & UINT8_MAX),
        0x00, 0x00,
    };

    read_data->set(dcpsync_ack);

    struct transaction_exception e;

    if(exception == nullptr)
        exception = &e;

    if(!process_only_once)
        cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                            transaction_process(t, expected_from_slave_fd, expected_to_slave_fd,
                                                exception));

    cppcut_assert_equal(last_status,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd,
                                            exception));
}

/*!\test
 * A whole simple register read transaction initiated by the slave device, one
 * byte of payload.
 */
void test_register_read_request_size_1_transaction()
{
    mock_messages->expect_msg_info_formatted("Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_info_formatted("Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_info_formatted("Allocated shutdown guard \"upnpname\"");
    register_init("12:23:34:45:56:67", "ab:bc:ce:de:ef:f0", "/somewhere", NULL);

    struct transaction *t = transaction_alloc(TRANSACTION_ALLOC_SLAVE_BY_SLAVE,
                                              TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

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

    struct transaction_exception e;
    cppcut_assert_equal(TRANSACTION_PUSH_BACK,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

    static auto *dummy_connman_iface_data =
        reinterpret_cast<struct ConnmanInterfaceData *>(123456);

    mock_messages->expect_msg_info("read 55 handler %p %zu");
    mock_connman->expect_find_active_primary_interface(dummy_connman_iface_data,
        "12:23:34:45:56:67", "12:23:34:45:56:67", "ab:bc:ce:de:ef:f0");
    mock_connman->expect_get_dhcp_mode(CONNMAN_DHCP_MANUAL, dummy_connman_iface_data, true);
    mock_connman->expect_free_interface_data(dummy_connman_iface_data);

    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);

    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

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

    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN, t);

    transaction_free(&t);
    cppcut_assert_null(t);

    register_deinit();
}

/*!\test
 * A whole simple register read transaction initiated by the slave device,
 * several bytes of payload.
 */
void test_register_read_request_size_16_transaction()
{
    mock_messages->expect_msg_info_formatted("Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_info_formatted("Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_info_formatted("Allocated shutdown guard \"upnpname\"");
    register_init("12:23:34:45:56:67", "ab:bc:ce:de:ef:f0", "/somewhere", NULL);

    struct transaction *t = transaction_alloc(TRANSACTION_ALLOC_SLAVE_BY_SLAVE,
                                              TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

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

    struct transaction_exception e;
    cppcut_assert_equal(TRANSACTION_PUSH_BACK,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

    static auto *dummy_connman_iface_data =
        reinterpret_cast<struct ConnmanInterfaceData *>(123456);

    mock_messages->expect_msg_info("read 56 handler %p %zu");
    mock_connman->expect_find_active_primary_interface(dummy_connman_iface_data,
        "12:23:34:45:56:67", "12:23:34:45:56:67", "ab:bc:ce:de:ef:f0");
    mock_connman->expect_get_ipv4_address_string("111.222.255.100",
                                                 dummy_connman_iface_data,
                                                 false, 16);
    mock_connman->expect_free_interface_data(dummy_connman_iface_data);

    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);

    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

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

    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN, t);

    transaction_free(&t);
    cppcut_assert_null(t);

    register_deinit();
}

/*!\test
 * A whole multi-step register read transaction initiated by the slave device.
 */
void test_register_multi_step_read_request_transaction()
{
    mock_messages->expect_msg_info_formatted("Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_info_formatted("Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_info_formatted("Allocated shutdown guard \"upnpname\"");
    register_init("12:34:56:78:9A:BC", NULL, NULL, NULL);

    struct transaction *t = transaction_alloc(TRANSACTION_ALLOC_SLAVE_BY_SLAVE,
                                              TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

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

    struct transaction_exception e;
    cppcut_assert_equal(TRANSACTION_PUSH_BACK,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

    mock_messages->expect_msg_info("read 51 handler %p %zu");
    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);

    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

    static const uint8_t expected_answer[] =
    {
        /* DCPSYNC answer */
        'c', UINT8_MAX, 0x80, 0x01, 0x00, DCP_HEADER_SIZE + 0x12,

        /* command header, payload size is 18 bytes */
        DCP_COMMAND_MULTI_READ_REGISTER, 0x33, 0x12, 0x00,

        /* MAC address 12:34:56:78:9A:BC */
        0x31, 0x32, 0x3a, 0x33, 0x34, 0x3a, 0x35, 0x36,
        0x3a, 0x37, 0x38, 0x3a, 0x39, 0x41, 0x3a, 0x42,
        0x43, 0x00
    };
    cut_assert_equal_memory(expected_answer, sizeof(expected_answer),
                            answer_written_to_fifo->data(), answer_written_to_fifo->size());

    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN, t);

    transaction_free(&t);
    cppcut_assert_null(t);

    register_deinit();
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

static bool return_big_data(struct dynamic_buffer *buffer)
{
    cut_assert(dynamic_buffer_is_empty(buffer));
    cut_assert(dynamic_buffer_resize(buffer, sizeof(big_data)));

    memcpy(buffer->data, big_data, sizeof(big_data));
    buffer->pos = sizeof(big_data);

    return true;
}

/*!\test
 * Reading a dynamically-size, big register by slave results in fragments being
 * generated on-the-fly.
 */
void test_big_data_is_sent_to_slave_in_fragments()
{
    mock_messages->expect_msg_info_formatted("Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_info_formatted("Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_info_formatted("Allocated shutdown guard \"upnpname\"");
    register_init("00:11:ff:ee:22:dd", "dd:22:ee:ff:11:00", "/somewhere", NULL);

    struct transaction *t = transaction_alloc(TRANSACTION_ALLOC_SLAVE_BY_SLAVE,
                                              TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

    struct transaction *head = t;

    /* append another transaction to the end to check if the fragmentation code
     * accidently cuts off the end of the queue */
    struct transaction *tail = transaction_alloc(TRANSACTION_ALLOC_MASTER_FOR_DRCPD_DATA,
                                                 TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(tail);
    transaction_queue_add(&head, tail);

    static const struct dcp_register_t big_register =
    {
        .address = 0,
        .minimum_protocol_version = { .code = REGISTER_MK_VERSION(1, 0, 0) },
        .maximum_protocol_version = { .code = REGISTER_MK_VERSION(UINT8_MAX, UINT8_MAX, UINT8_MAX) },
        .flags = 0,
        .max_data_size = 0,
        .read_handler = NULL,
        .read_handler_dynamic = return_big_data,
        .write_handler = NULL,
    };

    register_zero_for_unit_tests = &big_register;

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

    struct transaction_exception e;
    cppcut_assert_equal(TRANSACTION_PUSH_BACK,
                        transaction_process(head, expected_from_slave_fd, expected_to_slave_fd, &e));
    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(head, expected_from_slave_fd, expected_to_slave_fd, &e));

    /* the big transaction has been scattered over multiple transactions, head
     * element has been reused so that it contains the first fragment now */
    cppcut_assert_equal(head, t);
    cppcut_assert_not_equal(head, tail);

    uint16_t master_serial = DCPSYNC_MASTER_SERIAL_MIN + 1;
    size_t bytes_left = sizeof(big_data);
    cppcut_assert_operator(size_t(DCP_PACKET_MAX_PAYLOAD_SIZE), <, bytes_left);

    while(bytes_left > 0)
    {
        answer_written_to_fifo->clear();
        mock_os->expect_os_write_from_buffer_callback(read_answer);
        mock_os->expect_os_write_from_buffer_callback(read_answer);
        mock_os->expect_os_write_from_buffer_callback(read_answer);

        const enum transaction_process_status status =
            transaction_process(head, expected_from_slave_fd, expected_to_slave_fd, &e);
        cppcut_assert_equal(TRANSACTION_IN_PROGRESS, status);

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
            send_dcpsync_ack(master_serial, t);

            t = transaction_queue_remove(&head);
            cppcut_assert_not_null(t);
            cppcut_assert_not_null(head);
            cppcut_assert_not_equal(t, tail);
            transaction_free(&t);
        }
        else
            send_dcpsync_ack(master_serial, t, TRANSACTION_PUSH_BACK);

        bytes_left -= expected_data_size;
        ++master_serial;
    }

    cppcut_assert_equal(head, tail);

    t = transaction_queue_remove(&head);
    cppcut_assert_null(head);
    cppcut_assert_equal(t, tail);
    transaction_free(&t);

    register_deinit();
}

};

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

static MockMessages *mock_messages;
static MockOs *mock_os;
static MockDcpdDBus *mock_dcpd_dbus;

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

    mock_dcpd_dbus = new MockDcpdDBus();
    cppcut_assert_not_null(mock_dcpd_dbus);
    mock_dcpd_dbus->init();
    mock_dcpd_dbus_singleton = mock_dcpd_dbus;

    register_zero_for_unit_tests = NULL;

    read_data = new read_data_t;
    cppcut_assert_not_null(read_data);

    answer_written_to_fifo = new std::vector<uint8_t>;

    transaction_init_allocator();

    mock_messages->expect_msg_info_formatted("Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_info_formatted("Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_info_formatted("Allocated shutdown guard \"upnpname\"");
    register_init(NULL, NULL, NULL, NULL);
}

void cut_teardown()
{
    register_deinit();

    mock_messages->check();
    mock_os->check();
    mock_dcpd_dbus->check();

    mock_messages_singleton = nullptr;
    mock_os_singleton = nullptr;
    mock_dcpd_dbus_singleton = nullptr;

    delete mock_messages;
    delete mock_os;
    delete mock_dcpd_dbus;

    mock_messages = nullptr;
    mock_os = nullptr;
    mock_dcpd_dbus = nullptr;

    delete read_data;
    read_data = nullptr;

    delete answer_written_to_fifo;
    answer_written_to_fifo = nullptr;
}

static void send_dcpsync_ack(uint16_t serial, struct transaction *t,
                             enum transaction_process_status last_status = TRANSACTION_FINISHED,
                             bool process_only_once = false,
                             struct transaction_exception *exception = nullptr)
{
    cppcut_assert_not_null(t);

    const uint8_t dcpsync_ack[DCPSYNC_HEADER_SIZE] =
    {
        'a', 0x00,
        uint8_t(serial >> 8), uint8_t(serial & UINT8_MAX),
        0x00, 0x00,
    };

    read_data->set(dcpsync_ack);

    struct transaction_exception e;

    if(exception == nullptr)
        exception = &e;

    if(!process_only_once)
        cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                            transaction_process(t, expected_from_slave_fd, expected_to_slave_fd,
                                                exception));

    cppcut_assert_equal(last_status,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd,
                                            exception));
}

static void send_dcpsync_nack(uint16_t serial, uint8_t ttl,
                              struct transaction *t,
                              enum transaction_process_status expected_status = TRANSACTION_IN_PROGRESS,
                              struct transaction_exception *exception = nullptr)
{
    cppcut_assert_not_null(t);

    const uint8_t dcpsync_nack[DCPSYNC_HEADER_SIZE] =
    {
        'n', ttl,
        uint8_t(serial >> 8), uint8_t(serial & UINT8_MAX),
        0x00, 0x00,
    };

    read_data->set(dcpsync_nack, DCPSYNC_HEADER_SIZE);

    struct transaction_exception e;

    if(exception == nullptr)
        exception = &e;

    cppcut_assert_equal(expected_status,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd,
                                            exception));
}

/*!\test
 * A whole (former) simple register write transaction initiated by the slave
 * device.
 */
void test_register_write_request_transaction()
{
    struct transaction *t = transaction_alloc(TRANSACTION_ALLOC_SLAVE_BY_SLAVE,
                                              TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

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

    struct transaction_exception e;
    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

    mock_messages->expect_msg_info("write 54 handler %p %zu");
    cppcut_assert_equal(TRANSACTION_FINISHED,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

    transaction_free(&t);
    cppcut_assert_null(t);
}

/*!\test
 * Simple register write transactions are not supported anymore.
 *
 * This was done to keep the implementation a bit simpler.
 */
void test_register_simple_write_not_supported()
{
    struct transaction *t = transaction_alloc(TRANSACTION_ALLOC_SLAVE_BY_SLAVE,
                                              TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

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

    struct transaction_exception e;
    cppcut_assert_equal(TRANSACTION_ERROR,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

    transaction_free(&t);
    cppcut_assert_null(t);
}

/*!\test
 * Multi-step register read commands are not supported anymore.
 *
 * This was done to keep the implementation a bit simpler.
 */
void test_register_multi_read_not_supported()
{
    struct transaction *t = transaction_alloc(TRANSACTION_ALLOC_SLAVE_BY_SLAVE,
                                              TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

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

    struct transaction_exception e;
    cppcut_assert_equal(TRANSACTION_ERROR,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

    transaction_free(&t);
    cppcut_assert_null(t);
}

/*!\test
 * The SPI slave may send junk bytes, which we are ignoring.
 */
void test_junk_bytes_are_ignored()
{
    struct transaction *t = transaction_alloc(TRANSACTION_ALLOC_SLAVE_BY_SLAVE,
                                              TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

    static const uint8_t dcpsync_header[] = { 'c', 0x00, 0x66, 0x08, 0x00, DCP_HEADER_SIZE, };
    static const uint8_t junk_bytes[] = { 0x67, 0xac, 0x00, 0x20, };

    read_data->set(dcpsync_header);
    read_data->set(junk_bytes);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Invalid DCP header 0x67 0xac 0x00 0x20 (Invalid argument)");
    mock_messages->expect_msg_error(0, LOG_ERR, "Transaction %p failed in state %d");

    struct transaction_exception e;
    cppcut_assert_equal(TRANSACTION_ERROR,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

    transaction_free(&t);
    cppcut_assert_null(t);
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
    struct transaction *head =
        transaction_fragments_from_data(xml_data, sizeof(xml_data) - 1U, 71,
                                        TRANSACTION_CHANNEL_SPI);
    cppcut_assert_not_null(head);

    const size_t max_data_size = transaction_get_max_data_size(head);
    cppcut_assert_operator(sizeof(xml_data) - 1U, <, max_data_size);

    struct transaction *t = transaction_queue_remove(&head);
    cppcut_assert_null(head);
    cppcut_assert_not_null(t);

    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);

    struct transaction_exception e;
    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

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

    cppcut_assert_equal(sizeof(expected_headers) + sizeof(xml_data) - 1U,
                        answer_written_to_fifo->size());

    cut_assert_equal_memory(expected_headers, sizeof(expected_headers),
                            answer_written_to_fifo->data(), sizeof(expected_headers));
    cut_assert_equal_memory(xml_data, sizeof(xml_data) - 1U,
                            answer_written_to_fifo->data() + sizeof(expected_headers),
                            sizeof(xml_data) - 1U);

    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN, t);

    transaction_free(&t);
    cppcut_assert_null(t);
}

/*!\test
 * We try to repeat rejected master transactions.
 */
void test_master_transaction_retry_on_nack()
{
    static const uint8_t xml_data[] =
        "<view name=\"welcome\"><icon id=\"welcome\" text=\"Profile 1\">welcome</icon></view>";
    struct transaction *head =
        transaction_fragments_from_data(xml_data, sizeof(xml_data) - 1U, 71,
                                        TRANSACTION_CHANNEL_SPI);
    cppcut_assert_not_null(head);

    const size_t max_data_size = transaction_get_max_data_size(head);
    cppcut_assert_operator(sizeof(xml_data) - 1U, <, max_data_size);

    struct transaction *t = transaction_queue_remove(&head);
    cppcut_assert_null(head);
    cppcut_assert_not_null(t);

    /* first try */
    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);

    struct transaction_exception e;
    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

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

    cppcut_assert_equal(sizeof(expected_headers_first) + sizeof(xml_data) - 1U,
                        answer_written_to_fifo->size());

    cut_assert_equal_memory(expected_headers_first, sizeof(expected_headers_first),
                            answer_written_to_fifo->data(), sizeof(expected_headers_first));
    cut_assert_equal_memory(xml_data, sizeof(xml_data) - 1U,
                            answer_written_to_fifo->data() + sizeof(expected_headers_first),
                            sizeof(xml_data) - 1U);

    answer_written_to_fifo->clear();

    mock_messages->expect_msg_info_formatted(
        "Got NACK[9] for 0x8001, resending packet as 0x8002");

    send_dcpsync_nack(DCPSYNC_MASTER_SERIAL_MIN, 9, t);

    /* second try */
    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);

    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

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

    cppcut_assert_equal(sizeof(expected_headers_second) + sizeof(xml_data) - 1U,
                        answer_written_to_fifo->size());

    cut_assert_equal_memory(expected_headers_second, sizeof(expected_headers_second),
                            answer_written_to_fifo->data(), sizeof(expected_headers_second));
    cut_assert_equal_memory(xml_data, sizeof(xml_data) - 1U,
                            answer_written_to_fifo->data() + sizeof(expected_headers_second),
                            sizeof(xml_data) - 1U);

    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN + 1, t);

    transaction_free(&t);
    cppcut_assert_null(t);
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

    struct transaction *head =
        transaction_fragments_from_data(xml_data, sizeof(xml_data) - 1U, 71,
                                        TRANSACTION_CHANNEL_SPI);
    cppcut_assert_not_null(head);

    const size_t max_data_size = transaction_get_max_data_size(head);
    const unsigned int expected_number_of_transactions =
        (sizeof(xml_data) - 1U) / max_data_size + 1U;
    cppcut_assert_operator(1U, <, expected_number_of_transactions);

    const uint8_t *xml_data_ptr = xml_data;
    size_t bytes_left = sizeof(xml_data) - 1U;
    unsigned int number_of_transactions = 0;
    uint16_t expected_serial = DCPSYNC_MASTER_SERIAL_MIN;

    do
    {
        /* take next transaction of fragmented DRCP packet */
        struct transaction *t = transaction_queue_remove(&head);
        cppcut_assert_not_null(t);

        mock_os->expect_os_write_from_buffer_callback(read_answer);
        mock_os->expect_os_write_from_buffer_callback(read_answer);
        mock_os->expect_os_write_from_buffer_callback(read_answer);

        answer_written_to_fifo->clear();

        struct transaction_exception e;
        cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                            transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

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

        cppcut_assert_equal(sizeof(expected_headers) + expected_data_size,
                            answer_written_to_fifo->size());

        cut_assert_equal_memory(expected_headers, sizeof(expected_headers),
                                answer_written_to_fifo->data(), sizeof(expected_headers));
        cut_assert_equal_memory(xml_data_ptr, expected_data_size,
                                answer_written_to_fifo->data() + sizeof(expected_headers),
                                expected_data_size);

        send_dcpsync_ack(expected_serial, t);

        transaction_free(&t);
        cppcut_assert_null(t);

        bytes_left -= expected_data_size;
        xml_data_ptr += expected_data_size;
        ++number_of_transactions;
        ++expected_serial;
    }
    while(head != NULL && number_of_transactions < expected_number_of_transactions);

    cppcut_assert_null(head);
    cppcut_assert_equal(expected_number_of_transactions, number_of_transactions);
}

/*!\test
 * In case the slave sends a write command for an unsupported register, the
 * command is ignored and skipped.
 */
void test_bad_register_addresses_are_handled_in_slave_write_transactions()
{
    struct transaction *t = transaction_alloc(TRANSACTION_ALLOC_SLAVE_BY_SLAVE,
                                              TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

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

    struct transaction_exception e;
    cppcut_assert_equal(TRANSACTION_ERROR,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

    /* next transaction from slave is processed, indicating that the data from
     * the previously rejected command has indeed been skipped */
    transaction_reset_for_slave(t);

    static const uint8_t dcpsync_header[] = { 'c', 0x00, 0x4b, 0xd4, 0x00, DCP_HEADER_SIZE, };
    static const uint8_t read_device_status[] = { DCP_COMMAND_READ_REGISTER, 0x11, 0x00, 0x00, };

    read_data->set(dcpsync_header);
    read_data->set(read_device_status);

    cppcut_assert_equal(TRANSACTION_PUSH_BACK,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

    mock_messages->expect_msg_info("read 17 handler %p %zu");

    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);

    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

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

    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN, t);

    transaction_free(&t);
    cppcut_assert_null(t);
}

/*!\test
 * Register changes are pushed to slave by sending write commands.
 */
void test_register_push_transaction()
{
    struct transaction *t = NULL;

    cut_assert_true(transaction_push_register_to_slave(&t, 17, TRANSACTION_CHANNEL_SPI));
    cppcut_assert_not_null(t);

    mock_messages->expect_msg_info("read 17 handler %p %zu");

    struct transaction_exception e;
    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);

    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

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

    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN, t);

    transaction_free(&t);
    cppcut_assert_null(t);
}

static struct transaction *create_master_transaction_that_waits_for_ack(struct transaction *t,
                                                                        uint16_t expected_serial,
                                                                        uint8_t expected_ttl)
{
    struct transaction_exception e;

    if(t == NULL)
    {
        cut_assert_true(transaction_push_register_to_slave(&t, 17, TRANSACTION_CHANNEL_SPI));
        cppcut_assert_not_null(t);

        mock_messages->expect_msg_info("read 17 handler %p %zu");

        cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                            transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));
    }
    else
    {
        /* as part of NACK handling, send data for \p t again below */
    }

    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);

    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

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
    /* first try fails */
    struct transaction *t =
        create_master_transaction_that_waits_for_ack(NULL, DCPSYNC_MASTER_SERIAL_MIN, UINT8_MAX);
    mock_messages->expect_msg_info_formatted(
        "Got NACK[9] for 0x8001, resending packet as 0x8002");

    send_dcpsync_nack(DCPSYNC_MASTER_SERIAL_MIN, 9, t);

    /* second try fails */
    create_master_transaction_that_waits_for_ack(t, DCPSYNC_MASTER_SERIAL_MIN + 1, 9);
    mock_messages->expect_msg_info_formatted(
        "Got NACK[8] for 0x8002, resending packet as 0x8003");

    send_dcpsync_nack(DCPSYNC_MASTER_SERIAL_MIN + 1, 8, t);

    /* third try succeeds */
    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);

    struct transaction_exception e = {};
    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd, &e));

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

    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN + 2, t);

    transaction_free(&t);
    cppcut_assert_null(t);
}

/*!\test
 * Accesses to unsupported registers are intercepted when pushing registers to
 * slave.
 */
void test_bad_register_addresses_are_handled_in_push_transactions()
{
    struct transaction *t = NULL;

    mock_messages->expect_msg_error_formatted(0, LOG_CRIT,
                                              "BUG: Master requested register 0x2a, but is not implemented");

    cut_assert_false(transaction_push_register_to_slave(&t, 42, TRANSACTION_CHANNEL_SPI));
    cppcut_assert_null(t);
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
    cppcut_assert_null(transaction_fragments_from_data(&dummy, sizeof(dummy), 42,
                                                       TRANSACTION_CHANNEL_SPI));
}

/*!\test
 * While waiting for a new command, the slave sends an ACK packet.
 *
 * Caller must handle this situation and call
 * #transaction_process_out_of_order_ack() for the transaction.
 */
void test_waiting_for_command_interrupted_by_ack()
{
    struct transaction *to_be_acked =
        create_master_transaction_that_waits_for_ack(NULL, DCPSYNC_MASTER_SERIAL_MIN, UINT8_MAX);
    struct transaction *t = transaction_alloc(TRANSACTION_ALLOC_SLAVE_BY_SLAVE,
                                              TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

    mock_messages->expect_msg_info_formatted(
        "Got ACK for 0x8001 while waiting for new command packet");

    struct transaction_exception e = {};
    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN, t, TRANSACTION_EXCEPTION, true, &e);

    cppcut_assert_equal(TRANSACTION_EXCEPTION_OUT_OF_ORDER_ACK, e.exception_code);
    cppcut_assert_equal(uint16_t(DCPSYNC_MASTER_SERIAL_MIN), e.d.ack.serial);

    /* caller must handle this ACK by finding the transaction for the given
     * serial and processing it */
    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process_out_of_order_ack(to_be_acked, &e.d.ack));

    cppcut_assert_equal(TRANSACTION_FINISHED,
                        transaction_process(to_be_acked, expected_from_slave_fd,
                                            expected_to_slave_fd, &e));

    transaction_free(&to_be_acked);
    cppcut_assert_null(to_be_acked);

    /* now we could go on processing the interrupted transaction */
    transaction_free(&t);
    cppcut_assert_null(t);
}

/*!\test
 * While waiting for a new command, the slave sends an NACK packet.
 *
 * Caller must handle this situation and call
 * #transaction_process_out_of_order_nack() for the transaction.
 */
void test_waiting_for_command_interrupted_by_nack()
{
    struct transaction *to_be_acked =
        create_master_transaction_that_waits_for_ack(NULL, DCPSYNC_MASTER_SERIAL_MIN, UINT8_MAX);
    struct transaction *t = transaction_alloc(TRANSACTION_ALLOC_SLAVE_BY_SLAVE,
                                              TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

    mock_messages->expect_msg_info_formatted(
        "Got NACK[9] for 0x8001 while waiting for new command packet");

    struct transaction_exception e = {};
    send_dcpsync_nack(DCPSYNC_MASTER_SERIAL_MIN, 9, t, TRANSACTION_EXCEPTION, &e);

    cppcut_assert_equal(TRANSACTION_EXCEPTION_OUT_OF_ORDER_NACK, e.exception_code);
    cppcut_assert_equal(uint16_t(DCPSYNC_MASTER_SERIAL_MIN), e.d.nack.serial);
    cppcut_assert_equal(uint8_t(9), e.d.nack.ttl);

    /* caller must handle this NACK by finding the transaction for the given
     * serial and processing it */
    mock_messages->expect_msg_info_formatted(
        "Got NACK[9] for 0x8001, resending packet as 0x8002");
    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process_out_of_order_nack(to_be_acked, &e.d.nack));

    /* resend and succeed by receiving the ACK */
    create_master_transaction_that_waits_for_ack(to_be_acked, DCPSYNC_MASTER_SERIAL_MIN + 1, 9);
    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN + 1, to_be_acked);

    transaction_free(&to_be_acked);
    cppcut_assert_null(to_be_acked);

    /* now we could go on processing the interrupted transaction */
    transaction_free(&t);
    cppcut_assert_null(t);
}

/*!\test
 * While waiting for an ACK, the slave sends an ACK packet for a different
 * transaction.
 *
 * Caller must handle this situation and call
 * #transaction_process_out_of_order_ack() for the transaction.
 */
void test_waiting_for_master_ack_interrupted_by_ack_for_other_transaction()
{
    struct transaction *to_be_acked =
        create_master_transaction_that_waits_for_ack(NULL, DCPSYNC_MASTER_SERIAL_MIN, UINT8_MAX);
    struct transaction *t =
        create_master_transaction_that_waits_for_ack(NULL, DCPSYNC_MASTER_SERIAL_MIN + 1, UINT8_MAX);

    struct transaction_exception e = {};
    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN, t, TRANSACTION_EXCEPTION, true, &e);

    cppcut_assert_equal(TRANSACTION_EXCEPTION_OUT_OF_ORDER_ACK, e.exception_code);
    cppcut_assert_equal(uint16_t(DCPSYNC_MASTER_SERIAL_MIN), e.d.ack.serial);

    /* caller must handle this ACK by finding the transaction for the given
     * serial and processing it */
    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process_out_of_order_ack(to_be_acked, &e.d.ack));

    cppcut_assert_equal(TRANSACTION_FINISHED,
                        transaction_process(to_be_acked, expected_from_slave_fd,
                                            expected_to_slave_fd, &e));

    transaction_free(&to_be_acked);
    cppcut_assert_null(to_be_acked);

    /* now we could go on processing the interrupted transaction */
    transaction_free(&t);
    cppcut_assert_null(t);
}

/*!\test
 * While waiting for an ACK, the slave sends a NACK packet for a different
 * transaction.
 *
 * Caller must handle this situation and call
 * #transaction_process_out_of_order_nack() for the transaction.
 */
void test_waiting_for_master_ack_interrupted_by_nack_for_other_transaction()
{
    struct transaction *to_be_acked =
        create_master_transaction_that_waits_for_ack(NULL, DCPSYNC_MASTER_SERIAL_MIN, UINT8_MAX);
    struct transaction *t =
        create_master_transaction_that_waits_for_ack(NULL, DCPSYNC_MASTER_SERIAL_MIN + 1, UINT8_MAX);

    mock_messages->expect_msg_info_formatted(
        "Got NACK[9] for 0x8001 while waiting for 0x8002 ACK");

    struct transaction_exception e = {};
    send_dcpsync_nack(DCPSYNC_MASTER_SERIAL_MIN, 9, t, TRANSACTION_EXCEPTION, &e);

    cppcut_assert_equal(TRANSACTION_EXCEPTION_OUT_OF_ORDER_NACK, e.exception_code);
    cppcut_assert_equal(uint16_t(DCPSYNC_MASTER_SERIAL_MIN), e.d.nack.serial);
    cppcut_assert_equal(uint8_t(9), e.d.nack.ttl);

    /* caller must handle this NACK by finding the transaction for the given
     * serial and processing it */
    mock_messages->expect_msg_info_formatted(
        "Got NACK[9] for 0x8001, resending packet as 0x8003");
    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process_out_of_order_nack(to_be_acked, &e.d.nack));

    /* resend and succeed by receiving the ACK */
    create_master_transaction_that_waits_for_ack(to_be_acked, DCPSYNC_MASTER_SERIAL_MIN + 2, 9);
    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN + 2, to_be_acked);

    transaction_free(&to_be_acked);
    cppcut_assert_null(to_be_acked);

    /* now we could go on processing the interrupted transaction */
    transaction_free(&t);
    cppcut_assert_null(t);
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
    struct transaction_exception e;
    struct transaction *t_push =
        create_master_transaction_that_waits_for_ack(NULL, DCPSYNC_MASTER_SERIAL_MIN, UINT8_MAX);

    /* colliding slave read transaction */
    static const uint8_t dcpsync_header[] = { 'c', UINT8_MAX, 0x60, 0xc7, 0x00, DCP_HEADER_SIZE, };
    static const uint8_t read_reg_87_appliance_id[] = { DCP_COMMAND_READ_REGISTER, 0x57, 0x00, 0x00, };

    read_data->set(dcpsync_header);
    read_data->set(read_reg_87_appliance_id);

    mock_messages->expect_msg_info_formatted(
        "Collision: New packet 0x60c7 while waiting for 0x8001 ACK");

    cppcut_assert_equal(TRANSACTION_EXCEPTION,
                        transaction_process(t_push, expected_from_slave_fd, expected_to_slave_fd, &e));

    cppcut_assert_equal(TRANSACTION_EXCEPTION_COLLISION, e.exception_code);
    cppcut_assert_not_null(e.d.collision.t);

    struct transaction *t_slave = e.d.collision.t;

    /* the push transaction is moved to some other place for deferred
     * processing, a new transaction has been allocated for the newly detected
     * slave transaction; now continue processing that one */
    cppcut_assert_equal(TRANSACTION_PUSH_BACK,
                        transaction_process(t_slave, expected_from_slave_fd, expected_to_slave_fd, &e));
    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t_slave, expected_from_slave_fd, expected_to_slave_fd, &e));

    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);

    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t_slave, expected_from_slave_fd, expected_to_slave_fd, &e));

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

    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN + 1, t_slave);

    transaction_free(&t_slave);
    cppcut_assert_null(t_slave);

    /* continue with our push transaction, no resend because there was no NACK,
     * just an interspersed communication; this time we get the ACK and no
     * interruption occurs */
    send_dcpsync_ack(DCPSYNC_MASTER_SERIAL_MIN, t_push);

    transaction_free(&t_push);
    cppcut_assert_null(t_push);
}

};

/*!@}*/
