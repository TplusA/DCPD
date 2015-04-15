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

#include <cppcutter.h>
#include <array>
#include <algorithm>

#include "transactions.h"
#include "registers.h"

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

namespace dcp_transaction_tests_queue
{

void cut_setup(void)
{
    transaction_init_allocator();
}

void cut_teardown(void)
{
}

/*!\test
 * Single transactions can be allocated and deallocated for SPI channel.
 */
void test_allocation_and_deallocation_of_single_transaction_object_spi(void)
{
    struct transaction *t = transaction_alloc(false, TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);
    cppcut_assert_equal(TRANSACTION_CHANNEL_SPI, transaction_get_channel(t));
    cut_assert_false(transaction_is_pinned(t));

    transaction_free(&t);
    cppcut_assert_null(t);
}

/*!\test
 * Transactions can be pinned in memory.
 */
void test_pinned_transaction_object(void)
{
    struct transaction *t = transaction_alloc(false, TRANSACTION_CHANNEL_SPI, true);
    cppcut_assert_not_null(t);
    cut_assert_true(transaction_is_pinned(t));
}

/*!\test
 * Single transactions can be allocated and deallocated for IP channel.
 */
void test_allocation_and_deallocation_of_single_transaction_object_inet(void)
{
    struct transaction *t = transaction_alloc(false, TRANSACTION_CHANNEL_INET, false);
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
void test_deallocation_frees_payload_buffer(void)
{
    struct transaction *t = transaction_alloc(false, TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

    static const uint8_t payload_data[] = "test payload data";
    cut_assert_true(transaction_set_payload(t, payload_data, sizeof(payload_data)));

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
        dest[i] = transaction_alloc(false, TRANSACTION_CHANNEL_SPI, false);

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
void test_allocation_and_deallocation_of_all_transaction_objects(void)
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
void test_allocation_of_all_transaction_objects_reallocate_one(void)
{
    std::array<struct transaction *, max_allocs> objects;
    const size_t count = allocate_all_transactions(objects);

    const size_t reused_index = count / 4;
    struct transaction *const reused = objects[reused_index];
    cppcut_assert_not_null(reused);
    transaction_free(&objects[reused_index]);

    cppcut_assert_equal(reused, transaction_alloc(false, TRANSACTION_CHANNEL_SPI, false));
    cppcut_assert_null(transaction_alloc(false, TRANSACTION_CHANNEL_SPI, false));
}

/*!\test
 * Allocate all transaction objects, queue them up, deallocate by freeing head.
 */
void test_deallocation_of_linked_list(void)
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
void test_dequeue_from_middle_of_linked_list(void)
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
void test_dequeue_from_list_of_length_one(void)
{
    struct transaction *const head = transaction_alloc(false, TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(head);

    struct transaction *head_ptr = head;
    cppcut_assert_equal(head, transaction_queue_remove(&head_ptr));
    cppcut_assert_null(head_ptr);
}

};

namespace dcp_transaction_tests
{

static constexpr int expected_from_slave_fd = 23;
static constexpr int expected_to_slave_fd = 42;

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

static read_data_t *read_data;

static ssize_t test_os_read(int fd, void *dest, size_t count)
{
    cppcut_assert_equal(expected_from_slave_fd, fd);
    cppcut_assert_operator(read_data->fragment_, <, read_data->partial_.size());

    const read_data_partial_t &partial(read_data->partial_[read_data->fragment_++]);

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
static MockConnman *mock_connman;

static std::vector<uint8_t> *answer_written_to_fifo;

void cut_setup(void)
{
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

    mock_connman = new MockConnman();
    cppcut_assert_not_null(mock_connman);
    mock_connman->init();
    mock_connman_singleton = mock_connman;

    read_data = new read_data_t;
    cppcut_assert_not_null(read_data);

    answer_written_to_fifo = new std::vector<uint8_t>;

    transaction_init_allocator();
}

void cut_teardown(void)
{
    mock_messages->check();
    mock_os->check();
    mock_dcpd_dbus->check();
    mock_connman->check();

    mock_messages_singleton = nullptr;
    mock_os_singleton = nullptr;
    mock_dcpd_dbus_singleton = nullptr;
    mock_connman_singleton = nullptr;

    delete mock_messages;
    delete mock_os;
    delete mock_dcpd_dbus;
    delete mock_connman;

    mock_messages = nullptr;
    mock_os = nullptr;
    mock_dcpd_dbus = nullptr;
    mock_connman = nullptr;

    delete read_data;
    read_data = nullptr;

    delete answer_written_to_fifo;
    answer_written_to_fifo = nullptr;
}

/*!\test
 * A whole (former) simple register write transaction initiated by the slave
 * device.
 */
void test_register_write_request_transaction(void)
{
    struct transaction *t = transaction_alloc(true, TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

    static const uint8_t write_reg_54_selected_ip_profile[] = { 0x02, 0x36, 0x01, 0x00, 0x00 };
    read_data->set(write_reg_54_selected_ip_profile, 4);
    read_data->set(write_reg_54_selected_ip_profile + 4,
                   sizeof(write_reg_54_selected_ip_profile) - 4);


    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd));

    mock_messages->expect_msg_info("write 54 handler %p %zu");
    cppcut_assert_equal(TRANSACTION_FINISHED,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd));

    transaction_free(&t);
    cppcut_assert_null(t);
}

/*!\test
 * Simple register write transactions are not supported anymore.
 *
 * This was done to keep the implementation a bit simpler.
 */
void test_register_simple_write_not_supported(void)
{
    struct transaction *t = transaction_alloc(true, TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

    static const uint8_t oldstyle_write_reg_55_enable_dhcp[] = { 0x00, 0x37, 0x01, 0x00 };
    read_data->set(oldstyle_write_reg_55_enable_dhcp);

    mock_messages->expect_msg_error(EINVAL, LOG_ERR, "Simple write command not supported");
    mock_messages->expect_msg_error(EIO, LOG_NOTICE, "Transaction %p failed in state %d");

    cppcut_assert_equal(TRANSACTION_ERROR,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd));

    transaction_free(&t);
    cppcut_assert_null(t);
}

/*!\test
 * A whole multi-step register write transaction initiated by the slave device.
 */
void test_register_multi_step_write_request_transaction(void)
{
    struct transaction *t = transaction_alloc(true, TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

    static const uint8_t write_reg_51_set_mac_address[] =
    {
        /* command header, want to write 18 bytes */
        0x02, 0x33, 0x12, 0x00,

        /* MAC address 83:9F:0D:13:68:E1 */
        0x38, 0x33, 0x3a, 0x39, 0x46, 0x3a, 0x30, 0x44,
        0x3a, 0x31, 0x33, 0x3a, 0x36, 0x38, 0x3a, 0x45,
        0x31, 0x00
    };

    read_data->set(write_reg_51_set_mac_address, 4);
    read_data->set(write_reg_51_set_mac_address + 4, sizeof(write_reg_51_set_mac_address) - 4);

    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd));

    mock_messages->expect_msg_info("write 51 handler %p %zu");
    mock_messages->expect_msg_info_formatted("Received MAC address \"83:9F:0D:13:68:E1\", should validate address and configure adapter");
    cppcut_assert_equal(TRANSACTION_FINISHED,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd));

    transaction_free(&t);
    cppcut_assert_null(t);
}

static int read_answer(const void *src, size_t count, int fd)
{
    std::copy_n(static_cast<const uint8_t *>(src), count,
                std::back_inserter(*answer_written_to_fifo));
    return 0;
}

/*!\test
 * A whole simple register read transaction initiated by the slave device.
 */
void test_register_read_request_transaction(void)
{
    register_init("12:23:34:45:56:67", "ab:bc:ce:de:ef:f0", "/somewhere");

    struct transaction *t = transaction_alloc(true, TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

    static const uint8_t read_reg_55_read_dhcp_mode[] = { 0x01, 0x37, 0x00, 0x00 };
    read_data->set(read_reg_55_read_dhcp_mode);

    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd));

    static auto *dummy_connman_iface_data =
        reinterpret_cast<struct ConnmanInterfaceData *>(123456);

    mock_messages->expect_msg_info("read 55 handler %p %zu");
    mock_connman->expect_find_active_primary_interface(dummy_connman_iface_data,
        "12:23:34:45:56:67", "12:23:34:45:56:67", "ab:bc:ce:de:ef:f0");
    mock_connman->expect_get_dhcp_mode(false, dummy_connman_iface_data);
    mock_connman->expect_free_interface_data(dummy_connman_iface_data);

    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd));

    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);

    cppcut_assert_equal(TRANSACTION_FINISHED,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd));

    static const uint8_t expected_answer[] =
    {
        /* command header, payload size is 1 byte */
        0x03, 0x37, 0x01, 0x00,

        /* DHCP is not enabled */
        0x00
    };
    cut_assert_equal_memory(expected_answer, sizeof(expected_answer),
                            answer_written_to_fifo->data(), answer_written_to_fifo->size());

    transaction_free(&t);
    cppcut_assert_null(t);
}

/*!\test
 * A whole multi-step register read transaction initiated by the slave device.
 */
void test_register_multi_step_read_request_transaction(void)
{
    register_init("12:34:56:78:9A:BC", NULL, NULL);

    struct transaction *t = transaction_alloc(true, TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

    static const uint8_t read_reg_51_mac_address[] = { 0x01, 0x33, 0x00, 0x00 };
    read_data->set(read_reg_51_mac_address);

    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd));

    mock_messages->expect_msg_info("read 51 handler %p %zu");
    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd));

    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);

    cppcut_assert_equal(TRANSACTION_FINISHED,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd));

    static const uint8_t expected_answer[] =
    {
        /* command header, payload size is 18 bytes */
        0x03, 0x33, 0x12, 0x00,

        /* MAC address 12:34:56:78:9A:BC */
        0x31, 0x32, 0x3a, 0x33, 0x34, 0x3a, 0x35, 0x36,
        0x3a, 0x37, 0x38, 0x3a, 0x39, 0x41, 0x3a, 0x42,
        0x43, 0x00
    };
    cut_assert_equal_memory(expected_answer, sizeof(expected_answer),
                            answer_written_to_fifo->data(), answer_written_to_fifo->size());

    transaction_free(&t);
    cppcut_assert_null(t);
}

/*!\test
 * Multi-step register read commands are not supported anymore.
 *
 * This was done to keep the implementation a bit simpler.
 */
void test_register_multi_read_not_supported(void)
{
    struct transaction *t = transaction_alloc(true, TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

    static const uint8_t oldstyle_read_reg_51_mac_address[] = { 0x03, 0x33, 0x00, 0x00 };
    read_data->set(oldstyle_read_reg_51_mac_address);

    mock_messages->expect_msg_error(EINVAL, LOG_ERR, "Multiple read command not supported");
    mock_messages->expect_msg_error(EIO, LOG_NOTICE, "Transaction %p failed in state %d");

    cppcut_assert_equal(TRANSACTION_ERROR,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd));

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
void test_small_master_transaction(void)
{
    struct transaction *t = transaction_alloc(false, TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

    /* register 71 is DRCP, variable length */
    cut_assert_true(transaction_set_address_for_master(t, 71));

    static const uint8_t xml_data[] =
        "<view name=\"welcome\"><icon id=\"welcome\" text=\"Profile 1\">welcome</icon></view>";

    const size_t max_size = transaction_get_max_data_size(t);
    cppcut_assert_operator(sizeof(xml_data) - 1U, <, max_size);
    cut_assert_true(transaction_set_payload(t, xml_data, sizeof(xml_data) - 1U));

    cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd));

    mock_os->expect_os_write_from_buffer_callback(read_answer);
    mock_os->expect_os_write_from_buffer_callback(read_answer);

    cppcut_assert_equal(TRANSACTION_FINISHED,
                        transaction_process(t, expected_from_slave_fd, expected_to_slave_fd));

    static const uint8_t expected_header[] = { 0x03, 71, sizeof(xml_data) - 1U, 0x00 };
    cppcut_assert_equal(sizeof(expected_header) + sizeof(xml_data) - 1U,
                        answer_written_to_fifo->size());
    cut_assert_equal_memory(expected_header, sizeof(expected_header),
                            answer_written_to_fifo->data(), sizeof(expected_header));
    cut_assert_equal_memory(xml_data, sizeof(xml_data) - 1U,
                            answer_written_to_fifo->data() + sizeof(expected_header),
                            sizeof(xml_data) - 1U);

    struct transaction *temp = t;
    t = transaction_queue_remove(&temp);
    cppcut_assert_null(temp);

    transaction_free(&t);
    cppcut_assert_null(t);
}

/*!\test
 * A big, fragmented write transaction initiated by the master device.
 */
void test_big_master_transaction(void)
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

    do
    {
        /* take next transaction of fragmented DRCP packet */
        struct transaction *t = transaction_queue_remove(&head);
        cppcut_assert_not_null(t);

        cppcut_assert_equal(TRANSACTION_IN_PROGRESS,
                            transaction_process(t, expected_from_slave_fd, expected_to_slave_fd));

        mock_os->expect_os_write_from_buffer_callback(read_answer);
        mock_os->expect_os_write_from_buffer_callback(read_answer);

        answer_written_to_fifo->clear();

        cppcut_assert_equal(TRANSACTION_FINISHED,
                            transaction_process(t, expected_from_slave_fd, expected_to_slave_fd));

        /* check emitted DCP data */
        const size_t expected_data_size = std::min(bytes_left, max_data_size);
        const uint8_t expected_header[] =
        {
            0x03, 71,
            static_cast<uint8_t>(expected_data_size & 0xff),
            static_cast<uint8_t>(expected_data_size >> 8)
        };

        cppcut_assert_equal(sizeof(expected_header) + expected_data_size,
                            answer_written_to_fifo->size());

        cut_assert_equal_memory(expected_header, sizeof(expected_header),
                                answer_written_to_fifo->data(), sizeof(expected_header));
        cut_assert_equal_memory(xml_data_ptr, expected_data_size,
                                answer_written_to_fifo->data() + sizeof(expected_header),
                                expected_data_size);

        transaction_free(&t);
        cppcut_assert_null(t);

        bytes_left -= expected_data_size;
        xml_data_ptr += expected_data_size;
        ++number_of_transactions;
    }
    while(head != NULL && number_of_transactions < expected_number_of_transactions);

    cppcut_assert_null(head);
    cppcut_assert_equal(expected_number_of_transactions, number_of_transactions);
}

/*!\test
 * Accesses to unsupported registers are intercepted.
 */
void test_bad_register_addresses_are_handled_in_master_transactions(void)
{
    struct transaction *t = transaction_alloc(false, TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

    mock_messages->expect_msg_error_formatted(0, LOG_NOTICE,
                                              "Master requested unsupported register 0x2a");

    cut_assert_false(transaction_set_address_for_master(t, 42));
}

/*!\test
 * Accesses to unsupported registers are intercepted in fragmented
 * transactions.
 */
void test_bad_register_addresses_are_handled_in_fragmented_transactions(void)
{
    struct transaction *t = transaction_alloc(false, TRANSACTION_CHANNEL_SPI, false);
    cppcut_assert_not_null(t);

    mock_messages->expect_msg_error_formatted(0, LOG_NOTICE,
                                              "Master requested unsupported register 0x2a");

    static const uint8_t dummy = 23U;
    cppcut_assert_null(transaction_fragments_from_data(&dummy, sizeof(dummy), 42,
                                                       TRANSACTION_CHANNEL_SPI));
}

};

ssize_t (*os_read)(int fd, void *dest, size_t count) = dcp_transaction_tests::test_os_read;
ssize_t (*os_write)(int fd, const void *buf, size_t count) = dcp_transaction_tests::test_os_write;

/*!@}*/
