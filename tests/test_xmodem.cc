/*
 * Copyright (C) 2015, 2019  T+A elektroakustik GmbH & Co. KG
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

#include "xmodem.h"
#include "crc16.h"

/*!
 * \addtogroup xmodem_protocol_tests Unit tests
 * \ingroup xmodem_protocol
 *
 * XMODEM protocol unit tests.
 */
/*!@{*/

/*!
 * Protocol implementation tests.
 */
namespace xmodem_tests
{

static constexpr size_t BLOCK_SIZE = 128;

static struct XModemContext xmodem;
static struct os_mapped_file_data file;
static uint8_t expected_block[3U + BLOCK_SIZE + 2U];

template <size_t N>
static inline void set_file_data(const uint8_t (&data)[N])
{
    file.fd = 123;
    file.ptr = const_cast<uint8_t *>(data);
    file.length = N;
}

static void clear_expected_block()
{
    memset(expected_block, XMODEM_EOF, sizeof(expected_block));
}

static inline void copy_to_expected_block(const uint8_t *data, size_t n)
{
    memcpy(expected_block + 3, data, n);
}

template <size_t N>
static inline void copy_to_expected_block(const uint8_t (&data)[N])
{
    copy_to_expected_block(data, N);
}

static void set_expected_block_number(uint8_t block_number)
{
    expected_block[1] = block_number;
    expected_block[2] = ~block_number;
}

static void compute_expected_block_crc()
{
    /* we may use the #crc16_compute() function here in tests because we have
     * explicit unit tests for it as well */
    auto crc16 = crc16_compute(expected_block + 3, sizeof(expected_block) - 5);

    expected_block[sizeof(expected_block) - 2] = crc16 >> 8;
    expected_block[sizeof(expected_block) - 1] = crc16 & 0xff;
}

void cut_setup()
{
    memset(&file, 0, sizeof(file));
    file.fd = -1;
    clear_expected_block();

    xmodem_init(&xmodem, &file);
}

void cut_teardown()
{
}

/*!\test
 * Simulate transmission of a small piece of data that fits into a single
 * block.
 */
void test_full_transmission_of_small_data()
{
    static constexpr uint8_t data[] = { 0x60, 0x70, 0x80, 0x90 };
    set_file_data(data);;

    cppcut_assert_equal(XMODEM_RESULT_LAST_BLOCK,
                        xmodem_process(&xmodem, XMODEM_COMMAND_NACK_CRC));

    expected_block[0] = XMODEM_COMMAND_SOH;
    set_expected_block_number(1);
    copy_to_expected_block(data);
    compute_expected_block_crc();

    const uint8_t *block;
    ssize_t buffer_size = xmodem_get_block(&xmodem, &block);

    cppcut_assert_equal(ssize_t(sizeof(xmodem.buffer_data.tx_buffer)), buffer_size);
    cut_assert_equal_memory(expected_block, sizeof(expected_block),
                            block, buffer_size);

    cppcut_assert_equal(XMODEM_RESULT_EOT,
                        xmodem_process(&xmodem, XMODEM_COMMAND_ACK));
    cppcut_assert_equal(XMODEM_COMMAND_EOT, xmodem_byte_to_command(block[0]));

    block = NULL;
    buffer_size = xmodem_get_block(&xmodem, &block);
    cppcut_assert_equal(ssize_t(1), buffer_size);
    cppcut_assert_not_null(block);

    cppcut_assert_equal(XMODEM_RESULT_CLOSED,
                        xmodem_process(&xmodem, XMODEM_COMMAND_ACK));

    buffer_size = xmodem_get_block(&xmodem, &block);
    cppcut_assert_equal(ssize_t(0), buffer_size);
    cppcut_assert_null(block);
}

/*!\test
 * Simulate transmission of a piece of data that fits exactly into a single
 * block.
 */
void test_full_transmission_of_whole_block()
{
    static constexpr uint8_t data[BLOCK_SIZE] = { 0x20, 0x30, 0x40, };
    set_file_data(data);;

    cppcut_assert_equal(XMODEM_RESULT_LAST_BLOCK,
                        xmodem_process(&xmodem, XMODEM_COMMAND_NACK_CRC));

    expected_block[0] = XMODEM_COMMAND_SOH;
    set_expected_block_number(1);
    copy_to_expected_block(data);
    compute_expected_block_crc();

    const uint8_t *block;
    ssize_t buffer_size = xmodem_get_block(&xmodem, &block);

    cppcut_assert_equal(ssize_t(sizeof(xmodem.buffer_data.tx_buffer)), buffer_size);
    cut_assert_equal_memory(expected_block, sizeof(expected_block),
                            block, buffer_size);

    cppcut_assert_equal(XMODEM_RESULT_EOT,
                        xmodem_process(&xmodem, XMODEM_COMMAND_ACK));
    cppcut_assert_equal(XMODEM_COMMAND_EOT, xmodem_byte_to_command(block[0]));

    block = NULL;
    buffer_size = xmodem_get_block(&xmodem, &block);
    cppcut_assert_equal(ssize_t(1), buffer_size);
    cppcut_assert_not_null(block);
}

/*!\test
 * Simulate transmission of a piece of data that fits exactly into two blocks.
 */
void test_full_transmission_of_two_whole_blocks()
{
    static constexpr uint8_t data[2 * BLOCK_SIZE] = { 0x20, 0x30, 0x40, };
    set_file_data(data);;

    cppcut_assert_equal(XMODEM_RESULT_OK,
                        xmodem_process(&xmodem, XMODEM_COMMAND_NACK_CRC));

    expected_block[0] = XMODEM_COMMAND_SOH;
    set_expected_block_number(1);
    copy_to_expected_block(data, BLOCK_SIZE);
    compute_expected_block_crc();

    const uint8_t *block;
    ssize_t buffer_size = xmodem_get_block(&xmodem, &block);

    cppcut_assert_equal(ssize_t(sizeof(xmodem.buffer_data.tx_buffer)), buffer_size);
    cut_assert_equal_memory(expected_block, sizeof(expected_block),
                            block, buffer_size);

    cppcut_assert_equal(XMODEM_RESULT_LAST_BLOCK,
                        xmodem_process(&xmodem, XMODEM_COMMAND_ACK));

    clear_expected_block();
    expected_block[0] = XMODEM_COMMAND_SOH;
    set_expected_block_number(2);
    copy_to_expected_block(data + BLOCK_SIZE, BLOCK_SIZE);
    compute_expected_block_crc();

    buffer_size = xmodem_get_block(&xmodem, &block);

    cppcut_assert_equal(ssize_t(sizeof(xmodem.buffer_data.tx_buffer)), buffer_size);
    cut_assert_equal_memory(expected_block, sizeof(expected_block),
                            block, buffer_size);

    cppcut_assert_equal(XMODEM_RESULT_EOT,
                        xmodem_process(&xmodem, XMODEM_COMMAND_ACK));
    cppcut_assert_equal(XMODEM_COMMAND_EOT, xmodem_byte_to_command(block[0]));

    block = NULL;
    buffer_size = xmodem_get_block(&xmodem, &block);
    cppcut_assert_equal(ssize_t(1), buffer_size);
    cppcut_assert_not_null(block);
}

/*!\test
 * Simulate transmission of data that spans several blocks.
 */
void test_full_transmission_of_big_data()
{
    uint8_t data[8000] = { 0 };
    static constexpr uint8_t NUMBER_OF_BLOCKS = (sizeof(data) + BLOCK_SIZE - 1) / BLOCK_SIZE;

    /* prepare data so that each block is filled with the block number */
    for(uint8_t block = 1; block <= NUMBER_OF_BLOCKS; ++block)
    {
        const size_t offset = (block - 1) * BLOCK_SIZE;
        const size_t this_block_size =
            (block < NUMBER_OF_BLOCKS) ? BLOCK_SIZE : (sizeof(data) % BLOCK_SIZE);

        memset(data + offset, block, this_block_size);
    }

    set_file_data(data);;

    for(uint8_t block = 1; block <= NUMBER_OF_BLOCKS; ++block)
    {
        const size_t this_block_size =
            (block < NUMBER_OF_BLOCKS) ? BLOCK_SIZE : (sizeof(data) % BLOCK_SIZE);

        clear_expected_block();
        expected_block[0] = XMODEM_COMMAND_SOH;
        set_expected_block_number(block);
        copy_to_expected_block(data + (block - 1) * BLOCK_SIZE, this_block_size);
        compute_expected_block_crc();

        const auto command = (block > 1) ? XMODEM_COMMAND_ACK : XMODEM_COMMAND_NACK_CRC;
        const auto expected_xmodem_process_result =
            (block < NUMBER_OF_BLOCKS) ? XMODEM_RESULT_OK : XMODEM_RESULT_LAST_BLOCK;

        cppcut_assert_equal(expected_xmodem_process_result,
                            xmodem_process(&xmodem, command));

        /* make sure we see the correct block... */
        cppcut_assert_equal(block, expected_block[3 +                   0]);
        cppcut_assert_equal(block, expected_block[3 + this_block_size - 1]);

        const uint8_t *block_buffer;
        ssize_t buffer_size = xmodem_get_block(&xmodem, &block_buffer);

        cppcut_assert_equal(ssize_t(sizeof(xmodem.buffer_data.tx_buffer)), buffer_size);

        /* ...and compare it with the buffer we got from the implementation */
        cut_assert_equal_memory(expected_block, sizeof(expected_block),
                                block_buffer, buffer_size);
    }
}

/*!\test
 * After a number of tries to send data to the receiver which always responds
 * with NACK, the transmission is aborted.
 */
void test_abort_transmission_after_failed_retries()
{
    static constexpr uint8_t data[] = { 0xa0, 0xb0, 0xc0, 0xd0 };
    set_file_data(data);;

    cppcut_assert_equal(XMODEM_RESULT_LAST_BLOCK,
                        xmodem_process(&xmodem, XMODEM_COMMAND_NACK_CRC));

    expected_block[0] = XMODEM_COMMAND_SOH;
    set_expected_block_number(1);
    copy_to_expected_block(data);
    compute_expected_block_crc();

    const uint8_t *block;
    ssize_t buffer_size = xmodem_get_block(&xmodem, &block);

    cppcut_assert_equal(ssize_t(sizeof(xmodem.buffer_data.tx_buffer)), buffer_size);
    cut_assert_equal_memory(expected_block, sizeof(expected_block),
                            block, buffer_size);

    for(int i = 0; i < 10; ++i)
    {
        cppcut_assert_equal(XMODEM_RESULT_LAST_BLOCK,
                            xmodem_process(&xmodem, XMODEM_COMMAND_NACK));

        buffer_size = xmodem_get_block(&xmodem, &block);

        cppcut_assert_equal(ssize_t(sizeof(xmodem.buffer_data.tx_buffer)), buffer_size);
        cut_assert_equal_memory(expected_block, sizeof(expected_block),
                                block, buffer_size);
    }

    cppcut_assert_equal(XMODEM_RESULT_TIMEOUT,
                        xmodem_process(&xmodem, XMODEM_COMMAND_NACK));
}

/*!\test
 * Retry counter is reset after each successfully received block.
 */
void test_very_unreliable_connection()
{
    uint8_t data[500] = { 0 };
    static constexpr uint8_t NUMBER_OF_BLOCKS = (sizeof(data) + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for(uint8_t block = 1; block <= NUMBER_OF_BLOCKS; ++block)
    {
        const size_t offset = (block - 1) * BLOCK_SIZE;

        data[offset] = block;

        if(block < NUMBER_OF_BLOCKS)
            data[offset + BLOCK_SIZE - 1] = block;
        else
            data[offset + (sizeof(data) % BLOCK_SIZE) - 1] = block;
    }

    set_file_data(data);;

    cppcut_assert_equal(XMODEM_RESULT_OK,
                        xmodem_process(&xmodem, XMODEM_COMMAND_NACK_CRC));

    /* for each block, we let the receiver return NACK as many times as it is
     * allowed before experiencing a timeout, then let it return ACK to contiue
     * the transmission */
    for(uint8_t block = 1; block <= NUMBER_OF_BLOCKS; ++block)
    {
        const size_t this_block_size =
            (block < NUMBER_OF_BLOCKS) ? BLOCK_SIZE : (sizeof(data) % BLOCK_SIZE);

        clear_expected_block();
        expected_block[0] = XMODEM_COMMAND_SOH;
        set_expected_block_number(block);
        copy_to_expected_block(data + (block - 1) * BLOCK_SIZE, this_block_size);
        compute_expected_block_crc();

        cppcut_assert_equal(block, expected_block[3 +                   0]);
        cppcut_assert_equal(block, expected_block[3 + this_block_size - 1]);

        const uint8_t *block_buffer;
        ssize_t buffer_size = xmodem_get_block(&xmodem, &block_buffer);

        cppcut_assert_equal(ssize_t(sizeof(xmodem.buffer_data.tx_buffer)), buffer_size);
        cut_assert_equal_memory(expected_block, sizeof(expected_block),
                                block_buffer, buffer_size);

        const auto expected_xmodem_process_result =
            (block < NUMBER_OF_BLOCKS) ? XMODEM_RESULT_OK : XMODEM_RESULT_LAST_BLOCK;

        for(int i = 0; i < 10; ++i)
        {
            cppcut_assert_equal(expected_xmodem_process_result,
                                xmodem_process(&xmodem, XMODEM_COMMAND_NACK));

            buffer_size = xmodem_get_block(&xmodem, &block_buffer);

            cppcut_assert_equal(ssize_t(sizeof(xmodem.buffer_data.tx_buffer)), buffer_size);
            cut_assert_equal_memory(expected_block, sizeof(expected_block),
                                    block_buffer, buffer_size);
        }

        /* receiver accepts on last try */
        const auto expected_acked_xmodem_process_result =
            (expected_xmodem_process_result == XMODEM_RESULT_LAST_BLOCK
             ? XMODEM_RESULT_EOT
             : (block == NUMBER_OF_BLOCKS - 1
                ? XMODEM_RESULT_LAST_BLOCK
                : XMODEM_RESULT_OK));

        cppcut_assert_equal(expected_acked_xmodem_process_result,
                            xmodem_process(&xmodem, XMODEM_COMMAND_ACK));
    }
}

/*!\test
 * The receiver is expected to start with #XMODEM_COMMAND_NACK_CRC to request
 * CRC-16 mode, not #XMODEM_COMMAND_NACK as with the old single-byte checksum
 * scheme.
 */
void test_original_xmodem_with_single_byte_checksum_is_not_supported()
{
    cppcut_assert_equal(XMODEM_RESULT_PROTOCOL_VIOLATION,
                        xmodem_process(&xmodem, XMODEM_COMMAND_NACK));
}

/*!\test
 * The block buffer for an idle XMODEM context is invalid.
 */
void test_get_block_buffer_without_transmission_results_in_error()
{
    const uint8_t *buffer = reinterpret_cast<const uint8_t *>(1);
    cppcut_assert_equal(ssize_t(-1), xmodem_get_block(&xmodem, &buffer));
    cppcut_assert_equal(reinterpret_cast<const uint8_t *>(1), buffer);
}

}

/*!
 * CRC-16 computation tests.
 */
namespace crc16_tests
{

/*!\test
 * CRC-16 of nothing is 0.
 */
void test_checksum_of_empty_data_is_zero()
{
    cppcut_assert_equal(static_cast<uint16_t>(0), crc16_compute(NULL, 0));
}

class CRC16TestData
{
  public:
    CRC16TestData(const CRC16TestData &) = delete;
    CRC16TestData &operator=(const CRC16TestData &) = delete;
    CRC16TestData(CRC16TestData &&) = default;

    const uint8_t *const data_;
    const size_t length_;
    const uint16_t expected_crc16_;

    template <size_t N>
    constexpr explicit CRC16TestData(const char (&string)[N], uint16_t crc16):
        data_(reinterpret_cast<const uint8_t *>(&string)),
        length_(N - 1),
        expected_crc16_(crc16)
    {}
};

/*!\test
 * Compute CRC-16 of some example data with known CRC-16s.
 */
void test_checksum_of_data()
{
    /* Correct CRC-16 checksums were computed on
     * http://www.lammertbies.nl/comm/info/crc-calculation.html */
    static constexpr CRC16TestData test_data[] =
    {
        CRC16TestData("123456789", 0x31C3),
        CRC16TestData("987654321", 0x9CAD),
        CRC16TestData("a",         0x7C87),
        CRC16TestData("\0",        0x0000),
        CRC16TestData("\1",        0x1021),
        CRC16TestData("\2",        0x2042),
        CRC16TestData("Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.", 0x1B91),
    };

    for(const auto &d : test_data)
        cppcut_assert_equal(d.expected_crc16_,
                            crc16_compute(d.data_, d.length_));
}

}

/*!@}*/
