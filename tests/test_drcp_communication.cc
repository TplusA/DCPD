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
#include <algorithm>
#include <memory>

#include "named_pipe.h"
#include "drcp.h"
#include "dynamic_buffer_util.h"

#include "mock_messages.hh"
#include "mock_os.hh"

/*!
 * \addtogroup drcp_tests Unit tests
 * \ingroup drcp
 *
 * Communication with DRCPD unit tests.
 */
/*!@{*/

namespace drcpd_communication_tests
{

class FillBufferData
{
  public:
    std::string data_;
    int errno_value_;
    int return_value_;

    FillBufferData(const FillBufferData &) = delete;
    FillBufferData &operator=(const FillBufferData &) = delete;

    explicit FillBufferData():
        errno_value_(EBADMSG),
        return_value_(-666)
    {}

    explicit FillBufferData(const char *data, int err, int ret):
        data_(data),
        errno_value_(err),
        return_value_(ret)
    {}

    void set(const char *data, int err, int ret)
    {
        data_ = data;
        errno_value_ = err;
        return_value_ = ret;
    }
};

static MockMessages *mock_messages;
static MockOs *mock_os;
static std::unique_ptr<FillBufferData> fill_buffer_data;
static std::unique_ptr<FillBufferData> fill_buffer_data_second_try;
static struct dynamic_buffer buffer;
static const struct fifo_pair fds = { 10, 20 };

void cut_setup()
{
    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_os = new MockOs;
    cppcut_assert_not_null(mock_os);
    mock_os->init();
    mock_os_singleton = mock_os;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    fill_buffer_data.reset(new FillBufferData);
    fill_buffer_data_second_try.reset(nullptr);

    dynamic_buffer_init(&buffer);
}

void cut_teardown()
{
    mock_messages->check();
    mock_os->check();

    dynamic_buffer_free(&buffer);

    mock_messages_singleton = nullptr;
    mock_os_singleton = nullptr;

    delete mock_messages;
    delete mock_os;
    fill_buffer_data.reset(nullptr);
    fill_buffer_data_second_try.reset(nullptr);

    mock_messages = nullptr;
    mock_os = nullptr;
    fill_buffer_data = nullptr;
}


/*!
 * Local mock implementation of #os_try_read_to_buffer().
 */
static int fill_buffer(void *dest, size_t count, size_t *add_bytes_read,
                       int fd, bool suppress_error_on_eagain)
{
    uint8_t *dest_ptr = static_cast<uint8_t *>(dest);

    cppcut_assert_equal(buffer.data, dest_ptr);
    cppcut_assert_equal(buffer.size, count);
    cppcut_assert_not_null(add_bytes_read);
    cppcut_assert_equal(fds.in_fd, fd);
    cut_assert_false(suppress_error_on_eagain);

    const size_t n = std::min(count, fill_buffer_data->data_.length());
    std::copy_n(fill_buffer_data->data_.begin(), n, dest_ptr + *add_bytes_read);
    *add_bytes_read += n;

    errno = fill_buffer_data->errno_value_;

    return fill_buffer_data->return_value_;
}

/*!
 * Proxy function for exchanging data for second #os_try_read_to_buffer() call.
 */
static int fill_buffer_second_try(void *dest, size_t count,
                                  size_t *add_bytes_read,
                                  int fd, bool suppress_error_on_eagain)
{
    fill_buffer_data = std::move(fill_buffer_data_second_try);

    return fill_buffer(dest, count, add_bytes_read, fd, suppress_error_on_eagain);
}

/*!\test
 * Reading of a valid size header works.
 */
void test_read_drcp_size_header()
{
    dynamic_buffer_check_space(&buffer);
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer);

    static const char input_string[] = "Size: 731\n";
    fill_buffer_data->set(input_string, 0, 1);

    size_t size;
    size_t offset;
    cut_assert_true(drcp_read_size_from_fd(&buffer, fds.in_fd, &size, &offset));
    cppcut_assert_equal(size_t(731), size);
    cppcut_assert_equal(sizeof(input_string) - 1, offset);
}

/*!\test
 * Attempting to read size header from empty input results in more reads.
 *
 * In practice, this only happens on a heavily loaded system, but it may happen
 * regardless. While named pipes offer atomicity of reads and writes up to a
 * certain size, the atomicity also depends on how the writing end is
 * implemented. If the writer puts data in chunks using multiple system calls,
 * then atomicity is restricted to those chunks.
 */
void test_read_drcp_size_header_from_empty_input()
{
    dynamic_buffer_check_space(&buffer);
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer);
    mock_os->expect_os_sched_yield();
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer_second_try);

    fill_buffer_data->set("", 0, 0);
    fill_buffer_data_second_try.reset(new FillBufferData("Size: 15\n", 0, 0));

    size_t size = 0;
    size_t offset = 0;
    cut_assert_true(drcp_read_size_from_fd(&buffer, fds.in_fd, &size, &offset));

    static const size_t expected_size_value(15);
    static const size_t expected_payload_offset(9);
    cppcut_assert_equal(expected_size_value, size);
    cppcut_assert_equal(expected_payload_offset, offset);
}

/*!\test
 * Attempting to read size header from half-ready input results in more reads.
 *
 * In practice, this only happens on a heavily loaded system, but it may happen
 * regardless. While named pipes offer atomicity of reads and writes up to a
 * certain size, the atomicity also depends on how the writing end is
 * implemented. If the writer puts data in chunks using multiple system calls,
 * then atomicity is restricted to those chunks.
 */
void test_read_drcp_size_header_with_incomplete_size_token()
{
    dynamic_buffer_check_space(&buffer);
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer);
    mock_os->expect_os_sched_yield();
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer_second_try);

    fill_buffer_data->set("Si", 0, 0);
    fill_buffer_data_second_try.reset(new FillBufferData("ze: 4\n", 0, 0));

    size_t size = 0;
    size_t offset = 0;
    cut_assert_true(drcp_read_size_from_fd(&buffer, fds.in_fd, &size, &offset));

    static const size_t expected_size_value(4);
    static const size_t expected_payload_offset(8);
    cppcut_assert_equal(expected_size_value, size);
    cppcut_assert_equal(expected_payload_offset, offset);
}

/*!\test
 * Attempting to read size header not terminated with a newline character.
 *
 * To avoid misinterpretation of half-received buffers, any size header must be
 * terminated with a newline character.
 *
 * This should not happen in practice since we are operating on named pipes
 * which offer certain atomicity of reads and writes. Partial reads and writes
 * should therefore not be a problem, but we handle the theoretically
 * impossible case anyway and document the expected behavior in form of this
 * test.
 */
void test_read_drcp_size_header_with_incomplete_size_value()
{
    dynamic_buffer_check_space(&buffer);
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer);
    mock_os->expect_os_sched_yield();
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer_second_try);

    static const char input_string[] = "Size: 5";
    fill_buffer_data->set(input_string, 0, 0);
    fill_buffer_data_second_try.reset(new FillBufferData("10\n", 0, 0));

    size_t size = 0;
    size_t offset = 0;
    cut_assert_true(drcp_read_size_from_fd(&buffer, fds.in_fd, &size, &offset));

    static const size_t expected_size_value(510);
    static const size_t expected_payload_offset(10);
    cppcut_assert_equal(expected_size_value, size);
    cppcut_assert_equal(expected_payload_offset, offset);
}

/*!\test
 * Attempting to read size header with a number followed by some non-digit.
 */
void test_read_drcp_size_header_with_trailing_byte()
{
    dynamic_buffer_check_space(&buffer);
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer);

    static const char input_string[] = "Size: 123F\n";
    fill_buffer_data->set(input_string, 0, 0);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_CRIT, "Malformed XML size \"123F\" (Invalid argument)");

    size_t size = 500;
    size_t offset = 600;
    cut_assert_false(drcp_read_size_from_fd(&buffer, fds.in_fd, &size, &offset));
    cppcut_assert_equal(size_t(500), size);
    cppcut_assert_equal(size_t(600), offset);
}

/*!\test
 * Attempting to read size header containing negative size.
 */
void test_read_drcp_size_header_with_negative_size()
{
    dynamic_buffer_check_space(&buffer);
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer);

    static const char input_string[] = "Size: -5\n";
    fill_buffer_data->set(input_string, 0, 0);

    mock_messages->expect_msg_error_formatted(ERANGE, LOG_CRIT, "Too large XML size -5 (Numerical result out of range)");

    size_t size = 500;
    size_t offset = 600;
    cut_assert_false(drcp_read_size_from_fd(&buffer, fds.in_fd, &size, &offset));
    cppcut_assert_equal(size_t(500), size);
    cppcut_assert_equal(size_t(600), offset);
}

/*!\test
 * Attempting to read size header containing an unreasonably big size.
 */
void test_read_drcp_size_header_with_huge_size()
{
    dynamic_buffer_check_space(&buffer);
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer);

    static const char input_string[] = "Size: 65536\n";
    fill_buffer_data->set(input_string, 0, 0);

    mock_messages->expect_msg_error_formatted(ERANGE, LOG_CRIT, "Too large XML size 65536 (Numerical result out of range)");

    size_t size = 500;
    size_t offset = 600;
    cut_assert_false(drcp_read_size_from_fd(&buffer, fds.in_fd, &size, &offset));
    cppcut_assert_equal(size_t(500), size);
    cppcut_assert_equal(size_t(600), offset);
}

/*!\test
 * Attempting to read size header causing an integer overflow.
 */
void test_read_drcp_size_header_with_overflow_size()
{
    dynamic_buffer_check_space(&buffer);
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer);

    static const char input_string[] = "Size: 18446744073709551616\n";
    fill_buffer_data->set(input_string, 0, 0);

    mock_messages->expect_msg_error_formatted(ERANGE, LOG_CRIT, "Too large XML size 18446744073709551616 (Numerical result out of range)");

    size_t size = 500;
    size_t offset = 600;
    cut_assert_false(drcp_read_size_from_fd(&buffer, fds.in_fd, &size, &offset));
    cppcut_assert_equal(size_t(500), size);
    cppcut_assert_equal(size_t(600), offset);
}

/*!\test
 * Attempting to read size header from unrelated data fails.
 *
 * This may happen if the sender and receiver fall out of sync, maybe due to
 * some bug that causes the size header to be incorrect for some transaction.
 * Resynchronization is not handled here.
 */
void test_read_faulty_drcp_size_header()
{
    dynamic_buffer_check_space(&buffer);
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer);

    static const char input_string[] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    fill_buffer_data->set(input_string, 0, 1);

    mock_messages->expect_msg_error(EINVAL, LOG_CRIT, "Invalid input, expected XML size");

    size_t size = 500;
    size_t offset = 600;
    cut_assert_false(drcp_read_size_from_fd(&buffer, fds.in_fd, &size, &offset));
    cppcut_assert_equal(size_t(500), size);
    cppcut_assert_equal(size_t(600), offset);
}

/*!\test
 * Attempting to read size header fails hard at system level.
 *
 * The only reasonable situation in which this may happen is when the FIFO file
 * descriptor somehow got invalid. Maybe it was closed, maybe the kernel stops
 * playing nicely, maybe some other unpredictable error. Unlikely, but handled.
 */
void test_read_drcp_size_header_from_broken_file_descriptor()
{
    dynamic_buffer_check_space(&buffer);
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer);

    fill_buffer_data->set("", EBADF, -1);

    mock_messages->expect_msg_error(EBADF, LOG_CRIT, "Reading XML size failed");

    size_t size = 500;
    size_t offset = 600;
    cut_assert_false(drcp_read_size_from_fd(&buffer, fds.in_fd, &size, &offset));
    cppcut_assert_equal(size_t(0), buffer.pos);
    cppcut_assert_equal(size_t(500), size);
    cppcut_assert_equal(size_t(600), offset);
}

/*!\test
 * Attempting to read some data from the named pipe filled by DRCPD.
 */
void test_read_drcp_data()
{
    dynamic_buffer_check_space(&buffer);
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer);

    static const char input_string[] =
        "Here is some test data\nread straight from the guts of\na MOCK!";
    fill_buffer_data->set(input_string, 0, 0);

    cut_assert_true(dynamic_buffer_fill_from_fd(&buffer, fds.in_fd,
                                                false, "test data"));
    cut_assert_equal_memory(input_string, sizeof(input_string) - 1,
                            buffer.data, buffer.pos);
}

/*!\test
 * Attempting to read lots of data from the named pipe filled by DRCPD.
 *
 * \note This test relies on the fact that the dynamic buffers are allocated by
 *       pages, which are usually powers of 2 bytes, thus also multiples of 8.
 *       The test writes 8 bytes per read to the consumer's buffer. We expect
 *       the reader to stop reading when its buffer is full.
 */
void test_read_drcp_data_from_infinite_size_input()
{
    dynamic_buffer_check_space(&buffer);

    static const char input_string[] = "testdata";
    fill_buffer_data->set(input_string, 0, 1);

    for(size_t i = 0; i < buffer.size / (sizeof(input_string) - 1); ++i)
        mock_os->expect_os_try_read_to_buffer_callback(fill_buffer);

    cut_assert_true(dynamic_buffer_fill_from_fd(&buffer, fds.in_fd,
                                                false, "test data"));

    cppcut_assert_equal(buffer.size, buffer.pos);
    for(size_t i = 0; i < buffer.pos; i += sizeof(input_string) - 1)
        cut_assert_equal_memory(input_string, sizeof(input_string) - 1,
                                buffer.data + i, sizeof(input_string) - 1);
}

/*!\test
 * Attempting to read some data fails hard at system level.
 *
 * The only reasonable situation in which this may happen is when the FIFO file
 * descriptor somehow got invalid. Maybe it was closed, maybe the kernel stops
 * playing nicely, maybe some other unpredictable error. Unlikely, but handled.
 */
void test_read_drcp_data_from_broken_file_descriptor()
{
    dynamic_buffer_check_space(&buffer);
    mock_os->expect_os_try_read_to_buffer_callback(fill_buffer);

    fill_buffer_data->set("", EBADF, -1);

    mock_messages->expect_msg_error_formatted(EBADF, LOG_CRIT, "Failed reading DRCP data from fd 10 (Bad file descriptor)");

    cut_assert_false(dynamic_buffer_fill_from_fd(&buffer, fds.in_fd,
                                                 false, "DRCP data"));
    cppcut_assert_equal(size_t(0), buffer.pos);
}

/*!
 * Local mock implementation of #os_write_from_buffer().
 */
static int receive_buffer(const void *src, size_t count, int fd)
{
    cppcut_assert_equal(fds.out_fd, fd);

    cut_assert_true(dynamic_buffer_resize(&buffer, count));
    std::copy_n(static_cast<const uint8_t *>(src), count, buffer.data);
    buffer.pos += count;

    return 0;
}

/*!\test
 * Tell DRCPD that everything went fine.
 */
void test_write_drcp_result_successful()
{
    mock_os->expect_os_write_from_buffer_callback(receive_buffer);

    drcp_finish_request(true, fds.out_fd);
    cut_assert_equal_memory("OK\n", 3, buffer.data, buffer.pos);
}

/*!\test
 * Tell DRCPD that we got an error.
 */
void test_write_drcp_result_failed()
{
    mock_os->expect_os_write_from_buffer_callback(receive_buffer);

    drcp_finish_request(false, fds.out_fd);
    cut_assert_equal_memory("FF\n", 3, buffer.data, buffer.pos);
}

};

/*!@}*/
