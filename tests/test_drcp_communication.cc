#include <cppcutter.h>
#include <algorithm>

#include "drcp.h"

#include "mock_messages.hh"
#include "mock_named_pipe.hh"

/*!
 * \addtogroup drcp_tests Unit tests
 * \ingroup drcp
 *
 * Communication with DRCPD unit tests.
 */
/*!@{*/

namespace drcpd_communication_tests
{

struct fill_buffer_data_t
{
    std::string data;
    int return_value;
};

static MockMessages *mock_messages;
static MockNamedPipe *mock_named_pipe;
static struct dynamic_buffer buffer;
static const struct fifo_pair fds = { 10, 20 };

static fill_buffer_data_t fill_buffer_data;

void cut_setup(void)
{
    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_named_pipe = new MockNamedPipe;
    cppcut_assert_not_null(mock_named_pipe);
    mock_named_pipe->init();
    mock_named_pipe_singleton = mock_named_pipe;

    dynamic_buffer_init(&buffer);
}

void cut_teardown(void)
{
    mock_messages->check();
    mock_named_pipe->check();

    dynamic_buffer_free(&buffer);

    mock_messages_singleton = nullptr;
    mock_named_pipe_singleton = nullptr;

    delete mock_messages;
    delete mock_named_pipe;;

    mock_messages = nullptr;
    mock_named_pipe = nullptr;
}


/*!
 * Local mock implementation of #fifo_try_read_to_buffer().
 */
static int fill_buffer(uint8_t *dest, size_t count, size_t *add_bytes_read,
                       int fd)
{
    cppcut_assert_equal(buffer.data, dest);
    cppcut_assert_equal(buffer.size, count);
    cppcut_assert_not_null(add_bytes_read);
    cppcut_assert_equal(fds.in_fd, fd);

    const size_t n = std::min(count, fill_buffer_data.data.length());
    std::copy_n(fill_buffer_data.data.begin(), n, dest + *add_bytes_read);
    *add_bytes_read += n;

    return fill_buffer_data.return_value;
}

/*!\test
 * Reading of a valid size header works.
 */
void test_read_drcp_size_header(void)
{
    dynamic_buffer_check_space(&buffer);
    mock_named_pipe->expect_fifo_try_read_to_buffer_callback(fill_buffer);

    static const char input_string[] = "Size: 731\n";
    fill_buffer_data.data = input_string;
    fill_buffer_data.return_value = 1;

    size_t size;
    size_t offset;
    cut_assert_true(drcp_read_size_from_fd(&buffer, &fds, &size, &offset));
    cppcut_assert_equal(size_t(731), size);
    cppcut_assert_equal(sizeof(input_string) - 1, offset);
}

/*!\test
 * Attempting to read size header from empty input fails.
 */
void test_read_drcp_size_header_from_empty_input(void)
{
    dynamic_buffer_check_space(&buffer);
    mock_named_pipe->expect_fifo_try_read_to_buffer_callback(fill_buffer);

    fill_buffer_data.data = "";
    fill_buffer_data.return_value = 0;

    mock_messages->expect_msg_error(EINVAL, LOG_CRIT, "Too short input, expected XML size");

    size_t size = 500;
    size_t offset = 600;
    cut_assert_false(drcp_read_size_from_fd(&buffer, &fds, &size, &offset));
    cppcut_assert_equal(size_t(500), size);
    cppcut_assert_equal(size_t(600), offset);
}

/*!\test
 * Attempting to read size header from half-ready input fails.
 *
 * This should not happen in practice since we are operating on named pipes
 * which offer certain atomicity of reads and writes. Partial reads and writes
 * should therefore not be a problem, but we handle the theoretically
 * impossible case anyway and document the expected behavior in form of this
 * test.
 */
void test_read_drcp_size_header_from_nearly_empty_input(void)
{
    dynamic_buffer_check_space(&buffer);
    mock_named_pipe->expect_fifo_try_read_to_buffer_callback(fill_buffer);

    static const char input_string[] = "Size";
    fill_buffer_data.data = input_string;
    fill_buffer_data.return_value = 0;

    mock_messages->expect_msg_error(EINVAL, LOG_CRIT, "Too short input, expected XML size");

    size_t size = 500;
    size_t offset = 600;
    cut_assert_false(drcp_read_size_from_fd(&buffer, &fds, &size, &offset));
    cppcut_assert_equal(size_t(500), size);
    cppcut_assert_equal(size_t(600), offset);
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
void test_read_drcp_size_header_from_incomplete_input(void)
{
    dynamic_buffer_check_space(&buffer);
    mock_named_pipe->expect_fifo_try_read_to_buffer_callback(fill_buffer);

    static const char input_string[] = "Size: 5";
    fill_buffer_data.data = input_string;
    fill_buffer_data.return_value = 0;

    mock_messages->expect_msg_error(EINVAL, LOG_CRIT, "Incomplete XML size");

    size_t size = 500;
    size_t offset = 600;
    cut_assert_false(drcp_read_size_from_fd(&buffer, &fds, &size, &offset));
    cppcut_assert_equal(size_t(500), size);
    cppcut_assert_equal(size_t(600), offset);
}

/*!\test
 * Attempting to read size header with a number followed by some non-digit.
 */
void test_read_drcp_size_header_with_trailing_byte(void)
{
    dynamic_buffer_check_space(&buffer);
    mock_named_pipe->expect_fifo_try_read_to_buffer_callback(fill_buffer);

    static const char input_string[] = "Size: 123F\n";
    fill_buffer_data.data = input_string;
    fill_buffer_data.return_value = 0;

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_CRIT, "Malformed XML size \"123F\" (Invalid argument)");

    size_t size = 500;
    size_t offset = 600;
    cut_assert_false(drcp_read_size_from_fd(&buffer, &fds, &size, &offset));
    cppcut_assert_equal(size_t(500), size);
    cppcut_assert_equal(size_t(600), offset);
}

/*!\test
 * Attempting to read size header containing negative size.
 */
void test_read_drcp_size_header_with_negative_size(void)
{
    dynamic_buffer_check_space(&buffer);
    mock_named_pipe->expect_fifo_try_read_to_buffer_callback(fill_buffer);

    static const char input_string[] = "Size: -5\n";
    fill_buffer_data.data = input_string;
    fill_buffer_data.return_value = 0;

    mock_messages->expect_msg_error_formatted(ERANGE, LOG_CRIT, "Too large XML size -5 (Numerical result out of range)");

    size_t size = 500;
    size_t offset = 600;
    cut_assert_false(drcp_read_size_from_fd(&buffer, &fds, &size, &offset));
    cppcut_assert_equal(size_t(500), size);
    cppcut_assert_equal(size_t(600), offset);
}

/*!\test
 * Attempting to read size header containing an unreasonably big size.
 */
void test_read_drcp_size_header_with_huge_size(void)
{
    dynamic_buffer_check_space(&buffer);
    mock_named_pipe->expect_fifo_try_read_to_buffer_callback(fill_buffer);

    static const char input_string[] = "Size: 65536\n";
    fill_buffer_data.data = input_string;
    fill_buffer_data.return_value = 0;

    mock_messages->expect_msg_error_formatted(ERANGE, LOG_CRIT, "Too large XML size 65536 (Numerical result out of range)");

    size_t size = 500;
    size_t offset = 600;
    cut_assert_false(drcp_read_size_from_fd(&buffer, &fds, &size, &offset));
    cppcut_assert_equal(size_t(500), size);
    cppcut_assert_equal(size_t(600), offset);
}

/*!\test
 * Attempting to read size header causing an integer overflow.
 */
void test_read_drcp_size_header_with_overflow_size(void)
{
    dynamic_buffer_check_space(&buffer);
    mock_named_pipe->expect_fifo_try_read_to_buffer_callback(fill_buffer);

    static const char input_string[] = "Size: 18446744073709551616\n";
    fill_buffer_data.data = input_string;
    fill_buffer_data.return_value = 0;

    mock_messages->expect_msg_error_formatted(ERANGE, LOG_CRIT, "Too large XML size 18446744073709551616 (Numerical result out of range)");

    size_t size = 500;
    size_t offset = 600;
    cut_assert_false(drcp_read_size_from_fd(&buffer, &fds, &size, &offset));
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
void test_read_faulty_drcp_size_header(void)
{
    dynamic_buffer_check_space(&buffer);
    mock_named_pipe->expect_fifo_try_read_to_buffer_callback(fill_buffer);

    static const char input_string[] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    fill_buffer_data.data = input_string;
    fill_buffer_data.return_value = 1;

    mock_messages->expect_msg_error(EINVAL, LOG_CRIT, "Invalid input, expected XML size");

    size_t size = 500;
    size_t offset = 600;
    cut_assert_false(drcp_read_size_from_fd(&buffer, &fds, &size, &offset));
    cppcut_assert_equal(size_t(500), size);
    cppcut_assert_equal(size_t(600), offset);
}

};

/*!@}*/
