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

};

/*!@}*/
