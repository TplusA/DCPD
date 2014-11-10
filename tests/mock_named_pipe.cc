#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <cppcutter.h>

#include "mock_named_pipe.hh"

enum class FifoFn
{
    create_and_open,
    open,
    close_and_delete,
    close,
    reopen,
    write_from_buffer,
    try_read_to_buffer,

    first_valid_fifo_fn_id = create_and_open,
    last_valid_fifo_fn_id = try_read_to_buffer,
};


static std::ostream &operator<<(std::ostream &os, const FifoFn id)
{
    if(id < FifoFn::first_valid_fifo_fn_id ||
       id > FifoFn::last_valid_fifo_fn_id)
    {
        os << "INVALID";
        return os;
    }

    switch(id)
    {
      case FifoFn::create_and_open:
        os << "create_and_open";
        break;

      case FifoFn::open:
        os << "open";
        break;

      case FifoFn::close_and_delete:
        os << "close_and_delete";
        break;

      case FifoFn::close:
        os << "close";
        break;

      case FifoFn::reopen:
        os << "reopen";
        break;

      case FifoFn::write_from_buffer:
        os << "write_from_buffer";
        break;

      case FifoFn::try_read_to_buffer:
        os << "try_read_to_buffer";
        break;
    }

    os << "()";

    return os;
}

class MockNamedPipe::Expectation
{
  public:
    const FifoFn function_id_;

    const int ret_code_;
    const int ret_bool_;
    const std::string arg_devname_;
    const bool arg_write_not_read_;
    int *const arg_fd_pointer_;
    const int arg_fd_;
    const uint8_t *const arg_src_pointer_;
    uint8_t *const arg_dest_pointer_;
    const size_t arg_count_;
    size_t *const arg_add_bytes_read_pointer_;
    fifo_try_read_to_buffer_callback_t fifo_try_read_to_buffer_callback_;

    Expectation(const Expectation &) = delete;
    Expectation &operator=(const Expectation &) = delete;

    explicit Expectation(FifoFn id, int ret, const char *devname = "",
                         bool write_not_read = false):
        function_id_(id),
        ret_code_(ret),
        ret_bool_(false),
        arg_devname_(devname),
        arg_write_not_read_(write_not_read),
        arg_fd_pointer_(nullptr),
        arg_fd_(-5),
        arg_src_pointer_(nullptr),
        arg_dest_pointer_(nullptr),
        arg_count_(0),
        arg_add_bytes_read_pointer_(nullptr),
        fifo_try_read_to_buffer_callback_(nullptr)
    {}

    explicit Expectation(FifoFn id, bool ret, int *fd, const char *devname = "",
                         bool write_not_read = false):
        function_id_(id),
        ret_code_(-5),
        ret_bool_(ret),
        arg_devname_(devname),
        arg_write_not_read_(write_not_read),
        arg_fd_pointer_(fd),
        arg_fd_(-5),
        arg_src_pointer_(nullptr),
        arg_dest_pointer_(nullptr),
        arg_count_(0),
        arg_add_bytes_read_pointer_(nullptr),
        fifo_try_read_to_buffer_callback_(nullptr)
    {}

    explicit Expectation(int ret, const uint8_t *src, size_t count, int fd):
        function_id_(FifoFn::write_from_buffer),
        ret_code_(ret),
        ret_bool_(false),
        arg_write_not_read_(false),
        arg_fd_pointer_(nullptr),
        arg_fd_(fd),
        arg_src_pointer_(src),
        arg_dest_pointer_(nullptr),
        arg_count_(count),
        arg_add_bytes_read_pointer_(nullptr),
        fifo_try_read_to_buffer_callback_(nullptr)
    {}

    explicit Expectation(int ret, uint8_t *dest, size_t count,
                         size_t *add_bytes_read, int fd):
        function_id_(FifoFn::try_read_to_buffer),
        ret_code_(ret),
        ret_bool_(false),
        arg_write_not_read_(false),
        arg_fd_pointer_(nullptr),
        arg_fd_(fd),
        arg_src_pointer_(nullptr),
        arg_dest_pointer_(dest),
        arg_count_(count),
        arg_add_bytes_read_pointer_(add_bytes_read),
        fifo_try_read_to_buffer_callback_(nullptr)
    {}

    explicit Expectation(fifo_try_read_to_buffer_callback_t fn):
        function_id_(FifoFn::try_read_to_buffer),
        ret_code_(-5),
        ret_bool_(false),
        arg_write_not_read_(false),
        arg_fd_pointer_(nullptr),
        arg_fd_(-5),
        arg_src_pointer_(nullptr),
        arg_dest_pointer_(nullptr),
        arg_count_(0),
        arg_add_bytes_read_pointer_(nullptr),
        fifo_try_read_to_buffer_callback_(fn)
    {}

    Expectation(Expectation &&) = default;
};

MockNamedPipe::MockNamedPipe():
    ignore_all_(false)
{
    expectations_ = new MockExpectations();
}

MockNamedPipe::~MockNamedPipe()
{
    delete expectations_;
}

void MockNamedPipe::init()
{
    cppcut_assert_not_null(expectations_);
    expectations_->init();
}

void MockNamedPipe::check() const
{
    cppcut_assert_not_null(expectations_);
    expectations_->check();
}

void MockNamedPipe::expect_fifo_create_and_open(int ret, const char *devname, bool write_not_read)
{
    expectations_->add(Expectation(FifoFn::create_and_open, ret, devname, write_not_read));
}

void MockNamedPipe::expect_fifo_open(int ret, const char *devname, bool write_not_read)
{
    expectations_->add(Expectation(FifoFn::open, ret, devname, write_not_read));
}

void MockNamedPipe::expect_fifo_close_and_delete(int *fd, const char *devname)
{
    expectations_->add(Expectation(FifoFn::close_and_delete, false, fd, devname));
}

void MockNamedPipe::expect_fifo_close(int *fd)
{
    expectations_->add(Expectation(FifoFn::close, false, fd));
}

void MockNamedPipe::expect_fifo_reopen(bool ret, int *fd, const char *devname, bool write_not_read)
{
    expectations_->add(Expectation(FifoFn::reopen, ret, fd, devname, write_not_read));
}

void MockNamedPipe::expect_fifo_write_from_buffer(int ret, const uint8_t *src, size_t count, int fd)
{
    expectations_->add(Expectation(ret, src, count, fd));
}

void MockNamedPipe::expect_fifo_try_read_to_buffer(int ret, uint8_t *dest, size_t count, size_t *add_bytes_read, int fd)
{
    expectations_->add(Expectation(ret, dest, count, add_bytes_read, fd));
}

void MockNamedPipe::expect_fifo_try_read_to_buffer_callback(MockNamedPipe::fifo_try_read_to_buffer_callback_t fn)
{
    expectations_->add(Expectation(fn));
}


MockNamedPipe *mock_named_pipe_singleton = nullptr;

int fifo_create_and_open(const char *devname, bool write_not_read)
{
    const auto &expect(mock_named_pipe_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, FifoFn::create_and_open);
    cppcut_assert_equal(expect.arg_devname_, std::string(devname));
    cppcut_assert_equal(expect.arg_write_not_read_, write_not_read);
    return expect.ret_code_;
}

int fifo_open(const char *devname, bool write_not_read)
{
    const auto &expect(mock_named_pipe_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, FifoFn::open);
    cppcut_assert_equal(expect.arg_devname_, std::string(devname));
    cppcut_assert_equal(expect.arg_write_not_read_, write_not_read);
    return expect.ret_code_;
}

void fifo_close_and_delete(int *fd, const char *devname)
{
    const auto &expect(mock_named_pipe_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, FifoFn::close_and_delete);
    cppcut_assert_equal(expect.arg_fd_pointer_, fd);
    cppcut_assert_equal(expect.arg_devname_, std::string(devname));
}

void fifo_close(int *fd)
{
    const auto &expect(mock_named_pipe_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, FifoFn::close);
    cppcut_assert_equal(expect.arg_fd_pointer_, fd);
}

bool fifo_reopen(int *fd, const char *devname, bool write_not_read)
{
    const auto &expect(mock_named_pipe_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, FifoFn::reopen);
    cppcut_assert_equal(expect.arg_fd_pointer_, fd);
    cppcut_assert_equal(expect.arg_devname_, std::string(devname));
    cppcut_assert_equal(expect.arg_write_not_read_, write_not_read);
    return expect.ret_bool_;
}

int fifo_write_from_buffer(const uint8_t *src, size_t count, int fd)
{
    const auto &expect(mock_named_pipe_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, FifoFn::write_from_buffer);
    cppcut_assert_equal(expect.arg_src_pointer_, src);
    cppcut_assert_equal(expect.arg_count_, count);
    cppcut_assert_equal(expect.arg_fd_, fd);
    return expect.ret_code_;
}

int fifo_try_read_to_buffer(uint8_t *dest, size_t count, size_t *add_bytes_read, int fd)
{
    const auto &expect(mock_named_pipe_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, FifoFn::try_read_to_buffer);

    if(expect.fifo_try_read_to_buffer_callback_ != nullptr)
        return expect.fifo_try_read_to_buffer_callback_(dest, count, add_bytes_read, fd);

    cppcut_assert_equal(expect.arg_dest_pointer_, dest);
    cppcut_assert_equal(expect.arg_count_, count);
    cppcut_assert_equal(expect.arg_add_bytes_read_pointer_, add_bytes_read);
    cppcut_assert_equal(expect.arg_fd_, fd);
    return expect.ret_code_;
}
