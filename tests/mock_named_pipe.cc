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

    first_valid_fifo_fn_id = create_and_open,
    last_valid_fifo_fn_id = reopen,
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

    Expectation(const Expectation &) = delete;
    Expectation &operator=(const Expectation &) = delete;

    explicit Expectation(FifoFn id, int ret, const char *devname = "",
                         bool write_not_read = false):
        function_id_(id),
        ret_code_(ret),
        ret_bool_(false),
        arg_devname_(devname),
        arg_write_not_read_(write_not_read),
        arg_fd_pointer_(nullptr)
    {}

    explicit Expectation(FifoFn id, bool ret, int *fd, const char *devname = "",
                         bool write_not_read = false):
        function_id_(id),
        ret_code_(-5),
        ret_bool_(ret),
        arg_devname_(devname),
        arg_write_not_read_(write_not_read),
        arg_fd_pointer_(fd)
    {}

    Expectation(Expectation &&) = default;
};

MockNamedPipe::MockNamedPipe()
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
