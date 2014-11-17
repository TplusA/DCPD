#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <cppcutter.h>

#include "mock_os.hh"

enum class OsFn
{
    write_from_buffer,
    try_read_to_buffer,

    first_valid_os_fn_id = write_from_buffer,
    last_valid_os_fn_id = try_read_to_buffer,
};


static std::ostream &operator<<(std::ostream &os, const OsFn id)
{
    if(id < OsFn::first_valid_os_fn_id ||
       id > OsFn::last_valid_os_fn_id)
    {
        os << "INVALID";
        return os;
    }

    switch(id)
    {
      case OsFn::write_from_buffer:
        os << "write_from_buffer";
        break;

      case OsFn::try_read_to_buffer:
        os << "try_read_to_buffer";
        break;
    }

    os << "()";

    return os;
}

class MockOs::Expectation
{
  public:
    const OsFn function_id_;

    const int ret_code_;
    const int arg_fd_;
    const void *const arg_src_pointer_;
    void *const arg_dest_pointer_;
    const size_t arg_count_;
    size_t *const arg_add_bytes_read_pointer_;
    os_write_from_buffer_callback_t os_write_from_buffer_callback_;
    os_try_read_to_buffer_callback_t os_try_read_to_buffer_callback_;

    Expectation(const Expectation &) = delete;
    Expectation &operator=(const Expectation &) = delete;

    explicit Expectation(int ret, const void *src, size_t count, int fd):
        function_id_(OsFn::write_from_buffer),
        ret_code_(ret),
        arg_fd_(fd),
        arg_src_pointer_(src),
        arg_dest_pointer_(nullptr),
        arg_count_(count),
        arg_add_bytes_read_pointer_(nullptr)
    {}

    explicit Expectation(int ret, void *dest, size_t count,
                         size_t *add_bytes_read, int fd):
        function_id_(OsFn::try_read_to_buffer),
        ret_code_(ret),
        arg_fd_(fd),
        arg_src_pointer_(nullptr),
        arg_dest_pointer_(dest),
        arg_count_(count),
        arg_add_bytes_read_pointer_(add_bytes_read)
    {}

    explicit Expectation(os_write_from_buffer_callback_t fn):
        function_id_(OsFn::write_from_buffer),
        ret_code_(-5),
        arg_fd_(-5),
        arg_src_pointer_(nullptr),
        arg_dest_pointer_(nullptr),
        arg_count_(0),
        arg_add_bytes_read_pointer_(nullptr),
        os_write_from_buffer_callback_(fn),
        os_try_read_to_buffer_callback_(nullptr)
    {}

    explicit Expectation(os_try_read_to_buffer_callback_t fn):
        function_id_(OsFn::try_read_to_buffer),
        ret_code_(-5),
        arg_fd_(-5),
        arg_src_pointer_(nullptr),
        arg_dest_pointer_(nullptr),
        arg_count_(0),
        arg_add_bytes_read_pointer_(nullptr),
        os_write_from_buffer_callback_(nullptr),
        os_try_read_to_buffer_callback_(fn)
    {}

    Expectation(Expectation &&) = default;
};

MockOs::MockOs()
{
    expectations_ = new MockExpectations();
}

MockOs::~MockOs()
{
    delete expectations_;
}

void MockOs::init()
{
    cppcut_assert_not_null(expectations_);
    expectations_->init();
}

void MockOs::check() const
{
    cppcut_assert_not_null(expectations_);
    expectations_->check();
}

void MockOs::expect_os_write_from_buffer(int ret, const void *src, size_t count, int fd)
{
    expectations_->add(Expectation(ret, src, count, fd));
}

void MockOs::expect_os_write_from_buffer_callback(MockOs::os_write_from_buffer_callback_t fn)
{
    expectations_->add(Expectation(fn));
}

void MockOs::expect_os_try_read_to_buffer(int ret, void *dest, size_t count, size_t *add_bytes_read, int fd)
{
    expectations_->add(Expectation(ret, dest, count, add_bytes_read, fd));
}

void MockOs::expect_os_try_read_to_buffer_callback(MockOs::os_try_read_to_buffer_callback_t fn)
{
    expectations_->add(Expectation(fn));
}


int os_write_from_buffer(const void *src, size_t count, int fd)
{
    const auto &expect(mock_os_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, OsFn::write_from_buffer);

    if(expect.os_write_from_buffer_callback_ != nullptr)
        return expect.os_write_from_buffer_callback_(src, count, fd);

    cppcut_assert_equal(expect.arg_src_pointer_, src);
    cppcut_assert_equal(expect.arg_count_, count);
    cppcut_assert_equal(expect.arg_fd_, fd);
    return expect.ret_code_;
}

int os_try_read_to_buffer(void *dest, size_t count, size_t *add_bytes_read, int fd)
{
    const auto &expect(mock_os_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, OsFn::try_read_to_buffer);

    if(expect.os_try_read_to_buffer_callback_ != nullptr)
        return expect.os_try_read_to_buffer_callback_(dest, count, add_bytes_read, fd);

    cppcut_assert_equal(expect.arg_dest_pointer_, dest);
    cppcut_assert_equal(expect.arg_count_, count);
    cppcut_assert_equal(expect.arg_add_bytes_read_pointer_, add_bytes_read);
    cppcut_assert_equal(expect.arg_fd_, fd);
    return expect.ret_code_;
}
