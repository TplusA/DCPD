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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <cppcutter.h>
#include <string>

#include "mock_os.hh"

enum class OsFn
{
    write_from_buffer,
    try_read_to_buffer,
    stdlib_abort,
    file_new,
    file_close,
    file_delete,

    first_valid_os_fn_id = write_from_buffer,
    last_valid_os_fn_id = file_delete,
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

      case OsFn::stdlib_abort:
        os << "abort";
        break;

      case OsFn::file_new:
        os << "file_new";
        break;

      case OsFn::file_close:
        os << "file_close";
        break;

      case OsFn::file_delete:
        os << "file_delete";
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
    const std::string arg_filename_;
    const void *const arg_src_pointer_;
    void *const arg_dest_pointer_;
    bool arg_pointer_expect_concrete_value_;
    bool arg_pointer_shall_be_null_;
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
        arg_pointer_expect_concrete_value_(true),
        arg_pointer_shall_be_null_(src == nullptr),
        arg_count_(count),
        arg_add_bytes_read_pointer_(nullptr),
        os_write_from_buffer_callback_(nullptr),
        os_try_read_to_buffer_callback_(nullptr)
    {}

    explicit Expectation(int ret, bool expect_null_pointer, size_t count, int fd):
        function_id_(OsFn::write_from_buffer),
        ret_code_(ret),
        arg_fd_(fd),
        arg_src_pointer_(nullptr),
        arg_dest_pointer_(nullptr),
        arg_pointer_expect_concrete_value_(false),
        arg_pointer_shall_be_null_(expect_null_pointer),
        arg_count_(count),
        arg_add_bytes_read_pointer_(nullptr),
        os_write_from_buffer_callback_(nullptr),
        os_try_read_to_buffer_callback_(nullptr)
    {}

    explicit Expectation(int ret, void *dest, size_t count,
                         size_t *add_bytes_read, int fd):
        function_id_(OsFn::try_read_to_buffer),
        ret_code_(ret),
        arg_fd_(fd),
        arg_src_pointer_(nullptr),
        arg_dest_pointer_(dest),
        arg_pointer_expect_concrete_value_(true),
        arg_pointer_shall_be_null_(dest == nullptr),
        arg_count_(count),
        arg_add_bytes_read_pointer_(add_bytes_read),
        os_write_from_buffer_callback_(nullptr),
        os_try_read_to_buffer_callback_(nullptr)
    {}

    explicit Expectation(int ret, bool expect_null_pointer, size_t count,
                         size_t *add_bytes_read, int fd):
        function_id_(OsFn::try_read_to_buffer),
        ret_code_(ret),
        arg_fd_(fd),
        arg_src_pointer_(nullptr),
        arg_dest_pointer_(nullptr),
        arg_pointer_expect_concrete_value_(false),
        arg_pointer_shall_be_null_(expect_null_pointer),
        arg_count_(count),
        arg_add_bytes_read_pointer_(add_bytes_read),
        os_write_from_buffer_callback_(nullptr),
        os_try_read_to_buffer_callback_(nullptr)
    {}

    explicit Expectation(os_write_from_buffer_callback_t fn):
        function_id_(OsFn::write_from_buffer),
        ret_code_(-5),
        arg_fd_(-5),
        arg_src_pointer_(nullptr),
        arg_dest_pointer_(nullptr),
        arg_pointer_expect_concrete_value_(false),
        arg_pointer_shall_be_null_(false),
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
        arg_pointer_expect_concrete_value_(false),
        arg_pointer_shall_be_null_(false),
        arg_count_(0),
        arg_add_bytes_read_pointer_(nullptr),
        os_write_from_buffer_callback_(nullptr),
        os_try_read_to_buffer_callback_(fn)
    {}

    explicit Expectation(int ret, const char *filename):
        function_id_(OsFn::file_new),
        ret_code_(ret),
        arg_fd_(-5),
        arg_filename_(filename),
        arg_src_pointer_(nullptr),
        arg_dest_pointer_(nullptr),
        arg_pointer_expect_concrete_value_(false),
        arg_pointer_shall_be_null_(false),
        arg_count_(0),
        arg_add_bytes_read_pointer_(nullptr),
        os_write_from_buffer_callback_(nullptr),
        os_try_read_to_buffer_callback_(nullptr)
    {}

    explicit Expectation(OsFn fn, const char *filename):
        function_id_(fn),
        ret_code_(-5),
        arg_fd_(-5),
        arg_filename_(filename),
        arg_src_pointer_(nullptr),
        arg_dest_pointer_(nullptr),
        arg_pointer_expect_concrete_value_(false),
        arg_pointer_shall_be_null_(false),
        arg_count_(0),
        arg_add_bytes_read_pointer_(nullptr),
        os_write_from_buffer_callback_(nullptr),
        os_try_read_to_buffer_callback_(nullptr)
    {}

    explicit Expectation(OsFn fn, int fd):
        function_id_(fn),
        ret_code_(-5),
        arg_fd_(fd),
        arg_src_pointer_(nullptr),
        arg_dest_pointer_(nullptr),
        arg_pointer_expect_concrete_value_(false),
        arg_pointer_shall_be_null_(false),
        arg_count_(0),
        arg_add_bytes_read_pointer_(nullptr),
        os_write_from_buffer_callback_(nullptr),
        os_try_read_to_buffer_callback_(nullptr)
    {}

    explicit Expectation(OsFn fn):
        function_id_(fn),
        ret_code_(-5),
        arg_fd_(-5),
        arg_src_pointer_(nullptr),
        arg_dest_pointer_(nullptr),
        arg_pointer_expect_concrete_value_(false),
        arg_pointer_shall_be_null_(false),
        arg_count_(0),
        arg_add_bytes_read_pointer_(nullptr),
        os_write_from_buffer_callback_(nullptr),
        os_try_read_to_buffer_callback_(nullptr)
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

void MockOs::expect_os_write_from_buffer(int ret, bool expect_null_pointer, size_t count, int fd)
{
    if(expect_null_pointer)
        expectations_->add(Expectation(ret, nullptr, count, fd));
    else
        expectations_->add(Expectation(ret, false, count, fd));
}

void MockOs::expect_os_write_from_buffer_callback(MockOs::os_write_from_buffer_callback_t fn)
{
    expectations_->add(Expectation(fn));
}

void MockOs::expect_os_try_read_to_buffer(int ret, void *dest, size_t count, size_t *add_bytes_read, int fd)
{
    expectations_->add(Expectation(ret, dest, count, add_bytes_read, fd));
}

void MockOs::expect_os_try_read_to_buffer(int ret, bool expect_null_pointer, size_t count,
                                          size_t *add_bytes_read, int fd)
{
    if(expect_null_pointer)
        expectations_->add(Expectation(ret, nullptr, count, add_bytes_read, fd));
    else
        expectations_->add(Expectation(ret, false, count, add_bytes_read, fd));
}

void MockOs::expect_os_try_read_to_buffer_callback(MockOs::os_try_read_to_buffer_callback_t fn)
{
    expectations_->add(Expectation(fn));
}

void MockOs::expect_os_abort(void)
{
    expectations_->add(Expectation(OsFn::stdlib_abort));
}

void MockOs::expect_os_file_new(int ret, const char *filename)
{
    expectations_->add(Expectation(ret, filename));
}

void MockOs::expect_os_file_close(int fd)
{
    expectations_->add(Expectation(OsFn::file_close, fd));
}

void MockOs::expect_os_file_delete(const char *filename)
{
    expectations_->add(Expectation(OsFn::file_delete, filename));
}


MockOs *mock_os_singleton = nullptr;

int os_write_from_buffer(const void *src, size_t count, int fd)
{
    const auto &expect(mock_os_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, OsFn::write_from_buffer);

    if(expect.os_write_from_buffer_callback_ != nullptr)
        return expect.os_write_from_buffer_callback_(src, count, fd);

    if(expect.arg_pointer_expect_concrete_value_)
        cppcut_assert_equal(expect.arg_src_pointer_, src);
    else if(expect.arg_pointer_shall_be_null_)
        cppcut_assert_null(src);
    else
        cppcut_assert_not_null(src);

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

    if(expect.arg_pointer_expect_concrete_value_)
        cppcut_assert_equal(expect.arg_dest_pointer_, dest);
    else if(expect.arg_pointer_shall_be_null_)
        cppcut_assert_null(dest);
    else
        cppcut_assert_not_null(dest);

    cppcut_assert_equal(expect.arg_count_, count);
    cppcut_assert_equal(expect.arg_add_bytes_read_pointer_, add_bytes_read);
    cppcut_assert_equal(expect.arg_fd_, fd);
    return expect.ret_code_;
}

void os_abort(void)
{
    const auto &expect(mock_os_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, OsFn::stdlib_abort);
}

int os_file_new(const char *filename)
{
    const auto &expect(mock_os_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, OsFn::file_new);
    cppcut_assert_equal(expect.arg_filename_, std::string(filename));
    return expect.ret_code_;
}

void os_file_close(int fd)
{
    const auto &expect(mock_os_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, OsFn::file_close);
    cppcut_assert_equal(expect.arg_fd_, fd);
}

void os_file_delete(const char *filename)
{
    const auto &expect(mock_os_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.function_id_, OsFn::file_delete);
    cppcut_assert_equal(expect.arg_filename_, std::string(filename));
}
