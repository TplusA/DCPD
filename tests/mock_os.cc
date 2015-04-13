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
    map_file_to_memory,
    unmap_file,

    first_valid_os_fn_id = write_from_buffer,
    last_valid_os_fn_id = unmap_file,
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

      case OsFn::map_file_to_memory:
        os << "map_file_to_memory";
        break;

      case OsFn::unmap_file:
        os << "unmap_file";
        break;
    }

    os << "()";

    return os;
}

class MockOs::Expectation
{
  public:
    struct Data
    {
        const OsFn function_id_;

        int ret_code_;
        int arg_fd_;
        std::string arg_filename_;
        const void *arg_src_pointer_;
        void *arg_dest_pointer_;
        struct os_mapped_file_data *arg_mapped_pointer_;
        const struct os_mapped_file_data *arg_mapped_template_;
        bool arg_pointer_expect_concrete_value_;
        bool arg_pointer_shall_be_null_;
        size_t arg_count_;
        size_t *arg_add_bytes_read_pointer_;
        os_write_from_buffer_callback_t os_write_from_buffer_callback_;
        os_try_read_to_buffer_callback_t os_try_read_to_buffer_callback_;

        explicit Data(OsFn fn):
            function_id_(fn),
            ret_code_(-5),
            arg_fd_(-5),
            arg_src_pointer_(nullptr),
            arg_dest_pointer_(nullptr),
            arg_mapped_pointer_(nullptr),
            arg_mapped_template_(nullptr),
            arg_pointer_expect_concrete_value_(false),
            arg_pointer_shall_be_null_(false),
            arg_count_(0),
            arg_add_bytes_read_pointer_(nullptr),
            os_write_from_buffer_callback_(nullptr),
            os_try_read_to_buffer_callback_(nullptr)
        {}
    };

    const Data d;

  private:
    /* writable reference for simple ctor code */
    Data &data_ = *const_cast<Data *>(&d);

  public:
    Expectation(const Expectation &) = delete;
    Expectation &operator=(const Expectation &) = delete;

    explicit Expectation(int ret, const void *src, size_t count, int fd):
        d(OsFn::write_from_buffer)
    {
        data_.ret_code_ = ret;
        data_.arg_fd_ = fd;
        data_.arg_src_pointer_ = src;
        data_.arg_pointer_expect_concrete_value_ = true;
        data_.arg_pointer_shall_be_null_ = (src == nullptr);
        data_.arg_count_ = count;
    }

    explicit Expectation(int ret, bool expect_null_pointer, size_t count, int fd):
        d(OsFn::write_from_buffer)
    {
        data_.ret_code_ = ret;
        data_.arg_fd_ = fd;
        data_.arg_pointer_shall_be_null_ = expect_null_pointer;
        data_.arg_count_ = count;
    }

    explicit Expectation(int ret, void *dest, size_t count,
                         size_t *add_bytes_read, int fd):
        d(OsFn::try_read_to_buffer)
    {
        data_.ret_code_ = ret;
        data_.arg_fd_ = fd;
        data_.arg_dest_pointer_ = dest;
        data_.arg_pointer_expect_concrete_value_ = true;
        data_.arg_pointer_shall_be_null_ = (dest == nullptr);
        data_.arg_count_ = count;
        data_.arg_add_bytes_read_pointer_ = add_bytes_read;
    }

    explicit Expectation(int ret, bool expect_null_pointer, size_t count,
                         size_t *add_bytes_read, int fd):
        d(OsFn::try_read_to_buffer)
    {
        data_.ret_code_ = ret;
        data_.arg_fd_ = fd;
        data_.arg_pointer_shall_be_null_ = expect_null_pointer;
        data_.arg_count_ = count;
        data_.arg_add_bytes_read_pointer_ = add_bytes_read;
    }

    explicit Expectation(os_write_from_buffer_callback_t fn):
        d(OsFn::write_from_buffer)
    {
        data_.os_write_from_buffer_callback_ = fn;
    }

    explicit Expectation(os_try_read_to_buffer_callback_t fn):
        d(OsFn::try_read_to_buffer)
    {
        data_.os_try_read_to_buffer_callback_ = fn;
    }

    explicit Expectation(int ret, const char *filename):
        d(OsFn::file_new)
    {
        data_.ret_code_ = ret;
        data_.arg_filename_ = filename;
    }

    explicit Expectation(OsFn fn, const char *filename):
        d(fn)
    {
        data_.arg_filename_ = filename;
    }

    explicit Expectation(OsFn fn, int fd):
        d(fn)
    {
        data_.arg_fd_ = fd;
    }

    explicit Expectation(OsFn fn, bool expect_null_pointer):
        d(fn)
    {
        data_.arg_pointer_shall_be_null_ = expect_null_pointer;
    }

    explicit Expectation(int ret, struct os_mapped_file_data *mapped,
                         const char *filename):
        d(OsFn::map_file_to_memory)
    {
        data_.ret_code_ = ret;
        data_.arg_mapped_pointer_ = mapped;
        data_.arg_pointer_shall_be_null_ = (mapped == nullptr);
        data_.arg_filename_ = filename;
    }

    explicit Expectation(const struct os_mapped_file_data *mapped,
                         const char *filename):
        d(OsFn::map_file_to_memory)
    {
        data_.ret_code_ = (mapped != nullptr && mapped->fd >= 0 && mapped->ptr != NULL) ? 0 : -1;
        data_.arg_mapped_template_ = mapped;
        data_.arg_filename_ = filename;
    }

    explicit Expectation(int ret, bool expect_null_pointer,
                         const char *filename):
        d(OsFn::map_file_to_memory)
    {
        data_.ret_code_ = ret;
        data_.arg_pointer_shall_be_null_ = expect_null_pointer;
        data_.arg_filename_ = filename;
    }

    explicit Expectation(struct os_mapped_file_data *mapped):
        d(OsFn::unmap_file)
    {
        data_.arg_mapped_pointer_ = mapped;
        data_.arg_pointer_shall_be_null_ = (mapped == nullptr);
    }

    explicit Expectation(const struct os_mapped_file_data *mapped):
        d(OsFn::unmap_file)
    {
        data_.arg_mapped_template_ = mapped;
    }

    explicit Expectation(OsFn fn):
        d(fn)
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

void MockOs::expect_os_map_file_to_memory(int ret, struct os_mapped_file_data *mapped,
                                          const char *filename)
{
    expectations_->add(Expectation(ret, mapped, filename));
}

void MockOs::expect_os_map_file_to_memory(int ret, bool expect_null_pointer,
                                          const char *filename)
{
    if(expect_null_pointer)
        expectations_->add(Expectation(ret, nullptr, filename));
    else
        expectations_->add(Expectation(ret, false, filename));
}

void MockOs::expect_os_map_file_to_memory(const struct os_mapped_file_data *mapped,
                                          const char *filename)
{
    expectations_->add(Expectation(mapped, filename));
}

void MockOs::expect_os_unmap_file(struct os_mapped_file_data *mapped)
{
    expectations_->add(Expectation(mapped));
}

void MockOs::expect_os_unmap_file(const struct os_mapped_file_data *mapped)
{
    expectations_->add(Expectation(mapped));
}

void MockOs::expect_os_unmap_file(bool expect_null_pointer)
{
    if(expect_null_pointer)
        expectations_->add(Expectation(static_cast<struct os_mapped_file_data *>(nullptr)));
    else
        expectations_->add(Expectation(OsFn::unmap_file, false));
}


MockOs *mock_os_singleton = nullptr;

int os_write_from_buffer(const void *src, size_t count, int fd)
{
    const auto &expect(mock_os_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, OsFn::write_from_buffer);

    if(expect.d.os_write_from_buffer_callback_ != nullptr)
        return expect.d.os_write_from_buffer_callback_(src, count, fd);

    if(expect.d.arg_pointer_expect_concrete_value_)
        cppcut_assert_equal(expect.d.arg_src_pointer_, src);
    else if(expect.d.arg_pointer_shall_be_null_)
        cppcut_assert_null(src);
    else
        cppcut_assert_not_null(src);

    cppcut_assert_equal(expect.d.arg_count_, count);
    cppcut_assert_equal(expect.d.arg_fd_, fd);
    return expect.d.ret_code_;
}

int os_try_read_to_buffer(void *dest, size_t count, size_t *add_bytes_read, int fd)
{
    const auto &expect(mock_os_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, OsFn::try_read_to_buffer);

    if(expect.d.os_try_read_to_buffer_callback_ != nullptr)
        return expect.d.os_try_read_to_buffer_callback_(dest, count, add_bytes_read, fd);

    if(expect.d.arg_pointer_expect_concrete_value_)
        cppcut_assert_equal(expect.d.arg_dest_pointer_, dest);
    else if(expect.d.arg_pointer_shall_be_null_)
        cppcut_assert_null(dest);
    else
        cppcut_assert_not_null(dest);

    cppcut_assert_equal(expect.d.arg_count_, count);
    cppcut_assert_equal(expect.d.arg_add_bytes_read_pointer_, add_bytes_read);
    cppcut_assert_equal(expect.d.arg_fd_, fd);
    return expect.d.ret_code_;
}

void os_abort(void)
{
    const auto &expect(mock_os_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, OsFn::stdlib_abort);
}

int os_file_new(const char *filename)
{
    const auto &expect(mock_os_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, OsFn::file_new);
    cppcut_assert_equal(expect.d.arg_filename_, std::string(filename));
    return expect.d.ret_code_;
}

void os_file_close(int fd)
{
    const auto &expect(mock_os_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, OsFn::file_close);
    cppcut_assert_equal(expect.d.arg_fd_, fd);
}

void os_file_delete(const char *filename)
{
    const auto &expect(mock_os_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, OsFn::file_delete);
    cppcut_assert_equal(expect.d.arg_filename_, std::string(filename));
}

int os_map_file_to_memory(struct os_mapped_file_data *mapped,
                          const char *filename)
{
    const auto &expect(mock_os_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, OsFn::map_file_to_memory);

    if(expect.d.arg_mapped_template_ != nullptr)
        *mapped = *expect.d.arg_mapped_template_;
    else
    {
        if(expect.d.arg_pointer_expect_concrete_value_)
            cppcut_assert_equal(expect.d.arg_mapped_pointer_, mapped);
        else if(expect.d.arg_pointer_shall_be_null_)
            cppcut_assert_null(mapped);
        else
            cppcut_assert_not_null(mapped);
    }

    cppcut_assert_equal(expect.d.arg_filename_, std::string(filename));

    return expect.d.ret_code_;
}

void os_unmap_file(struct os_mapped_file_data *mapped)
{
    const auto &expect(mock_os_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, OsFn::unmap_file);

    if(expect.d.arg_mapped_template_ != nullptr)
        *mapped = *expect.d.arg_mapped_template_;
    else
    {
        if(expect.d.arg_pointer_expect_concrete_value_)
            cppcut_assert_equal(expect.d.arg_mapped_pointer_, mapped);
        else if(expect.d.arg_pointer_shall_be_null_)
            cppcut_assert_null(mapped);
        else
            cppcut_assert_not_null(mapped);
    }
}
