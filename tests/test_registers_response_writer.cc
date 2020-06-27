/*
 * Copyright (C) 2020  T+A elektroakustik GmbH & Co. KG
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
#include <array>
#include <functional>

#include "registers.hh"
#include "register_response_writer.hh"

/*!
 * \addtogroup registers_tests Unit tests
 */
/*!@{*/

namespace register_response_writer_tests
{

class BufferWithRedzones
{
  public:
    static constexpr const size_t BUFFER_SIZE = 128;
    static constexpr const uint8_t BUFFER_FILL_BYTE = 0x55;

  private:
    static constexpr const size_t REDZONE_SIZE = 32;
    static constexpr const uint8_t REDZONE_MAGIC = 0xaa;

    static const std::array<const uint8_t, REDZONE_SIZE> expected_redzone_;
    static const std::array<const uint8_t, BUFFER_SIZE>  expected_empty_buffer_;

    std::array<uint8_t, BUFFER_SIZE + 2 * REDZONE_SIZE> buffer_;

  public:
    BufferWithRedzones(const BufferWithRedzones &) = delete;
    BufferWithRedzones &operator=(const BufferWithRedzones &) = delete;

    constexpr explicit BufferWithRedzones():
        buffer_{0}
    {}

    void init()
    {
        std::fill(buffer_.data(),      get(),               REDZONE_MAGIC);
        std::fill(get(),               get() + BUFFER_SIZE, BUFFER_FILL_BYTE);
        std::fill(get() + BUFFER_SIZE, buffer_.end(),       REDZONE_MAGIC);
    }

    void check_redzones() const
    {
        cut_assert_equal_memory(expected_redzone_.data(), expected_redzone_.size(),
                                buffer_.data(),           REDZONE_SIZE);
        cut_assert_equal_memory(expected_redzone_.data(), expected_redzone_.size(),
                                get() + BUFFER_SIZE,      REDZONE_SIZE);
    }

    template <size_t N>
    void check_buffer(const std::array<const uint8_t, N> &expected_content, size_t last) const
    {
        check_buffer(expected_content.data(), expected_content.size(), last);
    }

    template <size_t N>
    void check_buffer(const std::array<uint8_t, N> &expected_content, size_t last) const
    {
        check_buffer(expected_content.data(), expected_content.size(), last);
    }

    void check_buffer(const std::vector<uint8_t> &expected_content, size_t last) const
    {
        check_buffer(expected_content.data(), expected_content.size(), last);
    }

    void check_buffer(const std::string &expected_content, size_t last) const
    {
        check_buffer(reinterpret_cast<const uint8_t *>(expected_content.data()),
                     expected_content.length() + 1, last);
    }

    void check_buffer(size_t last)
    {
        check_buffer(nullptr, 0, last);
    }

    void check_buffer(const uint8_t *expected_content, size_t expected_size, size_t last) const
    {
        cppcut_assert_operator(BUFFER_SIZE, >=, expected_size);
        cppcut_assert_equal(expected_size, last);

        if(expected_size > 0)
        {
            cppcut_assert_not_null(expected_content);
            cut_assert_equal_memory(expected_content, expected_size, get(), last);
        }

        cut_assert_equal_memory(expected_empty_buffer_.data(), BUFFER_SIZE - last,
                                get() + last,                  BUFFER_SIZE - last);
    }

    uint8_t *get() { return &buffer_[REDZONE_SIZE]; }

    const uint8_t *get() const { return const_cast<BufferWithRedzones *>(this)->get(); }
};

constexpr const size_t BufferWithRedzones::BUFFER_SIZE;
constexpr const uint8_t BufferWithRedzones::BUFFER_FILL_BYTE;
constexpr const uint8_t BufferWithRedzones::REDZONE_MAGIC;

const std::array<const uint8_t, BufferWithRedzones::REDZONE_SIZE>
BufferWithRedzones::expected_redzone_
{
    REDZONE_MAGIC, REDZONE_MAGIC, REDZONE_MAGIC, REDZONE_MAGIC,
    REDZONE_MAGIC, REDZONE_MAGIC, REDZONE_MAGIC, REDZONE_MAGIC,
    REDZONE_MAGIC, REDZONE_MAGIC, REDZONE_MAGIC, REDZONE_MAGIC,
    REDZONE_MAGIC, REDZONE_MAGIC, REDZONE_MAGIC, REDZONE_MAGIC,
    REDZONE_MAGIC, REDZONE_MAGIC, REDZONE_MAGIC, REDZONE_MAGIC,
    REDZONE_MAGIC, REDZONE_MAGIC, REDZONE_MAGIC, REDZONE_MAGIC,
    REDZONE_MAGIC, REDZONE_MAGIC, REDZONE_MAGIC, REDZONE_MAGIC,
    REDZONE_MAGIC, REDZONE_MAGIC, REDZONE_MAGIC, REDZONE_MAGIC,
};

const std::array<const uint8_t, BufferWithRedzones::BUFFER_SIZE>
BufferWithRedzones::expected_empty_buffer_
{
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
    BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE, BUFFER_FILL_BYTE,
};

static BufferWithRedzones response_buffer;
static RegisterResponseWriter *w;

void cut_setup()
{
    w = new RegisterResponseWriter(response_buffer.get(), response_buffer.BUFFER_SIZE);
    cppcut_assert_not_null(w);

    response_buffer.init();
}

void cut_teardown()
{
    response_buffer.check_redzones();
    delete w;
}

/*!\test
 * Newly created writer behaves as expected.
 */
void test_properties_of_fresh_writer()
{
    cut_assert_false(w->is_overflown());
    response_buffer.check_buffer(w->get_length());
}

/*!\test
 * Writing a single byte succeeds.
 */
void test_write_single_byte()
{
    static const uint8_t value(0xe2);

    w->push_back(value);

    cut_assert_false(w->is_overflown());
    response_buffer.check_buffer(&value, 1, w->get_length());
}

/*!\test
 * Writing several bytes succeeds.
 */
void test_write_multiple_bytes()
{
    static const std::array<const uint8_t, 4> bytes { 0x00, 0xe1, 0x7f, 0xae, };

    for(size_t i = 0; i < bytes.size(); ++i)
        w->push_back(bytes[i]);

    cut_assert_false(w->is_overflown());
    cppcut_assert_equal(bytes.size(), w->get_length());
    response_buffer.check_buffer(bytes, w->get_length());
}

/*!\test
 * Writing an empty string succeeds. The zero-terminator is written.
 */
void test_write_empty_string()
{
    static const std::string empty;

    w->push_back(empty);

    cut_assert_false(w->is_overflown());
    response_buffer.check_buffer(empty, w->get_length());
}

/*!\test
 * Writing a string consisting of a single character results in two bytes being
 * written.
 */
void test_write_single_char_string()
{
    static const std::string string = "x";

    w->push_back(string);

    cut_assert_false(w->is_overflown());
    response_buffer.check_buffer(string, w->get_length());
}

/*!\test
 * Writing any string works as expected.
 */
void test_write_string()
{
    static const std::string string = "Hello world!";

    w->push_back(string);

    cut_assert_false(w->is_overflown());
    response_buffer.check_buffer(string, w->get_length());
}

/*!\test
 * Writing several data items causes appending these items to the buffer.
 */
void test_write_mixed_data()
{
    static const std::string s1 = "Foo";
    static const std::string s2 = "Bar";

    w->push_back(0x00);
    w->push_back(s1);
    w->push_back(0x90);
    w->push_back(32);
    w->push_back(s2);
    w->push_back(0xff);

    cut_assert_false(w->is_overflown());

    static const std::array<const uint8_t, 12> expected
    {
        0x00, 0x46, 0x6f, 0x6f, 0x00, 0x90, 0x20, 0x42, 0x61, 0x72, 0x00, 0xff,
    };

    response_buffer.check_buffer(expected, w->get_length());
}

static void write_bytes_and_fill_buffer_then_overflow(std::function<void()> &&overflow_fun)
{
    static std::array<uint8_t, response_buffer.BUFFER_SIZE> expected {0};

    expected[0] = 0x90;
    expected[expected.size() - 1] = 0x90;

    for(const auto &b : expected)
        w->push_back(b);

    cut_assert_false(w->is_overflown());
    response_buffer.check_buffer(expected, w->get_length());

    overflow_fun();

    cut_assert_true(w->is_overflown());
    response_buffer.check_buffer(expected, w->get_length());
}

static void write_string_and_fill_buffer_then_overflow(std::function<void()> &&overflow_fun)
{
    static const std::string expected =
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "123456789012345678901234567"
        ;

    cppcut_assert_equal(response_buffer.BUFFER_SIZE, expected.length() + 1);

    w->push_back(expected);

    cut_assert_false(w->is_overflown());
    response_buffer.check_buffer(expected, w->get_length());

    overflow_fun();

    cut_assert_true(w->is_overflown());
    response_buffer.check_buffer(expected, w->get_length());
}

/*!\test
 * Write as many bytes as there is space in the buffer, then overflow by
 * writing a single byte.
 */
void test_write_bytes_and_fill_whole_buffer_then_overflow_with_byte()
{
    write_bytes_and_fill_buffer_then_overflow([] () { w->push_back(0xcd); });
}

/*!\test
 * Write as many bytes as there is space in the buffer, then overflow by
 * writing an empty string.
 */
void test_write_bytes_and_fill_whole_buffer_then_overflow_with_empty_string()
{
    write_bytes_and_fill_buffer_then_overflow([] () { w->push_back(""); });
}

/*!\test
 * Write as many bytes as there is space in the buffer, then overflow by
 * writing a non-empty string.
 */
void test_write_bytes_and_fill_whole_buffer_then_overflow_with_nonempty_string()
{
    write_bytes_and_fill_buffer_then_overflow([] () { w->push_back("test"); });
}

/*!\test
 * Write as many bytes as there is space in the buffer, then overflow by
 * writing multiple empty strings.
 */
void test_write_bytes_and_fill_whole_buffer_then_overflow_with_empty_strings()
{
    write_bytes_and_fill_buffer_then_overflow([] ()
                                              {
                                                  w->push_back("");
                                                  w->push_back("");
                                                  w->push_back("");
                                                  w->push_back("");
                                              });
}

/*!\test
 * Write a very long string matching the size of the buffer, then overflow by
 * writing a single byte.
 */
void test_write_string_and_fill_whole_buffer_then_overflow_with_byte()
{
    write_string_and_fill_buffer_then_overflow([] () { w->push_back(0xdc); });
}

/*!\test
 * Write a very long string matching the size of the buffer, then overflow by
 * writing an empty string.
 */
void test_write_string_and_fill_whole_buffer_then_overflow_with_empty_string()
{
    write_string_and_fill_buffer_then_overflow([] () { w->push_back(""); });
}

/*!\test
 * Write a very long string matching the size of the buffer, then overflow by
 * writing a non-empty string.
 */
void test_write_string_and_fill_whole_buffer_then_overflow_with_nonempty_string()
{
    write_string_and_fill_buffer_then_overflow([] () { w->push_back("test"); });
}

/*!\test
 * Write a very long string matching the size of the buffer, then overflow by
 * writing multiple empty strings.
 */
void test_write_string_and_fill_whole_buffer_then_overflow_with_empty_strings()
{
    write_string_and_fill_buffer_then_overflow([] ()
                                               {
                                                   w->push_back("");
                                                   w->push_back("");
                                                   w->push_back("");
                                                   w->push_back("");
                                               });
}

/*!\test
 * Writing a very long string overflows the buffer.
 */
void test_write_too_long_string()
{
    static const std::string written =
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "1234567890123456789012345678"
        ;

    cppcut_assert_equal(response_buffer.BUFFER_SIZE, written.length());

    w->push_back(written);

    cut_assert_true(w->is_overflown());
    response_buffer.check_buffer(reinterpret_cast<const uint8_t *>(written.data()),
                                 written.length(), w->get_length());
}

/*!\test
 * Appending a too long string to the end of the buffer overflows the buffer.
 */
void test_append_too_long_string()
{
    static constexpr size_t REMAINING = 10;
    std::vector<uint8_t> expected;

    for(size_t i = 0; i < response_buffer.BUFFER_SIZE - REMAINING; ++i)
    {
        w->push_back(0xc4);
        expected.push_back(0xc4);
    }

    cut_assert_false(w->is_overflown());
    response_buffer.check_buffer(expected, w->get_length());

    static const std::string too_long = "This string is too long to fit inside the buffer";
    w->push_back(too_long);

    cppcut_assert_not_equal(size_t(0), REMAINING);
    cut_assert_false(too_long.empty());
    cppcut_assert_operator(REMAINING, <=, too_long.length());

    for(size_t i = 0; i < REMAINING; ++i)
        expected.push_back(too_long[i]);

    cut_assert_true(w->is_overflown());
    response_buffer.check_buffer(expected, w->get_length());
}

/*!\test
 * Overflown buffer cannot be written to anymore.
 */
void test_writes_to_overflown_buffer_are_ignored()
{
    std::vector<uint8_t> expected;

    for(size_t i = 0; i < response_buffer.BUFFER_SIZE; ++i)
    {
        w->push_back(0xaf);
        expected.push_back(0xaf);
    }

    cut_assert_false(w->is_overflown());

    for(size_t i = 0; i < 10; ++i)
    {
        w->push_back(0x16);
        w->push_back("foo");
    }

    cut_assert_true(w->is_overflown());
    response_buffer.check_buffer(expected, w->get_length());
}

static RegisterResponseWriter mk_writer_to_empty_buffer()
{
    RegisterResponseWriter writer(response_buffer.get(), 0);

    cut_assert_true(writer.is_overflown());
    cppcut_assert_equal(size_t(0), w->get_length());

    return writer;
}

/*!\test
 * Any writes of bytes to buffers of size 0 are ignored.
 */
void test_write_byte_to_writer_with_empty_backing_storage()
{
    RegisterResponseWriter writer(mk_writer_to_empty_buffer());

    writer.push_back(0xb3);

    cut_assert_true(writer.is_overflown());
    cppcut_assert_equal(size_t(0), w->get_length());
    response_buffer.check_buffer(w->get_length());
}

/*!\test
 * Any writes of strings to buffers of size 0 are ignored.
 */
void test_write_string_to_writer_with_empty_backing_storage()
{
    RegisterResponseWriter writer(mk_writer_to_empty_buffer());

    writer.push_back("test");

    cut_assert_true(writer.is_overflown());
    cppcut_assert_equal(size_t(0), w->get_length());
    response_buffer.check_buffer(w->get_length());
}

}

/*!@}*/
