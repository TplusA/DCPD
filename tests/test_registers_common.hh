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

#ifndef TEST_REGISTERS_COMMON_HH
#define TEST_REGISTERS_COMMON_HH

#include <vector>
#include <cinttypes>

class RegisterChangedData
{
  private:
    std::vector<uint8_t> changed_registers_;

  public:
    RegisterChangedData(const RegisterChangedData &) = delete;
    RegisterChangedData &operator=(const RegisterChangedData &) = delete;

    explicit RegisterChangedData() {}

    void init() { changed_registers_.clear(); }
    void append(uint8_t reg) { changed_registers_.push_back(reg); }

    void check()
    {
        cppcut_assert_equal(size_t(0), changed_registers_.size());
    }

    void check(uint8_t expected_register)
    {
        cppcut_assert_equal(size_t(1), changed_registers_.size());
        cppcut_assert_equal(uint16_t(expected_register), uint16_t(changed_registers_[0]));

        changed_registers_.clear();
    }

    template <size_t N>
    void check(const std::array<uint8_t, N> &expected_registers)
    {
        cut_assert_equal_memory(expected_registers.data(), N,
                                changed_registers_.data(), changed_registers_.size());

        changed_registers_.clear();
    }
};

static const Regs::Register *lookup_register_expect_handlers_full(
    uint8_t register_number,
    ssize_t (*const expected_read_handler)(uint8_t *, size_t),
    bool (*const expected_read_handler_dynamic)(std::vector<uint8_t> &buffer),
    int (*const expected_write_handler)(const uint8_t *, size_t),
    uint8_t version_major = 0, uint8_t version_minor = 0, uint8_t version_patch = 0)
{
    const auto protocol_level(Regs::get_protocol_level());

    if(version_major > 0)
        cut_assert_true(Regs::set_protocol_level(version_major, version_minor, version_patch));
    else
    {
        cppcut_assert_equal(uint8_t(0), version_minor);
        cppcut_assert_equal(uint8_t(0), version_patch);
    }

    const auto *reg = Regs::lookup(register_number);
    cppcut_assert_not_null(reg);

    if(version_major > 0)
    {
        Regs::unpack_protocol_level(protocol_level, &version_major,
                                    &version_minor, &version_patch);
        cut_assert_true(Regs::set_protocol_level(version_major, version_minor, version_patch));
    }

    cut_assert_true(reg->has_handler(expected_read_handler));
    cut_assert_true(reg->has_handler(expected_read_handler_dynamic));
    cut_assert_true(reg->has_handler(expected_write_handler));

    return reg;
}

/*
 * For write-only registers.
 */
static inline const Regs::Register *lookup_register_expect_handlers(
    uint8_t register_number,
    int (*const expected_write_handler)(const uint8_t *, size_t))
{
    return lookup_register_expect_handlers_full(register_number,
                                                nullptr, nullptr,
                                                expected_write_handler);
}

static inline const Regs::Register *lookup_register_expect_handlers(
    uint8_t register_number,
    uint8_t version_major, uint8_t version_minor, uint8_t version_patch,
    int (*const expected_write_handler)(const uint8_t *, size_t))
{
    return lookup_register_expect_handlers_full(register_number,
                                                nullptr, nullptr,
                                                expected_write_handler,
                                                version_major, version_minor, version_patch);
}

/*
 * For readable registers with static size.
 */
static inline const Regs::Register *lookup_register_expect_handlers(
    uint8_t register_number,
    ssize_t (*const expected_read_handler)(uint8_t *, size_t),
    int (*const expected_write_handler)(const uint8_t *, size_t))
{
    return lookup_register_expect_handlers_full(register_number,
                                                expected_read_handler, nullptr,
                                                expected_write_handler);
}

static inline const Regs::Register *lookup_register_expect_handlers(
    uint8_t register_number,
    uint8_t version_major, uint8_t version_minor, uint8_t version_patch,
    ssize_t (*const expected_read_handler)(uint8_t *, size_t),
    int (*const expected_write_handler)(const uint8_t *, size_t))
{
    return lookup_register_expect_handlers_full(register_number,
                                                expected_read_handler, nullptr,
                                                expected_write_handler,
                                                version_major, version_minor, version_patch);
}

/*
 * For readable registers with dynamic size.
 */
static inline const Regs::Register *lookup_register_expect_handlers(
    uint8_t register_number,
    bool (*const expected_read_handler)(std::vector<uint8_t> &buffer),
    int (*const expected_write_handler)(const uint8_t *, size_t))
{
    return lookup_register_expect_handlers_full(register_number,
                                                nullptr, expected_read_handler,
                                                expected_write_handler);
}

static inline const Regs::Register *lookup_register_expect_handlers(
    uint8_t register_number,
    uint8_t version_major, uint8_t version_minor, uint8_t version_patch,
    bool (*const expected_read_handler)(std::vector<uint8_t> &buffer),
    int (*const expected_write_handler)(const uint8_t *, size_t))
{
    return lookup_register_expect_handlers_full(register_number,
                                                nullptr, expected_read_handler,
                                                expected_write_handler,
                                                version_major, version_minor, version_patch);
}

static inline void read_buffer_expect_failure(const Regs::Register *reg,
                                              uint8_t *buffer, size_t buffer_size,
                                              int expected_error_code)
{
    try
    {
        reg->read(buffer, buffer_size);
        cppcut_assert_equal(0, expected_error_code);
    }
    catch(const Regs::io_error &e)
    {
        cppcut_assert_equal(ssize_t(expected_error_code), e.result());
    }
}

static inline void write_buffer_expect_failure(const Regs::Register *reg,
                                               const uint8_t *buffer, size_t buffer_size,
                                               int expected_error_code)
{
    try
    {
        reg->write(buffer, buffer_size);
        cppcut_assert_equal(0, expected_error_code);
    }
    catch(const Regs::io_error &e)
    {
        cppcut_assert_equal(ssize_t(expected_error_code), e.result());
    }
}

static inline void write_buffer_expect_failure(const Regs::Register *reg,
                                               const char *buffer, size_t buffer_size,
                                               int expected_error_code)
{
    write_buffer_expect_failure(reg, reinterpret_cast<const uint8_t *>(buffer),
                                buffer_size, expected_error_code);
}

#endif /* !TEST_REGISTERS_COMMON_HH */
