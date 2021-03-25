/*
 * Copyright (C) 2015--2021  T+A elektroakustik GmbH & Co. KG
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
#include <algorithm>

#include "registers.hh"
#include "networkprefs.h"
#include "dcpregs_protolevel.hh"
#include "connman_service_list.hh"
#include "network_device_list.hh"
#include "mainloop.hh"

#include "mock_messages.hh"

#include "test_registers_common.hh"

#if LOGGED_LOCKS_ENABLED && LOGGED_LOCKS_THREAD_CONTEXTS
thread_local LoggedLock::Context LoggedLock::context;
#endif

MainLoop::Queue MainLoop::detail::queued_work;

/*!
 * \addtogroup registers_tests Unit tests
 * \ingroup registers
 *
 * SPI registers unit tests.
 */
/*!@{*/

static ssize_t test_os_read(int fd, void *dest, size_t count)
{
    cut_fail("Unexpected call of os_read()");
    return -99999;
}

ssize_t (*os_read)(int fd, void *dest, size_t count) = test_os_read;

#if !LOGGED_LOCKS_ENABLED

namespace spi_registers_tests
{

static MockMessages *mock_messages;

class RegisterSetPerVersion
{
  public:
    const uint8_t version_major_;
    const uint8_t version_minor_;
    const uint8_t version_patch_;
    const uint8_t *const registers_;
    const size_t number_of_registers_;

    RegisterSetPerVersion(const RegisterSetPerVersion &) = delete;
    RegisterSetPerVersion(RegisterSetPerVersion &&) = default;
    RegisterSetPerVersion &operator=(const RegisterSetPerVersion &) = delete;

    template <size_t N>
    constexpr explicit RegisterSetPerVersion(uint8_t version_major,
                                             uint8_t version_minor,
                                             uint8_t version_patch,
                                             const std::array<uint8_t, N> &registers):
        version_major_(version_major),
        version_minor_(version_minor),
        version_patch_(version_patch),
        registers_(registers.data()),
        number_of_registers_(N)
    {}

    constexpr explicit RegisterSetPerVersion(uint8_t version_major,
                                             uint8_t version_minor,
                                             uint8_t version_patch):
        version_major_(version_major),
        version_minor_(version_minor),
        version_patch_(version_patch),
        registers_(nullptr),
        number_of_registers_(0)
    {}
};

static const std::array<uint8_t, 38> existing_registers_v1_0_0 =
{
    1,
    17,
    37,
    40, 41, 44, 45,
    50, 51, 53, 54, 55, 56, 57, 58,
    62, 63,
    71, 72, 74, 75, 76, 78, 79,
    92, 93, 94,
    101, 102, 104, 105, 106,
    119,
    120, 121,
    209,
    238, 239,
};

static const std::array<uint8_t, 2> existing_registers_v1_0_1 =
{
    87, 88,
};

static const std::array<uint8_t, 2> existing_registers_v1_0_2 =
{
    95, 210,
};

static const std::array<uint8_t, 1> existing_registers_v1_0_3 =
{
    73,
};

static const std::array<uint8_t, 4> existing_registers_v1_0_4 =
{
    47, 80, 64, 81,
};

static const std::array<uint8_t, 2> existing_registers_v1_0_5 =
{
    18, 19,
};

static const std::array<uint8_t, 1> existing_registers_v1_0_6 =
{
    88,
};

static const std::array<uint8_t, 2> existing_registers_v1_0_7 =
{
    89, 107,
};

static const std::array<uint8_t, 1> existing_registers_v1_0_8 =
{
    207,
};

static const std::array<uint8_t, 1> existing_registers_v1_0_9 =
{
    82,
};

static const std::array<uint8_t, 1> existing_registers_v1_0_10 =
{
    211,
};

static const std::array<RegisterSetPerVersion, 12> all_registers
{
    RegisterSetPerVersion(1, 0, 0, existing_registers_v1_0_0),
    RegisterSetPerVersion(1, 0, 1, existing_registers_v1_0_1),
    RegisterSetPerVersion(1, 0, 2, existing_registers_v1_0_2),
    RegisterSetPerVersion(1, 0, 3, existing_registers_v1_0_3),
    RegisterSetPerVersion(1, 0, 4, existing_registers_v1_0_4),
    RegisterSetPerVersion(1, 0, 5, existing_registers_v1_0_5),
    RegisterSetPerVersion(1, 0, 6, existing_registers_v1_0_6),
    RegisterSetPerVersion(1, 0, 7, existing_registers_v1_0_7),
    RegisterSetPerVersion(1, 0, 8, existing_registers_v1_0_8),
    RegisterSetPerVersion(1, 0, 9, existing_registers_v1_0_9),
    RegisterSetPerVersion(1, 0, 10, existing_registers_v1_0_10),
    RegisterSetPerVersion(1, 1, 0),
};

void cut_setup()
{
    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    Connman::ServiceList::get_singleton_for_update().first.clear();
    Connman::NetworkDeviceList::get_singleton_for_update().first.clear();

    network_prefs_init(nullptr, nullptr);
    Regs::init(nullptr, nullptr);
}

void cut_teardown()
{
    Regs::deinit();
    network_prefs_deinit();

    mock_messages->check();
    mock_messages_singleton = nullptr;
    delete mock_messages;
    mock_messages = nullptr;
}

/*!\test
 * Look up some register known to be implemented.
 */
void test_lookup_existing_register()
{
    const auto *reg = Regs::lookup(51);

    cppcut_assert_not_null(reg);
    cppcut_assert_equal(51U, unsigned(reg->address_));
}

/*!\test
 * Look up some register known not to be implemented.
 */
void test_lookup_nonexistent_register_fails_gracefully()
{
    cppcut_assert_null(Regs::lookup(10));
}

/*!\test
 * Look up all registers that should be implemented.
 *
 * Also check if the register structures are consistently defined.
 */
void test_lookup_all_existing_registers()
{
    for(const auto &regset : all_registers)
    {
        cut_assert_true(Regs::set_protocol_level(regset.version_major_,
                                                 regset.version_minor_,
                                                 regset.version_patch_));

        for(size_t i = 0; i < regset.number_of_registers_; ++i)
        {
            const uint8_t &r = regset.registers_[i];
            const auto *reg = Regs::lookup(r);

            cppcut_assert_not_null(reg);
            cppcut_assert_equal(unsigned(r), unsigned(reg->address_));
            cut_assert(reg->max_data_size_ > 0 ||
                       !reg->has_handler(static_cast<bool (*)(std::vector<uint8_t> &)>(nullptr)));
            cppcut_assert_operator(reg->minimum_protocol_version_.code, <=, reg->maximum_protocol_version_.code);
            cppcut_assert_equal(uint32_t(REGISTER_MK_VERSION(regset.version_major_,
                                                             regset.version_minor_,
                                                             regset.version_patch_)),
                                reg->minimum_protocol_version_.code);
        }
    }
}

/*!\test
 * Look up all registers that should not be implemented.
 */
void test_lookup_all_nonexistent_registers()
{
    std::vector<uint8_t> all_registers_up_to_selected_version;

    for(const auto &regset : all_registers)
    {
        std::copy(regset.registers_,
                  &regset.registers_[regset.number_of_registers_],
                  std::back_inserter(all_registers_up_to_selected_version));

        cut_assert_true(Regs::set_protocol_level(regset.version_major_,
                                                 regset.version_minor_,
                                                 regset.version_patch_));

        const uint32_t selected_version_code(REGISTER_MK_VERSION(regset.version_major_,
                                                                 regset.version_minor_,
                                                                 regset.version_patch_));

        for(unsigned int r = 0; r <= UINT8_MAX; ++r)
        {
            const auto found(std::find(all_registers_up_to_selected_version.begin(),
                                       all_registers_up_to_selected_version.end(),
                                       r));

            if(found == all_registers_up_to_selected_version.end())
                cppcut_assert_null(Regs::lookup(r));
            else
            {
                const auto *reg = Regs::lookup(r);

                cppcut_assert_not_null(reg);
                cppcut_assert_operator(selected_version_code, >=, reg->minimum_protocol_version_.code);
            }
        }
    }
}

/*!\test
 * Make sure we are actually testing all registers from all protocol versions.
 * */
void test_assert_all_registers_are_checked_by_unit_tests()
{
    const Regs::ProtocolLevel *level_ranges = nullptr;
    const size_t level_ranges_count = Regs::get_supported_protocol_levels(&level_ranges);

    cppcut_assert_equal(size_t(2), level_ranges_count);

    const uint32_t lowest_checked_version(REGISTER_MK_VERSION(all_registers[0].version_major_,
                                                              all_registers[0].version_minor_,
                                                              all_registers[0].version_patch_));
    const uint32_t highest_checked_version(REGISTER_MK_VERSION(all_registers[all_registers.size() - 1].version_major_,
                                                               all_registers[all_registers.size() - 1].version_minor_,
                                                               all_registers[all_registers.size() - 1].version_patch_));
    cppcut_assert_equal(level_ranges[0].code, lowest_checked_version);
    cppcut_assert_equal(level_ranges[level_ranges_count * 2 - 1].code, highest_checked_version);
}

}

namespace spi_registers_protocol_level
{

static MockMessages *mock_messages;

static RegisterChangedData *register_changed_data;

static const uint8_t expected_default_protocol_level[3] = { 1, 1, 0, };

static void register_changed_callback(uint8_t reg_number)
{
    register_changed_data->append(reg_number);
}

void cut_setup()
{
    register_changed_data = new RegisterChangedData;

    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    register_changed_data->init();

    Regs::DCPVersion::init();

    Connman::ServiceList::get_singleton_for_update().first.clear();
    Connman::NetworkDeviceList::get_singleton_for_update().first.clear();

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    network_prefs_init(nullptr, nullptr);
    Regs::init(register_changed_callback, nullptr);
}

void cut_teardown()
{
    Regs::deinit();
    network_prefs_deinit();

    register_changed_data->check();

    delete register_changed_data;
    register_changed_data = nullptr;

    mock_messages->check();
    mock_messages_singleton = nullptr;
    delete mock_messages;
    mock_messages = nullptr;
}

void test_read_out_protocol_level()
{
    auto *reg = lookup_register_expect_handlers(1,
                                                Regs::DCPVersion::DCP::read_1_protocol_level,
                                                Regs::DCPVersion::DCP::write_1_protocol_level);

    uint8_t redzone_content[10];
    memset(redzone_content, 0xff, sizeof(redzone_content));

    uint8_t buffer[sizeof(redzone_content) + 3 + sizeof(redzone_content)];
    memset(buffer, 0xff, sizeof(buffer));

    reg->read(buffer + sizeof(redzone_content), sizeof(buffer) - 2 * sizeof(redzone_content));

    cut_assert_equal_memory(redzone_content, sizeof(redzone_content), buffer,
                            sizeof(redzone_content));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + sizeof(redzone_content) + 3, sizeof(redzone_content));

    cut_assert_equal_memory(expected_default_protocol_level,
                            sizeof(expected_default_protocol_level),
                            buffer + sizeof(redzone_content), 3);
}

void test_protocol_level_negotiation_does_not_set_protocol_level()
{
    static const uint8_t range[] = { 1, 0, 2, 1, 0, 2, };

    auto *reg = lookup_register_expect_handlers(1,
                                                Regs::DCPVersion::DCP::read_1_protocol_level,
                                                Regs::DCPVersion::DCP::write_1_protocol_level);

    reg->write(range, sizeof(range));
    register_changed_data->check(1);

    static const uint8_t expected[3] = { 1, 0, 2, };

    /* read out result of negotiation */
    uint8_t buffer[3] = {0};
    cppcut_assert_equal(sizeof(buffer), reg->read(buffer, sizeof(buffer)));
    cut_assert_equal_memory(expected, sizeof(expected), buffer, sizeof(buffer));

    /* read out configured protocol version, still at default */
    buffer[0] = 0;
    cppcut_assert_equal(sizeof(buffer), reg->read(buffer, sizeof(buffer)));

    cut_assert_equal_memory(expected_default_protocol_level,
                            sizeof(expected_default_protocol_level),
                            buffer, sizeof(buffer));
}

void test_protocol_level_can_be_changed()
{
    auto *reg = lookup_register_expect_handlers(1,
                                                Regs::DCPVersion::DCP::read_1_protocol_level,
                                                Regs::DCPVersion::DCP::write_1_protocol_level);

    uint8_t buffer[3] = {0};
    cppcut_assert_equal(sizeof(buffer), reg->read(buffer, sizeof(buffer)));
    cut_assert_equal_memory(expected_default_protocol_level,
                            sizeof(expected_default_protocol_level),
                            buffer, sizeof(buffer));

    static const uint8_t version[3] = { 1, 0, 2, };

    reg->write(version, sizeof(version));
    register_changed_data->check(1);

    buffer[0] = {0};
    cppcut_assert_equal(sizeof(buffer), reg->read(buffer, sizeof(buffer)));
    cut_assert_equal_memory(version, sizeof(version), buffer, sizeof(buffer));

    buffer[0] = {0};
    cppcut_assert_equal(sizeof(buffer), reg->read(buffer, sizeof(buffer)));
    cut_assert_equal_memory(version, sizeof(version), buffer, sizeof(buffer));
}

void test_negotiate_protocol_level_single_range_with_match()
{
    static const uint8_t requests[][6] =
    {
        /* any version */
        { 0, 0, 0, UINT8_MAX, UINT8_MAX, UINT8_MAX, },

        /* major version must match */
        { 1, 0, 0, 1, UINT8_MAX, UINT8_MAX, },

        /* major and minor versions must match */
        { 1, 0, 0, 1, 0, UINT8_MAX, },

        /* major and minor versions must match */
        { 1, 1, 0, 1, 1, UINT8_MAX, },

        /* a range of several supported protocol levels */
        { 1, 0, 0,
          expected_default_protocol_level[0],
          expected_default_protocol_level[1],
          expected_default_protocol_level[2], },

        /* a single, specific protocol level */
        { expected_default_protocol_level[0],
          expected_default_protocol_level[1],
          expected_default_protocol_level[2],
          expected_default_protocol_level[0],
          expected_default_protocol_level[1],
          expected_default_protocol_level[2], },

        /* another specific protocol level */
        {  1, 0, 2, 1, 0, 2, }
    };

    static const uint8_t expected[sizeof(requests) / sizeof(requests[0])][3] =
    {
        { expected_default_protocol_level[0],
          expected_default_protocol_level[1],
          expected_default_protocol_level[2], },
        { expected_default_protocol_level[0],
          expected_default_protocol_level[1],
          expected_default_protocol_level[2], },
        { 1, 0, 10 },
        { expected_default_protocol_level[0],
          expected_default_protocol_level[1],
          expected_default_protocol_level[2], },
        { expected_default_protocol_level[0],
          expected_default_protocol_level[1],
          expected_default_protocol_level[2], },
        { expected_default_protocol_level[0],
          expected_default_protocol_level[1],
          expected_default_protocol_level[2], },
        { 1, 0, 2 },
    };

    auto *reg = lookup_register_expect_handlers(1,
                                                Regs::DCPVersion::DCP::read_1_protocol_level,
                                                Regs::DCPVersion::DCP::write_1_protocol_level);

    for(size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); ++i)
    {
        reg->write(requests[i], sizeof(requests[0]));
        register_changed_data->check(1);

        uint8_t buffer[3] = {0};
        cppcut_assert_equal(sizeof(buffer), reg->read(buffer, sizeof(buffer)));

        cut_assert_equal_memory(expected[i], sizeof(expected[0]),
                                buffer, sizeof(buffer));
    }
}

void test_negotiate_protocol_level_multiple_ranges_with_match()
{
    static const uint8_t match_in_first_range[3 * 6] =
    {
        1, 0, 0, 1, 5, 20,
        0, 0, 1, 0, UINT8_MAX, UINT8_MAX,
        2, 0, 0, UINT8_MAX, UINT8_MAX, UINT8_MAX,
    };

    static const uint8_t match_in_middle_range[3 * 6] =
    {
        0, 0, 1, 0, UINT8_MAX, UINT8_MAX,
        1, 0, 0, 1, 5, 20,
        2, 0, 0, UINT8_MAX, UINT8_MAX, UINT8_MAX,
    };

    static const uint8_t match_in_last_range[3 * 6] =
    {
        0, 0, 1, 0, UINT8_MAX, UINT8_MAX,
        2, 0, 0, UINT8_MAX, UINT8_MAX, UINT8_MAX,
        1, 0, 0, 1, 5, 20,
    };

    static const uint8_t *requests[] =
    {
        match_in_first_range, match_in_middle_range, match_in_last_range,
    };

    /* the test code below is written in sort of a primitive way and assumes
     * equal size of all requests */
    cppcut_assert_equal(sizeof(match_in_first_range), sizeof(match_in_middle_range));
    cppcut_assert_equal(sizeof(match_in_first_range), sizeof(match_in_last_range));

    auto *reg = lookup_register_expect_handlers(1,
                                                Regs::DCPVersion::DCP::read_1_protocol_level,
                                                Regs::DCPVersion::DCP::write_1_protocol_level);

    for(size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); ++i)
    {
        reg->write(requests[i], sizeof(match_in_first_range));
        register_changed_data->check(1);

        uint8_t buffer[3] = {0};
        cppcut_assert_equal(sizeof(buffer), reg->read(buffer, sizeof(buffer)));

        cut_assert_equal_memory(expected_default_protocol_level,
                                sizeof(expected_default_protocol_level),
                                buffer, sizeof(buffer));
    }
}

void test_negotiate_protocol_level_single_range_with_mismatch()
{
    static const uint8_t requests[][6] =
    {
        /* any too high level */
        { expected_default_protocol_level[0],
          expected_default_protocol_level[1],
          uint8_t(expected_default_protocol_level[2] + 1),
          UINT8_MAX, UINT8_MAX, UINT8_MAX, },

        /* any too low level */
        { 0, 0, 0, 0, UINT8_MAX, UINT8_MAX, },

        /* major and minor versions must match */
        { 2, 0, 0, 2, 0, UINT8_MAX, },

        /* a range of three supported protocol levels */
        { 6, 0, 0, 6, 0, 2, },

        /* a single, specific protocol level */
        { 0, 6, 3, 0, 6, 3, },
    };

    auto *reg = lookup_register_expect_handlers(1,
                                                Regs::DCPVersion::DCP::read_1_protocol_level,
                                                Regs::DCPVersion::DCP::write_1_protocol_level);

    for(size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); ++i)
    {
        reg->write(requests[i], sizeof(requests[0]));
        register_changed_data->check(1);

        uint8_t buffer[3] = {0};
        cppcut_assert_equal(size_t(1), reg->read(buffer, sizeof(buffer)));
        cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[0]);
    }
}

void test_negotiate_protocol_level_multiple_ranges_with_mismatch()
{
    static const uint8_t mismatch[3 * 6] =
    {
        0, 0, 0, 0, UINT8_MAX, UINT8_MAX,
        2, 0, 0, 2, UINT8_MAX, UINT8_MAX,
        3, 0, 0, 3, 4, UINT8_MAX,
    };

    auto *reg = lookup_register_expect_handlers(1,
                                                Regs::DCPVersion::DCP::read_1_protocol_level,
                                                Regs::DCPVersion::DCP::write_1_protocol_level);

    reg->write(mismatch, sizeof(mismatch));
    register_changed_data->check(1);

    uint8_t buffer[3] = {0};
    cppcut_assert_equal(size_t(1), reg->read(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[0]);
}

static void choose_maximum_level_of_overlapping_ranges(const uint8_t *const overlapping,
                                                       size_t overlapping_size,
                                                       const uint8_t *const expected)
{
    auto *reg = lookup_register_expect_handlers(1,
                                                Regs::DCPVersion::DCP::read_1_protocol_level,
                                                Regs::DCPVersion::DCP::write_1_protocol_level);

    reg->write(overlapping, overlapping_size);
    register_changed_data->check(1);

    uint8_t buffer[3] = {0};
    cppcut_assert_equal(sizeof(buffer), reg->read(buffer, sizeof(buffer)));

    cut_assert_equal_memory(expected, sizeof(expected_default_protocol_level),
                            buffer, sizeof(buffer));
}

void test_default_level_is_chosen_from_ranges_if_default_is_maximum()
{
    static const uint8_t overlapping[] =
    {
        1, 0, 0, 1, 0, 2,
        1, 5, 7, 6, UINT8_MAX, UINT8_MAX,
        0, 1, 2, 2, 0, 0,
    };

    choose_maximum_level_of_overlapping_ranges(overlapping, sizeof(overlapping),
                                               expected_default_protocol_level);
}

void test_maximum_supported_level_is_chosen_from_ranges()
{
    static const uint8_t overlapping[] =
    {
        1, 5, 7, 6, UINT8_MAX, UINT8_MAX,
        0, 1, 2, 1, 0, 1,
        1, 0, 0, 1, 0, 3,
        1, 0, 1, 1, 0, 2,
    };

    static const uint8_t expected[] = { 1, 0, 3, };

    choose_maximum_level_of_overlapping_ranges(overlapping, sizeof(overlapping),
                                               expected);
}

void test_maximum_supported_level_is_chosen_from_embedded_range()
{
    static const uint8_t embedded[] = { 1, 0, 1, 1, 0, 3, };
    static const uint8_t expected[] = { 1, 0, 3, };

    choose_maximum_level_of_overlapping_ranges(embedded, sizeof(embedded),
                                               expected);
}

void test_maximum_supported_level_is_chosen_from_overlapping_range()
{
    static const uint8_t overlapping[] = { 0, 9, 0, 1, 0, 2, };
    static const uint8_t expected[] = { 1, 0, 2, };

    choose_maximum_level_of_overlapping_ranges(overlapping, sizeof(overlapping),
                                               expected);
}

void test_default_level_is_chosen_from_overlapping_range()
{
    static const uint8_t overlapping[] = { 1, 0, 2, 1, UINT8_MAX, UINT8_MAX, };

    choose_maximum_level_of_overlapping_ranges(overlapping, sizeof(overlapping),
                                               expected_default_protocol_level);
}

void test_broken_ranges_are_ignored()
{
    static const uint8_t broken[][6] =
    {
        { 1, 0, 1, 1, 0, 0, },
        { 1, UINT8_MAX, UINT8_MAX, 1, 0, 0, },
        { UINT8_MAX, UINT8_MAX, UINT8_MAX, 0, 0, 0, },
        { 1, 5, 20, 1, 0, 0, },
    };

    auto *reg = lookup_register_expect_handlers(1,
                                                Regs::DCPVersion::DCP::read_1_protocol_level,
                                                Regs::DCPVersion::DCP::write_1_protocol_level);

    for(size_t i = 0; i < sizeof(broken) / sizeof(broken[0]); ++i)
    {
        reg->write(broken[i], sizeof(broken[0]));
        register_changed_data->check(1);

        uint8_t buffer[3] = {0};
        cppcut_assert_equal(size_t(1), reg->read(buffer, sizeof(buffer)));
        cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[0]);
    }
}

void test_negotiation_requires_at_least_one_range()
{
    static const uint8_t too_short[5] = {0, 0, 0, UINT8_MAX, UINT8_MAX, };

    auto *reg = lookup_register_expect_handlers(1,
                                                Regs::DCPVersion::DCP::read_1_protocol_level,
                                                Regs::DCPVersion::DCP::write_1_protocol_level);

    reg->write(too_short, sizeof(too_short));
    register_changed_data->check(1);

    /* because this register is really important, even broken requests generate
     * an answer */
    uint8_t buffer[3] = {0};
    cppcut_assert_equal(size_t(1), reg->read(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[0]);
}

}

#endif /* !LOGGED_LOCKS_ENABLED  */

/*!@}*/
