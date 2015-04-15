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

#include <cutter.h>
#include <string.h>
#include <stdlib.h>

#include "dynamic_buffer.h"

/*!
 * \addtogroup dynbuffer_tests Unit tests
 * \ingroup dynbuffer
 *
 * Dynamic buffer unit tests.
 */
/*!@{*/

static struct dynamic_buffer buffer;

void cut_setup(void)
{
    dynamic_buffer_init(&buffer);
}

void cut_teardown(void)
{
    dynamic_buffer_free(&buffer);
}

/*!\test
 * Fresh buffers are empty and have no allocated space.
 */
void test_empty_buffer_properties(void);
void test_empty_buffer_properties(void)
{
    cut_assert_true(dynamic_buffer_is_empty(&buffer));
    cut_assert_false(dynamic_buffer_is_allocated(&buffer));
    cut_assert_null(buffer.data);
    cut_assert_equal_size(0, buffer.size);
    cut_assert_equal_size(0, buffer.pos);
}

/*!\test
 * Resizing empty buffer to any size works.
 */
void test_resize_empty_buffer(void);
void test_resize_empty_buffer(void)
{
    static const size_t expected_size = 23;

    cut_assert_true(dynamic_buffer_resize(&buffer, expected_size));
    cut_assert_true(dynamic_buffer_is_empty(&buffer));
    cut_assert_true(dynamic_buffer_is_allocated(&buffer));
    cut_assert_not_null(buffer.data);
    cut_assert_equal_size(expected_size, buffer.size);
}

/*!\test
 * Checking buffer's available space allocates space on an empty buffer.
 */
void test_check_space_on_empty_buffer_allocates_space(void);
void test_check_space_on_empty_buffer_allocates_space(void)
{
    cut_assert_true(dynamic_buffer_check_space(&buffer));
    cut_assert_true(dynamic_buffer_is_empty(&buffer));
    cut_assert_true(dynamic_buffer_is_allocated(&buffer));
    cut_assert_not_null(buffer.data);
    cut_assert_equal_size(0, buffer.pos);
}

/*!\test
 * Checking buffer's available space allocates space when running out of space.
 */
void test_check_space_on_nonfull_buffer_does_not_allocate_space(void);
void test_check_space_on_nonfull_buffer_does_not_allocate_space(void)
{
    static const size_t expected_size = 42;

    cut_assert_true(dynamic_buffer_resize(&buffer, expected_size));

    const uint8_t *const expected_pointer = buffer.data;

    cut_assert_equal_size(expected_size, buffer.size);
    cut_assert_equal_size(0, buffer.pos);

    /* check empty, but allocated buffer */
    cut_assert_true(dynamic_buffer_check_space(&buffer));
    cut_assert_equal_pointer(expected_pointer, buffer.data);
    cut_assert_equal_size(expected_size, buffer.size);
    cut_assert_equal_size(0, buffer.pos);

    /* check partially filled buffer */
    buffer.pos = 20;
    cut_assert_true(dynamic_buffer_check_space(&buffer));
    cut_assert_equal_pointer(expected_pointer, buffer.data);
    cut_assert_equal_size(expected_size, buffer.size);
    cut_assert_equal_size(20, buffer.pos);
}

/*!\test
 * Checking buffer's available space allocates space when running out of space.
 */
void test_check_space_on_full_buffer_allocates_space(void);
void test_check_space_on_full_buffer_allocates_space(void)
{
    static const size_t expected_size = 64;

    cut_assert_true(dynamic_buffer_resize(&buffer, expected_size));

    const uint8_t *const expected_pointer = buffer.data;

    /* nearly full, nothing happens on check */
    buffer.pos = expected_size - 1;
    cut_assert_true(dynamic_buffer_check_space(&buffer));
    cut_assert_equal_pointer(expected_pointer, buffer.data);
    cut_assert_equal_size(expected_size, buffer.size);
    cut_assert_equal_size(expected_size - 1, buffer.pos);

    /* full, should resize */
    buffer.pos = expected_size;
    cut_assert_true(dynamic_buffer_check_space(&buffer));
    cut_assert(expected_size < buffer.size);
    cut_assert_equal_size(expected_size, buffer.pos);
}

/*!\test
 * Resize buffer preserves content in case the allocated memory had to be
 * moved.
 */
void test_buffer_space_is_not_changed_by_resize(void);
void test_buffer_space_is_not_changed_by_resize(void)
{
    uint8_t random_junk[1024UL];

    for(size_t i = 0; i < sizeof(random_junk); ++i)
        random_junk[i] = rand() & UINT8_MAX;

    cut_assert_true(dynamic_buffer_resize(&buffer, sizeof(random_junk)));
    const uint8_t *const original_pointer = buffer.data;

    memcpy(buffer.data, random_junk, sizeof(random_junk));
    buffer.pos += sizeof(random_junk);
    cut_assert_equal_memory(buffer.data, sizeof(random_junk),
                            random_junk, sizeof(random_junk));

    static const size_t max_size = 16UL * 1024UL * 1824UL;

    for(size_t size = 2UL * 1024UL;
        size <= max_size && buffer.data == original_pointer;
        size *= 2UL)
    {
        cut_assert_true(dynamic_buffer_resize(&buffer, size));
    }

    /* for sure the pointer has changed in the loop above---if not, we'll call
     * it an error and we'll need to do something more clever here */
    cut_assert(original_pointer != buffer.data);

    cut_assert(buffer.size > sizeof(random_junk));
    cut_assert_equal_memory(buffer.data, buffer.pos,
                            random_junk, sizeof(random_junk));
}

/*!\test
 * Clearing an allocated buffer works.
 */
void test_cleared_buffer_properties(void);
void test_cleared_buffer_properties(void)
{
    cut_assert_true(dynamic_buffer_check_space(&buffer));

    buffer.pos = buffer.size;
    memset(buffer.data, 0x55, buffer.pos);

    dynamic_buffer_clear(&buffer);
    cut_assert_true(dynamic_buffer_is_empty(&buffer));
    cut_assert_equal_size(0, buffer.pos);
}

/*!@}*/
