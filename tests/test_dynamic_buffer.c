#include <cutter.h>

#include "dynamic_buffer.h"

static struct dynamic_buffer buffer;

void cut_setup(void)
{
    dynamic_buffer_init(&buffer);
}

void cut_teardown(void)
{
    dynamic_buffer_free(&buffer);
}

void test_check_space_on_empty_buffer_allocates_space(void);
void test_check_space_on_empty_buffer_allocates_space(void)
{
    cut_assert_true(dynamic_buffer_is_empty(&buffer));
    cut_assert_false(dynamic_buffer_is_allocated(&buffer));

    cut_assert_true(dynamic_buffer_check_space(&buffer));

    cut_assert_true(dynamic_buffer_is_empty(&buffer));
    cut_assert_true(dynamic_buffer_is_allocated(&buffer));
}
