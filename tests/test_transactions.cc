#include <cppcutter.h>
#include <array>

#include "transactions.h"

/*!
 * \addtogroup dcp_transaction_tests Unit tests
 * \ingroup dcp_transaction
 *
 * DCP transaction unit tests.
 */
/*!@{*/

namespace dcp_transaction_tests_queue
{

void cut_setup(void)
{
    transaction_init_allocator();
}

void cut_teardown(void)
{
}

/*!\test
 * Single transactions can be allocated and deallocated.
 */
void test_allocation_and_deallocation_of_single_transaction_object(void)
{
    struct transaction *t = transaction_alloc(false);
    cppcut_assert_not_null(t);

    transaction_free(&t);
    cppcut_assert_null(t);
}

/*!\test
 * Deallocation of transaction frees the internal payload buffer.
 *
 * This test relies on Valgrind's memcheck. We actually should mock away
 * dynamic_buffer_free(), but since Valgrind is run anyway, this half-assed
 * test is all we need to stay on the green side.
 */
void test_deallocation_frees_payload_buffer(void)
{
    struct transaction *t = transaction_alloc(false);
    cppcut_assert_not_null(t);

    static const uint8_t payload_data[] = "test payload data";
    cut_assert_true(transaction_set_payload(t, payload_data, sizeof(payload_data)));

    transaction_free(&t);
    cppcut_assert_null(t);
}

/*!
 * Protect ourselves against infinite loop in case of broken SUT code.
 */
static constexpr size_t max_allocs = 1000;

/*!
 * Use up all transaction objects.
 */
static size_t allocate_all_transactions(std::array<struct transaction *, max_allocs> &dest)
{
    size_t count = 0;

    for(size_t i = 0; i < dest.size(); ++i)
    {
        dest[i] = transaction_alloc(false);

        if(dest[i] == NULL)
            break;

        ++count;
    }

    cppcut_assert_operator(size_t(0), <, count);
    cppcut_assert_operator(max_allocs, >, count);

    return count;
}

/*!
 * Queue up first \p count transactions in passed array.
 */
static struct transaction *
queue_up_all_transactions(std::array<struct transaction *, max_allocs> &objects,
                          size_t count)
{
    struct transaction *head = NULL;

    for(size_t i = 0; i < count; ++i)
    {
        cppcut_assert_not_null(objects[i]);
        transaction_queue_add(&head, objects[i]);
        cppcut_assert_equal(objects[0], head);
    }

    return head;
}

/*!\test
 * Allocate all transaction objects, free them, allocate them again.
 */
void test_allocation_and_deallocation_of_all_transaction_objects(void)
{
    std::array<struct transaction *, max_allocs> objects;
    const size_t count = allocate_all_transactions(objects);

    for(size_t i = 0; i < count; ++i)
    {
        cppcut_assert_not_null(objects[i]);
        transaction_free(&objects[i]);
    }

    const size_t count_second_time = allocate_all_transactions(objects);
    cppcut_assert_equal(count, count_second_time);
}


/*!\test
 * Allocate all transaction objects, free one in the middle, allocate it again.
 */
void test_allocation_of_all_transaction_objects_reallocate_one(void)
{
    std::array<struct transaction *, max_allocs> objects;
    const size_t count = allocate_all_transactions(objects);

    const size_t reused_index = count / 4;
    struct transaction *const reused = objects[reused_index];
    cppcut_assert_not_null(reused);
    transaction_free(&objects[reused_index]);

    cppcut_assert_equal(reused, transaction_alloc(false));
    cppcut_assert_null(transaction_alloc(false));
}

/*!\test
 * Allocate all transaction objects, queue them up, deallocate by freeing head.
 */
void test_deallocation_of_linked_list(void)
{
    std::array<struct transaction *, max_allocs> objects;
    const size_t count = allocate_all_transactions(objects);
    struct transaction *head = queue_up_all_transactions(objects, count);

    transaction_free(&head);
    cppcut_assert_null(head);

    const size_t count_second_time = allocate_all_transactions(objects);
    cppcut_assert_equal(count, count_second_time);
}

/*!\test
 * Allocate all transaction objects, queue them up, dequeue one in the middle.
 */
void test_dequeue_from_middle_of_linked_list(void)
{
    std::array<struct transaction *, max_allocs> objects;
    const size_t count = allocate_all_transactions(objects);
    struct transaction *head = queue_up_all_transactions(objects, count);

    const size_t removed_index = count / 3;
    struct transaction *const removed = objects[removed_index];
    cppcut_assert_not_null(removed);

    cppcut_assert_equal(removed, transaction_queue_remove(&objects[removed_index]));
    cppcut_assert_equal(objects[removed_index + 1], objects[removed_index]);

    transaction_free(&head);

    const size_t count_second_time = allocate_all_transactions(objects);
    cppcut_assert_equal(count - 1, count_second_time);
}

/*!\test
 * Dequeue single element from list.
 */
void test_dequeue_from_list_of_length_one(void)
{
    struct transaction *const head = transaction_alloc(false);
    cppcut_assert_not_null(head);

    struct transaction *head_ptr = head;
    cppcut_assert_equal(head, transaction_queue_remove(&head_ptr));
    cppcut_assert_null(head_ptr);
}

};

/*!@}*/
