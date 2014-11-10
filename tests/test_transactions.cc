#include <cppcutter.h>

#include "transactions.h"

/*!
 * \addtogroup dcp_transaction_tests Unit tests
 * \ingroup dcp_transaction
 *
 * DCP transaction unit tests.
 */
/*!@{*/

namespace dcp_transaction_tests
{

void cut_setup(void)
{
    transaction_init_allocator();
}

void cut_teardown(void)
{
}

};

/*!@}*/
