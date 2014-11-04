#include <cppcutter.h>

#include "registers.h"

#include "mock_dcpd_dbus.hh"

/*!
 * \addtogroup registers_tests Unit tests
 * \ingroup registers
 *
 * SPI registers unit tests.
 */
/*!@{*/

namespace spi_registers_tests
{

static MockDcpdDBus *mock_dcpd_dbus;

void cut_setup(void)
{
    mock_dcpd_dbus = new MockDcpdDBus();
    cppcut_assert_not_null(mock_dcpd_dbus);
    mock_dcpd_dbus->init();
    mock_dcpd_dbus_singleton = mock_dcpd_dbus;
}

void cut_teardown(void)
{
    mock_dcpd_dbus->check();

    delete mock_dcpd_dbus;

    mock_dcpd_dbus_singleton = nullptr;
    mock_dcpd_dbus = nullptr;
}

/*!\test
 * Look up some register known not to be implemented.
 */
void test_lookup_nonexistent_register_fails_gracefully(void)
{
    cppcut_assert_null(register_lookup(10));
}

};

/*!@}*/
