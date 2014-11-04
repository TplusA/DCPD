#include <cppcutter.h>
#include <array>
#include <algorithm>

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
static const std::array<uint8_t, 6> existing_registers = { 17, 37, 51, 55, 71, 72, };

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
 * Look up some register known to be implemented.
 */
void test_lookup_existing_register(void)
{
    const struct dcp_register_t *reg = register_lookup(51);

    cppcut_assert_not_null(reg);
    cppcut_assert_equal(51U, unsigned(reg->address));
}

/*!\test
 * Look up some register known not to be implemented.
 */
void test_lookup_nonexistent_register_fails_gracefully(void)
{
    cppcut_assert_null(register_lookup(10));
}

/*!\test
 * Look up all registers that should be implemented.
 *
 * Also check if the register structures are consistently defined.
 */
void test_lookup_all_existing_registers(void)
{
    for(auto r : existing_registers)
    {
        const struct dcp_register_t *reg = register_lookup(r);

        cppcut_assert_not_null(reg);
        cppcut_assert_equal(unsigned(r), unsigned(reg->address));
        cut_assert(((reg->flags & DCP_REGISTER_FLAG_IS_VARIABLE_LENGTH) != 0) ^ (reg->max_data_size == 0));
    }
}

/*!\test
 * Look up all registers that should not be implemented.
 */
void test_lookup_all_nonexistent_registers(void)
{
    for(unsigned int r = 0; r <= UINT8_MAX; ++r)
    {
        auto found =
            std::find(existing_registers.begin(), existing_registers.end(), r);

        if(found == existing_registers.end())
            cppcut_assert_null(register_lookup(r));
        else
            cppcut_assert_not_null(register_lookup(r));
    }
}

};

/*!@}*/
