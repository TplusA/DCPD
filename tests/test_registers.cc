#include <cppcutter.h>
#include <array>
#include <algorithm>

#include "registers.h"
#include "dcpregs_drcp.h"
#include "drcp_command_codes.h"

#include "mock_dcpd_dbus.hh"
#include "mock_dbus_iface.hh"
#include "mock_messages.hh"

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

namespace spi_registers_tests_drc
{

static MockMessages *mock_messages;
static MockDcpdDBus *mock_dcpd_dbus;
static MockDBusIface *mock_dbus_iface;

static tdbusdcpdPlayback *const dbus_dcpd_playback_iface_dummy =
    reinterpret_cast<tdbusdcpdPlayback *>(0x12345678);

void cut_setup(void)
{
    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_dcpd_dbus = new MockDcpdDBus();
    cppcut_assert_not_null(mock_dcpd_dbus);
    mock_dcpd_dbus->init();
    mock_dcpd_dbus_singleton = mock_dcpd_dbus;

    mock_dbus_iface = new MockDBusIface;
    cppcut_assert_not_null(mock_dbus_iface);
    mock_dbus_iface->init();
    mock_dbus_iface_singleton = mock_dbus_iface;
}

void cut_teardown(void)
{
    mock_messages->check();
    mock_dcpd_dbus->check();
    mock_dbus_iface->check();

    mock_messages_singleton = nullptr;
    mock_dcpd_dbus_singleton = nullptr;
    mock_dbus_iface_singleton = nullptr;

    delete mock_messages;
    delete mock_dcpd_dbus;
    delete mock_dbus_iface;

    mock_messages = nullptr;
    mock_dcpd_dbus = nullptr;
    mock_dbus_iface = nullptr;
}

void test_slave_drc_invalid_command(void)
{
    static const uint8_t buffer[2] = { 0xbe, 0xef };

    mock_messages->expect_msg_info_formatted("DRC: command code 0xbe, data 0xef");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Received unsupported DRC command 0xbe (Invalid argument)");
    cppcut_assert_equal(-1, dcpregs_write_drcp_command(buffer, 2));
}

void test_slave_drc_playback_start(void)
{
    static const uint8_t buffer[2] = { DRCP_PLAYBACK_START, 0x00 };

    mock_messages->expect_msg_info_formatted("DRC: command code 0xb3, data 0x00");
    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_start(dbus_dcpd_playback_iface_dummy);
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, 2));
}

};

/*!@}*/
