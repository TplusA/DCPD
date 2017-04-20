/*
 * Copyright (C) 2015, 2016, 2017  T+A elektroakustik GmbH & Co. KG
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

#include <cppcutter.h>
#include <array>
#include <algorithm>
#include <glib.h>

#include "registers.h"
#include "registers_priv.h"
#include "networkprefs.h"
#include "dcpregs_drcp.h"
#include "dcpregs_protolevel.h"
#include "dcpregs_networkconfig.h"
#include "dcpregs_wlansurvey.h"
#include "dcpregs_upnpname.h"
#include "dcpregs_filetransfer.h"
#include "dcpregs_filetransfer.hh"
#include "dcpregs_filetransfer_priv.h"
#include "dcpregs_playstream.h"
#include "dcpregs_playstream.hh"
#include "dcpregs_mediaservices.h"
#include "dcpregs_searchparameters.h"
#include "dcpregs_status.h"
#include "drcp_command_codes.h"
#include "dbus_handlers_connman_manager_glue.h"
#include "stream_id.hh"
#include "actor_id.h"
#include "md5.hh"
#include "gvariantwrapper.hh"

#include "mock_dcpd_dbus.hh"
#include "mock_file_transfer_dbus.hh"
#include "mock_streamplayer_dbus.hh"
#include "mock_credentials_dbus.hh"
#include "mock_airable_dbus.hh"
#include "mock_artcache_dbus.hh"
#include "mock_logind_manager_dbus.hh"
#include "mock_dbus_iface.hh"
#include "mock_connman.hh"
#include "mock_messages.hh"
#include "mock_os.hh"

/*
 * Here. Here it is, right down there.
 *
 * It is a stupid hack to speed up development. Instead of putting this little
 * fellow into a libtool convenience library like a good developer would
 * usually do, we are simply including that little C file. It will stay that
 * little, right?
 *
 * Watch it fail later.
 */
#include "dbus_common.c"

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

static ssize_t test_os_write(int fd, const void *buf, size_t count)
{
    cut_fail("Unexpected call of os_write()");
    return -99999;
}

ssize_t (*os_read)(int fd, void *dest, size_t count) = test_os_read;
ssize_t (*os_write)(int fd, const void *buf, size_t count) = test_os_write;

static const struct dcp_register_t *lookup_register_expect_handlers_full(
    uint8_t register_number,
    ssize_t (*const expected_read_handler)(uint8_t *, size_t),
    bool (*const expected_read_handler_dynamic)(struct dynamic_buffer *buffer),
    int (*const expected_write_handler)(const uint8_t *, size_t))
{
    const struct dcp_register_t *reg = register_lookup(register_number);
    cppcut_assert_not_null(reg);

    cut_assert(reg->read_handler == expected_read_handler);
    cut_assert(reg->write_handler == expected_write_handler);
    cut_assert(reg->read_handler_dynamic == expected_read_handler_dynamic);
    cut_assert(!(reg->read_handler != nullptr && reg->read_handler_dynamic != nullptr));

    return reg;
}

/*
 * For write-only registers.
 */
static const struct dcp_register_t *lookup_register_expect_handlers(
    uint8_t register_number,
    int (*const expected_write_handler)(const uint8_t *, size_t))
{
    return lookup_register_expect_handlers_full(register_number,
                                                nullptr, nullptr,
                                                expected_write_handler);
}

/*
 * For readable registers with static size.
 */
static const struct dcp_register_t *lookup_register_expect_handlers(
    uint8_t register_number,
    ssize_t (*const expected_read_handler)(uint8_t *, size_t),
    int (*const expected_write_handler)(const uint8_t *, size_t))
{
    return lookup_register_expect_handlers_full(register_number,
                                                expected_read_handler, nullptr,
                                                expected_write_handler);
}

/*
 * For readable registers with dynamic size.
 */
static const struct dcp_register_t *lookup_register_expect_handlers(
    uint8_t register_number,
    bool (*const expected_read_handler)(struct dynamic_buffer *buffer),
    int (*const expected_write_handler)(const uint8_t *, size_t))
{
    return lookup_register_expect_handlers_full(register_number,
                                                nullptr, expected_read_handler,
                                                expected_write_handler);
}

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

class SurveyCompleteNotificationData
{
  private:
    bool is_expected_;
    bool direct_call_;
    bool was_called_;
    bool was_processed_;
    ConnmanSurveyDoneFn callback_;
    enum ConnmanSiteScanResult callback_result_;

  public:
    SurveyCompleteNotificationData(const SurveyCompleteNotificationData &) = delete;
    SurveyCompleteNotificationData &operator=(const SurveyCompleteNotificationData &) = delete;

    explicit SurveyCompleteNotificationData() { init(); }

    void init()
    {
        is_expected_ = false;
        direct_call_  = false;
        was_called_ = false;
        was_processed_ = false;
        callback_ = nullptr;
        callback_result_ = ConnmanSiteScanResult(CONNMAN_SITE_SCAN_RESULT_LAST + 1);
    }

    void expect(bool direct_call = false)
    {
        is_expected_ = true;
        direct_call_ = direct_call;
    }

    void set(ConnmanSurveyDoneFn callback,
             enum ConnmanSiteScanResult callback_result)
    {
        cut_assert_true(is_expected_);
        cut_assert_false(was_called_);
        cut_assert_false(was_processed_);
        cppcut_assert_not_null(reinterpret_cast<void *>(callback));
        callback_ = callback;
        callback_result_ = callback_result;
        was_called_ = true;

        if(direct_call_)
            (*this)();
    }

    void check()
    {
        cppcut_assert_equal(is_expected_, was_called_);
        cppcut_assert_equal(is_expected_, was_processed_);
        init();
    }

    /*!
     * Deferred execution of callback to simulate threaded execution.
     *
     * Also, there is a mutex involved that would lead to a deadlock situtation
     * would the callback be called directly.
     */
    void operator()()
    {
        cut_assert_false(was_processed_);
        cppcut_assert_not_null(reinterpret_cast<void *>(callback_));
        callback_(callback_result_);
        was_processed_ = true;
    }
};

static SurveyCompleteNotificationData survey_complete_notification_data;

static void survey_complete(ConnmanSurveyDoneFn callback,
                            enum ConnmanSiteScanResult callback_result)
{
    survey_complete_notification_data.set(callback, callback_result);
}

class ConnectToConnManServiceData
{
  public:
    enum class Mode
    {
        NONE,
        FROM_CONFIG,
        WPS_DIRECT_BY_SSID,
        WPS_DIRECT_BY_NAME,
        WPS_SCAN,
    };

  private:
    Mode expected_mode_;
    enum NetworkPrefsTechnology expected_tech_;
    std::string expected_service_;
    const char *expected_service_cstr_;
    std::string expected_network_name_;
    const char *expected_network_name_cstr_;
    std::vector<uint8_t> expected_network_ssid_;

    Mode called_mode_;

  public:
    ConnectToConnManServiceData(const ConnectToConnManServiceData &) = delete;
    ConnectToConnManServiceData &operator=(const ConnectToConnManServiceData &) = delete;

    explicit ConnectToConnManServiceData() { init(); }

    void init()
    {
        expected_mode_ = Mode::NONE;
        expected_tech_ = NWPREFSTECH_UNKNOWN;
        expected_service_.clear();
        expected_service_cstr_ = nullptr;
        expected_network_name_.clear();
        expected_network_name_cstr_ = nullptr;
        expected_network_ssid_.clear();
        called_mode_ = Mode::NONE;
    }

    void expect(enum NetworkPrefsTechnology expected_tech,
                const char *expected_service_to_be_disabled)
    {
        cppcut_assert_not_equal(NWPREFSTECH_UNKNOWN, expected_tech);

        expected_mode_ = Mode::FROM_CONFIG;
        expected_tech_ = expected_tech;

        if(expected_service_to_be_disabled != nullptr)
        {
            expected_service_ = expected_service_to_be_disabled;
            expected_service_cstr_ = expected_service_.c_str();
        }

        called_mode_ = Mode::NONE;
    }

    void expect(const char *expected_service_to_be_disabled,
                const char *expected_network_name,
                const std::vector<uint8_t> *expected_network_ssid)
    {
        if(expected_service_to_be_disabled != nullptr)
        {
            expected_service_ = expected_service_to_be_disabled;
            expected_service_cstr_ = expected_service_.c_str();
        }

        if(expected_network_name != nullptr)
        {
            expected_network_name_ = expected_network_name;
            expected_network_name_cstr_ = expected_network_name_.c_str();
            expected_mode_ = Mode::WPS_DIRECT_BY_NAME;
        }
        else if(expected_network_ssid != nullptr)
        {
            expected_network_ssid_ = *expected_network_ssid;
            expected_mode_ = Mode::WPS_DIRECT_BY_SSID;
        }
        else
            expected_mode_ = Mode::WPS_SCAN;

        called_mode_ = Mode::NONE;
    }

    void called(enum NetworkPrefsTechnology tech,
                const char *service_to_be_disabled)
    {
        cppcut_assert_equal(Mode::FROM_CONFIG, expected_mode_);
        cppcut_assert_equal(Mode::NONE, called_mode_);

        called_mode_ = Mode::FROM_CONFIG;

        cppcut_assert_equal(expected_tech_, tech);
        cppcut_assert_equal(expected_service_cstr_, service_to_be_disabled);
    }

    void called(const char *network_name, const char *network_ssid,
                const char *service_to_be_disabled)
    {
        cppcut_assert_equal(Mode::NONE, called_mode_);

        switch(expected_mode_)
        {
          case Mode::NONE:
            cut_fail("Unexpected mode NONE");
            break;

          case Mode::FROM_CONFIG:
            cut_fail("Unexpected mode FROM_CONFIG");
            break;

          case Mode::WPS_DIRECT_BY_SSID:
            called_mode_ = expected_mode_;

            {
                std::string temp;
                for(const uint8_t &byte : expected_network_ssid_)
                {
                    temp.push_back(nibble_to_char(byte >> 4));
                    temp.push_back(nibble_to_char(byte & 0x0f));
                }

                cppcut_assert_equal(temp.c_str(), network_ssid);
            }

            break;

          case Mode::WPS_DIRECT_BY_NAME:
            called_mode_ = expected_mode_;
            cppcut_assert_equal(expected_network_name_cstr_, network_name);
            cppcut_assert_null(network_ssid);
            break;

          case Mode::WPS_SCAN:
            called_mode_ = expected_mode_;
            cppcut_assert_null(network_name);
            cppcut_assert_null(network_ssid);
            break;
        }

        cppcut_assert_equal(expected_service_cstr_, service_to_be_disabled);
    }

    void check()
    {
        cppcut_assert_equal(expected_mode_, called_mode_);
        init();
    }

  private:
    static char nibble_to_char(uint8_t nibble)
    {
        return (nibble < 10) ? '0' + nibble : 'a' + nibble - 10;
    }
};

static std::ostream &operator<<(std::ostream &os, ConnectToConnManServiceData::Mode mode)
{
    switch(mode)
    {
      case ConnectToConnManServiceData::Mode::NONE:
        os << "NONE";
        break;

      case ConnectToConnManServiceData::Mode::FROM_CONFIG:
        os << "FROM_CONFIG";
        break;

      case ConnectToConnManServiceData::Mode::WPS_DIRECT_BY_SSID:
        os << "WPS_DIRECT_BY_SSID";
        break;

      case ConnectToConnManServiceData::Mode::WPS_DIRECT_BY_NAME:
        os << "WPS_DIRECT_BY_NAME";
        break;

      case ConnectToConnManServiceData::Mode::WPS_SCAN:
        os << "WPS_SCAN";
        break;
    }

    return os;
}

static ConnectToConnManServiceData connect_to_connman_service_data;

/* Instead of writing a full mock for the ConnMan D-Bus API, we'll just have
 * this little function as a poor, but quick replacement */
void dbussignal_connman_manager_connect_to_service(enum NetworkPrefsTechnology tech,
                                                   const char *service_to_be_disabled)
{
    connect_to_connman_service_data.called(tech, service_to_be_disabled);
}

/* Another quick replacement for the Connman D-Bus API */
void dbussignal_connman_manager_connect_to_wps_service(const char *network_name,
                                                       const char *network_ssid,
                                                       const char *service_to_be_disabled)
{
    connect_to_connman_service_data.called(network_name, network_ssid,
                                           service_to_be_disabled);
}

namespace spi_registers_tests
{

static MockMessages *mock_messages;
static MockDcpdDBus *mock_dcpd_dbus;

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

static const std::array<RegisterSetPerVersion, 4> all_registers
{
    RegisterSetPerVersion(1, 0, 0, existing_registers_v1_0_0),
    RegisterSetPerVersion(1, 0, 1, existing_registers_v1_0_1),
    RegisterSetPerVersion(1, 0, 2, existing_registers_v1_0_2),
    RegisterSetPerVersion(1, 0, 3, existing_registers_v1_0_3),
};

void cut_setup()
{
    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_dcpd_dbus = new MockDcpdDBus();
    cppcut_assert_not_null(mock_dcpd_dbus);
    mock_dcpd_dbus->init();
    mock_dcpd_dbus_singleton = mock_dcpd_dbus;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    network_prefs_init(NULL, NULL, NULL, NULL);
    register_init(NULL);
}

void cut_teardown()
{
    register_deinit();
    network_prefs_deinit();

    mock_messages->check();
    mock_dcpd_dbus->check();

    mock_messages_singleton = nullptr;
    mock_dcpd_dbus_singleton = nullptr;

    delete mock_messages;
    delete mock_dcpd_dbus;

    mock_messages = nullptr;
    mock_dcpd_dbus = nullptr;
}

/*!\test
 * Look up some register known to be implemented.
 */
void test_lookup_existing_register()
{
    const struct dcp_register_t *reg = register_lookup(51);

    cppcut_assert_not_null(reg);
    cppcut_assert_equal(51U, unsigned(reg->address));
}

/*!\test
 * Look up some register known not to be implemented.
 */
void test_lookup_nonexistent_register_fails_gracefully()
{
    cppcut_assert_null(register_lookup(10));
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
        cut_assert_true(register_set_protocol_level(regset.version_major_,
                                                    regset.version_minor_,
                                                    regset.version_patch_));

        for(size_t i = 0; i < regset.number_of_registers_; ++i)
        {
            const uint8_t &r = regset.registers_[i];
            const struct dcp_register_t *reg = register_lookup(r);

            cppcut_assert_not_null(reg);
            cppcut_assert_equal(unsigned(r), unsigned(reg->address));
            cut_assert(reg->max_data_size > 0 || reg->read_handler_dynamic != nullptr);
            cppcut_assert_operator(reg->minimum_protocol_version.code, <=, reg->maximum_protocol_version.code);
            cppcut_assert_equal(uint32_t(REGISTER_MK_VERSION(regset.version_major_, regset.version_minor_, regset.version_patch_)),
                                reg->minimum_protocol_version.code);
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

        cut_assert_true(register_set_protocol_level(regset.version_major_,
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
                cppcut_assert_null(register_lookup(r));
            else
            {
                const struct dcp_register_t *reg = register_lookup(r);

                cppcut_assert_not_null(reg);
                cppcut_assert_operator(selected_version_code, >=, reg->minimum_protocol_version.code);
            }
        }
    }
}

/*!\test
 * Make sure we are actually testing all registers from all protocol versions.
 * */
void test_assert_all_registers_are_checked_by_unit_tests()
{
    const struct RegisterProtocolLevel *level_ranges = nullptr;
    const size_t level_ranges_count = register_get_supported_protocol_levels(&level_ranges);

    cppcut_assert_equal(size_t(1), level_ranges_count);

    const uint32_t lowest_checked_version(REGISTER_MK_VERSION(all_registers[0].version_major_,
                                                              all_registers[0].version_minor_,
                                                              all_registers[0].version_patch_));
    const uint32_t highest_checked_version(REGISTER_MK_VERSION(all_registers[all_registers.size() - 1].version_major_,
                                                               all_registers[all_registers.size() - 1].version_minor_,
                                                               all_registers[all_registers.size() - 1].version_patch_));
    cppcut_assert_equal(level_ranges[0].code, lowest_checked_version);
    cppcut_assert_equal(level_ranges[1].code, highest_checked_version);
}

};

namespace spi_registers_tests_drc
{

static MockMessages *mock_messages;
static MockOs *mock_os;
static MockDcpdDBus *mock_dcpd_dbus;
static MockLogindManagerDBus *mock_logind_manager_dbus;
static MockDBusIface *mock_dbus_iface;

static tdbusdcpdPlayback *const dbus_dcpd_playback_iface_dummy =
    reinterpret_cast<tdbusdcpdPlayback *>(0x12345678);

static tdbusdcpdViews *const dbus_dcpd_views_iface_dummy =
    reinterpret_cast<tdbusdcpdViews *>(0x87654321);

static tdbusdcpdListNavigation *const dbus_dcpd_list_navigation_iface_dummy =
    reinterpret_cast<tdbusdcpdListNavigation *>(0x24681357);

static tdbusdcpdListItem *const dbus_dcpd_list_item_iface_dummy =
    reinterpret_cast<tdbusdcpdListItem *>(0x75318642);

static tdbuslogindManager *const dbus_logind_manager_iface_dummy =
    reinterpret_cast<tdbuslogindManager *>(0x35127956);

void cut_setup()
{
    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_os = new MockOs;
    cppcut_assert_not_null(mock_os);
    mock_os->init();
    mock_os_singleton = mock_os;

    mock_dcpd_dbus = new MockDcpdDBus();
    cppcut_assert_not_null(mock_dcpd_dbus);
    mock_dcpd_dbus->init();
    mock_dcpd_dbus_singleton = mock_dcpd_dbus;

    mock_logind_manager_dbus = new MockLogindManagerDBus();
    cppcut_assert_not_null(mock_logind_manager_dbus);
    mock_logind_manager_dbus->init();
    mock_logind_manager_dbus_singleton = mock_logind_manager_dbus;

    mock_dbus_iface = new MockDBusIface;
    cppcut_assert_not_null(mock_dbus_iface);
    mock_dbus_iface->init();
    mock_dbus_iface_singleton = mock_dbus_iface;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);
}

void cut_teardown()
{
    mock_messages->check();
    mock_os->check();
    mock_dcpd_dbus->check();
    mock_logind_manager_dbus->check();
    mock_dbus_iface->check();

    mock_messages_singleton = nullptr;
    mock_os_singleton = nullptr;
    mock_dcpd_dbus_singleton = nullptr;
    mock_logind_manager_dbus_singleton = nullptr;
    mock_dbus_iface_singleton = nullptr;

    delete mock_messages;
    delete mock_os;
    delete mock_dcpd_dbus;
    delete mock_logind_manager_dbus;
    delete mock_dbus_iface;

    mock_messages = nullptr;
    mock_os = nullptr;
    mock_dcpd_dbus = nullptr;
    mock_logind_manager_dbus = nullptr;
    mock_dbus_iface = nullptr;
}

/*!\test
 * Check that writes to register 72 (DRC command) are indeed wired to calls of
 * dcpregs_write_drcp_command(), and that reading from register 72 is not
 * possible.
 */
void test_dcp_register_72_calls_correct_write_handler()
{
    const struct dcp_register_t *reg = register_lookup(72);

    cppcut_assert_not_null(reg);
    cppcut_assert_equal(72U, unsigned(reg->address));
    cut_assert(reg->write_handler == dcpregs_write_drcp_command);
    cut_assert(reg->read_handler == NULL);
}

/*!\test
 * Slave sends some unsupported DRC command over DCP.
 */
void test_slave_drc_invalid_command()
{
    static const uint8_t buffer[] = { 0xbe };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0xbe");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Received unsupported DRC command 0xbe (Invalid argument)");
    cppcut_assert_equal(-1, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for starting playback.
 */
void test_slave_drc_playback_start()
{
    static const uint8_t buffer[] = { DRCP_PLAYBACK_START };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0xb3");
    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_start(dbus_dcpd_playback_iface_dummy);
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for opening the view with binary ID 0.
 */
void test_slave_drc_views_goto_view_by_id_0()
{
    static const uint8_t buffer[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x00, DRCP_ACCEPT };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x9a");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_open(dbus_dcpd_views_iface_dummy, "UPnP");
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for opening the view with binary ID 1.
 */
void test_slave_drc_views_goto_view_by_id_1()
{
    static const uint8_t buffer[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x01, DRCP_ACCEPT };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x9a");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_open(dbus_dcpd_views_iface_dummy, "TuneIn");
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for opening the view with binary ID 2.
 */
void test_slave_drc_views_goto_view_by_id_2()
{
    static const uint8_t buffer[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x02, DRCP_ACCEPT };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x9a");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_open(dbus_dcpd_views_iface_dummy, "Filesystem");
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for opening a view with unknown binary ID.
 */
void test_slave_drc_views_goto_view_by_id_unknown_id()
{
    static const uint8_t buffer_lowest_unknown[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x03, DRCP_ACCEPT };
    static const uint8_t buffer_highest_unknown[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, UINT8_MAX, DRCP_ACCEPT };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x9a");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_NOTICE, "Unknown view ID 0x03 (Invalid argument)");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0x9a failed: -1");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    cppcut_assert_equal(-1, dcpregs_write_drcp_command(buffer_lowest_unknown, sizeof(buffer_lowest_unknown)));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x9a");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_NOTICE, "Unknown view ID 0xff (Invalid argument)");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0x9a failed: -1");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    cppcut_assert_equal(-1, dcpregs_write_drcp_command(buffer_highest_unknown, sizeof(buffer_highest_unknown)));
}

/*!\test
 * Slave sends malformed DRC command for opening a view by ID.
 */
void test_slave_drc_views_goto_view_by_id_must_be_terminated_with_accept_code()
{
    static const uint8_t buffer[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x00, DRCP_ACCEPT - 1U };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x9a");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0x9a failed: -1");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    cppcut_assert_equal(-1, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends too short DRC command for opening view by ID.
 */
void test_slave_drc_views_goto_view_by_id_with_too_few_data_bytes()
{
    static const uint8_t buffer[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x00 };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x9a");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_NOTICE, "Unexpected data length 1, expected 2 (Invalid argument)");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0x9a failed: -1");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    cppcut_assert_equal(-1, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends too long DRC command for opening view by ID.
 */
void test_slave_drc_views_goto_view_by_id_with_too_many_data_bytes()
{
    static const uint8_t buffer[] = { DRCP_BROWSE_VIEW_OPEN_SOURCE, 0x00, DRCP_ACCEPT, 0x00 };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x9a");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_NOTICE, "Unexpected data length 3, expected 2 (Invalid argument)");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0x9a failed: -1");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    cppcut_assert_equal(-1, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for opening the internet radio view.
 */
void test_slave_drc_views_goto_internet_radio()
{
    static const uint8_t buffer[] = { DRCP_GOTO_INTERNET_RADIO, 0x00 };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0xaa");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_open(dbus_dcpd_views_iface_dummy, "Internet Radio");
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for toggling between browsing and playing views.
 */
void test_slave_drc_views_toggle_browse_and_play()
{
    static const uint8_t buffer[] = { DRCP_BROWSE_PLAY_VIEW_TOGGLE, 0x00 };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0xba");
    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_toggle(dbus_dcpd_views_iface_dummy, "Browse", "Play");
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for moving the cursor one line up.
 */
void test_slave_drc_list_navigation_scroll_one_line_up()
{
    static const uint8_t buffer[] = { DRCP_SCROLL_UP_ONE, 0x00 };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x26");
    mock_dbus_iface->expect_dbus_get_list_navigation_iface(dbus_dcpd_list_navigation_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_list_navigation_emit_move_lines(dbus_dcpd_list_navigation_iface_dummy, -1);
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for moving the cursor one page down.
 */
void test_slave_drc_list_navigation_scroll_one_page_down()
{
    static const uint8_t buffer[] = { DRCP_SCROLL_PAGE_DOWN, 0x00 };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x98");
    mock_dbus_iface->expect_dbus_get_list_navigation_iface(dbus_dcpd_list_navigation_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_list_navigation_emit_move_pages(dbus_dcpd_list_navigation_iface_dummy, 1);
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for moving the cursor 10 lines up.
 */
void test_slave_drc_list_navigation_scroll_10_lines_up()
{
    static const uint8_t buffer[] = { DRCP_SCROLL_UP_MANY, 0x0a, DRCP_ACCEPT, };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x21");
    mock_dbus_iface->expect_dbus_get_list_navigation_iface(dbus_dcpd_list_navigation_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_list_navigation_emit_move_lines(dbus_dcpd_list_navigation_iface_dummy, -10);
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for moving the cursor 8 lines down.
 */
void test_slave_drc_list_navigation_scroll_8_lines_down()
{
    static const uint8_t buffer[] = { DRCP_SCROLL_DOWN_MANY, 0x08, DRCP_ACCEPT, };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x22");
    mock_dbus_iface->expect_dbus_get_list_navigation_iface(dbus_dcpd_list_navigation_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_list_navigation_emit_move_lines(dbus_dcpd_list_navigation_iface_dummy, 8);
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Fast scrolling by zero lines has no effect whatsoever.
 */
void test_slave_drc_list_navigation_scroll_fast_by_0_lines_is_ignored()
{
    static const uint8_t buffer_up[]   = { DRCP_SCROLL_UP_MANY,   0x00, DRCP_ACCEPT, };
    static const uint8_t buffer_down[] = { DRCP_SCROLL_DOWN_MANY, 0x00, DRCP_ACCEPT, };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x21");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0x21 failed: -1");
    mock_dbus_iface->expect_dbus_get_list_navigation_iface(dbus_dcpd_list_navigation_iface_dummy);
    cppcut_assert_equal(-1, dcpregs_write_drcp_command(buffer_up, sizeof(buffer_up)));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x22");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "DRC command 0x22 failed: -1");
    mock_dbus_iface->expect_dbus_get_list_navigation_iface(dbus_dcpd_list_navigation_iface_dummy);
    cppcut_assert_equal(-1, dcpregs_write_drcp_command(buffer_down, sizeof(buffer_down)));
}


/*!\test
 * Slave sends DRC command for adding the currently selected item to the
 * favorites list.
 */
void test_slave_drc_list_item_add_to_favorites()
{
    static const uint8_t buffer[] = { DRCP_FAVORITES_ADD_ITEM, 0x00 };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x2d");
    mock_dbus_iface->expect_dbus_get_list_item_iface(dbus_dcpd_list_item_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_list_item_emit_add_to_list(dbus_dcpd_list_item_iface_dummy, "Favorites", 0);
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends DRC command for power off.
 */
void test_slave_drc_power_off()
{
    static const uint8_t buffer[] = { DRCP_POWER_OFF, 0x00 };

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DEBUG, "DRC: command code 0x03");
    mock_dbus_iface->expect_dbus_get_logind_manager_iface(dbus_logind_manager_iface_dummy);
    mock_logind_manager_dbus->expect_tdbus_logind_manager_call_power_off_sync(true, dbus_logind_manager_iface_dummy, false);
    cppcut_assert_equal(0, dcpregs_write_drcp_command(buffer, sizeof(buffer)));
}

};

namespace spi_registers_protocol_level
{

static MockMessages *mock_messages;

static RegisterChangedData *register_changed_data;

static const uint8_t expected_protocol_level[3] = { 1, 0, 0, };

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

    dcpregs_protocol_level_init();

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    network_prefs_init(NULL, NULL, NULL, NULL);
    register_init(register_changed_callback);
}

void cut_teardown()
{
    register_deinit();
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
                                                dcpregs_read_1_protocol_level,
                                                dcpregs_write_1_protocol_level);

    uint8_t redzone_content[10];
    memset(redzone_content, 0xff, sizeof(redzone_content));

    uint8_t buffer[sizeof(redzone_content) + 3 + sizeof(redzone_content)];
    memset(buffer, 0xff, sizeof(buffer));

    reg->read_handler(buffer + sizeof(redzone_content), sizeof(buffer) - 2 * sizeof(redzone_content));

    cut_assert_equal_memory(redzone_content, sizeof(redzone_content), buffer,
                            sizeof(redzone_content));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + sizeof(redzone_content) + 3, sizeof(redzone_content));

    cut_assert_equal_memory(expected_protocol_level, sizeof(expected_protocol_level),
                            buffer + sizeof(redzone_content), 3);
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

        /* a range of three supported protocol levels */
        { 1, 0, 0, 1, 0, 2, },

        /* a single, specific protocol level */
        { 1, 0, 0, 1, 0, 0, },
    };

    auto *reg = lookup_register_expect_handlers(1,
                                                dcpregs_read_1_protocol_level,
                                                dcpregs_write_1_protocol_level);

    for(size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); ++i)
    {
        cppcut_assert_equal(0, reg->write_handler(requests[i], sizeof(requests[0])));
        register_changed_data->check(1);

        uint8_t buffer[3];
        cppcut_assert_equal(ssize_t(sizeof(buffer)), reg->read_handler(buffer, sizeof(buffer)));

        cut_assert_equal_memory(expected_protocol_level, sizeof(expected_protocol_level),
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
                                                dcpregs_read_1_protocol_level,
                                                dcpregs_write_1_protocol_level);

    for(size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); ++i)
    {
        cppcut_assert_equal(0, reg->write_handler(requests[i], sizeof(match_in_first_range)));
        register_changed_data->check(1);

        uint8_t buffer[3];
        cppcut_assert_equal(ssize_t(sizeof(buffer)), reg->read_handler(buffer, sizeof(buffer)));

        cut_assert_equal_memory(expected_protocol_level, sizeof(expected_protocol_level),
                                buffer, sizeof(buffer));
    }
}

void test_negotiate_protocol_level_single_range_with_mismatch()
{
    static const uint8_t requests[][6] =
    {
        /* any too high level */
        { 1, 0, 1, UINT8_MAX, UINT8_MAX, UINT8_MAX, },

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
                                                dcpregs_read_1_protocol_level,
                                                dcpregs_write_1_protocol_level);

    for(size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); ++i)
    {
        cppcut_assert_equal(0, reg->write_handler(requests[i], sizeof(requests[0])));
        register_changed_data->check(1);

        uint8_t buffer[3];
        cppcut_assert_equal(ssize_t(1), reg->read_handler(buffer, sizeof(buffer)));
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
                                                dcpregs_read_1_protocol_level,
                                                dcpregs_write_1_protocol_level);

    cppcut_assert_equal(0, reg->write_handler(mismatch, sizeof(mismatch)));
    register_changed_data->check(1);

    uint8_t buffer[3];
    cppcut_assert_equal(ssize_t(1), reg->read_handler(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[0]);
}

void test_maximum_level_of_multiple_overlapping_ranges_is_chosen()
{
    static const uint8_t overlapping[4 * 6] =
    {
        1, 0, 0, 2, UINT8_MAX, UINT8_MAX,
        1, 5, 7, 6, UINT8_MAX, UINT8_MAX,
        1, 0, 0, 3, 4, 5,
        0, 1, 2, 2, 0, 0,
    };

    auto *reg = lookup_register_expect_handlers(1,
                                                dcpregs_read_1_protocol_level,
                                                dcpregs_write_1_protocol_level);

    cppcut_assert_equal(0, reg->write_handler(overlapping, sizeof(overlapping)));
    register_changed_data->check(1);

    uint8_t buffer[3];
    cppcut_assert_equal(ssize_t(sizeof(buffer)), reg->read_handler(buffer, sizeof(buffer)));

    cut_assert_equal_memory(expected_protocol_level, sizeof(expected_protocol_level),
                            buffer, sizeof(buffer));
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
                                                dcpregs_read_1_protocol_level,
                                                dcpregs_write_1_protocol_level);

    for(size_t i = 0; i < sizeof(broken) / sizeof(broken[0]); ++i)
    {
        cppcut_assert_equal(0, reg->write_handler(broken[i], sizeof(broken[0])));
        register_changed_data->check(1);

        uint8_t buffer[3];
        cppcut_assert_equal(ssize_t(1), reg->read_handler(buffer, sizeof(buffer)));
        cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[0]);
    }
}

void test_negotiation_requires_at_least_one_range()
{
    static const uint8_t too_short[5] = {0, 0, 0, UINT8_MAX, UINT8_MAX, };

    auto *reg = lookup_register_expect_handlers(1,
                                                dcpregs_read_1_protocol_level,
                                                dcpregs_write_1_protocol_level);

    cppcut_assert_equal(0, reg->write_handler(too_short, sizeof(too_short)));
    register_changed_data->check(1);

    /* because this register is really important, even broken requests generate
     * an answer */
    uint8_t buffer[3];
    cppcut_assert_equal(ssize_t(1), reg->read_handler(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[0]);
}

};

namespace spi_registers_networking
{

static MockConnman *mock_connman;
static MockMessages *mock_messages;
static MockOs *mock_os;

static constexpr char connman_config_path[] = "/var/lib/connman";
static constexpr char network_config_path[] = "/var/local/etc";
static constexpr char network_config_file[] = "/var/local/etc/network.ini";

static constexpr char ethernet_mac_address[] = "DE:CA:FD:EA:DB:AD";
static constexpr char wlan_mac_address[]     = "BA:DD:EA:DB:EE:F1";
static struct ConnmanInterfaceData *const dummy_connman_iface =
    reinterpret_cast<struct ConnmanInterfaceData *>(0xbeefbeef);

static constexpr char standard_ipv4_address[] = "192.168.166.177";
static constexpr char standard_ipv4_netmask[] = "255.255.255.0";
static constexpr char standard_ipv4_gateway[] = "192.168.166.15";
static constexpr char standard_dns1_address[] = "113.224.135.246";
static constexpr char standard_dns2_address[] = "114.225.136.247";

static std::vector<char> os_write_buffer;
static constexpr int expected_os_write_fd = 42;
static constexpr int expected_os_map_file_to_memory_fd = 23;

static int write_from_buffer_callback(const void *src, size_t count, int fd)
{
    cppcut_assert_equal(expected_os_write_fd, fd);
    cppcut_assert_not_null(src);
    cppcut_assert_operator(size_t(0), <, count);

    std::copy_n(static_cast<const char *>(src), count,
                std::back_inserter<std::vector<char>>(os_write_buffer));

    return 0;
}

static RegisterChangedData *register_changed_data;

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

    mock_os = new MockOs;
    cppcut_assert_not_null(mock_os);
    mock_os->init();
    mock_os_singleton = mock_os;

    mock_connman = new MockConnman;
    cppcut_assert_not_null(mock_connman);
    mock_connman->init();
    mock_connman_singleton = mock_connman;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    os_write_buffer.clear();

    survey_complete_notification_data.init();
    connect_to_connman_service_data.init();
    register_changed_data->init();

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    network_prefs_init(ethernet_mac_address, wlan_mac_address,
                       network_config_path, network_config_file);
    register_init(register_changed_callback);
}

void cut_teardown()
{
    register_deinit();
    network_prefs_deinit();

    register_changed_data->check();

    delete register_changed_data;
    register_changed_data = nullptr;

    connect_to_connman_service_data.check();
    survey_complete_notification_data.check();

    os_write_buffer.clear();
    os_write_buffer.shrink_to_fit();

    mock_messages->check();
    mock_os->check();
    mock_connman->check();

    mock_messages_singleton = nullptr;
    mock_os_singleton = nullptr;
    mock_connman_singleton = nullptr;

    delete mock_messages;
    delete mock_os;
    delete mock_connman;

    mock_messages = nullptr;
    mock_os = nullptr;
    mock_connman = nullptr;
}

/*!\test
 * Read out MAC address of built-in Ethernet interface.
 */
void test_read_mac_address()
{
    auto *reg = lookup_register_expect_handlers(51,
                                                dcpregs_read_51_mac_address,
                                                NULL);
    uint8_t redzone_content[10];
    memset(redzone_content, 0xff, sizeof(redzone_content));

    uint8_t buffer[sizeof(redzone_content) + 18 + sizeof(redzone_content)];
    memset(buffer, 0xff, sizeof(buffer));

    reg->read_handler(buffer + sizeof(redzone_content), sizeof(buffer) - 2 * sizeof(redzone_content));

    cut_assert_equal_memory(redzone_content, sizeof(redzone_content), buffer,
                            sizeof(redzone_content));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + sizeof(redzone_content) + 18, sizeof(redzone_content));
    cut_assert_equal_memory(ethernet_mac_address, sizeof(ethernet_mac_address),
                            buffer + sizeof(redzone_content), 18);
}

/*!\test
 * MAC address of built-in Ethernet interface is an invalid address if not set.
 */
void test_read_mac_address_default()
{
    register_deinit();
    network_prefs_deinit();

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    network_prefs_init(NULL, NULL, NULL, NULL);
    register_init(NULL);

    auto *reg = lookup_register_expect_handlers(51,
                                                dcpregs_read_51_mac_address,
                                                NULL);
    uint8_t buffer[18];
    reg->read_handler(buffer, sizeof(buffer));

    const char *buffer_ptr = static_cast<const char *>(static_cast<void *>(buffer));
    cppcut_assert_equal("02:00:00:00:00:00", buffer_ptr);
}

static void start_ipv4_config()
{
    auto *reg = lookup_register_expect_handlers(54,
                                                dcpregs_write_54_selected_ip_profile);

    static const uint8_t zero = 0;
    cppcut_assert_equal(0, reg->write_handler(&zero, 1));
}

/* TODO: Remove add_message_expectation parameter */
static void commit_ipv4_config(bool add_message_expectation,
                               enum NetworkPrefsTechnology tech,
                               int expected_return_value = 0,
                               bool is_taking_config_from_file = true,
                               const char *wps_name = nullptr,
                               const std::vector<uint8_t> *wps_ssid = nullptr)
{
    auto *reg = lookup_register_expect_handlers(53,
                                                dcpregs_write_53_active_ip_profile);

    if(tech != NWPREFSTECH_UNKNOWN)
    {
        /* XXX: The empty string passed as second parameter is most certainly
         *      incorrect. Likely, there is something wrong with the test setup
         *      and/or mocks. */
        if(is_taking_config_from_file)
            connect_to_connman_service_data.expect(tech, "");
        else
            connect_to_connman_service_data.expect("", wps_name, wps_ssid);
    }

    static const uint8_t zero = 0;
    cppcut_assert_equal(expected_return_value, reg->write_handler(&zero, 1));
}

static void move_os_write_buffer_to_file(struct os_mapped_file_data &mapped_file,
                                         std::vector<char> &backing_buffer)
{
    backing_buffer.clear();
    backing_buffer.swap(os_write_buffer);

    mapped_file.fd = expected_os_map_file_to_memory_fd;
    mapped_file.ptr = backing_buffer.data();
    mapped_file.length = backing_buffer.size();
}

static const struct os_mapped_file_data *
expect_create_default_network_preferences(struct os_mapped_file_data &file_with_written_default_contents,
                                          std::vector<char> &written_default_contents)
{
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                                    "Creating default network preferences file");
    mock_os->expect_os_file_new(expected_os_write_fd, network_config_file);
    for(int i = 0; i < 3 + 2 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);
    mock_os->expect_os_sync_dir_callback(network_config_path,
                                         std::bind(move_os_write_buffer_to_file,
                                                   std::ref(file_with_written_default_contents),
                                                   std::ref(written_default_contents)));

    const struct os_mapped_file_data *mf = &file_with_written_default_contents;

    mock_os->expect_os_map_file_to_memory(0, mf, network_config_file);
    mock_os->expect_os_unmap_file(mf);

    return mf;
}

static size_t expect_default_network_preferences_content(char *buffer_for_expected,
                                                         size_t buffer_for_expected_size,
                                                         const std::vector<char> &buffer)
{
    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = yes\n";

    snprintf(buffer_for_expected, buffer_for_expected_size,
             expected_config_file_format, ethernet_mac_address);

    const size_t written_config_file_length = strlen(buffer_for_expected);

    cut_assert_equal_memory(buffer_for_expected, written_config_file_length,
                            buffer.data(), buffer.size());

    return written_config_file_length;
}

static void expect_default_network_preferences_content(const std::vector<char> &buffer)
{
    char dummy[512];
    expect_default_network_preferences_content(dummy, sizeof(dummy), buffer);
}

static size_t do_test_set_static_ipv4_config(const struct os_mapped_file_data *existing_file,
                                             char *written_config_file,
                                             size_t written_config_file_size)
{
    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(56,
                                                dcpregs_read_56_ipv4_address,
                                                dcpregs_write_56_ipv4_address);

    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(standard_ipv4_address)), sizeof(standard_ipv4_address)));

    reg = lookup_register_expect_handlers(57,
                                          dcpregs_read_57_ipv4_netmask,
                                          dcpregs_write_57_ipv4_netmask);

    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(standard_ipv4_netmask)), sizeof(standard_ipv4_netmask)));

    reg = lookup_register_expect_handlers(58,
                                          dcpregs_read_58_ipv4_gateway,
                                          dcpregs_write_58_ipv4_gateway);

    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(standard_ipv4_gateway)), sizeof(standard_ipv4_gateway)));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1 };
    std::vector<char> written_default_contents;

    if(existing_file == nullptr)
    {
        mock_os->expect_os_map_file_to_memory(-1, false, network_config_file);

        existing_file =
            expect_create_default_network_preferences(file_with_written_default_contents,
                                                      written_default_contents);
    }
    else
    {
        mock_os->expect_os_map_file_to_memory(existing_file, network_config_file);
        mock_os->expect_os_unmap_file(existing_file);
    }

    mock_os->expect_os_file_new(expected_os_write_fd, network_config_file);
    for(int i = 0; i < 3 + 5 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);
    mock_os->expect_os_sync_dir(network_config_path);

    commit_ipv4_config(false, NWPREFSTECH_ETHERNET);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = no\n"
        "IPv4Address = %s\n"
        "IPv4Netmask = %s\n"
        "IPv4Gateway = %s\n";

    snprintf(written_config_file, written_config_file_size,
             expected_config_file_format,
             ethernet_mac_address, standard_ipv4_address,
             standard_ipv4_netmask, standard_ipv4_gateway);

    size_t written_config_file_length = strlen(written_config_file);

    cut_assert_equal_memory(written_config_file, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());

    return written_config_file_length;
}

static size_t do_test_set_dhcp_ipv4_config(const struct os_mapped_file_data *existing_file,
                                           char *written_config_file,
                                           size_t written_config_file_size)
{
    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(55,
                                                dcpregs_read_55_dhcp_enabled,
                                                dcpregs_write_55_dhcp_enabled);

    mock_messages->expect_msg_info_formatted("Enable DHCP");
    static const uint8_t one = 1;
    cppcut_assert_equal(0, reg->write_handler(&one, 1));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1 };
    std::vector<char> written_default_contents;

    if(existing_file == nullptr)
    {
        mock_os->expect_os_map_file_to_memory(-1, false, network_config_file);

        existing_file =
            expect_create_default_network_preferences(file_with_written_default_contents,
                                                      written_default_contents);
    }
    else
    {
        mock_os->expect_os_map_file_to_memory(existing_file, network_config_file);
        mock_os->expect_os_unmap_file(existing_file);
    }

    mock_os->expect_os_file_new(expected_os_write_fd, network_config_file);
    for(int i = 0; i < 3 + 2 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);
    mock_os->expect_os_sync_dir(network_config_path);
    commit_ipv4_config(false, NWPREFSTECH_ETHERNET);

    return expect_default_network_preferences_content(written_config_file,
                                                      written_config_file_size,
                                                      os_write_buffer);
}

/*!\test
 * Initial setting of static IPv4 configuration generates a network preferences
 * file.
 */
void test_set_initial_static_ipv4_configuration()
{
    char buffer[512];
    (void)do_test_set_static_ipv4_config(NULL, buffer, sizeof(buffer));
}

/*!\test
 * Addresses such as "192.168.060.000" are converted to "192.168.60.0".
 *
 * Connman (and most other software) doesn't like leading zeros in IP addresses
 * because they look like octal numbers. In fact, \c inet_pton(3) also chokes
 * on those.
 */
void test_leading_zeros_are_removed_from_ipv4_addresses()
{
    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(56,
                                                dcpregs_read_56_ipv4_address,
                                                dcpregs_write_56_ipv4_address);

    static const std::array<std::pair<const char *, const char *>, 3> addresses_with_zeros =
    {
        std::make_pair("123.045.006.100", "123.45.6.100"),
        std::make_pair("135.07.80.010",   "135.7.80.10"),
        std::make_pair("009.000.00.0",    "9.0.0.0"),
    };

    for(const auto &p : addresses_with_zeros)
    {
        cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(p.first)), strlen(p.first)));

        uint8_t buffer[32];
        const ssize_t len = reg->read_handler(buffer, sizeof(buffer));
        buffer[sizeof(buffer) - 1] = '\0';
        cppcut_assert_equal(p.second, static_cast<const char *>(static_cast<const void *>(buffer)));
        cppcut_assert_equal(ssize_t(strlen(p.second) + 1), len);
    }
}

/*!\test
 * Initial enabling of DHCPv4 generates a network preferences file.
 */
void test_set_initial_dhcp_ipv4_configuration()
{
    char buffer[512];
    (void)do_test_set_dhcp_ipv4_config(NULL, buffer, sizeof(buffer));
}

/*!\test
 * Setting static IPv4 configuration while a DHCPv4 configuration is active
 * rewrites the network preferences file.
 */
void test_switch_to_dhcp_ipv4_configuration()
{
    char config_file_buffer[512];
    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = do_test_set_static_ipv4_config(NULL, config_file_buffer,
                                                 sizeof(config_file_buffer)),
    };

    os_write_buffer.clear();

    char new_config_file_buffer[512];
    (void)do_test_set_dhcp_ipv4_config(&config_file, new_config_file_buffer,
                                       sizeof(new_config_file_buffer));
}

/*!\test
 * Enabling DHCPv4 while a static IPv4 configuration is active rewrites the
 * network preferences file.
 */
void test_switch_to_static_ipv4_configuration()
{
    char config_file_buffer[512];
    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = do_test_set_dhcp_ipv4_config(NULL, config_file_buffer,
                                               sizeof(config_file_buffer)),
    };

    os_write_buffer.clear();

    char new_config_file_buffer[512];
    (void)do_test_set_static_ipv4_config(&config_file, new_config_file_buffer,
                                         sizeof(new_config_file_buffer));
}

/*!\test
 * Only values 0 and 1 are valid parameters for register 55.
 */
void test_dhcp_parameter_boundaries()
{
    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(55,
                                                dcpregs_read_55_dhcp_enabled,
                                                dcpregs_write_55_dhcp_enabled);

    uint8_t buffer = 2;

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Received invalid DHCP configuration parameter 0x02 (Invalid argument)");
    cppcut_assert_equal(-1, reg->write_handler(&buffer, 1));

    buffer = UINT8_MAX;

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Received invalid DHCP configuration parameter 0xff (Invalid argument)");
    cppcut_assert_equal(-1, reg->write_handler(&buffer, 1));
}

/*!\test
 * Switching DHCP off and setting no IPv4 configuration tells us to disable the
 * interface for IPv4.
 */
void test_explicitly_disabling_dhcp_disables_whole_interface()
{
    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(55,
                                                dcpregs_read_55_dhcp_enabled,
                                                dcpregs_write_55_dhcp_enabled);

    static const uint8_t zero = 0;

    mock_messages->expect_msg_info_formatted("Disable DHCP");
    cppcut_assert_equal(0, reg->write_handler(&zero, 1));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents);

    mock_messages->expect_msg_error_formatted(0, LOG_WARNING,
        "Disabling IPv4 on interface DE:CA:FD:EA:DB:AD because DHCPv4 "
        "was disabled and static IPv4 configuration was not sent");

    mock_os->expect_os_file_new(expected_os_write_fd, network_config_file);
    for(int i = 0; i < 3 + 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);
    mock_os->expect_os_sync_dir(network_config_path);

    commit_ipv4_config(false, NWPREFSTECH_ETHERNET);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n";

    char buffer[512];
    snprintf(buffer, sizeof(buffer),
             expected_config_file_format, ethernet_mac_address);

    size_t written_config_file_length = strlen(buffer);

    cut_assert_equal_memory(buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * When being asked for DHCP mode in normal mode, Connman is consulted
 * (reporting "disabled" in this test).
 */
void test_read_dhcp_mode_in_normal_mode_with_dhcp_disabled()
{
    auto *reg = lookup_register_expect_handlers(55,
                                                dcpregs_read_55_dhcp_enabled,
                                                dcpregs_write_55_dhcp_enabled);

    mock_connman->expect_find_active_primary_interface(dummy_connman_iface,
                                                       ethernet_mac_address,
                                                       ethernet_mac_address,
                                                       wlan_mac_address);
    mock_connman->expect_get_dhcp_mode(CONNMAN_DHCP_MANUAL, dummy_connman_iface,
                                       CONNMAN_IP_VERSION_4,
                                       CONNMAN_READ_CONFIG_SOURCE_CURRENT);
    mock_connman->expect_free_interface_data(dummy_connman_iface);

    uint8_t buffer = UINT8_MAX;
    cppcut_assert_equal(ssize_t(1), reg->read_handler(&buffer, 1));

    cppcut_assert_equal(0, int(buffer));
}

/*!\test
 * When being asked for DHCP mode in normal mode, Connman is consulted
 * (reporting "enabled" in this test).
 */
void test_read_dhcp_mode_in_normal_mode_with_dhcp_enabled()
{
    auto *reg = lookup_register_expect_handlers(55,
                                                dcpregs_read_55_dhcp_enabled,
                                                dcpregs_write_55_dhcp_enabled);

    mock_connman->expect_find_active_primary_interface(dummy_connman_iface,
                                                       ethernet_mac_address,
                                                       ethernet_mac_address,
                                                       wlan_mac_address);
    mock_connman->expect_get_dhcp_mode(CONNMAN_DHCP_ON, dummy_connman_iface,
                                       CONNMAN_IP_VERSION_4,
                                       CONNMAN_READ_CONFIG_SOURCE_CURRENT);
    mock_connman->expect_free_interface_data(dummy_connman_iface);

    uint8_t buffer = UINT8_MAX;
    cppcut_assert_equal(ssize_t(1), reg->read_handler(&buffer, 1));

    cppcut_assert_equal(1, int(buffer));
}

/*!\test
 * When being asked for DHCP mode in edit mode, Connman is consulted if the
 * mode has not been set during this edit session.
 */
void test_read_dhcp_mode_in_edit_mode_before_any_changes()
{
    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(55,
                                                dcpregs_read_55_dhcp_enabled,
                                                dcpregs_write_55_dhcp_enabled);

    mock_connman->expect_find_interface(dummy_connman_iface, ethernet_mac_address);
    mock_connman->expect_get_dhcp_mode(CONNMAN_DHCP_ON, dummy_connman_iface,
                                       CONNMAN_IP_VERSION_4,
                                       CONNMAN_READ_CONFIG_SOURCE_CURRENT);
    mock_connman->expect_free_interface_data(dummy_connman_iface);

    uint8_t buffer = UINT8_MAX;
    cppcut_assert_equal(ssize_t(1), reg->read_handler(&buffer, 1));

    cppcut_assert_equal(1, int(buffer));
}

/*!\test
 * When being asked for DHCP mode in edit mode, the mode written during this
 * edit session is returned.
 */
void test_read_dhcp_mode_in_edit_mode_after_change()
{
    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(55,
                                                dcpregs_read_55_dhcp_enabled,
                                                dcpregs_write_55_dhcp_enabled);

    mock_messages->expect_msg_info_formatted("Enable DHCP");
    static const uint8_t one = 1;
    cppcut_assert_equal(0, reg->write_handler(&one, 1));

    uint8_t buffer = UINT8_MAX;
    cppcut_assert_equal(ssize_t(1), reg->read_handler(&buffer, 1));

    cppcut_assert_equal(1, int(buffer));
}

template <uint8_t Register>
struct RegisterTraits;

template <>
struct RegisterTraits<56U>
{
    static constexpr auto expected_read_handler = &dcpregs_read_56_ipv4_address;
    static constexpr auto expected_write_handler = &dcpregs_write_56_ipv4_address;
    static constexpr auto expect_get_string_memberfn = &MockConnman::expect_get_address_string;
};

template <>
struct RegisterTraits<57U>
{
    static constexpr auto expected_read_handler = &dcpregs_read_57_ipv4_netmask;
    static constexpr auto expected_write_handler = &dcpregs_write_57_ipv4_netmask;
    static constexpr auto expect_get_string_memberfn = &MockConnman::expect_get_netmask_string;
};

template <>
struct RegisterTraits<58U>
{
    static constexpr auto expected_read_handler = &dcpregs_read_58_ipv4_gateway;
    static constexpr auto expected_write_handler = &dcpregs_write_58_ipv4_gateway;
    static constexpr auto expect_get_string_memberfn = &MockConnman::expect_get_gateway_string;
};

template <>
struct RegisterTraits<62U>
{
    static constexpr auto expected_read_handler = &dcpregs_read_62_primary_dns;
    static constexpr auto expected_write_handler = &dcpregs_write_62_primary_dns;
    static constexpr auto expect_get_string_memberfn = &MockConnman::expect_get_gateway_string;
};

template <>
struct RegisterTraits<63U>
{
    static constexpr auto expected_read_handler = &dcpregs_read_63_secondary_dns;
    static constexpr auto expected_write_handler = &dcpregs_write_63_secondary_dns;
    static constexpr auto expect_get_string_memberfn = &MockConnman::expect_get_gateway_string;
};

template <uint8_t Register, typename RegTraits = RegisterTraits<Register>>
static void read_ipv4_parameter_in_normal_mode()
{
    auto *reg = lookup_register_expect_handlers(Register,
                                                RegTraits::expected_read_handler,
                                                RegTraits::expected_write_handler);
    uint8_t buffer[50];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    mock_connman->expect_find_active_primary_interface(dummy_connman_iface,
                                                       ethernet_mac_address,
                                                       ethernet_mac_address,
                                                       wlan_mac_address);
    (mock_connman->*RegTraits::expect_get_string_memberfn)(standard_ipv4_address,
                                                           dummy_connman_iface,
                                                           CONNMAN_IP_VERSION_4,
                                                           CONNMAN_READ_CONFIG_SOURCE_CURRENT,
                                                           false,
                                                           sizeof(buffer));
    mock_connman->expect_free_interface_data(dummy_connman_iface);

    cppcut_assert_equal(ssize_t(sizeof(standard_ipv4_address)),
                        reg->read_handler(buffer, sizeof(buffer)));

    cut_assert_equal_memory(standard_ipv4_address, sizeof(standard_ipv4_address),
                            buffer, sizeof(standard_ipv4_address));
}

template <uint8_t Register, typename RegTraits = RegisterTraits<Register>>
static void read_ipv4_parameter_in_edit_mode_before_any_changes()
{
    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(Register,
                                                RegTraits::expected_read_handler,
                                                RegTraits::expected_write_handler);
    uint8_t buffer[50];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    mock_connman->expect_find_interface(dummy_connman_iface, ethernet_mac_address);
    (mock_connman->*RegTraits::expect_get_string_memberfn)(standard_ipv4_address,
                                                           dummy_connman_iface,
                                                           CONNMAN_IP_VERSION_4,
                                                           CONNMAN_READ_CONFIG_SOURCE_CURRENT,
                                                           false,
                                                           sizeof(buffer));
    mock_connman->expect_free_interface_data(dummy_connman_iface);

    cppcut_assert_equal(ssize_t(sizeof(standard_ipv4_address)),
                        reg->read_handler(buffer, sizeof(buffer)));

    cut_assert_equal_memory(standard_ipv4_address, sizeof(standard_ipv4_address),
                            buffer, sizeof(standard_ipv4_address));
}

template <uint8_t Register, typename RegTraits = RegisterTraits<Register>>
static void read_ipv4_parameter_in_edit_mode_after_change()
{
    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(Register,
                                                RegTraits::expected_read_handler,
                                                RegTraits::expected_write_handler);
    cppcut_assert_equal(0, reg->write_handler((uint8_t *)standard_ipv4_address,
                                              sizeof(standard_ipv4_address)));

    uint8_t buffer[4 + 16 + 4];
    memset(buffer, UINT8_MAX, sizeof(buffer));
    cppcut_assert_operator(sizeof(standard_ipv4_address), <=, sizeof(buffer));

    cppcut_assert_equal(ssize_t(sizeof(standard_ipv4_address)),
                        reg->read_handler(buffer + 4, sizeof(standard_ipv4_address)));

    cut_assert_equal_memory(standard_ipv4_address, sizeof(standard_ipv4_address), buffer + 4, sizeof(standard_ipv4_address));

    static const uint8_t red_zone_bytes[] =
    {
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX
    };

    cut_assert_equal_memory(red_zone_bytes, sizeof(red_zone_bytes),
                            buffer, sizeof(red_zone_bytes));
    cut_assert_equal_memory(red_zone_bytes, sizeof(red_zone_bytes),
                            buffer + sizeof(standard_ipv4_address) + sizeof(red_zone_bytes),
                            sizeof(red_zone_bytes));
}

/*!\test
 * When being asked for the IPv4 address in normal mode, Connman is consulted.
 */
void test_read_ipv4_address_in_normal_mode()
{
    read_ipv4_parameter_in_normal_mode<56>();
}

/*!\test
 * When being asked for the IPv4 address in edit mode, Connman is consulted if
 * the address has not been set during this edit session.
 */
void test_read_ipv4_address_in_edit_mode_before_any_changes()
{
    read_ipv4_parameter_in_edit_mode_before_any_changes<56>();
}

/*!\test
 * When being asked for the IPv4 address in edit mode, the address written
 * during this edit session is returned.
 */
void test_read_ipv4_address_in_edit_mode_after_change()
{
    read_ipv4_parameter_in_edit_mode_after_change<56>();
}

/*!\test
 * When being asked for the IPv4 netmask in normal mode, Connman is consulted.
 */
void test_read_ipv4_netmask_in_normal_mode()
{
    read_ipv4_parameter_in_normal_mode<57>();
}

/*!\test
 * When being asked for the IPv4 netmask in edit mode, Connman is consulted if
 * the mask has not been set during this edit session.
 */
void test_read_ipv4_netmask_in_edit_mode_before_any_changes()
{
    read_ipv4_parameter_in_edit_mode_before_any_changes<57>();
}

/*!\test
 * When being asked for the IPv4 netmask in edit mode, the address written
 * during this edit session is returned.
 */
void test_read_ipv4_netmask_in_edit_mode_after_change()
{
    read_ipv4_parameter_in_edit_mode_after_change<57>();
}

/*!\test
 * When being asked for the IPv4 gateway in normal mode, Connman is consulted.
 */
void test_read_ipv4_gateway_in_normal_mode()
{
    read_ipv4_parameter_in_normal_mode<58>();
}

/*!\test
 * When being asked for the IPv4 gateway in edit mode, Connman is consulted if
 * the gateway has not been set during this edit session.
 */
void test_read_ipv4_gateway_in_edit_mode_before_any_changes()
{
    read_ipv4_parameter_in_edit_mode_before_any_changes<58>();
}

/*!\test
 * When being asked for the IPv4 gateway in edit mode, the gateway written
 * during this edit session is returned.
 */
void test_read_ipv4_gateway_in_edit_mode_after_change()
{
    read_ipv4_parameter_in_edit_mode_after_change<58>();
}

template <uint8_t Register, typename RegTraits = RegisterTraits<Register>>
static void set_one_dns_server(const char *dns_server_address, size_t dns_server_size,
                               const char *old_primary_dns,
                               const char *old_secondary_dns)
{
    char config_file_buffer[512];
    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = do_test_set_static_ipv4_config(NULL, config_file_buffer,
                                                 sizeof(config_file_buffer)),
    };

    os_write_buffer.clear();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(Register,
                                                RegTraits::expected_read_handler,
                                                RegTraits::expected_write_handler);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(dns_server_address)), dns_server_size));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");
    mock_connman->expect_find_active_primary_interface(
        dummy_connman_iface,
        ethernet_mac_address, ethernet_mac_address, wlan_mac_address);
    mock_connman->expect_get_primary_dns_string(old_primary_dns, dummy_connman_iface, false, 16);
    mock_connman->expect_get_secondary_dns_string(old_secondary_dns, dummy_connman_iface, false, 16);
    mock_connman->expect_free_interface_data(dummy_connman_iface);
    mock_os->expect_os_map_file_to_memory(&config_file, network_config_file);
    mock_os->expect_os_unmap_file(&config_file);
    mock_os->expect_os_file_new(expected_os_write_fd, network_config_file);
    for(int i = 0; i < 3 + 6 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);
    mock_os->expect_os_sync_dir(network_config_path);

    commit_ipv4_config(false, NWPREFSTECH_ETHERNET);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = no\n"
        "IPv4Address = %s\n"
        "IPv4Netmask = %s\n"
        "IPv4Gateway = %s\n"
        "PrimaryDNS = %s\n";

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format,
             ethernet_mac_address, standard_ipv4_address,
             standard_ipv4_netmask, standard_ipv4_gateway,
             dns_server_address);

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Add primary DNS server address to static IPv4 configuration without
 * previously defined DNS servers.
 */
void test_set_only_first_dns_server()
{
    set_one_dns_server<62>(standard_dns1_address, sizeof(standard_dns1_address),
                           NULL, NULL);
}

/*!\test
 * Add secondary DNS server address to static IPv4 configuration without
 * previously defined DNS servers.
 *
 * Since this is the only address sent to the device, it becomes the primary
 * DNS server.
 */
void test_set_only_second_dns_server()
{
    set_one_dns_server<63>(standard_dns2_address, sizeof(standard_dns2_address),
                           NULL, NULL);
}

/*!\test
 * Add two DNS servers to static IPv4 configuration without previously defined
 * DNS servers.
 */
void test_set_both_dns_servers()
{
    char config_file_buffer[512];
    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = do_test_set_static_ipv4_config(NULL, config_file_buffer,
                                                 sizeof(config_file_buffer)),
    };

    os_write_buffer.clear();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(62,
                                                dcpregs_read_62_primary_dns,
                                                dcpregs_write_62_primary_dns);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(standard_dns1_address)), sizeof(standard_dns1_address)));

    reg = lookup_register_expect_handlers(63,
                                          dcpregs_read_63_secondary_dns,
                                          dcpregs_write_63_secondary_dns);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(standard_dns2_address)), sizeof(standard_dns2_address)));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");
    mock_os->expect_os_map_file_to_memory(&config_file, network_config_file);
    mock_os->expect_os_unmap_file(&config_file);
    mock_os->expect_os_file_new(expected_os_write_fd, network_config_file);
    for(int i = 0; i < 3 + 7 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);
    mock_os->expect_os_sync_dir(network_config_path);

    commit_ipv4_config(false, NWPREFSTECH_ETHERNET);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = no\n"
        "IPv4Address = %s\n"
        "IPv4Netmask = %s\n"
        "IPv4Gateway = %s\n"
        "PrimaryDNS = %s\n"
        "SecondaryDNS = %s\n";

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format,
             ethernet_mac_address, standard_ipv4_address,
             standard_ipv4_netmask, standard_ipv4_gateway,
             standard_dns1_address, standard_dns2_address);

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Read out the primary DNS in edit mode, Connman is consulted if the primary
 * DNS server has not been set during this edit session.
 */
void test_read_primary_dns_in_edit_mode_before_any_changes()
{
    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(62,
                                                dcpregs_read_62_primary_dns,
                                                dcpregs_write_62_primary_dns);

    static constexpr char assumed_primary_dns[] = "50.60.117.208";

    char buffer[128];

    mock_connman->expect_find_interface(dummy_connman_iface, ethernet_mac_address);
    mock_connman->expect_get_primary_dns_string(assumed_primary_dns,
                                                dummy_connman_iface,
                                                false, sizeof(buffer));
    mock_connman->expect_free_interface_data(dummy_connman_iface);

    ssize_t dns_server_size = reg->read_handler(static_cast<uint8_t *>(static_cast<void *>(buffer)), sizeof(buffer));

    cppcut_assert_equal(ssize_t(sizeof(assumed_primary_dns)), dns_server_size);
    cppcut_assert_equal(assumed_primary_dns, static_cast<const char *>(buffer));

    commit_ipv4_config(true, NWPREFSTECH_UNKNOWN);
}

/*!\test
 * Read out the secondary DNS in edit mode, Connman is consulted if the
 * secondary DNS server has not been set during this edit session.
 */
void test_read_secondary_dns_in_edit_mode_before_any_changes()
{
    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(63,
                                                dcpregs_read_63_secondary_dns,
                                                dcpregs_write_63_secondary_dns);

    static constexpr char assumed_secondary_dns[] = "1.2.3.4";

    char buffer[128];

    mock_connman->expect_find_interface(dummy_connman_iface, ethernet_mac_address);
    mock_connman->expect_get_secondary_dns_string(assumed_secondary_dns,
                                                  dummy_connman_iface,
                                                  false, sizeof(buffer));
    mock_connman->expect_free_interface_data(dummy_connman_iface);

    ssize_t dns_server_size = reg->read_handler(static_cast<uint8_t *>(static_cast<void *>(buffer)), sizeof(buffer));

    cppcut_assert_equal(ssize_t(sizeof(assumed_secondary_dns)), dns_server_size);
    cppcut_assert_equal("1.2.3.4", static_cast<const char *>(buffer));

    commit_ipv4_config(true, NWPREFSTECH_UNKNOWN);
}

/*!\test
 * Given two previously defined DNS servers, replace the primary one.
 */
void test_replace_primary_dns_server_of_two_servers()
{
    start_ipv4_config();

    static constexpr char assumed_primary_dns[] = "50.60.117.208";
    static constexpr char assumed_secondary_dns[] = "1.2.3.4";

    auto *reg = lookup_register_expect_handlers(62,
                                                dcpregs_read_62_primary_dns,
                                                dcpregs_write_62_primary_dns);

    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(standard_dns1_address)), sizeof(standard_dns1_address)));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents);

    mock_connman->expect_find_active_primary_interface(dummy_connman_iface,
                                                       ethernet_mac_address,
                                                       ethernet_mac_address,
                                                       wlan_mac_address);
    mock_connman->expect_get_primary_dns_string(assumed_primary_dns,
                                                dummy_connman_iface,
                                                false, 16);
    mock_connman->expect_get_secondary_dns_string(assumed_secondary_dns,
                                                  dummy_connman_iface,
                                                  false, 16);
    mock_connman->expect_free_interface_data(dummy_connman_iface);
    mock_os->expect_os_file_new(expected_os_write_fd, network_config_file);
    for(int i = 0; i < 3 + 4 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);
    mock_os->expect_os_sync_dir(network_config_path);

    commit_ipv4_config(false, NWPREFSTECH_ETHERNET);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "PrimaryDNS = %s\n"
        "SecondaryDNS = %s\n";

    char output_config_file[512];

    snprintf(output_config_file, sizeof(output_config_file),
             expected_config_file_format,
             ethernet_mac_address, standard_dns1_address, assumed_secondary_dns);

    size_t output_config_file_length = strlen(output_config_file);

    cut_assert_equal_memory(output_config_file, output_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Given two previously defined DNS servers, replace the secondary one.
 */
void test_replace_secondary_dns_server_of_two_servers()
{
    start_ipv4_config();

    static constexpr char assumed_primary_dns[] = "50.60.117.208";
    static constexpr char assumed_secondary_dns[] = "1.2.3.4";

    auto *reg = lookup_register_expect_handlers(63,
                                                dcpregs_read_63_secondary_dns,
                                                dcpregs_write_63_secondary_dns);

    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(standard_dns2_address)), sizeof(standard_dns2_address)));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents);

    mock_connman->expect_find_active_primary_interface(dummy_connman_iface,
                                                       ethernet_mac_address,
                                                       ethernet_mac_address,
                                                       wlan_mac_address);
    mock_connman->expect_get_primary_dns_string(assumed_primary_dns,
                                                dummy_connman_iface,
                                                false, 16);
    mock_connman->expect_get_secondary_dns_string(assumed_secondary_dns,
                                                  dummy_connman_iface,
                                                  false, 16);
    mock_connman->expect_free_interface_data(dummy_connman_iface);
    mock_os->expect_os_file_new(expected_os_write_fd, network_config_file);
    for(int i = 0; i < 3 + 4 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);
    mock_os->expect_os_sync_dir(network_config_path);

    commit_ipv4_config(false, NWPREFSTECH_ETHERNET);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "PrimaryDNS = %s\n"
        "SecondaryDNS = %s\n";

    char output_config_file[512];

    snprintf(output_config_file, sizeof(output_config_file),
             expected_config_file_format,
             ethernet_mac_address, assumed_primary_dns, standard_dns2_address);

    size_t output_config_file_length = strlen(output_config_file);

    cut_assert_equal_memory(output_config_file, output_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Given one previously defined DNS server, add a secondary one.
 */
void test_add_secondary_dns_server_to_primary_server()
{
    start_ipv4_config();

    static constexpr char assumed_primary_dns[] = "213.1.92.9";

    auto *reg = lookup_register_expect_handlers(63,
                                                dcpregs_read_63_secondary_dns,
                                                dcpregs_write_63_secondary_dns);

    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(standard_dns2_address)), sizeof(standard_dns2_address)));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents);

    mock_connman->expect_find_active_primary_interface(dummy_connman_iface,
                                                       ethernet_mac_address,
                                                       ethernet_mac_address,
                                                       wlan_mac_address);
    mock_connman->expect_get_primary_dns_string(assumed_primary_dns,
                                                dummy_connman_iface,
                                                false, 16);
    mock_connman->expect_get_secondary_dns_string("",
                                                  dummy_connman_iface,
                                                  false, 16);
    mock_connman->expect_free_interface_data(dummy_connman_iface);
    mock_os->expect_os_file_new(expected_os_write_fd, network_config_file);
    for(int i = 0; i < 3 + 4 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);
    mock_os->expect_os_sync_dir(network_config_path);

    commit_ipv4_config(false, NWPREFSTECH_ETHERNET);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "PrimaryDNS = %s\n"
        "SecondaryDNS = %s\n";

    char output_config_file[512];

    snprintf(output_config_file, sizeof(output_config_file),
             expected_config_file_format,
             ethernet_mac_address, assumed_primary_dns, standard_dns2_address);

    size_t output_config_file_length = strlen(output_config_file);

    cut_assert_equal_memory(output_config_file, output_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * WPA passphrase for Ethernet connections is ignored and not written to file.
 */
void test_set_wlan_security_mode_on_ethernet_service_is_ignored()
{
    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(92,
                                                dcpregs_read_92_wlan_security,
                                                dcpregs_write_92_wlan_security);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>("none")), 4));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents);

    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                                    "Ignoring wireless parameters for active wired interface");

    mock_os->expect_os_file_new(expected_os_write_fd, network_config_file);
    for(int i = 0; i < 3 + 2 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);
    mock_os->expect_os_sync_dir(network_config_path);

    commit_ipv4_config(false, NWPREFSTECH_ETHERNET);

    expect_default_network_preferences_content(os_write_buffer);
}

/*!\test
 * There is no wireless security mode for Ethernet connections.
 */
void test_get_wlan_security_mode_for_ethernet_returns_error()
{
    uint8_t buffer[64];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    auto *reg = lookup_register_expect_handlers(92,
                                                dcpregs_read_92_wlan_security,
                                                dcpregs_write_92_wlan_security);

    mock_connman->expect_find_active_primary_interface(dummy_connman_iface,
                                                       ethernet_mac_address,
                                                       ethernet_mac_address,
                                                       wlan_mac_address);
    mock_connman->expect_get_wlan_security_type_string(false, "", dummy_connman_iface, false, sizeof(buffer));
    mock_messages->expect_msg_error(EINVAL, LOG_ERR,
                                    "No Connman security type set for active interface");
    mock_connman->expect_free_interface_data(dummy_connman_iface);

    cppcut_assert_equal(ssize_t(-1), reg->read_handler(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(0), buffer[0]);
    cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[1]);
}

static void assume_wlan_interface_is_active()
{
    struct register_configuration_t *config = registers_get_nonconst_data();

    config->active_interface = &config->builtin_wlan_interface;
}

static void set_wlan_name(const char *wps_name)
{
    cppcut_assert_not_null(wps_name);

    auto *reg = lookup_register_expect_handlers(94,
                                                dcpregs_read_94_ssid,
                                                dcpregs_write_94_ssid);

    cppcut_assert_equal(0,
                        reg->write_handler(static_cast<const uint8_t *>(
                                               static_cast<const void *>(wps_name)),
                                           strlen(wps_name)));
}

static void set_wlan_name(const std::vector<uint8_t> &wps_ssid)
{
    cut_assert_false(wps_ssid.empty());

    auto *reg = lookup_register_expect_handlers(94,
                                                dcpregs_read_94_ssid,
                                                dcpregs_write_94_ssid);

    cppcut_assert_equal(0, reg->write_handler(wps_ssid.data(), wps_ssid.size()));
}

static void set_wlan_security_mode(const char *requested_security_mode,
                                   bool expecting_configuration_file_be_written = true,
                                   const char *wps_name = nullptr,
                                   const std::vector<uint8_t> *wps_ssid = nullptr)
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(92,
                                                dcpregs_read_92_wlan_security,
                                                dcpregs_write_92_wlan_security);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(requested_security_mode)), strlen(requested_security_mode)));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address BA:DD:EA:DB:EE:F1");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents);

    if(expecting_configuration_file_be_written)
    {
        mock_os->expect_os_file_new(expected_os_write_fd, network_config_file);
        for(int i = 0; i < 2 * 3 + (2 + 3) * 4; ++i)
            mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
        mock_os->expect_os_file_close(expected_os_write_fd);
        mock_os->expect_os_sync_dir(network_config_path);
    }

    if(wps_ssid != nullptr)
        set_wlan_name(*wps_ssid);
    else if(wps_name != nullptr)
        set_wlan_name(wps_name);

    commit_ipv4_config(false, NWPREFSTECH_WLAN, 0,
                       expecting_configuration_file_be_written,
                       wps_name, wps_ssid);

    if(expecting_configuration_file_be_written)
    {
        static const char expected_config_file_format[] =
            "[ethernet]\n"
            "MAC = %s\n"
            "DHCP = yes\n"
            "[wifi]\n"
            "MAC = %s\n"
            "DHCP = yes\n"
            "Security = %s\n";

        char new_config_file_buffer[512];
        snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
                 expected_config_file_format, ethernet_mac_address,
                 wlan_mac_address, requested_security_mode);

        size_t written_config_file_length = strlen(new_config_file_buffer);

        cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                                os_write_buffer.data(), os_write_buffer.size());
    }
}

/*!\test
 * Disable WLAN security.
 */
void test_set_wlan_security_mode_none()
{
    set_wlan_security_mode("none");
}

/*!\test
 * Set WLAN security mode to WPA/PSK.
 */
void test_set_wlan_security_mode_wpa_psk()
{
    set_wlan_security_mode("psk");
}

/*!\test
 * Set WLAN security mode to WPA EAP mode ("WPA Enterprise").
 */
void test_set_wlan_security_mode_wpa_eap()
{
    set_wlan_security_mode("ieee8021x");
}

/*!\test
 * Set WLAN security mode to WPS, name is given.
 */
void test_set_wlan_security_mode_wps_with_name()
{
    set_wlan_security_mode("wps", false, "MyNetwork", nullptr);
}

/*!\test
 * Set WLAN security mode to WPS, SSID is given.
 */
void test_set_wlan_security_mode_wps_with_ssid()
{
    const std::vector<uint8_t> ssid { 0x05, 0xfb, 0x81, 0xc2, 0x7a, };
    set_wlan_security_mode("wps", false, nullptr, &ssid);
}

/*!\test
 * Set WLAN security mode to WPS, scan mode.
 */
void test_set_wlan_security_mode_wps()
{
    set_wlan_security_mode("wps", false, nullptr, nullptr);
}

/*!\test
 * Setting WLAN security mode to WEP is not implemented yet.
 */
void test_set_wlan_security_mode_wep()
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(92,
                                                dcpregs_read_92_wlan_security,
                                                dcpregs_write_92_wlan_security);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>("wep")), 3));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address BA:DD:EA:DB:EE:F1");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents);

    mock_messages->expect_msg_error(0, LOG_CRIT,
                                    "BUG: Support for insecure WLAN mode "
                                    "\"WEP\" not implemented yet");
    mock_messages->expect_msg_error(EINVAL, LOG_ERR,
                                    "Cannot set WLAN parameters, security mode missing");

    commit_ipv4_config(false, NWPREFSTECH_UNKNOWN, -1);

    expect_default_network_preferences_content(written_default_contents);
}

/*!\test
 * Setting invalid WLAN security mode is detected when attempting to write
 * configuration.
 */
void test_set_invalid_wlan_security_mode()
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(92,
                                                dcpregs_read_92_wlan_security,
                                                dcpregs_write_92_wlan_security);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>("foo")), 3));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address BA:DD:EA:DB:EE:F1");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
                                              "Invalid WLAN security mode \"foo\" (Invalid argument)");
    mock_messages->expect_msg_error(EINVAL, LOG_ERR,
                                    "Cannot set WLAN parameters, security mode missing");

    commit_ipv4_config(false, NWPREFSTECH_UNKNOWN, -1);

    expect_default_network_preferences_content(written_default_contents);
}

static void get_wlan_security_mode(const char *assumed_connman_security_mode,
                                   const char *expected_error_message = nullptr)
{
    assume_wlan_interface_is_active();

    static const uint8_t redzone_content[] =
    {
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
    };

    uint8_t buffer[32];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    static constexpr const size_t read_size = sizeof(buffer) - 2 * sizeof(redzone_content);

    auto *reg = lookup_register_expect_handlers(92,
                                                dcpregs_read_92_wlan_security,
                                                dcpregs_write_92_wlan_security);
    uint8_t *const dest = &buffer[sizeof(redzone_content)];

    if(expected_error_message != nullptr)
        mock_messages->expect_msg_error_formatted(0, LOG_ERR,
                                                  expected_error_message);

    mock_connman->expect_find_active_primary_interface(dummy_connman_iface,
                                                       wlan_mac_address,
                                                       ethernet_mac_address,
                                                       wlan_mac_address);
    mock_connman->expect_get_wlan_security_type_string(true,
                                                       assumed_connman_security_mode,
                                                       dummy_connman_iface,
                                                       false, read_size);
    mock_connman->expect_free_interface_data(dummy_connman_iface);

    const ssize_t mode_length = reg->read_handler(dest, read_size);

    cppcut_assert_operator(ssize_t(0), <, mode_length);
    cppcut_assert_equal('\0', static_cast<char>(dest[mode_length - 1]));
    cppcut_assert_equal(assumed_connman_security_mode,
                        static_cast<char *>(static_cast<void *>(dest)));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer, sizeof(redzone_content));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + sizeof(buffer) - sizeof(redzone_content),
                            sizeof(redzone_content));
}

/*!\test
 * Read out WLAN security mode when no security mode is enabled.
 */
void test_get_wlan_security_mode_assume_none()
{
    get_wlan_security_mode("none");
}

/*!\test
 * Read out WLAN security mode in WEP mode.
 */
void test_get_wlan_security_mode_assume_wep()
{
    get_wlan_security_mode("wep");
}

/*!\test
 * Read out WLAN security mode in WPA/WPA2 PSK mode.
 */
void test_get_wlan_security_mode_assume_psk()
{
    get_wlan_security_mode("psk");
}

/*!\test
 * Read out WLAN security mode in WPA EAP mode ("WPA Enterprise").
 */
void test_get_wlan_security_mode_assume_wpa_eap()
{
    get_wlan_security_mode("ieee8021x");
}

/*!\test
 * Read out WLAN security mode in some unknown future mode.
 *
 * This test shows that we are simply passing through any mode name that is
 * currently configured into Connman configuration.
 */
void test_get_wlan_security_mode_assume_unknown_mode()
{
    get_wlan_security_mode("fortknox");
}

static void set_passphrase_with_security_mode(const char *passphrase,
                                              size_t passphrase_size,
                                              const char *connman_security_mode)
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(102,
                                                dcpregs_read_102_passphrase,
                                                dcpregs_write_102_passphrase);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(passphrase)), passphrase_size));

    reg = lookup_register_expect_handlers(92,
                                          dcpregs_read_92_wlan_security,
                                          dcpregs_write_92_wlan_security);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(connman_security_mode)), strlen(connman_security_mode)));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address BA:DD:EA:DB:EE:F1");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents);

    mock_os->expect_os_file_new(expected_os_write_fd, network_config_file);

    if(strcmp(connman_security_mode, "none") == 0)
    {
        passphrase = "";
        passphrase_size = 0;
    }

    const int expected_number_of_writes =
        2 * 3 + (2 + 3 + ((passphrase_size == 0) ? 0 : 1)) * 4;

    for(int i = 0; i < expected_number_of_writes; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);

    mock_os->expect_os_file_close(expected_os_write_fd);
    mock_os->expect_os_sync_dir(network_config_path);

    commit_ipv4_config(false, NWPREFSTECH_WLAN);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "[wifi]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "Security = %s\n"
        "Passphrase = %s\n";

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format, ethernet_mac_address,
             wlan_mac_address,
             connman_security_mode, passphrase);

    const size_t written_config_file_length =
        strlen(new_config_file_buffer) -
        ((passphrase_size == 0) ? 14 : 0);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Passphrase may be sent as ASCII string.
 */
void test_set_ascii_passphrase_with_psk_security_mode()
{
    static constexpr char ascii_passphrase[] = "My Secret 123&Foo~Bar";

    cppcut_assert_operator(size_t(64), >, sizeof(ascii_passphrase) - 1);
    set_passphrase_with_security_mode(ascii_passphrase, sizeof(ascii_passphrase) - 1,
                                      "psk");
}

/*!\test
 * Passphrase may be sent as string containing only hex characters.
 */
void test_set_hex_passphrase_with_psk_security_mode()
{
    static constexpr char hex_passphrase[] =
        "1234567890abcdef"
        "1234567890abcdef"
        "1234567890abcdef"
        "1234567890abcdef";

    cppcut_assert_equal(size_t(64), sizeof(hex_passphrase) - 1);
    set_passphrase_with_security_mode(hex_passphrase, sizeof(hex_passphrase) - 1,
                                      "psk");
}

/*!\test
 * ASCII passphrase lengths must be with certain limits.
 */
void test_ascii_passphrase_minimum_and_maximum_length()
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    static constexpr char passphrase[] =
        "12345678901234567890"
        "abcdefghijklmnopqrst"
        "12345678901234567890"
        "1234";
    static const uint8_t *passphrase_arg =
        static_cast<const uint8_t *>(static_cast<const void *>(passphrase));

    auto *reg = lookup_register_expect_handlers(102,
                                                dcpregs_read_102_passphrase,
                                                dcpregs_write_102_passphrase);

    cppcut_assert_equal(0, reg->write_handler(passphrase_arg, 0));
    cppcut_assert_equal(0, reg->write_handler(passphrase_arg, 1));
    cppcut_assert_equal(0, reg->write_handler(passphrase_arg, 63));

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Invalid passphrase: not a hex-string (Invalid argument)");
    cppcut_assert_equal(-1, reg->write_handler(passphrase_arg, 64));

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Unexpected data length 65 (expected 0...64) (Invalid argument)");
    cppcut_assert_equal(-1, reg->write_handler(passphrase_arg,
                                               sizeof(passphrase)));
}

struct StringWithLength
{
    const size_t length_;
    const uint8_t *string_;

    StringWithLength(const StringWithLength &) = delete;
    StringWithLength &operator=(const StringWithLength &) = delete;
    StringWithLength(StringWithLength &&) = default;
    StringWithLength &operator=(StringWithLength &&) = delete;

    template <size_t Length>
    explicit StringWithLength(const char (&str)[Length]):
        length_(Length - 1),
        string_(static_cast<const uint8_t *>(static_cast<const void *>(str)))
    {}
};

/*!\test
 * ASCII passphrase must contain characters in certain range
 */
void test_ascii_passphrase_character_set()
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(102,
                                                dcpregs_read_102_passphrase,
                                                dcpregs_write_102_passphrase);

    static const std::array<StringWithLength, 7> non_ascii_passphrases =
    {
        StringWithLength("\0""012345678ghij"),
        StringWithLength("01\0""2345678ghij"),
        StringWithLength("abcde\x01ghij"),
        StringWithLength("abcde\tfghij"),
        StringWithLength("\nabcdefghijklmno"),
        StringWithLength("abcdefghijklmno\x7f"),
        StringWithLength("abcdefghi\x1fklmno"),
    };

    for(const auto &str : non_ascii_passphrases)
    {
        mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
            "Invalid passphrase: expected ASCII passphrase (Invalid argument)");
        cppcut_assert_equal(-1, reg->write_handler(str.string_, str.length_));
    }
}

/*!\test
 * Passphrase with security mode "none" makes no sense and is ignored.
 */
void test_set_passphrase_with_security_mode_none_works()
{
    static constexpr char ascii_passphrase[] = "SuperSecret";

    cppcut_assert_operator(size_t(64), >, sizeof(ascii_passphrase) - 1);
    set_passphrase_with_security_mode(ascii_passphrase, sizeof(ascii_passphrase) - 1,
                                      "none");
}

/*!\test
 * Explicitly empty passphrase with security mode "none" is accepted.
 */
void test_set_empty_passphrase_with_security_mode_none_works()
{
    set_passphrase_with_security_mode("", 0, "none");
}

/*!\test
 * Passphrase without any security mode makes no sense and is rejected.
 */
void test_set_passphrase_without_security_mode_does_not_work()
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    static constexpr char passphrase[] = "SuperSecret";
    auto *reg = lookup_register_expect_handlers(102,
                                                dcpregs_read_102_passphrase,
                                                dcpregs_write_102_passphrase);
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(passphrase)), sizeof(passphrase) - 1));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address BA:DD:EA:DB:EE:F1");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents);

    mock_connman->expect_find_active_primary_interface(dummy_connman_iface,
                                                       wlan_mac_address,
                                                       ethernet_mac_address,
                                                       wlan_mac_address);
    mock_connman->expect_get_wlan_security_type_string(true, "", dummy_connman_iface, false, 12);
    mock_connman->expect_free_interface_data(dummy_connman_iface);
    mock_messages->expect_msg_error(EINVAL, LOG_ERR,
                                    "Cannot set WLAN parameters, security mode missing");

    commit_ipv4_config(false, NWPREFSTECH_UNKNOWN, -1);

    expect_default_network_preferences_content(written_default_contents);
}

/*!\test
 * Passphrase can be read out while the configuration is in edit mode.
 */
void test_get_wlan_passphrase_in_edit_mode()
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    static const uint8_t redzone_content[] =
    {
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
    };

    uint8_t buffer[64 + 2 * sizeof(redzone_content)];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    auto *reg = lookup_register_expect_handlers(102,
                                                dcpregs_read_102_passphrase,
                                                dcpregs_write_102_passphrase);

    mock_messages->expect_msg_info("No passphrase set yet");

    cppcut_assert_equal(ssize_t(0), reg->read_handler(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[0]);
    cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[sizeof(buffer) - 1]);

    /* set hex passphrase and read back */
    static const uint8_t passphrase[] =
        "12345678901234567890"
        "abcdefabcdefabcdefab"
        "12345678901234567890"
        "abcd";

    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(passphrase)), sizeof(passphrase) - 1));

    uint8_t *const dest = &buffer[sizeof(redzone_content)];
    const ssize_t passphrase_length = reg->read_handler(dest, 64);

    cppcut_assert_equal(ssize_t(64), passphrase_length);
    cut_assert_equal_memory(passphrase, sizeof(passphrase) - 1,
                            dest, 64);
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer, sizeof(redzone_content));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + sizeof(buffer) - sizeof(redzone_content),
                            sizeof(redzone_content));

    /* wipe out passphrase and read back */
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(passphrase)), 0));

    mock_messages->expect_msg_info("Passphrase set, but empty");

    memset(buffer, UINT8_MAX, sizeof(buffer));
    cppcut_assert_equal(ssize_t(0), reg->read_handler(dest, 64));
    cppcut_assert_equal(uint8_t(UINT8_MAX), dest[0]);
    cppcut_assert_equal(uint8_t(UINT8_MAX), dest[63]);
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer, sizeof(redzone_content));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + sizeof(buffer) - sizeof(redzone_content),
                            sizeof(redzone_content));
}

/*!\test
 * Passphrase cannot be read out while the configuration is in read-only mode.
 */
void test_get_wlan_passphrase_in_regular_mode()
{
    assume_wlan_interface_is_active();

    uint8_t buffer[64];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    auto *reg = lookup_register_expect_handlers(102,
                                                dcpregs_read_102_passphrase,
                                                dcpregs_write_102_passphrase);

    mock_messages->expect_msg_error(0, LOG_NOTICE,
                                    "Passphrase cannot be read out while in non-edit mode");

    cppcut_assert_equal(ssize_t(-1), reg->read_handler(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[0]);
    cppcut_assert_equal(uint8_t(UINT8_MAX), buffer[sizeof(buffer) - 1]);
}

/*!\test
 * In most cases, the SSID will be a rather simple ASCII string.
 *
 * Here, "simple" means regular ASCII characters and no spaces. If the SSID is
 * simple enough, it will be written to the "NetworkName" field of the
 * configuration file.
 *
 * The zero-terminator is usually not part of the SSID and must not be sent
 * over DCP (otherwise the SSID will be considered binary because it ends with
 * a 0 byte).
 */
void test_set_simple_ascii_wlan_ssid()
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(94,
                                                dcpregs_read_94_ssid,
                                                dcpregs_write_94_ssid);

    static constexpr char ssid[] = "MyNiceWLAN";

    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(ssid)), sizeof(ssid) - 1));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address BA:DD:EA:DB:EE:F1");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents);

    mock_connman->expect_find_active_primary_interface(
        dummy_connman_iface,
        wlan_mac_address, ethernet_mac_address, wlan_mac_address);
    mock_connman->expect_get_wlan_security_type_string(true, "none", dummy_connman_iface, false, 12);
    mock_connman->expect_free_interface_data(dummy_connman_iface);
    mock_os->expect_os_file_new(expected_os_write_fd, network_config_file);
    for(int i = 0; i < 2 * 3 + (2 + 4) * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);
    mock_os->expect_os_sync_dir(network_config_path);

    commit_ipv4_config(false, NWPREFSTECH_WLAN);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "[wifi]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "NetworkName = %s\n"
        "Security = none\n";

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format, ethernet_mac_address,
             wlan_mac_address, ssid);

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * An SSID may be any binary string with a length of up to 32 bytes.
 */
void test_set_binary_wlan_ssid()
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(94,
                                                dcpregs_read_94_ssid,
                                                dcpregs_write_94_ssid);

    static constexpr uint8_t ssid[] =
    {
        0x00, 0x08, 0xfe, 0xff, 0x41, 0x42, 0x43, 0x7f,
    };

    static constexpr char ssid_as_hex_string[] = "0008feff4142437f";

    cppcut_assert_equal(0, reg->write_handler(ssid, sizeof(ssid)));

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address BA:DD:EA:DB:EE:F1");

    struct os_mapped_file_data file_with_written_default_contents = { .fd = -1 };
    std::vector<char> written_default_contents;
    mock_os->expect_os_map_file_to_memory(-1, false, network_config_file);
    expect_create_default_network_preferences(file_with_written_default_contents,
                                              written_default_contents);

    mock_connman->expect_find_active_primary_interface(
        dummy_connman_iface,
        wlan_mac_address, ethernet_mac_address, wlan_mac_address);
    mock_connman->expect_get_wlan_security_type_string(true, "none", dummy_connman_iface, false, 12);
    mock_connman->expect_free_interface_data(dummy_connman_iface);
    mock_os->expect_os_file_new(expected_os_write_fd, network_config_file);
    for(int i = 0; i < 2 * 3 + (2 + 4) * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);
    mock_os->expect_os_sync_dir(network_config_path);

    commit_ipv4_config(false, NWPREFSTECH_WLAN);

    static const char expected_config_file_format[] =
        "[ethernet]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "[wifi]\n"
        "MAC = %s\n"
        "DHCP = yes\n"
        "SSID = %s\n"
        "Security = none\n";

    char new_config_file_buffer[512];
    snprintf(new_config_file_buffer, sizeof(new_config_file_buffer),
             expected_config_file_format, ethernet_mac_address,
             wlan_mac_address, ssid_as_hex_string);

    size_t written_config_file_length = strlen(new_config_file_buffer);

    cut_assert_equal_memory(new_config_file_buffer, written_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * The empty SSID is a special wildcard SSID and cannot be used here.
 */
void test_set_empty_wlan_ssid_is_an_error()
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(94,
                                                dcpregs_read_94_ssid,
                                                dcpregs_write_94_ssid);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Unexpected data length 0 (expected 1...32) (Invalid argument)");

    uint8_t dummy = UINT8_MAX;
    cppcut_assert_equal(-1, reg->write_handler(&dummy, 0));

    commit_ipv4_config(true, NWPREFSTECH_UNKNOWN);
}

/*!\test
 * Read out the SSID for displaying purposes.
 */
void test_get_wlan_ssid_in_normal_mode()
{
    assume_wlan_interface_is_active();

    static constexpr uint8_t redzone_content[] =
    {
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
    };

    static constexpr uint8_t assumed_ssid[] =
    {
        0x09, 0x20, 0x60, 0xfe, 0x00, 0x01, 0xff, 0x80,
        0x7e, 0x7f, 0x00, 0x08, 0x61, 0xcb, 0xa7, 0xd0,
        0x0a, 0x21, 0x61, 0xff, 0x01, 0x02, 0x00, 0x81,
        0x7f, 0x80, 0x01, 0x09, 0x62, 0xcc, 0xa8, 0xd1,
    };

    uint8_t buffer[32 + 2 * sizeof(redzone_content)];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    auto *reg = lookup_register_expect_handlers(94,
                                                dcpregs_read_94_ssid,
                                                dcpregs_write_94_ssid);
    uint8_t *const dest = &buffer[sizeof(redzone_content)];

    mock_connman->expect_find_active_primary_interface(dummy_connman_iface,
                                                       wlan_mac_address,
                                                       ethernet_mac_address,
                                                       wlan_mac_address);
    mock_connman->expect_get_wlan_ssid(assumed_ssid, sizeof(assumed_ssid),
                                       dummy_connman_iface, false, 32);
    mock_connman->expect_free_interface_data(dummy_connman_iface);

    const ssize_t ssid_length = reg->read_handler(dest, 32);

    cut_assert_equal_memory(assumed_ssid, ssize_t(sizeof(assumed_ssid)),
                            dest, ssid_length);
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer, sizeof(redzone_content));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + sizeof(buffer) - sizeof(redzone_content),
                            sizeof(redzone_content));
}

/*!\test
 * Read out the SSID in edit mode, Connman is consulted if the SSID has not
 * been set during this edit session.
 */
void test_get_wlan_ssid_in_edit_mode_before_any_changes()
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    static constexpr uint8_t redzone_content[] =
    {
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
    };

    static constexpr uint8_t assumed_ssid[] =
    {
        0x7e, 0x7f, 0x00, 0x08, 0x61, 0xcb, 0xa7, 0xd0,
        0x09, 0x20, 0x60, 0xfe, 0x00, 0x01, 0xff, 0x80,
        0x0a, 0x21, 0x61, 0xff, 0x01, 0x02, 0x00, 0x81,
    };

    cppcut_assert_operator(size_t(32), <=, sizeof(assumed_ssid) + sizeof(redzone_content));

    uint8_t buffer[sizeof(assumed_ssid) + 2 * sizeof(redzone_content)];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    auto *reg = lookup_register_expect_handlers(94,
                                                dcpregs_read_94_ssid,
                                                dcpregs_write_94_ssid);
    uint8_t *const dest = &buffer[sizeof(redzone_content)];

    mock_connman->expect_find_interface(dummy_connman_iface, wlan_mac_address);
    mock_connman->expect_get_wlan_ssid(assumed_ssid, sizeof(assumed_ssid),
                                       dummy_connman_iface, false, 32);
    mock_connman->expect_free_interface_data(dummy_connman_iface);

    const ssize_t ssid_length = reg->read_handler(dest, 32);

    cut_assert_equal_memory(dest, ssize_t(sizeof(assumed_ssid)),
                            buffer + sizeof(redzone_content), ssid_length);
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer, sizeof(redzone_content));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + sizeof(buffer) - sizeof(redzone_content),
                            sizeof(redzone_content));
}

/*!\test
 * Read out the SSID in edit mode, return SSID currently being edited.
 */
void test_get_wlan_ssid_in_edit_mode_after_change()
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(94,
                                                dcpregs_read_94_ssid,
                                                dcpregs_write_94_ssid);

    static constexpr uint8_t ssid[] =
    {
        0x0a, 0x21, 0x61, 0xff, 0x01, 0x02, 0x00, 0x81,
        0x09, 0x20, 0x60, 0xfe, 0x00, 0x01, 0xff, 0x80,
        0x7f, 0x80, 0x01, 0x09, 0x62, 0xcc, 0xa8, 0xd1,
    };

    static constexpr uint8_t redzone_content[] =
    {
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
    };

    cppcut_assert_equal(size_t(32), sizeof(ssid) + sizeof(redzone_content));

    cppcut_assert_equal(0, reg->write_handler(ssid, sizeof(ssid)));

    uint8_t buffer[32];
    memset(buffer, UINT8_MAX, sizeof(buffer));

    const ssize_t ssid_length = reg->read_handler(buffer, sizeof(buffer));

    cut_assert_equal_memory(ssid, ssize_t(sizeof(ssid)),
                            buffer, ssid_length);
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + ssid_length, sizeof(redzone_content));
}

/*!\test
 * Attempting to set ad-hoc mode results in an error.
 *
 * Connman does not support ad-hoc mode, so we do not either.
 */
void test_set_ibss_mode_adhoc_is_not_supported()
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(93,
                                                dcpregs_read_93_ibss,
                                                dcpregs_write_93_ibss);

    mock_messages->expect_msg_error(EINVAL, LOG_NOTICE,
                                    "Cannot change IBSS mode to ad-hoc, "
                                    "always using infrastructure mode");
    cppcut_assert_equal(-1, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>("true")), 4));
}

/*!\test
 * Attempting to set infrastructure mode succeeds, but the attempt is logged
 * and gets ignored.
 */
void test_set_ibss_mode_infrastructure_is_ignored()
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(93,
                                                dcpregs_read_93_ibss,
                                                dcpregs_write_93_ibss);

    mock_messages->expect_msg_info("Ignoring IBSS infrastructure mode request "
                                   "(always using that mode)");
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>("false")), 5));
}

/*!\test
 * Even though we do not support setting IBSS mode, it is still not allowed to
 * send junk.
 */
void test_set_junk_ibss_mode_is_an_error()
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    static const std::array<StringWithLength, 13> junk_requests =
    {
        StringWithLength("\0\0\0\0"),
        StringWithLength("\0\0\0\0\0\0\0\0"),
        StringWithLength("t\0\0\0"),
        StringWithLength("tru\0"),
        StringWithLength("rue\0"),
        StringWithLength("f\0\0\0"),
        StringWithLength("fals"),
        StringWithLength("alse"),
        StringWithLength("abcdefg"),
        StringWithLength("\ntrue"),
        StringWithLength("\nfalse"),
        StringWithLength("\0true"),
        StringWithLength("\0false"),
    };

    auto *reg = lookup_register_expect_handlers(93,
                                                dcpregs_read_93_ibss,
                                                dcpregs_write_93_ibss);

    for(const auto &str : junk_requests)
    {
        mock_messages->expect_msg_error(EINVAL, LOG_ERR,
                                        "Got invalid IBSS mode request");
        cppcut_assert_equal(-1, reg->write_handler(str.string_, str.length_));
    }
}

/*!\test
 * We always tell we are operating in infrastructure mode.
 */
void test_get_ibss_mode_returns_infrastructure_mode()
{
    assume_wlan_interface_is_active();

    auto *reg = lookup_register_expect_handlers(93,
                                                dcpregs_read_93_ibss,
                                                dcpregs_write_93_ibss);

    uint8_t response[8];
    cppcut_assert_equal(ssize_t(6), reg->read_handler(response, sizeof(response)));
    cppcut_assert_equal("false", static_cast<const char *>(static_cast<const void *>(response)));
}

/*!\test
 * Attempting to set WPA cipher mode succeeds, but the attempt is logged and
 * gets ignored.
 */
void test_set_wpa_cipher_is_ignored()
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    auto *reg = lookup_register_expect_handlers(101,
                                                dcpregs_read_101_wpa_cipher,
                                                dcpregs_write_101_wpa_cipher);

    mock_messages->expect_msg_info("Ignoring setting WPA cipher (automatic, AES preferred)");
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>("TKIP")), 4));

    mock_messages->expect_msg_info("Ignoring setting WPA cipher (automatic, AES preferred)");
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>("TKIP")), 5));

    mock_messages->expect_msg_info("Ignoring setting WPA cipher (automatic, AES preferred)");
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>("AES")), 3));

    mock_messages->expect_msg_info("Ignoring setting WPA cipher (automatic, AES preferred)");
    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>("AES")), 4));
}

/*!\test
 * Even though we do not support setting WPA cipher, it is still not allowed to
 * send junk.
 */
void test_set_junk_wpa_cipher_is_an_error()
{
    assume_wlan_interface_is_active();

    start_ipv4_config();

    static const std::array<StringWithLength, 16> junk_requests =
    {
        StringWithLength("\0\0\0\0"),
        StringWithLength("\0\0\0\0\0\0\0\0"),
        StringWithLength("aes"),
        StringWithLength("A\0\0"),
        StringWithLength("ES\0"),
        StringWithLength("tkip"),
        StringWithLength("T\0\0"),
        StringWithLength("KIP"),
        StringWithLength("abcdefg"),
        StringWithLength("DES"),
        StringWithLength("RSA"),
        StringWithLength("RIJNDAEL"),
        StringWithLength("\nAES"),
        StringWithLength("\nTKIP"),
        StringWithLength("\0AES"),
        StringWithLength("\0TKIP"),
    };

    auto *reg = lookup_register_expect_handlers(101,
                                                dcpregs_read_101_wpa_cipher,
                                                dcpregs_write_101_wpa_cipher);

    for(const auto &str : junk_requests)
    {
        mock_messages->expect_msg_error(EINVAL, LOG_ERR,
                                        "Got invalid WPA cipher");
        cppcut_assert_equal(-1, reg->write_handler(str.string_, str.length_));
    }
}

/*!\test
 * We always tell we are using AES.
 */
void test_get_wpa_cipher_returns_aes()
{
    assume_wlan_interface_is_active();

    auto *reg = lookup_register_expect_handlers(101,
                                                dcpregs_read_101_wpa_cipher,
                                                dcpregs_write_101_wpa_cipher);

    uint8_t response[8];
    cppcut_assert_equal(ssize_t(4), reg->read_handler(response, sizeof(response)));
    cppcut_assert_equal("AES", static_cast<const char *>(static_cast<const void *>(response)));
}

/*!\test
 * Network configuration cannot be saved after shutdown.
 */
void test_configuration_update_is_blocked_after_shutdown()
{
    start_ipv4_config();

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Shutdown guard \"networkconfig\" down");
    dcpregs_networkconfig_prepare_for_shutdown();

    /* in-memory edits are still working... */
    auto *reg = lookup_register_expect_handlers(55,
                                                dcpregs_read_55_dhcp_enabled,
                                                dcpregs_write_55_dhcp_enabled);
    static const uint8_t zero = 0;

    mock_messages->expect_msg_info_formatted("Disable DHCP");
    cppcut_assert_equal(0, reg->write_handler(&zero, 1));

    /* ...but writing to file is blocked */
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Writing new network configuration for MAC address DE:CA:FD:EA:DB:AD");
    mock_messages->expect_msg_info("Not writing network configuration during shutdown.");
    commit_ipv4_config(false, NWPREFSTECH_UNKNOWN, -1);
}

/*!\test
 * Attempting to shut down twice has no effect.
 */
void test_shutdown_can_be_called_only_once()
{
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Shutdown guard \"networkconfig\" down");
    dcpregs_networkconfig_prepare_for_shutdown();

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Shutdown guard \"networkconfig\" down");
    dcpregs_networkconfig_prepare_for_shutdown();
}

/*!\test
 * WLAN site survey can be started.
 */
void test_start_wlan_site_survey()
{
    auto *reg = lookup_register_expect_handlers(104,
                                                dcpregs_write_104_start_wlan_site_survey);

    mock_messages->expect_msg_info("WLAN site survey started");
    mock_connman->expect_connman_start_wlan_site_survey(
        true, survey_complete, CONNMAN_SITE_SCAN_OK);
    survey_complete_notification_data.expect();
    cppcut_assert_equal(0, reg->write_handler(NULL, 0));

    mock_messages->expect_msg_info_formatted("WLAN site survey done, succeeded (0)");
    survey_complete_notification_data();
    register_changed_data->check(105);
}

/*!\test
 * XML with list of networks is sent if WLAN site survey was successful.
 */
void test_wlan_site_survey_returns_list_of_wlan_networks()
{
    test_start_wlan_site_survey();

    auto *reg = lookup_register_expect_handlers(105,
                                                dcpregs_read_105_wlan_site_survey_results,
                                                NULL);

    static constexpr const std::array<const MockConnman::ServiceIterData, 5> services_data =
    {
        MockConnman::ServiceIterData("wifi",  "First WLAN",         100, MockConnman::sec_psk_wsp),
        MockConnman::ServiceIterData("wired", "Some ethernet NIC",  100, MockConnman::sec_none),
        MockConnman::ServiceIterData("wifi",  "Not the Internet",    78, MockConnman::sec_none),
        MockConnman::ServiceIterData("wifi",  "Last on the list",    56, MockConnman::sec_psk),
        MockConnman::ServiceIterData("wired", "Ethernet adapter 2",  10, MockConnman::sec_none),
    };

    mock_connman->set_connman_service_iterator_data(*services_data.data(), services_data.size());

    struct dynamic_buffer buffer;
    dynamic_buffer_init(&buffer);
    static constexpr char expected_xml[] =
        "<bss_list count=\"3\">"
        "<bss index=\"0\">"
        "<ssid>First WLAN</ssid>"
        "<quality>100</quality>"
        "<security_list count=\"2\">"
        "<security index=\"0\">psk</security>"
        "<security index=\"1\">wsp</security>"
        "</security_list>"
        "</bss>"
        "<bss index=\"1\">"
        "<ssid>Not the Internet</ssid>"
        "<quality>78</quality>"
        "<security_list count=\"1\">"
        "<security index=\"0\">none</security>"
        "</security_list>"
        "</bss>"
        "<bss index=\"2\">"
        "<ssid>Last on the list</ssid>"
        "<quality>56</quality>"
        "<security_list count=\"1\">"
        "<security index=\"0\">psk</security>"
        "</security_list>"
        "</bss>"
        "</bss_list>";

    cut_assert_true(reg->read_handler_dynamic(&buffer));

    cppcut_assert_operator(size_t(0), <, buffer.pos);
    cut_assert_equal_memory(expected_xml, sizeof(expected_xml) - 1,
                            buffer.data, buffer.pos);

    dynamic_buffer_free(&buffer);
}

/*!\test
 * WLAN site survey request does not accept data.
 */
void test_start_wlan_site_survey_command_has_no_data_bytes()
{
    auto *reg = lookup_register_expect_handlers(104,
                                                dcpregs_write_104_start_wlan_site_survey);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Unexpected data length 1 (expected 0) (Invalid argument)");

    static const uint8_t zero = 0;
    cppcut_assert_equal(-1, reg->write_handler(&zero, 1));
}

/*!\test
 * Starting WLAN site survey twice has no effect.
 */
void test_start_wlan_site_survey_has_no_effect_if_survey_is_active()
{
    auto *reg = lookup_register_expect_handlers(104,
                                                dcpregs_write_104_start_wlan_site_survey);

    mock_messages->expect_msg_info("WLAN site survey started");
    mock_connman->expect_connman_start_wlan_site_survey(true);
    cppcut_assert_equal(0, reg->write_handler(NULL, 0));

    /* no extra expectations to add here, this handler will simply return */
    mock_messages->expect_msg_error(0, LOG_NOTICE,
                                    "WLAN site survey already in progress---please hold the line");
    cppcut_assert_equal(0, reg->write_handler(NULL, 0));
}

/*!\test
 * XML with error is sent if WLAN site survey errors out with a late failure
 * from Connman.
 */
void test_start_wlan_site_survey_fails_on_connman_failure()
{
    auto *reg = lookup_register_expect_handlers(104,
                                                dcpregs_write_104_start_wlan_site_survey);

    mock_connman->expect_connman_start_wlan_site_survey(
        false, survey_complete, CONNMAN_SITE_SCAN_CONNMAN_ERROR);
    survey_complete_notification_data.expect();
    cppcut_assert_equal(0, reg->write_handler(NULL, 0));

    mock_messages->expect_msg_info_formatted("WLAN site survey done, failed (1)");
    survey_complete_notification_data();
    register_changed_data->check(105);

    reg = lookup_register_expect_handlers(105,
                                          dcpregs_read_105_wlan_site_survey_results,
                                          NULL);

    struct dynamic_buffer buffer;
    dynamic_buffer_init(&buffer);
    static constexpr char expected_xml[] = "<bss_list count=\"-1\" error=\"network\"/>";
    cut_assert_true(reg->read_handler_dynamic(&buffer));

    cppcut_assert_operator(size_t(0), <, buffer.pos);
    cut_assert_equal_memory(expected_xml, sizeof(expected_xml) - 1,
                            buffer.data, buffer.pos);

    dynamic_buffer_free(&buffer);
}

/*!\test
 * XML with error is sent if WLAN site survey errors out with a D-Bus failure.
 */
void test_start_wlan_site_survey_fails_on_dbus_failure()
{
    auto *reg = lookup_register_expect_handlers(104,
                                                dcpregs_write_104_start_wlan_site_survey);

    mock_messages->expect_msg_info_formatted("WLAN site survey done, failed (2)");
    mock_connman->expect_connman_start_wlan_site_survey(
        false, survey_complete, CONNMAN_SITE_SCAN_DBUS_ERROR);
    survey_complete_notification_data.expect(true);
    cppcut_assert_equal(0, reg->write_handler(NULL, 0));
    register_changed_data->check(105);

    reg = lookup_register_expect_handlers(105,
                                          dcpregs_read_105_wlan_site_survey_results,
                                          NULL);

    struct dynamic_buffer buffer;
    dynamic_buffer_init(&buffer);
    static constexpr char expected_xml[] = "<bss_list count=\"-1\" error=\"internal\"/>";
    cut_assert_true(reg->read_handler_dynamic(&buffer));

    cppcut_assert_operator(size_t(0), <, buffer.pos);
    cut_assert_equal_memory(expected_xml, sizeof(expected_xml) - 1,
                            buffer.data, buffer.pos);

    dynamic_buffer_free(&buffer);
}

/*!\test
 * XML with error is sent if WLAN site survey cannot be started due to lack of
 * hardware.
 */
void test_start_wlan_site_survey_fails_if_no_hardware_available()
{
    auto *reg = lookup_register_expect_handlers(104,
                                                dcpregs_write_104_start_wlan_site_survey);

    mock_messages->expect_msg_info_formatted("WLAN site survey done, failed (4)");
    mock_connman->expect_connman_start_wlan_site_survey(
        false, survey_complete, CONNMAN_SITE_SCAN_NO_HARDWARE);
    survey_complete_notification_data.expect(true);
    cppcut_assert_equal(0, reg->write_handler(NULL, 0));
    register_changed_data->check(105);

    reg = lookup_register_expect_handlers(105,
                                          dcpregs_read_105_wlan_site_survey_results,
                                          NULL);

    struct dynamic_buffer buffer;
    dynamic_buffer_init(&buffer);
    static constexpr char expected_xml[] = "<bss_list count=\"-1\" error=\"hardware\"/>";
    cut_assert_true(reg->read_handler_dynamic(&buffer));

    cppcut_assert_operator(size_t(0), <, buffer.pos);
    cut_assert_equal_memory(expected_xml, sizeof(expected_xml) - 1,
                            buffer.data, buffer.pos);

    dynamic_buffer_free(&buffer);
}

/*!\test
 * XML with empty list of WLAN networks is returned if no scan has ever been
 * performed before.
 *
 * This is actually not quite true. If Connman knows any networks already, then
 * it will tell us about them and we will report them to the slave. In this
 * test, however, we assume that Connman does not have any networks for us.
 */
void test_reading_out_ssids_without_scan_returns_empty_list()
{
    auto *reg = lookup_register_expect_handlers(105,
                                                dcpregs_read_105_wlan_site_survey_results,
                                                NULL);

    mock_connman->expect_connman_service_iterator_get(NULL);
    mock_connman->expect_connman_service_iterator_free(NULL);

    struct dynamic_buffer buffer;
    dynamic_buffer_init(&buffer);
    static constexpr char expected_xml[] = "<bss_list count=\"0\"/>";
    cut_assert_true(reg->read_handler_dynamic(&buffer));

    cppcut_assert_operator(size_t(0), <, buffer.pos);
    cut_assert_equal_memory(expected_xml, sizeof(expected_xml) - 1,
                            buffer.data, buffer.pos);

    dynamic_buffer_free(&buffer);
}

};

namespace spi_registers_upnp
{

static MockMessages *mock_messages;
static MockOs *mock_os;

static std::vector<char> os_write_buffer;
static constexpr int expected_os_write_fd = 85;
static constexpr int expected_os_map_file_to_memory_fd = 67;

static const char expected_rc_path[]     = "/var/local/etc";
static const char expected_rc_filename[] = "/var/local/etc/upnp_settings.rc";

static int write_from_buffer_callback(const void *src, size_t count, int fd)
{
    cppcut_assert_equal(expected_os_write_fd, fd);
    cppcut_assert_not_null(src);
    cppcut_assert_operator(size_t(0), <, count);

    std::copy_n(static_cast<const char *>(src), count,
                std::back_inserter<std::vector<char>>(os_write_buffer));

    return 0;
}

void cut_setup()
{
    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_os = new MockOs;
    cppcut_assert_not_null(mock_os);
    mock_os->init();
    mock_os_singleton = mock_os;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    os_write_buffer.clear();

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    network_prefs_init(NULL, NULL, NULL, NULL);
    register_init(NULL);
}

void cut_teardown()
{
    register_deinit();
    network_prefs_deinit();

    os_write_buffer.clear();
    os_write_buffer.shrink_to_fit();

    mock_messages->check();
    mock_os->check();

    mock_messages_singleton = nullptr;
    mock_os_singleton = nullptr;

    delete mock_messages;
    delete mock_os;

    mock_messages = nullptr;
    mock_os = nullptr;
}

void test_read_out_default_friendly_name()
{
    auto *reg = lookup_register_expect_handlers(88,
                                                dcpregs_read_88_upnp_friendly_name,
                                                dcpregs_write_88_upnp_friendly_name);
    cppcut_assert_not_null(reg);

    mock_os->expect_os_map_file_to_memory(-1, false, expected_rc_filename);

    uint8_t buffer[64];
    ssize_t bytes = reg->read_handler(buffer, sizeof(buffer));

    static const char expected_name[] = "T+A Streaming Board";

    cppcut_assert_equal(ssize_t(sizeof(expected_name) - 1), bytes);
    cut_assert_equal_memory(expected_name, sizeof(expected_name) - 1,
                            buffer, bytes);
}

static void write_and_read_name(const char *name,
                                const char *expected_escaped_name)
{
    auto *reg = lookup_register_expect_handlers(88,
                                                dcpregs_read_88_upnp_friendly_name,
                                                dcpregs_write_88_upnp_friendly_name);
    cppcut_assert_not_null(reg);

    const size_t name_length = strlen(name);

    mock_os->expect_os_map_file_to_memory(-1, false, expected_rc_filename);
    mock_os->expect_os_file_new(expected_os_write_fd, expected_rc_filename);
    mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);
    mock_os->expect_os_sync_dir(expected_rc_path);
    mock_os->expect_os_system(EXIT_SUCCESS, true, "/bin/systemctl restart flagpole");

    cppcut_assert_equal(0, reg->write_handler((const uint8_t *)name, name_length));

    static const char expected_config_file_format[] = "FRIENDLY_NAME_OVERRIDE='%s'\n";
    char config_file_buffer[1024];

    const int config_len = snprintf(config_file_buffer, sizeof(config_file_buffer),
                                    expected_config_file_format,
                                    expected_escaped_name);

    cut_assert_equal_memory(config_file_buffer, config_len,
                            os_write_buffer.data(), os_write_buffer.size());

    /* nice, now let's check if the code can read back what it has just
     * written */
    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = size_t(config_len),
    };

    mock_os->expect_os_map_file_to_memory(&config_file, expected_rc_filename);
    mock_os->expect_os_unmap_file(&config_file);

    uint8_t buffer[1024];
    ssize_t bytes = reg->read_handler(buffer, sizeof(buffer));

    cppcut_assert_equal(ssize_t(name_length), bytes);
    cut_assert_equal_memory(name, name_length, buffer, bytes);
}

void test_write_and_read_out_simple_friendly_name()
{
    static const char simple_name[] = "UPnP name in unit test";

    write_and_read_name(simple_name, simple_name);
}

void test_write_and_read_out_friendly_name_with_special_characters()
{
    static const char evil_name[] = "a'b#c<d>e\"f&g%%h*i(j)k\\l/m.n^o''''p";
    static const char escaped[]   = "a'\\''b#c<d>e\"f&g%%h*i(j)k\\l/m.n^o'\\'''\\'''\\'''\\''p";

    write_and_read_name(evil_name, escaped);
}

void test_writing_same_name_does_not_change_files_nor_flagpole_service()
{
    auto *reg = lookup_register_expect_handlers(88,
                                                dcpregs_read_88_upnp_friendly_name,
                                                dcpregs_write_88_upnp_friendly_name);
    cppcut_assert_not_null(reg);

    static char config_file_content[] = "FRIENDLY_NAME_OVERRIDE='My UPnP Device'\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_content,
        .length = sizeof(config_file_content) - 1,
    };

    static const char upnp_name[] = "My UPnP Device";

    mock_os->expect_os_map_file_to_memory(&config_file, expected_rc_filename);
    mock_os->expect_os_unmap_file(&config_file);
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DEBUG, "UPnP name unchanged");

    cppcut_assert_equal(0, reg->write_handler((const uint8_t *)upnp_name, sizeof(upnp_name)));
}

};

namespace spi_registers_file_transfer
{

static MockMessages *mock_messages;
static MockOs *mock_os;
static MockFileTransferDBus *mock_file_transfer_dbus;
static MockLogindManagerDBus *mock_logind_manager_dbus;
static MockDBusIface *mock_dbus_iface;

static tdbusFileTransfer *const dbus_dcpd_file_transfer_iface_dummy =
    reinterpret_cast<tdbusFileTransfer *>(0x55990011);

static tdbuslogindManager *const dbus_logind_manager_iface_dummy =
    reinterpret_cast<tdbuslogindManager *>(0x35790011);

static RegisterChangedData *register_changed_data;

static std::vector<char> os_write_buffer;
static constexpr int expected_os_write_fd = 812;
static constexpr int expected_os_map_file_to_memory_fd = 64;
static constexpr const char feed_config_filename[] = "/var/local/etc/update_feeds.ini";
static constexpr const char feed_config_override_filename[] = "/var/local/etc/update_feeds_override.ini";
static constexpr const char feed_config_path[] = "/var/local/etc";
static constexpr const char opkg_configuration_path[] = "/etc/opkg";

static int write_from_buffer_callback(const void *src, size_t count, int fd)
{
    cppcut_assert_equal(expected_os_write_fd, fd);
    cppcut_assert_not_null(src);
    cppcut_assert_operator(size_t(0), <, count);

    std::copy_n(static_cast<const char *>(src), count,
                std::back_inserter<std::vector<char>>(os_write_buffer));

    return 0;
}

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

    mock_os = new MockOs;
    cppcut_assert_not_null(mock_os);
    mock_os->init();
    mock_os_singleton = mock_os;

    mock_file_transfer_dbus = new MockFileTransferDBus;
    cppcut_assert_not_null(mock_file_transfer_dbus);
    mock_file_transfer_dbus->init();
    mock_file_transfer_dbus_singleton = mock_file_transfer_dbus;

    mock_logind_manager_dbus = new MockLogindManagerDBus;
    cppcut_assert_not_null(mock_logind_manager_dbus);
    mock_logind_manager_dbus->init();
    mock_logind_manager_dbus_singleton = mock_logind_manager_dbus;

    mock_dbus_iface = new MockDBusIface;
    cppcut_assert_not_null(mock_dbus_iface);
    mock_dbus_iface->init();
    mock_dbus_iface_singleton = mock_dbus_iface;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    os_write_buffer.clear();

    register_changed_data->init();

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    network_prefs_init(NULL, NULL, NULL, NULL);
    register_init(register_changed_callback);
    dcpregs_filetransfer_set_picture_provider(dcpregs_playstream_get_picture_provider());
}

void cut_teardown()
{
    register_deinit();
    network_prefs_deinit();

    register_changed_data->check();

    delete register_changed_data;
    register_changed_data = nullptr;

    os_write_buffer.clear();
    os_write_buffer.shrink_to_fit();

    mock_messages->check();
    mock_os->check();
    mock_file_transfer_dbus->check();
    mock_logind_manager_dbus->check();
    mock_dbus_iface->check();

    mock_messages_singleton = nullptr;
    mock_os_singleton = nullptr;
    mock_file_transfer_dbus_singleton = nullptr;
    mock_logind_manager_dbus_singleton = nullptr;
    mock_dbus_iface_singleton = nullptr;

    delete mock_messages;
    delete mock_os;
    delete mock_file_transfer_dbus;
    delete mock_logind_manager_dbus;
    delete mock_dbus_iface;

    mock_messages = nullptr;
    mock_os = nullptr;
    mock_file_transfer_dbus = nullptr;
    mock_logind_manager_dbus = nullptr;
    mock_dbus_iface = nullptr;
}

/*!\test
 * Download URL buffer size must be within a certain range.
 */
void test_download_url_length_restrictions()
{
    auto *reg =
        lookup_register_expect_handlers(209, dcpregs_write_209_download_url);

    uint8_t url_buffer[8 + 1024 + 1];

    memset(url_buffer, 'x', sizeof(url_buffer));
    url_buffer[0] = HCR_FILE_TRANSFER_CRC_MODE_NONE;
    url_buffer[3] = HCR_FILE_TRANSFER_ENCRYPTION_NONE;

    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DEBUG, "Cleared URL");
    cppcut_assert_equal(0, reg->write_handler(url_buffer, 0));

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Unexpected data length 1 (expected 9...1032) (Invalid argument)");
    cppcut_assert_equal(-1, reg->write_handler(url_buffer, 1));

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Unexpected data length 8 (expected 9...1032) (Invalid argument)");
    cppcut_assert_equal(-1, reg->write_handler(url_buffer, 8));

    mock_messages->expect_msg_info_formatted("Set URL \"x\"");
    cppcut_assert_equal(0, reg->write_handler(url_buffer, 9));

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Unexpected data length 1033 (expected 9...1032) (Invalid argument)");
    cppcut_assert_equal(-1, reg->write_handler(url_buffer, sizeof(url_buffer)));

    mock_messages->expect_msg_info("Set URL \"%s\"");
    cppcut_assert_equal(0, reg->write_handler(url_buffer, sizeof(url_buffer) - 1));
}

static void start_download(const std::string &url, uint32_t download_id)
{
    uint8_t url_buffer[8 + url.length()];

    memset(url_buffer, 0, 8);
    url_buffer[3] = HCR_FILE_TRANSFER_ENCRYPTION_NONE;
    memcpy(url_buffer + 8, url.c_str(), url.length());

    auto *reg =
        lookup_register_expect_handlers(209, dcpregs_write_209_download_url);
    mock_messages->expect_msg_info("Set URL \"%s\"");

    cppcut_assert_equal(0, reg->write_handler(url_buffer, 8 + url.length()));

    static constexpr uint8_t hcr_command[] =
        { HCR_COMMAND_CATEGORY_LOAD_TO_DEVICE, HCR_COMMAND_LOAD_TO_DEVICE_DOWNLOAD };

    reg = lookup_register_expect_handlers(40, dcpregs_write_40_download_control);

    int expected_write_handler_retval;

    if(download_id == 0)
    {
        mock_messages->expect_msg_info("Not transferring files during shutdown.");
        expected_write_handler_retval = -1;
    }
    else
    {
        mock_messages->expect_msg_info("Download started, transfer ID %u");
        mock_dbus_iface->expect_dbus_get_file_transfer_iface(dbus_dcpd_file_transfer_iface_dummy);
        mock_file_transfer_dbus->expect_tdbus_file_transfer_call_download_sync(
            TRUE, download_id, dbus_dcpd_file_transfer_iface_dummy, url.c_str(), 20);
        expected_write_handler_retval = 0;
    }

    cppcut_assert_equal(expected_write_handler_retval,
                        reg->write_handler(hcr_command, sizeof(hcr_command)));
}

static void cancel_download(uint32_t download_id)
{
    auto *reg =
        lookup_register_expect_handlers(209, dcpregs_write_209_download_url);
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DEBUG, "Cleared URL");
    mock_dbus_iface->expect_dbus_get_file_transfer_iface(dbus_dcpd_file_transfer_iface_dummy);
    mock_file_transfer_dbus->expect_tdbus_file_transfer_call_cancel_sync(
        TRUE, dbus_dcpd_file_transfer_iface_dummy, download_id);

    cppcut_assert_equal(0, reg->write_handler(NULL, 0));

}

/*!\test
 * Request to download a URL triggers a D-Bus message to D-Bus DL.
 */
void test_download_url()
{
    start_download("http://this.is.a.test.com/releases/image_v1.0.bin", 5);
}

/*!\test
 * Request to download without setting the URL is an error.
 */
void test_download_without_url_returns_error()
{
    static constexpr uint8_t hcr_command[] =
    {
        HCR_COMMAND_CATEGORY_LOAD_TO_DEVICE,
        HCR_COMMAND_LOAD_TO_DEVICE_DOWNLOAD
    };

    auto *reg =
        lookup_register_expect_handlers(40, dcpregs_write_40_download_control);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_NOTICE,
                                              "Download URL not configured (Invalid argument)");

    cppcut_assert_equal(-1, reg->write_handler(hcr_command, sizeof(hcr_command)));
}

static void get_download_status(uint8_t (&buffer)[2])
{
    auto *reg =
        lookup_register_expect_handlers(41, dcpregs_read_41_download_status,
                                        NULL);

    cppcut_assert_equal(static_cast<ssize_t>(sizeof(buffer)),
                        reg->read_handler(buffer, sizeof(buffer)));
}

/*!\test
 * Reading out the download status when idle yields plain OK code.
 */
void test_download_status_while_not_downloading_is_OK_code()
{
    uint8_t buffer[2];
    get_download_status(buffer);

    static constexpr uint8_t expected_answer[] =
        { HCR_STATUS_CATEGORY_GENERIC, HCR_STATUS_GENERIC_OK };
    cut_assert_equal_memory(expected_answer, sizeof(expected_answer),
                            buffer, sizeof(buffer));
}

/*!\test
 * Reading out the download status while download is in progress yields
 * progress percentage.
 */
void test_download_status_during_download_is_percentage()
{
    static constexpr uint32_t xfer_id = 3;
    start_download("http://download.something.com/file", xfer_id);

    uint8_t buffer[2];
    get_download_status(buffer);

    static constexpr uint8_t expected_answer_1[] =
        { HCR_STATUS_CATEGORY_PROGRESS, 0 };
    cut_assert_equal_memory(expected_answer_1, sizeof(expected_answer_1),
                            buffer, sizeof(buffer));

    /* simulate D-Bus DL progress report */
    dcpregs_filetransfer_progress_notification(xfer_id, 10, 20);
    register_changed_data->check(41);

    get_download_status(buffer);

    static constexpr uint8_t expected_answer_2[] =
        { HCR_STATUS_CATEGORY_PROGRESS, 50 };
    cut_assert_equal_memory(expected_answer_2, sizeof(expected_answer_2),
                            buffer, sizeof(buffer));
}

/*!\test
 * Reading out the download status after successful download yields download
 * status code OK.
 */
void test_download_status_after_successful_download_is_status_code()
{
    static constexpr uint32_t xfer_id = 7;
    start_download("https://updates.server.com/file", xfer_id);

    uint8_t buffer[2];
    get_download_status(buffer);

    static constexpr uint8_t expected_answer_1[] =
        { HCR_STATUS_CATEGORY_PROGRESS, 0 };
    cut_assert_equal_memory(expected_answer_1, sizeof(expected_answer_1),
                            buffer, sizeof(buffer));

    /* simulate D-Bus DL progress report */
    dcpregs_filetransfer_progress_notification(xfer_id, 100, 100);
    register_changed_data->check(41);

    /* progress 100% */
    get_download_status(buffer);

    static constexpr uint8_t expected_answer_2[] =
        { HCR_STATUS_CATEGORY_PROGRESS, 100 };
    cut_assert_equal_memory(expected_answer_2, sizeof(expected_answer_2),
                            buffer, sizeof(buffer));

    /* simulate D-Bus DL done report */
    dcpregs_filetransfer_done_notification(xfer_id, LIST_ERROR_OK,
                                           "/some/path/0000000007.dbusdl");
    register_changed_data->check(41);

    /* Download OK status */
    get_download_status(buffer);

    static constexpr uint8_t expected_answer_3[] =
        { HCR_STATUS_CATEGORY_DOWNLOAD, HCR_STATUS_DOWNLOAD_OK };
    cut_assert_equal_memory(expected_answer_3, sizeof(expected_answer_3),
                            buffer, sizeof(buffer));

    /* Reading out the status again yields the same answer */
    get_download_status(buffer);
    cut_assert_equal_memory(expected_answer_3, sizeof(expected_answer_3),
                            buffer, sizeof(buffer));
}

/*!\test
 * Reading out the download status after failed download yields appropriate
 * download status code.
 */
void test_download_status_after_failed_download_is_status_code()
{
    static constexpr uint32_t xfer_id = 15;
    start_download("https://does.not.exist/file", xfer_id);

    uint8_t buffer[2];
    get_download_status(buffer);

    static constexpr uint8_t expected_answer_1[] =
        { HCR_STATUS_CATEGORY_PROGRESS, 0 };
    cut_assert_equal_memory(expected_answer_1, sizeof(expected_answer_1),
                            buffer, sizeof(buffer));

    /* simulate D-Bus DL done report with error */
    dcpregs_filetransfer_done_notification(xfer_id, LIST_ERROR_NET_IO, NULL);
    register_changed_data->check(41);

    /* No network connection status */
    get_download_status(buffer);

    static constexpr uint8_t expected_answer_2[] =
        { HCR_STATUS_CATEGORY_DOWNLOAD, HCR_STATUS_DOWNLOAD_NETWORK_ERROR };
    cut_assert_equal_memory(expected_answer_2, sizeof(expected_answer_2),
                            buffer, sizeof(buffer));

    /* Reading out the status again yields the same answer */
    get_download_status(buffer);
    cut_assert_equal_memory(expected_answer_2, sizeof(expected_answer_2),
                            buffer, sizeof(buffer));
}

/*!\test
 * Reading out the download status after canceling a download yields generic OK
 * status code.
 */
void test_cancel_download_resets_download_status()
{
    static constexpr uint32_t xfer_id = 23;
    start_download("ftp://short.com/f", xfer_id);

    uint8_t buffer[2];
    get_download_status(buffer);

    static constexpr uint8_t expected_answer_1[] =
        { HCR_STATUS_CATEGORY_PROGRESS, 0 };
    cut_assert_equal_memory(expected_answer_1, sizeof(expected_answer_1),
                            buffer, sizeof(buffer));

    cancel_download(xfer_id);

    get_download_status(buffer);

    static constexpr uint8_t expected_answer_2[] =
        { HCR_STATUS_CATEGORY_GENERIC, HCR_STATUS_GENERIC_OK };
    cut_assert_equal_memory(expected_answer_2, sizeof(expected_answer_2),
                            buffer, sizeof(buffer));
}

/*!\test
 * Rebooting the system via DCP command is possible.
 */
void test_send_reboot_request()
{
    auto *reg =
        lookup_register_expect_handlers(40, dcpregs_write_40_download_control);

    static constexpr uint8_t hcr_command[] =
        { HCR_COMMAND_CATEGORY_RESET, HCR_COMMAND_REBOOT_SYSTEM };

    mock_os->expect_os_path_get_type(OS_PATH_TYPE_IO_ERROR, "/tmp/do_update.sh");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
                                              "Shutdown requested via DCP command");
    mock_dbus_iface->expect_dbus_get_logind_manager_iface(dbus_logind_manager_iface_dummy);
    mock_logind_manager_dbus->expect_tdbus_logind_manager_call_reboot_sync(true, dbus_logind_manager_iface_dummy, false);
    cppcut_assert_equal(0, reg->write_handler(hcr_command, sizeof(hcr_command)));
}

/*!\test
 * Rebooting the system via DCP command is blocked during updates.
 */
void test_send_reboot_request_during_update()
{
    auto *reg =
        lookup_register_expect_handlers(40, dcpregs_write_40_download_control);

    static constexpr uint8_t hcr_command[] =
        { HCR_COMMAND_CATEGORY_RESET, HCR_COMMAND_REBOOT_SYSTEM };

    mock_os->expect_os_path_get_type(OS_PATH_TYPE_FILE, "/tmp/do_update.sh");
    mock_messages->expect_msg_error(0, LOG_ERR,
        "System reboot request ignored, we are in the middle of an update");
    cppcut_assert_equal(0, reg->write_handler(hcr_command, sizeof(hcr_command)));
}

/*!\test
 * Download is canceled on shutdown.
 */
void test_transfer_is_interrupted_on_shutdown()
{
    start_download("http://this.is.a.test.com/releases/image_v1.0.bin", 99);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Shutdown guard \"filetransfer\" down");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DEBUG, "Cleared URL");
    mock_dbus_iface->expect_dbus_get_file_transfer_iface(dbus_dcpd_file_transfer_iface_dummy);
    mock_file_transfer_dbus->expect_tdbus_file_transfer_call_cancel_sync(
        TRUE, dbus_dcpd_file_transfer_iface_dummy, 99);
    dcpregs_filetransfer_prepare_for_shutdown();
}

/*!\test
 * Download cannot be started after shutdown.
 */
void test_new_transfer_is_blocked_after_shutdown()
{
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Shutdown guard \"filetransfer\" down");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DEBUG, "Cleared URL");
    dcpregs_filetransfer_prepare_for_shutdown();

    start_download("http://this.is.a.test.com/releases/image_v1.0.bin", 0);
}

/*!\test
 * Request download of empty cover art via XMODEM.
 */
void test_download_empty_cover_art()
{
    /* no picture hash available */
    auto *reg =
        lookup_register_expect_handlers(210, dcpregs_read_210_current_cover_art_hash, nullptr);

    mock_messages->expect_msg_info("Cover art: Send empty hash to SPI slave");

    uint8_t buffer[16];
    cppcut_assert_equal(ssize_t(0), reg->read_handler(buffer, sizeof(buffer)));

    mock_messages->check();

    static constexpr uint8_t hcr_command[] =
        { HCR_COMMAND_CATEGORY_LOAD_TO_DEVICE, HCR_COMMAND_LOAD_TO_DEVICE_COVER_ART };

    /* no picture available */
    reg = lookup_register_expect_handlers(40, dcpregs_write_40_download_control);

    mock_messages->expect_msg_info("Download of cover art requested");
    mock_messages->expect_msg_info("No cover art available");

    cppcut_assert_equal(0, reg->write_handler(hcr_command, sizeof(hcr_command)));
}

/*!\test
 * Attempting to shut down twice has no effect.
 */
void test_shutdown_can_be_called_only_once()
{
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Shutdown guard \"filetransfer\" down");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DEBUG, "Cleared URL");
    dcpregs_filetransfer_prepare_for_shutdown();

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Shutdown guard \"filetransfer\" down");
    dcpregs_filetransfer_prepare_for_shutdown();
}

static int write_feed_conf_from_buffer_callback(const void *src, size_t count, int fd,
                                                const char *expected_content)
{
    cppcut_assert_equal(expected_os_write_fd, fd);
    cppcut_assert_not_null(src);
    cppcut_assert_operator(size_t(0), <, count);

    const size_t expected_content_size = strlen(expected_content);
    cut_assert_equal_memory(expected_content, expected_content_size,
                            src, count);

    return 0;
}

static void set_update_package_feed_configuration(bool have_regular_inifile,
                                                  bool have_override_inifile)
{
    static constexpr char old_release_name[] = "oldtest";
    static constexpr char old_url[] = "http://attic.ta-hifi.de/StrBo";
    static constexpr char updated_release_name[] = "testing";
    static constexpr char updated_url[] = "http://updates.ta-hifi.de/StrBo";
    static constexpr char override_release_name[] = "experimental";
    static constexpr char override_url[] = "http://files.ta-hifi.de/override/StrBo";

    /* send new update feed configuration: opkg feed configuration files are
     * deleted and new settings are written to configuration file (in this
     * particular order!) */
    static constexpr const char url[] = "http://updates.ta-hifi.de/StrBo testing";
    uint8_t url_buffer[8 + sizeof(url) - 1];

    memset(url_buffer, 0, 8);
    url_buffer[3] = HCR_FILE_TRANSFER_ENCRYPTION_NONE;
    memcpy(url_buffer + 8, url, sizeof(url) - 1);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Set package update URL \"http://updates.ta-hifi.de/StrBo\" for release \"testing\"");

    static constexpr const char config_file_format[] =
        "[global]\n"
        "release = %s\n"
        "url = %s\n"
        "method = src/gz\n"
        "[feed all]\n"
        "[feed arm1176jzfshf-vfp]\n"
        "[feed raspberrypi]\n";

    static char existing_config_file_buffer[1024];
    const size_t existing_config_file_length =
        snprintf(existing_config_file_buffer, sizeof(existing_config_file_buffer),
                 config_file_format, old_release_name, old_url);

    const struct os_mapped_file_data existing_config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = existing_config_file_buffer,
        .length = existing_config_file_length,
    };

    if(have_regular_inifile)
    {
        mock_os->expect_os_map_file_to_memory(&existing_config_file, feed_config_filename);
        mock_os->expect_os_unmap_file(&existing_config_file);
    }
    else
        mock_os->expect_os_map_file_to_memory(-1, false, feed_config_filename);

    std::vector<MockOs::ForeachItemData> items_before;
    items_before.emplace_back(MockOs::ForeachItemData("somedir", true));
    items_before.emplace_back(MockOs::ForeachItemData("hello.conf"));
    items_before.emplace_back(MockOs::ForeachItemData("all-feed.conf"));
    items_before.emplace_back(MockOs::ForeachItemData("arm1176jzfshf-vfp-feed.conf"));
    items_before.emplace_back(MockOs::ForeachItemData("raspberrypi-feed.conf"));
    items_before.emplace_back(MockOs::ForeachItemData("-feed.conf"));
    items_before.emplace_back(MockOs::ForeachItemData("extra-feed.conf"));
    items_before.emplace_back(MockOs::ForeachItemData("not-a-feed.conf "));
    items_before.emplace_back(MockOs::ForeachItemData("xyzfeed.conf"));
    items_before.emplace_back(MockOs::ForeachItemData(".conf"));

    std::vector<MockOs::ForeachItemData> items_after;
    items_after.emplace_back(MockOs::ForeachItemData("somedir", true));
    items_after.emplace_back(MockOs::ForeachItemData("hello.conf"));
    items_after.emplace_back(MockOs::ForeachItemData("-feed.conf"));
    items_after.emplace_back(MockOs::ForeachItemData("not-a-feed.conf "));
    items_after.emplace_back(MockOs::ForeachItemData("xyzfeed.conf"));
    items_after.emplace_back(MockOs::ForeachItemData(".conf"));

    static constexpr std::array<const char *, 3> expected_generated_feed_file_names =
    {
        "/etc/opkg/all-feed.conf",
        "/etc/opkg/arm1176jzfshf-vfp-feed.conf",
        "/etc/opkg/raspberrypi-feed.conf",
    };

    mock_os->expect_os_foreach_in_path(0, opkg_configuration_path, items_before);
    mock_os->expect_os_file_delete(expected_generated_feed_file_names[0]);
    mock_os->expect_os_file_delete(expected_generated_feed_file_names[1]);
    mock_os->expect_os_file_delete(expected_generated_feed_file_names[2]);
    mock_os->expect_os_file_delete("/etc/opkg/extra-feed.conf");
    mock_os->expect_os_sync_dir(opkg_configuration_path);

    mock_os->expect_os_file_new(expected_os_write_fd, feed_config_filename);
    for(unsigned int i = 0; i < (expected_generated_feed_file_names.size() + 1) * 3 + 3 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);
    mock_os->expect_os_sync_dir(feed_config_path);

    auto *reg = lookup_register_expect_handlers(209, dcpregs_write_209_download_url);

    cppcut_assert_equal(0, reg->write_handler(url_buffer, sizeof(url_buffer)));

    /* the data passed to the register is always written straight to the
     * regular configuration file (unless the content wasn't changed), the
     * override file does not interfere */
    static char expected_config_file_buffer[1024];
    const size_t expected_config_file_length =
        snprintf(expected_config_file_buffer, sizeof(expected_config_file_buffer),
                 config_file_format, updated_release_name, updated_url);

    cut_assert_equal_memory(expected_config_file_buffer, expected_config_file_length,
                            os_write_buffer.data(), os_write_buffer.size());

    os_write_buffer.clear();

    mock_messages->check();
    mock_os->check();


    /* probe opkg feed configuration files, then read update feed configuration
     * from our file, then generate opkg configuration files, then start the
     * update */
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                                    "Attempting to START SYSTEM UPDATE");

    mock_os->expect_os_foreach_in_path(0, opkg_configuration_path, items_after);

    const struct os_mapped_file_data modified_config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = expected_config_file_buffer,
        .length = expected_config_file_length,
    };

    static char override_config_file_buffer[1024];
    const size_t override_config_file_length =
        snprintf(override_config_file_buffer, sizeof(override_config_file_buffer),
                 config_file_format, override_release_name, override_url);

    const struct os_mapped_file_data override_config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = override_config_file_buffer,
        .length = override_config_file_length,
    };

    static constexpr decltype(expected_generated_feed_file_names) expected_generated_feed_file_formats =
    {
        "# Generated file, do not edit!\n"
        "src/gz %s-all %s/%s/all\n",
        "# Generated file, do not edit!\n"
        "src/gz %s-arm1176jzfshf-vfp %s/%s/arm1176jzfshf-vfp\n",
        "# Generated file, do not edit!\n"
        "src/gz %s-raspberrypi %s/%s/raspberrypi\n",
    };

    std::array<char[512], expected_generated_feed_file_formats.size()> expected_generated_feed_file_contents;

    const char *expected_release_name =
        have_override_inifile ? override_release_name : updated_release_name;
    const char *expected_url =
        have_override_inifile ? override_url : updated_url;

    for(size_t i = 0; i < expected_generated_feed_file_formats.size(); ++i)
        snprintf(expected_generated_feed_file_contents[i],
                 sizeof(expected_generated_feed_file_contents[i]),
                 expected_generated_feed_file_formats[i],
                 expected_release_name, expected_url, expected_release_name);

    if(have_override_inifile)
    {
        mock_os->expect_os_map_file_to_memory(&override_config_file,
                                              feed_config_override_filename);
        mock_os->expect_os_unmap_file(&override_config_file);
    }
    else
    {
        mock_os->expect_os_map_file_to_memory(-1, false, feed_config_override_filename);
        mock_os->expect_os_map_file_to_memory(&modified_config_file, feed_config_filename);
        mock_os->expect_os_unmap_file(&modified_config_file);
    }

    for(size_t i = 0; i < expected_generated_feed_file_names.size(); ++i)
    {
        mock_os->expect_os_file_new(expected_os_write_fd, expected_generated_feed_file_names[i]);
        mock_os->expect_os_write_from_buffer_callback(std::bind(write_feed_conf_from_buffer_callback,
                                                                std::placeholders::_1,
                                                                std::placeholders::_2,
                                                                std::placeholders::_3,
                                                                expected_generated_feed_file_contents[i]));
        mock_os->expect_os_file_close(expected_os_write_fd);
    }

    mock_os->expect_os_sync_dir(opkg_configuration_path);

    /* let's stop it at this point, we have tested what we wanted */
    mock_messages->expect_msg_info("Update in progress, not starting again");
    mock_os->expect_os_path_get_type(OS_PATH_TYPE_FILE, "/tmp/do_update.sh");

    reg = lookup_register_expect_handlers(40, dcpregs_write_40_download_control);

    static constexpr uint8_t hcr_command[] =
        { HCR_COMMAND_CATEGORY_UPDATE_FROM_INET, HCR_COMMAND_UPDATE_MAIN_SYSTEM };

    cppcut_assert_equal(-1, reg->write_handler(hcr_command, sizeof(hcr_command)));
}

/*!\test
 * Update existing package feed configuration with new data from regular
 * configuration file.
 */
void test_set_update_package_feed_configuration()
{
    set_update_package_feed_configuration(true, false);
}

/*!\test
 * Update existing package feed configuration with new data, override inifile
 * is in place, but regular configuration file is not.
 */
void test_set_update_package_feed_configuration_with_override()
{
    set_update_package_feed_configuration(false, true);
}

/*!\test
 * Update existing package feed configuration with new data, no configuration
 * files exist.
 *
 * This is be similar to #test_set_update_package_feed_configuration(), but the
 * default configuration file is generated.
 */
void test_set_update_package_feed_configuration_with_no_configs()
{
    set_update_package_feed_configuration(false, false);
}

/*!\test
 * Update existing package feed configuration with new data, both override and
 * regular inifiles are in place.
 *
 * The override inifile takes precedence over the regular file and over what
 * has been written there.
 */
void test_set_update_package_feed_configuration_with_regular_and_override()
{
    set_update_package_feed_configuration(true, true);
}

static void feed_configuration_file_is_created_on_system_update(bool have_override_inifile)
{
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                                    "Attempting to START SYSTEM UPDATE");

    mock_os->expect_os_foreach_in_path(0, opkg_configuration_path);

    static char override_config_file_buffer[] =
        "[global]\n"
        "release = alphaomega\n"
        "url = http://alpha.ta-hifi.de/omega\n"
        "method = src/gz\n"
        "[feed all]\n"
        "[feed arm1176jzfshf-vfp]\n"
        "[feed raspberrypi]\n";

    const struct os_mapped_file_data override_config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = override_config_file_buffer,
        .length = sizeof(override_config_file_buffer) - 1,
    };

    if(have_override_inifile)
    {
        mock_os->expect_os_map_file_to_memory(&override_config_file,
                                              feed_config_override_filename);
        mock_os->expect_os_unmap_file(&override_config_file);
    }
    else
    {
        mock_os->expect_os_map_file_to_memory(-1, false, feed_config_override_filename);
        mock_os->expect_os_map_file_to_memory(-1, false, feed_config_filename);
    }

    static constexpr std::array<const char *, 3> expected_generated_feed_file_names =
    {
        "/etc/opkg/all-feed.conf",
        "/etc/opkg/arm1176jzfshf-vfp-feed.conf",
        "/etc/opkg/raspberrypi-feed.conf",
    };

    static constexpr decltype(expected_generated_feed_file_names) expected_generated_feed_file_formats =
    {
        "# Generated file, do not edit!\n"
        "src/gz %s-all %s/%s/all\n",
        "# Generated file, do not edit!\n"
        "src/gz %s-arm1176jzfshf-vfp %s/%s/arm1176jzfshf-vfp\n",
        "# Generated file, do not edit!\n"
        "src/gz %s-raspberrypi %s/%s/raspberrypi\n",
    };

    std::array<char[512], expected_generated_feed_file_formats.size()> expected_generated_feed_file_contents;

    const char *expected_release_name = have_override_inifile
        ? "alphaomega"
        : "stable";
    const char *expected_url = have_override_inifile
        ? "http://alpha.ta-hifi.de/omega"
        : "http://www.ta-hifi.de/fileadmin/auto_download/StrBo";

    for(size_t i = 0; i < expected_generated_feed_file_formats.size(); ++i)
        snprintf(expected_generated_feed_file_contents[i],
                 sizeof(expected_generated_feed_file_contents[i]),
                 expected_generated_feed_file_formats[i],
                 expected_release_name, expected_url, expected_release_name);

    for(size_t i = 0; i < expected_generated_feed_file_names.size(); ++i)
    {
        mock_os->expect_os_file_new(expected_os_write_fd, expected_generated_feed_file_names[i]);
        mock_os->expect_os_write_from_buffer_callback(std::bind(write_feed_conf_from_buffer_callback,
                                                                std::placeholders::_1,
                                                                std::placeholders::_2,
                                                                std::placeholders::_3,
                                                                expected_generated_feed_file_contents[i]));
        mock_os->expect_os_file_close(expected_os_write_fd);
    }

    mock_os->expect_os_sync_dir(opkg_configuration_path);

    /* let's stop it at this point, we have tested what we wanted */
    mock_messages->expect_msg_info("Update in progress, not starting again");
    mock_os->expect_os_path_get_type(OS_PATH_TYPE_FILE, "/tmp/do_update.sh");

    auto *reg = lookup_register_expect_handlers(40, dcpregs_write_40_download_control);

    static constexpr uint8_t hcr_command[] =
        { HCR_COMMAND_CATEGORY_UPDATE_FROM_INET, HCR_COMMAND_UPDATE_MAIN_SYSTEM };

    cppcut_assert_equal(-1, reg->write_handler(hcr_command, sizeof(hcr_command)));
}

/*!\test
 * System update is possible even if neither our configuration file nor the
 * opkg feed configuraton files exist.
 *
 * In case our configuraton file does not exist yet when the system update
 * command comes in, a default file is generated in RAM. This is used to
 * generate the opkg feed configuration files so that the update request may
 * proceed.
 */
void test_feed_configuration_file_is_created_on_system_update_if_does_not_exist()
{
    feed_configuration_file_is_created_on_system_update(false);
}

/*!\test
 * System update is possible of only the override file exists, in which case
 * its values are used.
 */
void test_feed_configuration_file_is_not_created_if_override_file_exists()
{
    feed_configuration_file_is_created_on_system_update(true);
}

/*!\test
 * Setting feed configuration suceeds if there is no configuration file yet.
 *
 * In the configuration file does not exist, a default file is generated in
 * RAM. This file is then updated according to the command and written to a
 * real file.
 */
void test_feed_configuration_file_is_created_on_config_if_does_not_exist()
{
    /* send new update feed configuration: opkg feed configuration files are
     * deleted and new settings are written to configuration file (in this
     * particular order!) */
    static constexpr const char url[] = "http://dev.tua.local/Test experimental";
    uint8_t url_buffer[8 + sizeof(url) - 1];

    memset(url_buffer, 0, 8);
    url_buffer[3] = HCR_FILE_TRANSFER_ENCRYPTION_NONE;
    memcpy(url_buffer + 8, url, sizeof(url) - 1);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Set package update URL \"http://dev.tua.local/Test\" for release \"experimental\"");

    mock_os->expect_os_map_file_to_memory(-1, false, feed_config_filename);
    mock_os->expect_os_foreach_in_path(0, opkg_configuration_path);
    mock_os->expect_os_file_new(expected_os_write_fd, feed_config_filename);
    for(unsigned int i = 0; i < 4 * 3 + 3 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);
    mock_os->expect_os_sync_dir(feed_config_path);

    auto *reg = lookup_register_expect_handlers(209, dcpregs_write_209_download_url);

    cppcut_assert_equal(0, reg->write_handler(url_buffer, sizeof(url_buffer)));

    static char expected_config_file[] =
        "[global]\n"
        "release = experimental\n"
        "url = http://dev.tua.local/Test\n"
        "method = src/gz\n"
        "[feed all]\n"
        "[feed arm1176jzfshf-vfp]\n"
        "[feed raspberrypi]\n";

    cut_assert_equal_memory(expected_config_file, sizeof(expected_config_file) - 1,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Any zero byte tacked to the end of the input gets ignored.
 */
void test_feed_configurations_with_trailing_zero_bytes_are_accepted()
{
    static constexpr const char url[] = "http://dev.tua.local/foo bar\0\0\0";
    uint8_t url_buffer[8 + sizeof(url) - 1];

    memset(url_buffer, 0, 8);
    url_buffer[3] = HCR_FILE_TRANSFER_ENCRYPTION_NONE;
    memcpy(url_buffer + 8, url, sizeof(url) - 1);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_IMPORTANT,
        "Set package update URL \"http://dev.tua.local/foo\" for release \"bar\"");

    mock_os->expect_os_map_file_to_memory(-1, false, feed_config_filename);
    mock_os->expect_os_foreach_in_path(0, opkg_configuration_path);
    mock_os->expect_os_file_new(expected_os_write_fd, feed_config_filename);
    for(unsigned int i = 0; i < 4 * 3 + 3 * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);
    mock_os->expect_os_sync_dir(feed_config_path);

    auto *reg = lookup_register_expect_handlers(209, dcpregs_write_209_download_url);

    cppcut_assert_equal(0, reg->write_handler(url_buffer, sizeof(url_buffer)));

    static char expected_config_file[] =
        "[global]\n"
        "release = bar\n"
        "url = http://dev.tua.local/foo\n"
        "method = src/gz\n"
        "[feed all]\n"
        "[feed arm1176jzfshf-vfp]\n"
        "[feed raspberrypi]\n";

    cut_assert_equal_memory(expected_config_file, sizeof(expected_config_file) - 1,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * In case the configuration is does not differ from what is already stored on
 * configuration file, the file is neither rewritten nor are the opkg files
 * deleted.
 */
void test_feed_configuration_file_remains_unchanged_if_passed_config_is_same()
{
    static constexpr const char url[] = "http://did.not.change/in/any way";
    uint8_t url_buffer[8 + sizeof(url) - 1];

    memset(url_buffer, 0, 8);
    url_buffer[3] = HCR_FILE_TRANSFER_ENCRYPTION_NONE;
    memcpy(url_buffer + 8, url, sizeof(url) - 1);

    static char config_file_buffer[] =
        "[global]\n"
        "release = way\n"
        "url = http://did.not.change/in/any\n"
        "method = src/gz\n"
        "[feed all]\n"
        "[feed arm1176jzfshf-vfp]\n"
        "[feed raspberrypi]\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    mock_os->expect_os_map_file_to_memory(&config_file, feed_config_filename);
    mock_os->expect_os_unmap_file(&config_file);

    auto *reg = lookup_register_expect_handlers(209, dcpregs_write_209_download_url);

    cppcut_assert_equal(0, reg->write_handler(url_buffer, sizeof(url_buffer)));
}

/*!\test
 * For forward compatibility, multiple space-separated fields are accepted, but
 * only the first two of them are actually used.
 *
 * In this test, the configuration is not expected to be updated because the
 * first two fields are no different from what's already stored on file.
 */
void test_feed_configuration_with_more_than_two_fields_is_accepted()
{
    static constexpr const char url[] = "http://www.ta-hifi.de/StrBo testing beta";
    uint8_t url_buffer[8 + sizeof(url) - 1];

    memset(url_buffer, 0, 8);
    url_buffer[3] = HCR_FILE_TRANSFER_ENCRYPTION_NONE;
    memcpy(url_buffer + 8, url, sizeof(url) - 1);

    static char config_file_buffer[] =
        "[global]\n"
        "release = testing\n"
        "url = http://www.ta-hifi.de/StrBo\n"
        "method = src/gz\n"
        "[feed all]\n"
        "[feed arm1176jzfshf-vfp]\n"
        "[feed raspberrypi]\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    mock_os->expect_os_map_file_to_memory(&config_file, feed_config_filename);
    mock_os->expect_os_unmap_file(&config_file);

    auto *reg = lookup_register_expect_handlers(209, dcpregs_write_209_download_url);

    cppcut_assert_equal(0, reg->write_handler(url_buffer, sizeof(url_buffer)));
}

};

namespace spi_registers_play_app_stream
{

static MockMessages *mock_messages;
static MockStreamplayerDBus *mock_streamplayer_dbus;
static MockArtCacheDBus *mock_artcache_dbus;
static MockDcpdDBus *mock_dcpd_dbus;
static MockDBusIface *mock_dbus_iface;

static tdbussplayURLFIFO *const dbus_streamplayer_urlfifo_iface_dummy =
    reinterpret_cast<tdbussplayURLFIFO *>(0xd71b32aa);

static tdbussplayPlayback *const dbus_streamplayer_playback_iface_dummy =
    reinterpret_cast<tdbussplayPlayback *>(0xc9a018b0);

static tdbusdcpdPlayback *const dbus_dcpd_playback_iface_dummy =
    reinterpret_cast<tdbusdcpdPlayback *>(0x1337affe);

static tdbusdcpdViews *const dbus_dcpd_views_iface_dummy =
    reinterpret_cast<tdbusdcpdViews *>(0x87654321);

static tdbusartcacheRead *const dbus_artcache_read_iface_dummy =
    reinterpret_cast<tdbusartcacheRead *>(0x3bcb891a);

using OurStream = ::ID::SourcedStream<STREAM_ID_SOURCE_APP>;

static RegisterChangedData *register_changed_data;

const static MD5::Hash skey_dummy{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                   0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, };

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

    mock_streamplayer_dbus = new MockStreamplayerDBus;
    cppcut_assert_not_null(mock_streamplayer_dbus);
    mock_streamplayer_dbus->init();
    mock_streamplayer_dbus_singleton = mock_streamplayer_dbus;

    mock_artcache_dbus = new MockArtCacheDBus();
    cppcut_assert_not_null(mock_artcache_dbus);
    mock_artcache_dbus->init();
    mock_artcache_dbus_singleton = mock_artcache_dbus;

    mock_dcpd_dbus = new MockDcpdDBus();
    cppcut_assert_not_null(mock_dcpd_dbus);
    mock_dcpd_dbus->init();
    mock_dcpd_dbus_singleton = mock_dcpd_dbus;

    mock_dbus_iface = new MockDBusIface;
    cppcut_assert_not_null(mock_dbus_iface);
    mock_dbus_iface->init();
    mock_dbus_iface_singleton = mock_dbus_iface;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    register_changed_data->init();

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    network_prefs_init(NULL, NULL, NULL, NULL);
    register_init(register_changed_callback);
}

void cut_teardown()
{
    register_deinit();
    network_prefs_deinit();

    register_changed_data->check();

    delete register_changed_data;
    register_changed_data = nullptr;

    mock_messages->check();
    mock_streamplayer_dbus->check();
    mock_artcache_dbus->check();
    mock_dcpd_dbus->check();
    mock_dbus_iface->check();

    mock_messages_singleton = nullptr;
    mock_streamplayer_dbus_singleton = nullptr;
    mock_artcache_dbus_singleton = nullptr;
    mock_dcpd_dbus_singleton = nullptr;
    mock_dbus_iface_singleton = nullptr;

    delete mock_messages;
    delete mock_streamplayer_dbus;
    delete mock_artcache_dbus;
    delete mock_dcpd_dbus;
    delete mock_dbus_iface;

    mock_messages = nullptr;
    mock_streamplayer_dbus = nullptr;
    mock_artcache_dbus = nullptr;
    mock_dcpd_dbus = nullptr;
    mock_dbus_iface = nullptr;
}

static void set_start_title(const uint8_t *title, size_t length)
{
    const auto *const reg = register_lookup(78);

    cppcut_assert_equal(0, reg->write_handler(title, length));
}

static void set_start_title(const std::string title)
{
    const auto *const reg = register_lookup(78);

    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(title.c_str())), title.length()));
}

static void set_next_title(const std::string title)
{
    const auto *const reg = register_lookup(238);

    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(title.c_str())), title.length()));
}

static GVariantWrapper hash_to_variant(const MD5::Hash &hash)
{
    return GVariantWrapper(g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE,
                                                     hash.data(), hash.size(),
                                                     sizeof(hash[0])));
}

static void set_start_url(const std::string expected_artist,
                          const std::string expected_album,
                          const std::string expected_title,
                          const std::string expected_alttrack,
                          const std::string url,
                          const OurStream stream_id, bool assume_already_playing,
                          GVariantWrapper *expected_stream_key)
{
    MD5::Context ctx;
    MD5::init(ctx);
    MD5::update(ctx, reinterpret_cast<const uint8_t *>(url.c_str()), url.length());
    MD5::Hash hash;
    MD5::finish(ctx, hash);

    if(expected_stream_key != nullptr)
        *expected_stream_key = std::move(hash_to_variant(hash));

    const auto *const reg = register_lookup(79);

    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_stream_info(
            dbus_dcpd_playback_iface_dummy, stream_id.get().get_raw_id(),
            expected_artist.c_str(), expected_album.c_str(),
            expected_title.c_str(), expected_alttrack.c_str(),
            url.c_str());
    mock_dbus_iface->expect_dbus_get_streamplayer_urlfifo_iface(dbus_streamplayer_urlfifo_iface_dummy);
    mock_streamplayer_dbus->expect_tdbus_splay_urlfifo_call_push_sync(
        TRUE, dbus_streamplayer_urlfifo_iface_dummy,
        stream_id.get().get_raw_id(), url.c_str(), hash,
        0, "ms", 0, "ms", -2, FALSE, assume_already_playing);

    if(!assume_already_playing)
    {
        mock_dbus_iface->expect_dbus_get_streamplayer_playback_iface(dbus_streamplayer_playback_iface_dummy);
        mock_streamplayer_dbus->expect_tdbus_splay_playback_call_start_sync(TRUE, dbus_streamplayer_playback_iface_dummy);
    }

    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_open(dbus_dcpd_views_iface_dummy, "Play");

    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(url.c_str())), url.length()));

    uint8_t buffer[8];
    cppcut_assert_equal(ssize_t(0), reg->read_handler(buffer, sizeof(buffer)));
}

static void set_start_meta_data_and_url(const std::string meta_data,
                                        const std::string url,
                                        const std::string expected_artist,
                                        const std::string expected_album,
                                        const std::string expected_title,
                                        const OurStream stream_id,
                                        bool assume_already_playing,
                                        GVariantWrapper *expected_stream_key)
{
    set_start_title(meta_data);
    set_start_url(expected_artist, expected_album, expected_title, meta_data,
                  url, stream_id, assume_already_playing, expected_stream_key);
}

static void set_start_meta_data_and_url(const uint8_t *meta_data, size_t meta_data_length,
                                        const std::string url,
                                        const std::string expected_artist,
                                        const std::string expected_album,
                                        const std::string expected_title,
                                        const OurStream stream_id,
                                        bool assume_already_playing,
                                        GVariantWrapper *expected_stream_key)
{
    set_start_title(meta_data, meta_data_length);
    set_start_url(expected_artist, expected_album, expected_title,
                  std::string(static_cast<const char *>(static_cast<const void *>(meta_data)),
                              meta_data_length),
                  url, stream_id, assume_already_playing, expected_stream_key);
}

static void set_start_title_and_url(const std::string title, const std::string url,
                                    const OurStream stream_id,
                                    bool assume_already_playing,
                                    GVariantWrapper *expected_stream_key)
{
    set_start_title(title);
    set_start_url("", "", title, title, url,
                  stream_id, assume_already_playing, expected_stream_key);
}

static void set_next_url(const std::string title, const std::string url,
                         const OurStream stream_id,
                         bool assume_is_app_mode, bool assume_already_playing,
                         GVariantWrapper *expected_stream_key)
{
    const auto *const reg = register_lookup(239);

    if(assume_is_app_mode)
    {
        MD5::Context ctx;
        MD5::init(ctx);
        MD5::update(ctx, reinterpret_cast<const uint8_t *>(url.c_str()), url.length());
        MD5::Hash hash;
        MD5::finish(ctx, hash);

        if(expected_stream_key != nullptr)
            *expected_stream_key = std::move(hash_to_variant(hash));

        mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
        mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_stream_info(
            dbus_dcpd_playback_iface_dummy, stream_id.get().get_raw_id(),
            "", "", title.c_str(), title.c_str(), url.c_str());
        mock_dbus_iface->expect_dbus_get_streamplayer_urlfifo_iface(dbus_streamplayer_urlfifo_iface_dummy);
        mock_streamplayer_dbus->expect_tdbus_splay_urlfifo_call_push_sync(
            TRUE, dbus_streamplayer_urlfifo_iface_dummy,
            stream_id.get().get_raw_id(), url.c_str(), hash,
            0, "ms", 0, "ms", 0, FALSE, assume_already_playing);
    }
    else
    {
        mock_messages->expect_msg_error(0, LOG_ERR, "Can't queue next stream, didn't receive a start stream");

        if(expected_stream_key != nullptr)
            expected_stream_key->release();
    }

    cppcut_assert_equal(0, reg->write_handler(static_cast<const uint8_t *>(static_cast<const void *>(url.c_str())), url.length()));
}

static void set_next_title_and_url(const std::string title, const std::string url,
                                   const OurStream stream_id,
                                   bool assume_is_app_mode, bool assume_already_playing,
                                   GVariantWrapper *expected_stream_key)
{
    set_next_title(title);
    set_next_url(title, url, stream_id, assume_is_app_mode, assume_already_playing, expected_stream_key);
}

static void expect_current_title(const std::string &expected_title)
{
    const auto *const reg = register_lookup(75);

    char buffer[150];
    const ssize_t len = reg->read_handler((uint8_t *)buffer, sizeof(buffer));
    cppcut_assert_operator(ssize_t(sizeof(buffer)), >, len);
    buffer[len] = '\0';

    cppcut_assert_equal(expected_title.c_str(), buffer);
}

static void expect_current_url(const std::string &expected_url)
{
    const auto *const reg = register_lookup(76);

    char buffer[600];
    const ssize_t len = reg->read_handler((uint8_t *)buffer, sizeof(buffer));
    cppcut_assert_operator(ssize_t(sizeof(buffer)), >, len);
    buffer[len] = '\0';

    cppcut_assert_equal(expected_url.c_str(), buffer);
}

static void expect_current_title_and_url(const std::string &expected_title,
                                         const std::string &expected_url)
{
    expect_current_title(expected_title);
    expect_current_url(expected_url);
}

static void expect_next_url_empty()
{
    const auto *const reg = register_lookup(239);

    uint8_t buffer[16];
    memset(buffer, UINT8_MAX, sizeof(buffer));
    const ssize_t len = reg->read_handler((uint8_t *)buffer, sizeof(buffer));
    cppcut_assert_equal(ssize_t(0), len);

    uint8_t expected_url[sizeof(buffer)];
    memset(expected_url, UINT8_MAX, sizeof(expected_url));
    cut_assert_equal_memory(expected_url, sizeof(expected_url),
                            buffer, sizeof(buffer));
}

static GVariantWrapper empty_array_variant()
{
    GVariantBuilder builder;
    g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));

    return GVariantWrapper(g_variant_builder_end(&builder));
}

static void expect_cover_art_notification(GVariantWrapper stream_key,
                                          GVariantWrapper known_hash,
                                          const std::vector<uint8_t> &image_data,
                                          GVariantWrapper *image_hash = nullptr,
                                          bool is_not_in_cache_if_empty = false)
{
    GVariantWrapper image_hash_variant;
    GVariantWrapper image_data_variant;
    ArtCache::ReadError::Code read_error_code;

    if(image_data.empty())
    {
        image_hash_variant = std::move(empty_array_variant());
        image_data_variant = std::move(empty_array_variant());

        if(is_not_in_cache_if_empty)
        {
            read_error_code = ArtCache::ReadError::KEY_UNKNOWN;
            mock_messages->expect_msg_info("Cover art for current stream not in cache");
        }
        else
        {
            read_error_code = ArtCache::ReadError::OK;
            mock_messages->expect_msg_info("Cover art for current stream has not changed");
        }
    }
    else
    {
        MD5::Context ctx;
        MD5::init(ctx);
        MD5::update(ctx, image_data.data(), image_data.size());
        MD5::Hash hash;
        MD5::finish(ctx, hash);

        image_hash_variant = std::move(hash_to_variant(hash));
        image_data_variant =
            GVariantWrapper(g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE,
                                                      image_data.data(), image_data.size(),
                                                      sizeof(image_data[0])));

        read_error_code = ArtCache::ReadError::UNCACHED;
        mock_messages->expect_msg_info("Taking new cover art for current stream from cache");
    }

    if(stream_key == nullptr)
        stream_key = std::move(hash_to_variant(skey_dummy));

    if(known_hash == nullptr)
        known_hash = std::move(empty_array_variant());

    if(image_hash != nullptr)
        *image_hash = image_hash_variant;

    mock_dbus_iface->expect_dbus_get_artcache_read_iface(dbus_artcache_read_iface_dummy);
    mock_artcache_dbus->expect_tdbus_artcache_read_call_get_scaled_image_data_sync(
        true, dbus_artcache_read_iface_dummy,
        std::move(stream_key), "png@120x120",
        std::move(known_hash), read_error_code, 42,
        std::move(image_hash_variant),
        std::move(image_data_variant));
}

static void expect_empty_cover_art_notification(GVariantWrapper &stream_key)
{
    if(stream_key == nullptr)
        stream_key = std::move(hash_to_variant(skey_dummy));

    static const std::vector<uint8_t> empty;

    expect_cover_art_notification(stream_key, GVariantWrapper(), empty);
}

static void send_title_and_url(const ID::Stream stream_id,
                               const char *expected_title,
                               const char *expected_url,
                               bool expecting_direct_slave_notification)
{
    if(expected_title == NULL)
        expected_title = "";

    if(expected_url == NULL)
        expected_url = "";

    char buffer[512];
    snprintf(buffer, sizeof(buffer),
             "Received explicit title and URL information for stream %u",
             stream_id.get_raw_id());

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG, buffer);

    if(expecting_direct_slave_notification)
        mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");

    dcpregs_playstream_set_title_and_url(stream_id.get_raw_id(),
                                         expected_title, expected_url);
}

static void stop_stream()
{
    const auto *const reg = register_lookup(79);

    mock_dbus_iface->expect_dbus_get_streamplayer_playback_iface(dbus_streamplayer_playback_iface_dummy);
    mock_streamplayer_dbus->expect_tdbus_splay_playback_call_stop_sync(TRUE, dbus_streamplayer_playback_iface_dummy);

    static const uint8_t zero = 0;
    cppcut_assert_equal(0, reg->write_handler(&zero, sizeof(zero)));
}

/*!\test
 * App starts single stream with plain title information.
 */
void test_start_stream()
{
    set_start_title_and_url("Test stream", "http://app-provided.url.org/stream.flac",
                            OurStream::make(), false, nullptr);

    expect_current_title_and_url("", "");
}

/*!\test
 * App starts single stream with structured meta data information.
 */
void test_start_stream_with_meta_data()
{
    set_start_meta_data_and_url("The title\x1d""By some artist\x1dOn that album",
                                "http://app-provided.url.org/stream.aac",
                                "By some artist", "On that album", "The title",
                                OurStream::make(), false, nullptr);

    expect_current_title_and_url("", "");
}

/*!\test
 * App starts single stream with structured meta data information.
 */
void test_start_stream_with_unterminated_meta_data()
{
    static const uint8_t evil[] = { 'T', 'i', 't', 'l', 'e', 0x1d, };

    set_start_meta_data_and_url(evil, sizeof(evil),
                                "http://app-provided.url.org/stream.aac",
                                "", "", "Title",
                                OurStream::make(), false, nullptr);

    expect_current_title_and_url("", "");
}

/*!\test
 * App starts single stream with partial structured meta data information.
 */
void test_start_stream_with_partial_meta_data()
{
    set_start_meta_data_and_url("The title\x1d""By some artist on that album",
                                "http://app-provided.url.org/stream.aac",
                                "By some artist on that album", "", "The title",
                                OurStream::make(), false, nullptr);

    expect_current_title_and_url("", "");
}

/*!\test
 * App starts single stream with too many meta data information.
 */
void test_start_stream_with_too_many_meta_data()
{
    set_start_meta_data_and_url("The title\x1d""By some artist\x1dOn that album\x1dThat I like",
                                "http://app-provided.url.org/stream.aac",
                                "By some artist", "On that album", "The title",
                                OurStream::make(), false, nullptr);

    expect_current_title_and_url("", "");
}

/*!\test
 * App starts single stream with too many meta data information.
 */
void test_start_stream_with_way_too_many_meta_data()
{
    set_start_meta_data_and_url("The title\x1d""By some artist\x1dOn that album\x1dThat\x1dI\x1dlike",
                                "http://app-provided.url.org/stream.aac",
                                "By some artist", "On that album", "The title",
                                OurStream::make(), false, nullptr);

    expect_current_title_and_url("", "");
}

/*!\test
 * App starts single stream with title, but no other information
 */
void test_start_stream_with_title_name()
{
    set_start_meta_data_and_url("The Title\x1d\x1d",
                                "http://app-provided.url.org/stream.aac",
                                "", "", "The Title",
                                OurStream::make(), false, nullptr);

    expect_current_title_and_url("", "");
}

/*!\test
 * App starts single stream with artist, but no other information
 */
void test_start_stream_with_artist_name()
{
    set_start_meta_data_and_url("\x1dThe Artist\x1d",
                                "http://app-provided.url.org/stream.aac",
                                "The Artist", "", "",
                                OurStream::make(), false, nullptr);

    expect_current_title_and_url("", "");
}

/*!\test
 * App starts single stream with album, but no other information
 */
void test_start_stream_with_album_name()
{
    set_start_meta_data_and_url("\x1d\x1dThe Album",
                                "http://app-provided.url.org/stream.aac",
                                "", "The Album", "",
                                OurStream::make(), false, nullptr);

    expect_current_title_and_url("", "");
}

/*!\test
 * App starts single stream, then skips to another stream.
 */
void test_start_stream_then_start_another_stream()
{
    const std::vector<uint8_t> cached_image_first{0x30, 0x31, 0x32, 0x33, };
    const std::vector<uint8_t> cached_image_second{0x40, 0x41, 0x42, 0x43, 0x44, 0x46, };

    auto next_stream_id(OurStream::make());

    const auto stream_id_first(next_stream_id);
    GVariantWrapper skey_first;
    set_start_title_and_url("First", "http://app-provided.url.org/first.flac",
                            stream_id_first, false, &skey_first);
    register_changed_data->check();

    mock_messages->expect_msg_info_formatted("Enter app mode: started stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    GVariantWrapper hash_first;
    expect_cover_art_notification(skey_first, GVariantWrapper(), cached_image_first, &hash_first);
    dcpregs_playstream_start_notification(stream_id_first.get().get_raw_id(),
                                          GVariantWrapper::move(skey_first));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("First", "http://app-provided.url.org/first.flac");

    const auto stream_id_second(++next_stream_id);
    GVariantWrapper skey_second;
    set_start_title_and_url("Second", "http://app-provided.url.org/second.flac",
                            stream_id_second, true, &skey_second);
    register_changed_data->check();
    expect_current_title_and_url("First", "http://app-provided.url.org/first.flac");

    mock_messages->expect_msg_info_formatted("Next app stream 258");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_cover_art_notification(skey_second, hash_first, cached_image_second);
    dcpregs_playstream_start_notification(stream_id_second.get().get_raw_id(),
                                          GVariantWrapper::move(skey_second));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("Second", "http://app-provided.url.org/second.flac");
}

/*!\test
 * App starts single stream, then quickly skips to another stream.
 */
void test_start_stream_then_quickly_start_another_stream()
{
    auto next_stream_id(OurStream::make());

    const auto stream_id_first(next_stream_id);
    GVariantWrapper skey_first;
    set_start_title_and_url("First", "http://app-provided.url.org/first.flac",
                            stream_id_first, false, &skey_first);
    register_changed_data->check();

    const auto stream_id_second(++next_stream_id);
    GVariantWrapper skey_second;
    set_start_title_and_url("Second", "http://app-provided.url.org/second.flac",
                            stream_id_second, false, &skey_second);
    register_changed_data->check();
    expect_current_title_and_url("", "");

    mock_messages->expect_msg_error_formatted(0, LOG_NOTICE,
                                              "Got start notification for unknown app stream ID 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_first);
    dcpregs_playstream_start_notification(stream_id_first.get().get_raw_id(),
                                          GVariantWrapper::move(skey_first));
    register_changed_data->check(std::array<uint8_t, 3>{75, 76, 210});
    mock_messages->check();
    expect_current_title_and_url("First", "http://app-provided.url.org/first.flac");

    mock_messages->expect_msg_info_formatted("Enter app mode: started stream 258");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_second);
    dcpregs_playstream_start_notification(stream_id_second.get().get_raw_id(),
                                          GVariantWrapper::move(skey_second));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("Second", "http://app-provided.url.org/second.flac");
}

/*!\test
 * App starts stream while another source is playing.
 */
void test_app_can_start_stream_while_other_source_is_playing()
{
    GVariantWrapper dummy_stream_key;
    expect_empty_cover_art_notification(dummy_stream_key);
    dcpregs_playstream_start_notification(ID::Stream::make_for_source(STREAM_ID_SOURCE_UI).get_raw_id(),
                                          GVariantWrapper::move(dummy_stream_key));
    register_changed_data->check({210});
    expect_current_title_and_url("", "");

    const auto stream_id(OurStream::make());
    GVariantWrapper skey;
    set_start_title_and_url("Stream", "http://app-provided.url.org/stream.flac",
                            stream_id, true, &skey);
    register_changed_data->check();

    mock_messages->expect_msg_info_formatted("Switch to app mode: continue with stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey);
    dcpregs_playstream_start_notification(stream_id.get().get_raw_id(),
                                          GVariantWrapper::move(skey));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("Stream", "http://app-provided.url.org/stream.flac");
}

/*!\test
 * App mode ends when a non-app source such as the remote control starts
 * playing.
 *
 * UI sends title and URL after start notification in this test case. This
 * leads to a short glitch which could only be avoided by keeping outdated
 * information in registers 75/76. We chose not to.
 */
void test_app_mode_ends_when_another_source_starts_playing_info_after_start()
{
    const auto stream_id(OurStream::make());
    GVariantWrapper skey;
    set_start_title_and_url("Stream", "http://app-provided.url.org/stream.flac",
                            stream_id, false, &skey);
    register_changed_data->check();

    mock_messages->expect_msg_info_formatted("Enter app mode: started stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey);
    dcpregs_playstream_start_notification(stream_id.get().get_raw_id(),
                                          GVariantWrapper::move(skey));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("Stream", "http://app-provided.url.org/stream.flac");

    /* NOTE: In real life, there should have been a stop notification before
     *       this start notification, so this test stretches beyond spec; hence
     *       the harsh log message. */
    mock_messages->expect_msg_error_formatted(0, LOG_NOTICE,
        "Leave app mode: unexpected start of non-app stream 129 (expected next 0 or new 257)");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    const auto ui_stream_id(ID::Stream::make_for_source(STREAM_ID_SOURCE_UI));
    GVariantWrapper dummy_stream_key;
    expect_empty_cover_art_notification(dummy_stream_key);
    dcpregs_playstream_start_notification(ui_stream_id.get_raw_id(),
                                          GVariantWrapper::move(dummy_stream_key));
    register_changed_data->check(std::array<uint8_t, 4>{79, 75, 76, 210});
    expect_current_title_and_url("", "");

    send_title_and_url(ui_stream_id, "UI stream", "http://ui-provided.url.org/loud.flac", true);
    register_changed_data->check(std::array<uint8_t, 2>{75, 76});
    expect_current_title_and_url("UI stream", "http://ui-provided.url.org/loud.flac");
}

/*!\test
 * App mode ends when a non-app source such as the remote control starts
 * playing.
 *
 * UI sends title and URL before start notification in this test case.
 */
void test_app_mode_ends_when_another_source_starts_playing_start_after_info()
{
    const auto stream_id(OurStream::make());
    GVariantWrapper skey;
    set_start_title_and_url("Stream", "http://app-provided.url.org/stream.flac",
                            stream_id, false, &skey);
    register_changed_data->check();

    mock_messages->expect_msg_info_formatted("Enter app mode: started stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey);
    dcpregs_playstream_start_notification(stream_id.get().get_raw_id(),
                                          GVariantWrapper::move(skey));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("Stream", "http://app-provided.url.org/stream.flac");

    const auto ui_stream_id(ID::Stream::make_for_source(STREAM_ID_SOURCE_UI));

    send_title_and_url(ui_stream_id, "UI stream", "http://ui-provided.url.org/loud.flac", false);
    register_changed_data->check();

    /* NOTE: In real life, there should have been a stop notification before
     *       this start notification, so this test stretches beyond spec; hence
     *       the harsh log message. */
    mock_messages->expect_msg_error_formatted(0, LOG_NOTICE,
        "Leave app mode: unexpected start of non-app stream 129 (expected next 0 or new 257)");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    GVariantWrapper dummy_stream_key;
    expect_empty_cover_art_notification(dummy_stream_key);
    dcpregs_playstream_start_notification(ui_stream_id.get_raw_id(),
                                          GVariantWrapper::move(dummy_stream_key));
    register_changed_data->check(std::array<uint8_t, 4>{79, 75, 76, 210});
    expect_current_title_and_url("UI stream", "http://ui-provided.url.org/loud.flac");
}

static void start_stop_single_stream(bool with_notifications)
{
    const auto stream_id(OurStream::make());
    GVariantWrapper skey;
    set_start_title_and_url("Stream", "http://app-provided.url.org/stream.flac",
                            stream_id, false, &skey);
    register_changed_data->check();
    mock_messages->check();

    if(with_notifications)
    {
        mock_messages->expect_msg_info_formatted("Enter app mode: started stream 257");
        mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
        expect_empty_cover_art_notification(skey);
        dcpregs_playstream_start_notification(stream_id.get().get_raw_id(),
                                              GVariantWrapper::move(skey));
        register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
        mock_messages->check();
        expect_next_url_empty();
        expect_current_title_and_url("Stream", "http://app-provided.url.org/stream.flac");
    }

    stop_stream();
    mock_messages->check();

    if(with_notifications)
    {
        mock_messages->expect_msg_info("Leave app mode: streamplayer has stopped");
        mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
        dcpregs_playstream_stop_notification();
        register_changed_data->check(std::array<uint8_t, 3>{79, 75, 76});
        mock_messages->check();
        expect_current_title_and_url("", "");
    }
}

/*!\test
 * App starts single stream and stops it again.
 */
void test_start_stop_single_stream()
{
    start_stop_single_stream(true);
}

/*!\test
 * App starts single stream and stops it again very quickly.
 *
 * In case the app manages to send start and stop commands before the stream
 * player can react to them, the late stream player reactions are still
 * forwarded.
 */
void test_quick_start_stop_single_stream()
{
    start_stop_single_stream(false);

    /* late D-Bus signals are ignored */
    mock_messages->expect_msg_error_formatted(0, LOG_NOTICE,
                                              "Unexpected start of app stream 257");
    register_changed_data->check();

    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    GVariantWrapper dummy_stream_key;
    expect_empty_cover_art_notification(dummy_stream_key);
    dcpregs_playstream_start_notification(STREAM_ID_SOURCE_APP | STREAM_ID_COOKIE_MIN,
                                          GVariantWrapper::move(dummy_stream_key));
    register_changed_data->check(std::array<uint8_t, 3>{75, 76, 210});
    expect_current_title_and_url("Stream", "http://app-provided.url.org/stream.flac");

    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    dcpregs_playstream_stop_notification();
    register_changed_data->check(std::array<uint8_t, 2>{75, 76});
    expect_current_title_and_url("", "");
}

/*!\test
 * If new title and URL information are received, but only title is different,
 * then only the title is forwarded to SPI slave.
 *
 * Doesn't work for app streams (attempts to set stream information are
 * filtered out and result in a bug message).
 */
void test_url_is_not_sent_to_spi_slave_if_unchanged()
{
    static constexpr char url[] = "http://my.url.org/stream.m3u";
    const auto stream_id(ID::Stream::make_for_source(STREAM_ID_SOURCE_UI));

    GVariantWrapper dummy_stream_key;
    expect_empty_cover_art_notification(dummy_stream_key);
    dcpregs_playstream_start_notification(stream_id.get_raw_id(),
                                          GVariantWrapper::move(dummy_stream_key));

    register_changed_data->check({210});
    mock_messages->check();
    expect_current_title_and_url("", "");

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
             "Received explicit title and URL information for stream 129");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");

    dcpregs_playstream_set_title_and_url(stream_id.get_raw_id(), "My stream", url);

    register_changed_data->check(std::array<uint8_t, 2>{75, 76});
    mock_messages->check();
    expect_current_title_and_url("My stream", url);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
             "Received explicit title and URL information for stream 129");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send only new title to SPI slave");

    dcpregs_playstream_set_title_and_url(stream_id.get_raw_id(), "Other title", url);

    register_changed_data->check(75);
    expect_current_title_and_url("Other title", url);
}

/*!\test
 * Repetitively received same title and URL are forwarded to SPI slave only
 * once.
 *
 * Doesn't work for app streams (attempts to set stream information are
 * filtered out and result in a bug message).
 */
void test_nothing_is_sent_to_spi_slave_if_title_and_url_unchanged()
{
    static constexpr char url[] = "http://my.url.org/stream.m3u";
    static constexpr char title[] = "Stream Me";
    const auto stream_id(ID::Stream::make_for_source(STREAM_ID_SOURCE_UI));

    GVariantWrapper dummy_stream_key;
    expect_empty_cover_art_notification(dummy_stream_key);
    dcpregs_playstream_start_notification(stream_id.get_raw_id(),
                                          GVariantWrapper::move(dummy_stream_key));

    register_changed_data->check({210});
    mock_messages->check();
    expect_current_title_and_url("", "");

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
             "Received explicit title and URL information for stream 129");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG,
                                    "Send title and URL to SPI slave");

    dcpregs_playstream_set_title_and_url(stream_id.get_raw_id(), title, url);

    register_changed_data->check(std::array<uint8_t, 2>{75, 76});
    mock_messages->check();
    expect_current_title_and_url(title, url);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
             "Received explicit title and URL information for stream 129");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG,
                                    "Suppress sending title and URL to SPI slave");

    dcpregs_playstream_set_title_and_url(stream_id.get_raw_id(), title, url);

    register_changed_data->check();
    expect_current_title_and_url(title, url);
}

/*!\test
 * App starts stream and then sends another stream to play after the first one.
 *
 * The second stream is not played immediately.
 */
void test_start_stream_and_queue_next()
{
    auto next_stream_id(OurStream::make());

    const auto stream_id_first(next_stream_id);
    GVariantWrapper skey_first;
    set_start_title_and_url("First FLAC", "http://app-provided.url.org/first.flac",
                            stream_id_first, false, &skey_first);
    register_changed_data->check();
    expect_current_title_and_url("", "");

    mock_messages->expect_msg_info_formatted("Enter app mode: started stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_first);
    dcpregs_playstream_start_notification(stream_id_first.get().get_raw_id(),
                                          GVariantWrapper::move(skey_first));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    mock_messages->check();
    expect_next_url_empty();
    expect_current_title_and_url("First FLAC", "http://app-provided.url.org/first.flac");

    const auto stream_id_second(++next_stream_id);
    GVariantWrapper skey_second;
    set_next_title_and_url("Second FLAC", "http://app-provided.url.org/second.flac",
                           stream_id_second, true, true, &skey_second);

    mock_messages->expect_msg_info_formatted("Next app stream 258");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_second);
    dcpregs_playstream_start_notification(stream_id_second.get().get_raw_id(),
                                          GVariantWrapper::move(skey_second));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    mock_messages->check();
    expect_next_url_empty();
    expect_current_title_and_url("Second FLAC", "http://app-provided.url.org/second.flac");

    /* after a while, the stream may finish */
    mock_messages->expect_msg_info("Leave app mode: streamplayer has stopped");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    dcpregs_playstream_stop_notification();
    register_changed_data->check(std::array<uint8_t, 3>{79, 75, 76});
    expect_current_title_and_url("", "");
}

/*!\test
 * App plays 5 tracks in a row.
 */
void test_play_multiple_tracks_in_a_row()
{
    auto next_stream_id(OurStream::make());

    static const std::array<std::pair<const char *, const char *>, 5> title_and_url =
    {
        std::make_pair("First (FLAC)", "http://app-provided.url.org/stream.flac"),
        std::make_pair("Second (mp3)", "http://app-provided.url.org/stream.mp3"),
        std::make_pair("Third (wav)",  "http://app-provided.url.org/stream.wav"),
        std::make_pair("Fourth (ogg)", "http://app-provided.url.org/stream.ogg"),
        std::make_pair("Fifth (mp4)",  "http://app-provided.url.org/stream.mp4"),
    };

    /* queue first track */
    const auto stream_id_first(next_stream_id);
    GVariantWrapper skey;
    set_start_title_and_url(title_and_url[0].first, title_and_url[0].second,
                            stream_id_first, false, &skey);
    register_changed_data->check();
    expect_current_title_and_url("", "");

    /* first track starts playing */
    mock_messages->expect_msg_info_formatted("Enter app mode: started stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey);
    dcpregs_playstream_start_notification(stream_id_first.get().get_raw_id(),
                                          GVariantWrapper::move(skey));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url(title_and_url[0].first, title_and_url[0].second);

    for(size_t i = 1; i < title_and_url.size(); ++i)
    {
        const std::pair<const char *, const char *> &pair(title_and_url[i]);

        /* queue next track */
        const auto stream_id(++next_stream_id);
        set_next_title_and_url(pair.first, pair.second, stream_id, true, true, &skey);
        register_changed_data->check();

        /* next track starts playing */
        char buffer[64];
        snprintf(buffer, sizeof(buffer),
                 "Next app stream %u", stream_id.get().get_raw_id());
        mock_messages->expect_msg_info_formatted(buffer);
        mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
        expect_empty_cover_art_notification(skey);
        dcpregs_playstream_start_notification(stream_id.get().get_raw_id(),
                                              GVariantWrapper::move(skey));
        register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
        mock_messages->check();
        expect_next_url_empty();
        expect_current_title_and_url(pair.first, pair.second);
    }

    /* after a while, the last stream finishes playing */
    mock_messages->expect_msg_info("Leave app mode: streamplayer has stopped");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    dcpregs_playstream_stop_notification();
    register_changed_data->check(std::array<uint8_t, 3>{79, 75, 76});
    expect_current_title_and_url("", "");
}

/*!\test
 * App starts stream and then quickly sends another stream to play after the
 * first one.
 *
 * This situation is slightly out of spec. The SPI slave should wait for empty
 * register 239 before queuing the second stream. We'll handle it gracefully
 * regardless, so the second stream is queued and not played immediately.
 */
void test_start_stream_and_quickly_queue_next()
{
    auto next_stream_id(OurStream::make());

    const auto stream_id_first(next_stream_id);
    GVariantWrapper skey_first;
    set_start_title_and_url("First FLAC", "http://app-provided.url.org/first.flac",
                            stream_id_first, false, &skey_first);
    register_changed_data->check();
    expect_current_title_and_url("", "");

    const auto stream_id_second(++next_stream_id);
    GVariantWrapper skey_second;
    set_next_title_and_url("Second FLAC", "http://app-provided.url.org/second.flac",
                           stream_id_second, true, true, &skey_second);
    register_changed_data->check();
    expect_current_title_and_url("", "");

    mock_messages->expect_msg_info_formatted("Enter app mode: started stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_first);
    dcpregs_playstream_start_notification(stream_id_first.get().get_raw_id(),
                                          GVariantWrapper::move(skey_first));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("First FLAC", "http://app-provided.url.org/first.flac");

    mock_messages->expect_msg_info_formatted("Next app stream 258");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_second);
    dcpregs_playstream_start_notification(stream_id_second.get().get_raw_id(),
                                          GVariantWrapper::move(skey_second));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("Second FLAC", "http://app-provided.url.org/second.flac");
}

/*!\test
 * App starts stream and tries to queue another stream just after the first
 * stream ended.
 *
 * The second stream is not played at all.
 */
void test_queue_next_after_stop_notification_is_ignored()
{
    auto next_stream_id(OurStream::make());

    const auto stream_id_first(next_stream_id);
    GVariantWrapper skey_first;
    set_start_title_and_url("First FLAC", "http://app-provided.url.org/first.flac",
                            stream_id_first, false, &skey_first);
    register_changed_data->check();
    expect_current_title_and_url("", "");

    mock_messages->expect_msg_info_formatted("Enter app mode: started stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_first);
    dcpregs_playstream_start_notification(stream_id_first.get().get_raw_id(),
                                          GVariantWrapper::move(skey_first));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("First FLAC", "http://app-provided.url.org/first.flac");

    /* the stream finishes... */
    mock_messages->expect_msg_info("Leave app mode: streamplayer has stopped");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    dcpregs_playstream_stop_notification();
    register_changed_data->check(std::array<uint8_t, 3>{79, 75, 76});
    expect_current_title_and_url("", "");

    /* ...but the slave sends another stream just in that moment */
    const auto stream_id_second(++next_stream_id);
    set_next_title_and_url("Second FLAC", "http://app-provided.url.org/second.flac",
                           stream_id_second, false, false, nullptr);
    expect_current_title_and_url("", "");
}

/*!\test
 * App must start first stream before trying to queue next.
 */
void test_queue_next_with_prior_start_is_ignored()
{
    set_next_title_and_url("Stream", "http://app-provided.url.org/stream.flac",
                           OurStream::make(), false, false, nullptr);
    expect_current_title_and_url("", "");
}

/*!\test
 * App must start first stream before trying to queue next also if streamplayer
 * is already playing.
 */
void test_queue_next_with_prior_start_by_us_is_ignored()
{
    set_next_title_and_url("Stream", "http://app-provided.url.org/stream.flac",
                           OurStream::make(), false, true, nullptr);
    expect_current_title_and_url("", "");
}

/*!\test
 * SPI slave may send registers 238 and 239 as often as it likes; last stream
 * counts.
 */
void test_queued_stream_can_be_changed_as_long_as_it_is_not_played()
{
    auto next_stream_id(OurStream::make());

    const auto stream_id_first(next_stream_id);
    GVariantWrapper skey_first;
    set_start_title_and_url("Playing stream", "http://app-provided.url.org/first.mp3",
                            stream_id_first, false, &skey_first);
    register_changed_data->check();
    expect_current_title_and_url("", "");

    mock_messages->expect_msg_info_formatted("Enter app mode: started stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_first);
    dcpregs_playstream_start_notification(stream_id_first.get().get_raw_id(),
                                          GVariantWrapper::move(skey_first));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("Playing stream", "http://app-provided.url.org/first.mp3");

    const auto stream_id_second(++next_stream_id);
    set_next_title_and_url("Stream 2", "http://app-provided.url.org/2.mp3",
                           stream_id_second, true, true, nullptr);
    register_changed_data->check();
    expect_current_title_and_url("Playing stream", "http://app-provided.url.org/first.mp3");

    const auto stream_id_third(++next_stream_id);
    set_next_title_and_url("Stream 3", "http://app-provided.url.org/3.mp3",
                           stream_id_third, true, true, nullptr);
    register_changed_data->check();
    expect_current_title_and_url("Playing stream", "http://app-provided.url.org/first.mp3");

    const auto stream_id_fourth(++next_stream_id);
    GVariantWrapper skey_fourth;
    set_next_title_and_url("Stream 4", "http://app-provided.url.org/4.mp3",
                           stream_id_fourth, true, true, &skey_fourth);
    register_changed_data->check();
    expect_current_title_and_url("Playing stream", "http://app-provided.url.org/first.mp3");

    mock_messages->check();

    mock_messages->expect_msg_info_formatted("Next app stream 260");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_fourth);
    dcpregs_playstream_start_notification(stream_id_fourth.get().get_raw_id(),
                                          GVariantWrapper::move(skey_fourth));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("Stream 4", "http://app-provided.url.org/4.mp3");
}

void test_pause_and_continue()
{
    auto next_stream_id(OurStream::make());

    const auto stream_id_first(next_stream_id);
    GVariantWrapper skey_first;
    set_start_title_and_url("First FLAC", "http://app-provided.url.org/first.flac",
                            stream_id_first, false, &skey_first);
    register_changed_data->check();
    expect_current_title_and_url("", "");

    mock_messages->expect_msg_info_formatted("Enter app mode: started stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_first);
    dcpregs_playstream_start_notification(stream_id_first.get().get_raw_id(),
                                          GVariantWrapper::move(skey_first));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    mock_messages->check();
    expect_next_url_empty();
    expect_current_title_and_url("First FLAC", "http://app-provided.url.org/first.flac");

    const auto stream_id_second(++next_stream_id);
    GVariantWrapper skey_second;
    set_next_title_and_url("Second FLAC", "http://app-provided.url.org/second.flac",
                           stream_id_second, true, true, &skey_second);
    expect_current_title_and_url("First FLAC", "http://app-provided.url.org/first.flac");

    /* the pause signal itself is caught, but ignored by dcpd; however,
     * starting the same stream is treated as continue from pause */
    mock_messages->expect_msg_info_formatted("Continue with app stream 257");
    expect_empty_cover_art_notification(skey_first);
    dcpregs_playstream_start_notification(stream_id_first.get().get_raw_id(),
                                          GVariantWrapper::move(skey_first));
    expect_current_title_and_url("First FLAC", "http://app-provided.url.org/first.flac");

    /* also works a second time */
    mock_messages->expect_msg_info_formatted("Continue with app stream 257");
    expect_empty_cover_art_notification(skey_first);
    dcpregs_playstream_start_notification(stream_id_first.get().get_raw_id(),
                                          GVariantWrapper::move(skey_first));
    expect_current_title_and_url("First FLAC", "http://app-provided.url.org/first.flac");

    /* now assume the next stream has started */
    mock_messages->expect_msg_info_formatted("Next app stream 258");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_second);
    dcpregs_playstream_start_notification(stream_id_second.get().get_raw_id(),
                                          GVariantWrapper::move(skey_second));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("Second FLAC", "http://app-provided.url.org/second.flac");
}

};

namespace spi_registers_media_services
{

static tdbuscredentialsRead *const dbus_cred_read_iface_dummy =
    reinterpret_cast<tdbuscredentialsRead *>(0xf017bc12);

static tdbuscredentialsWrite *const dbus_cred_write_iface_dummy =
    reinterpret_cast<tdbuscredentialsWrite *>(0xf127ac82);

static tdbusAirable *const dbus_airable_iface_dummy =
    reinterpret_cast<tdbusAirable *>(0xf280be98);

static MockMessages *mock_messages;
static MockCredentialsDBus *mock_credentials_dbus = nullptr;
static MockAirableDBus *mock_airable_dbus = nullptr;
static MockDBusIface *mock_dbus_iface;

static RegisterChangedData *register_changed_data;

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

    mock_credentials_dbus = new MockCredentialsDBus;
    cppcut_assert_not_null(mock_credentials_dbus);
    mock_credentials_dbus->init();
    mock_credentials_dbus_singleton = mock_credentials_dbus;

    mock_airable_dbus = new MockAirableDBus;
    cppcut_assert_not_null(mock_airable_dbus);
    mock_airable_dbus->init();
    mock_airable_dbus_singleton = mock_airable_dbus;

    mock_dbus_iface = new MockDBusIface;
    cppcut_assert_not_null(mock_dbus_iface);
    mock_dbus_iface->init();
    mock_dbus_iface_singleton = mock_dbus_iface;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    register_changed_data->init();

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    network_prefs_init(NULL, NULL, NULL, NULL);
    register_init(register_changed_callback);
}

void cut_teardown()
{
    register_deinit();
    network_prefs_deinit();

    register_changed_data->check();

    delete register_changed_data;
    register_changed_data = nullptr;

    mock_messages->check();
    mock_credentials_dbus->check();
    mock_airable_dbus->check();
    mock_dbus_iface->check();

    mock_messages_singleton = nullptr;
    mock_credentials_dbus_singleton = nullptr;
    mock_airable_dbus_singleton = nullptr;
    mock_dbus_iface_singleton = nullptr;

    delete mock_messages;
    delete mock_credentials_dbus;
    delete mock_airable_dbus;
    delete mock_dbus_iface;

    mock_messages = nullptr;
    mock_credentials_dbus = nullptr;
    mock_airable_dbus = nullptr;
    mock_dbus_iface = nullptr;
}

/*!\test
 * In case no services are known, an XML indication so is returned.
 */
void test_read_out_empty_external_media_services()
{
    auto *reg = lookup_register_expect_handlers(106,
                                                dcpregs_read_106_media_service_list,
                                                dcpregs_write_106_media_service_list);

    struct dynamic_buffer buffer;
    dynamic_buffer_init(&buffer);

    const MockCredentialsDBus::ReadGetKnownCategoriesData categories;

    mock_dbus_iface->expect_dbus_get_credentials_read_iface(dbus_cred_read_iface_dummy);
    mock_credentials_dbus->expect_tdbus_credentials_read_call_get_known_categories_sync(TRUE, dbus_cred_read_iface_dummy, categories);

    cut_assert_true(reg->read_handler_dynamic(&buffer));

    const std::string expected_answer = "<services count=\"0\"/>";
    cut_assert_equal_memory(expected_answer.c_str(), expected_answer.size(),
                            buffer.data, buffer.pos);

    dynamic_buffer_free(&buffer);
}

/*!\test
 * Read out the whole set of media services and credentials.
 */
void test_read_out_external_media_services()
{
    auto *reg = lookup_register_expect_handlers(106,
                                                dcpregs_read_106_media_service_list,
                                                dcpregs_write_106_media_service_list);

    /* survey */
    static const uint8_t dummy = 0;
    cppcut_assert_equal(0, reg->write_handler(&dummy, 0));

    register_changed_data->check(106);

    /* read out */
    struct dynamic_buffer buffer;
    dynamic_buffer_init(&buffer);

    const MockCredentialsDBus::ReadGetKnownCategoriesData categories =
    {
        std::make_pair("tidal",  "TIDAL"),
        std::make_pair("qobuz",  "Qobuz"),
        std::make_pair("deezer", "Deezer"),
        std::make_pair("funny",  "Service w/o default user"),
    };

    const MockCredentialsDBus::ReadGetCredentialsData accounts_tidal =
    {
        std::make_pair("tidal.user@somewhere.com", "1234qwerasdf"),
    };

    const MockCredentialsDBus::ReadGetCredentialsData accounts_qobuz =
    {
        std::make_pair("Some guy", "secret"),
        std::make_pair("qobuz.user@somewhere.com", "abcdef"),
        std::make_pair("Someone else", "password"),
    };

    const MockCredentialsDBus::ReadGetCredentialsData accounts_deezer;

    const MockCredentialsDBus::ReadGetCredentialsData accounts_funny =
    {
        std::make_pair("Not the default", "funny&\"42>"),
    };

    mock_dbus_iface->expect_dbus_get_credentials_read_iface(dbus_cred_read_iface_dummy);
    mock_credentials_dbus->expect_tdbus_credentials_read_call_get_known_categories_sync(TRUE, dbus_cred_read_iface_dummy, categories);
    mock_dbus_iface->expect_dbus_get_credentials_read_iface(dbus_cred_read_iface_dummy);
    mock_credentials_dbus->expect_tdbus_credentials_read_call_get_credentials_sync(
        TRUE, dbus_cred_read_iface_dummy,
        accounts_tidal, accounts_tidal[0].first);
    mock_credentials_dbus->expect_tdbus_credentials_read_call_get_credentials_sync(
        TRUE, dbus_cred_read_iface_dummy,
        accounts_qobuz, accounts_qobuz[1].first);
    mock_credentials_dbus->expect_tdbus_credentials_read_call_get_credentials_sync(
        TRUE, dbus_cred_read_iface_dummy,
        accounts_deezer, "");
    mock_credentials_dbus->expect_tdbus_credentials_read_call_get_credentials_sync(
        TRUE, dbus_cred_read_iface_dummy,
        accounts_funny, "Does not exist");

    cut_assert_true(reg->read_handler_dynamic(&buffer));

    const std::string expected_answer =
        "<services count=\"4\">"
        "<service id=\"tidal\" name=\"TIDAL\">"
        "<account login=\"tidal.user@somewhere.com\" password=\"1234qwerasdf\" default=\"true\"/>"
        "</service>"
        "<service id=\"qobuz\" name=\"Qobuz\">"
        "<account login=\"Some guy\" password=\"secret\"/>"
        "<account login=\"qobuz.user@somewhere.com\" password=\"abcdef\" default=\"true\"/>"
        "<account login=\"Someone else\" password=\"password\"/>"
        "</service>"
        "<service id=\"deezer\" name=\"Deezer\"/>"
        "<service id=\"funny\" name=\"Service w/o default user\">"
        "<account login=\"Not the default\" password=\"funny&amp;&quot;42&gt;\"/>"
        "</service>"
        "</services>";
    cut_assert_equal_memory(expected_answer.c_str(), expected_answer.size(),
                            buffer.data, buffer.pos);

    dynamic_buffer_free(&buffer);
}

/*!\test
 * Read out the whole set of unconfigured media services.
 */
void test_read_out_unconfigured_external_media_services()
{
    auto *reg = lookup_register_expect_handlers(106,
                                                dcpregs_read_106_media_service_list,
                                                dcpregs_write_106_media_service_list);

    /* survey */
    static const uint8_t dummy = 0;
    cppcut_assert_equal(0, reg->write_handler(&dummy, 0));

    register_changed_data->check(106);

    /* read out */
    struct dynamic_buffer buffer;
    dynamic_buffer_init(&buffer);

    const MockCredentialsDBus::ReadGetKnownCategoriesData categories =
    {
        std::make_pair("tidal",  "TIDAL"),
        std::make_pair("deezer", "Deezer"),
    };

    const MockCredentialsDBus::ReadGetCredentialsData no_accounts;

    mock_dbus_iface->expect_dbus_get_credentials_read_iface(dbus_cred_read_iface_dummy);
    mock_credentials_dbus->expect_tdbus_credentials_read_call_get_known_categories_sync(TRUE, dbus_cred_read_iface_dummy, categories);
    mock_dbus_iface->expect_dbus_get_credentials_read_iface(dbus_cred_read_iface_dummy);
    mock_credentials_dbus->expect_tdbus_credentials_read_call_get_credentials_sync(
        TRUE, dbus_cred_read_iface_dummy,
        no_accounts, "");
    mock_credentials_dbus->expect_tdbus_credentials_read_call_get_credentials_sync(
        TRUE, dbus_cred_read_iface_dummy,
        no_accounts, "");

    cut_assert_true(reg->read_handler_dynamic(&buffer));

    const std::string expected_answer =
        "<services count=\"2\">"
        "<service id=\"tidal\" name=\"TIDAL\"/>"
        "<service id=\"deezer\" name=\"Deezer\"/>"
        "</services>";
    cut_assert_equal_memory(expected_answer.c_str(), expected_answer.size(),
                            buffer.data, buffer.pos);

    dynamic_buffer_free(&buffer);
}

/*!\test
 * Writing nothing to the register triggers a meda services survey.
 */
void test_trigger_media_services_survey()
{
    auto *reg = lookup_register_expect_handlers(106,
                                                dcpregs_read_106_media_service_list,
                                                dcpregs_write_106_media_service_list);

    static const uint8_t dummy = 0;
    cppcut_assert_equal(0, reg->write_handler(&dummy, 0));

    register_changed_data->check(106);
}

/*!\test
 * Write single user credentials for specific service.
 */
void test_set_service_credentials()
{
    auto *reg = lookup_register_expect_handlers(106,
                                                dcpregs_read_106_media_service_list,
                                                dcpregs_write_106_media_service_list);

    static const uint8_t data[] = "tidal\0login email\0my password";

    mock_dbus_iface->expect_dbus_get_credentials_write_iface(dbus_cred_write_iface_dummy);
    mock_credentials_dbus->expect_tdbus_credentials_write_call_delete_credentials_sync(
        TRUE, dbus_cred_write_iface_dummy,
        "tidal", "", "");
    mock_dbus_iface->expect_dbus_get_airable_sec_iface(dbus_airable_iface_dummy);
    mock_airable_dbus->expect_tdbus_airable_call_external_service_logout_sync(
        TRUE, dbus_airable_iface_dummy,
        "tidal", "", TRUE, guchar(ACTOR_ID_LOCAL_UI));
    mock_dbus_iface->expect_dbus_get_credentials_write_iface(dbus_cred_write_iface_dummy);
    mock_credentials_dbus->expect_tdbus_credentials_write_call_set_credentials_sync(
        TRUE, dbus_cred_write_iface_dummy,
        "tidal", "login email", "my password", TRUE);

    cppcut_assert_equal(0, reg->write_handler(data, sizeof(data) - 1));
}

/*!\test
 * Password may be zero-terminated.
 */
void test_password_may_be_zero_terminated()
{
    auto *reg = lookup_register_expect_handlers(106,
                                                dcpregs_read_106_media_service_list,
                                                dcpregs_write_106_media_service_list);

    static const uint8_t data[] = "deezer\0login\0password\0";

    mock_dbus_iface->expect_dbus_get_credentials_write_iface(dbus_cred_write_iface_dummy);
    mock_credentials_dbus->expect_tdbus_credentials_write_call_delete_credentials_sync(
        TRUE, dbus_cred_write_iface_dummy,
        "deezer", "", "");
    mock_dbus_iface->expect_dbus_get_airable_sec_iface(dbus_airable_iface_dummy);
    mock_airable_dbus->expect_tdbus_airable_call_external_service_logout_sync(
        TRUE, dbus_airable_iface_dummy,
        "deezer", "", TRUE, guchar(ACTOR_ID_LOCAL_UI));
    mock_dbus_iface->expect_dbus_get_credentials_write_iface(dbus_cred_write_iface_dummy);
    mock_credentials_dbus->expect_tdbus_credentials_write_call_set_credentials_sync(
        TRUE, dbus_cred_write_iface_dummy,
        "deezer", "login", "password", TRUE);

    cppcut_assert_equal(0, reg->write_handler(data, sizeof(data) - 1));
}

/*!\test
 * The service ID must always be set when writing credentials.
 */
void test_set_service_credentials_requires_service_id()
{
    auto *reg = lookup_register_expect_handlers(106,
                                                dcpregs_read_106_media_service_list,
                                                dcpregs_write_106_media_service_list);

    static const uint8_t data[] = "\0login email\0my password";

    mock_messages->expect_msg_error(0, EINVAL, "Empty service ID sent to register 106");

    cppcut_assert_equal(-1, reg->write_handler(data, sizeof(data) - 1));
}

/*!\test
 * If there is a password, then there must also be a login.
 */
void test_set_service_credentials_requires_login_for_password()
{
    auto *reg = lookup_register_expect_handlers(106,
                                                dcpregs_read_106_media_service_list,
                                                dcpregs_write_106_media_service_list);

    static const uint8_t data[] = "tidal\0\0my password";

    mock_messages->expect_msg_error(0, EINVAL, "Empty login sent to register 106");

    cppcut_assert_equal(-1, reg->write_handler(data, sizeof(data) - 1));
}

/*!\test
 * If there is a login, then there must also be a password.
 */
void test_set_service_credentials_requires_password_for_login()
{
    auto *reg = lookup_register_expect_handlers(106,
                                                dcpregs_read_106_media_service_list,
                                                dcpregs_write_106_media_service_list);

    static const uint8_t data[] = "tidal\0login\0";

    mock_messages->expect_msg_error(0, EINVAL, "Empty password sent to register 106");

    cppcut_assert_equal(-1, reg->write_handler(data, sizeof(data) - 1));
}

/*!\test
 * There must be no junk after a zero-terminated password.
 */
void test_no_junk_after_password_allowed()
{
    auto *reg = lookup_register_expect_handlers(106,
                                                dcpregs_read_106_media_service_list,
                                                dcpregs_write_106_media_service_list);

    static const uint8_t data[] = "tidal\0login\0password\0\0";

    mock_messages->expect_msg_error(0, EINVAL, "Malformed data written to register 106");

    cppcut_assert_equal(-1, reg->write_handler(data, sizeof(data) - 1));
}

};

namespace spi_registers_search
{

static tdbusdcpdViews *const dbus_dcpd_views_iface_dummy =
    reinterpret_cast<tdbusdcpdViews *>(0x87654321);

static MockMessages *mock_messages;
static MockDcpdDBus *mock_dcpd_dbus;
static MockDBusIface *mock_dbus_iface;

void cut_setup()
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

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    network_prefs_init(NULL, NULL, NULL, NULL);
    register_init(NULL);
}

void cut_teardown()
{
    register_deinit();
    network_prefs_deinit();

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

/*!\test
 */
void test_start_search_in_default_context()
{
    auto *reg = lookup_register_expect_handlers(74,
                                                dcpregs_write_74_search_parameters);

    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_search_parameters(
            dbus_dcpd_views_iface_dummy, "default", nullptr);

    static const char query[] = "default";

    cppcut_assert_equal(0, reg->write_handler((const uint8_t *)query, sizeof(query)));
}

/*!\test
 */
void test_search_single_string_in_default_context()
{
    static const char *key_value_table[] =
    {
        "text0", "Some search string",
        nullptr,
    };

    auto *reg = lookup_register_expect_handlers(74,
                                                dcpregs_write_74_search_parameters);

    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_search_parameters(
            dbus_dcpd_views_iface_dummy, "default", key_value_table);

    static const char query[] = "default\0text0=Some search string";

    cppcut_assert_equal(0, reg->write_handler((const uint8_t *)query, sizeof(query)));
}

/*!\test
 */
void test_search_with_multiple_parameters_in_usb_context()
{
    static const char *key_value_table[] =
    {
        "text0",   "First string",
        "text3",   "Second string",
        "select0", "2",
        "text4",   "Third string",
        "select2", "yes",
        nullptr,
    };

    auto *reg = lookup_register_expect_handlers(74,
                                                dcpregs_write_74_search_parameters);

    mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_search_parameters(
            dbus_dcpd_views_iface_dummy, "usb", key_value_table);

    static const char query[] =
        "usb\0"
        "text0=First string\0"
        "text3=Second string\0"
        "select0=2\0"
        "text4=Third string\0"
        "select2=yes";

    cppcut_assert_equal(0, reg->write_handler((const uint8_t *)query, sizeof(query)));
}

/*!\test
 */
void test_search_parameter_value_must_not_be_empty()
{
    auto *reg = lookup_register_expect_handlers(74,
                                                dcpregs_write_74_search_parameters);

    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "Missing value in query");

    static const char query[] = "default\0text0=";

    cppcut_assert_equal(-1, reg->write_handler((const uint8_t *)query, sizeof(query)));
}

/*!\test
 */
void test_search_parameter_variable_must_not_be_empty()
{
    auto *reg = lookup_register_expect_handlers(74,
                                                dcpregs_write_74_search_parameters);

    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "Missing ID in query");

    static const char query[] = "default\0=Some search string";

    cppcut_assert_equal(-1, reg->write_handler((const uint8_t *)query, sizeof(query)));
}

/*!\test
 */
void test_context_must_not_be_empty()
{
    auto *reg = lookup_register_expect_handlers(74,
                                                dcpregs_write_74_search_parameters);

    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "No search context defined");

    static const char query[] = "\0text0=Some search string";

    cppcut_assert_equal(-1, reg->write_handler((const uint8_t *)query, sizeof(query)));
}

/*!\test
 */
void test_context_must_not_contain_equals_character()
{
    auto *reg = lookup_register_expect_handlers(74,
                                                dcpregs_write_74_search_parameters);

    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "Invalid characters in search context");

    static const char query[] = "default=yes\0text0=Some search string";

    cppcut_assert_equal(-1, reg->write_handler((const uint8_t *)query, sizeof(query)));
}

/*!\test
 */
void test_search_parameter_specification_must_contain_equals_character()
{
    auto *reg = lookup_register_expect_handlers(74,
                                                dcpregs_write_74_search_parameters);

    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "Missing assignment in query");

    static const char query[] = "default\0text0 Some search string";

    cppcut_assert_equal(-1, reg->write_handler((const uint8_t *)query, sizeof(query)));
}

/*!\test
 */
void test_search_parameter_specification_must_not_be_empty()
{
    auto *reg = lookup_register_expect_handlers(74,
                                                dcpregs_write_74_search_parameters);

    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "Empty query");

    static const char query[] = "default\0";

    cppcut_assert_equal(-1, reg->write_handler((const uint8_t *)query, sizeof(query)));
}

/*!\test
 */
void test_embedded_search_parameter_specification_must_not_be_empty()
{
    auto *reg = lookup_register_expect_handlers(74,
                                                dcpregs_write_74_search_parameters);

    mock_messages->expect_msg_error_formatted(0, LOG_ERR, "Empty query");

    static const char query[] = "default\0text0=My Query\0";

    cppcut_assert_equal(-1, reg->write_handler((const uint8_t *)query, sizeof(query)));
}

};

namespace spi_registers_misc
{

static MockMessages *mock_messages;
static MockOs *mock_os;
static MockDcpdDBus *mock_dcpd_dbus;
static MockDBusIface *mock_dbus_iface;

static tdbusdcpdPlayback *const dbus_dcpd_playback_iface_dummy =
    reinterpret_cast<tdbusdcpdPlayback *>(0x12345678);

static constexpr char expected_config_filename[] = "/etc/os-release";

static constexpr int expected_os_map_file_to_memory_fd = 5;

static RegisterChangedData *register_changed_data;

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

    mock_os = new MockOs;
    cppcut_assert_not_null(mock_os);
    mock_os->init();
    mock_os_singleton = mock_os;

    mock_dcpd_dbus = new MockDcpdDBus();
    cppcut_assert_not_null(mock_dcpd_dbus);
    mock_dcpd_dbus->init();
    mock_dcpd_dbus_singleton = mock_dcpd_dbus;

    mock_dbus_iface = new MockDBusIface;
    cppcut_assert_not_null(mock_dbus_iface);
    mock_dbus_iface->init();
    mock_dbus_iface_singleton = mock_dbus_iface;

    mock_messages->ignore_messages_with_level_or_above(MESSAGE_LEVEL_TRACE);

    register_changed_data->init();

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"networkconfig\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"filetransfer\"");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                              "Allocated shutdown guard \"upnpname\"");

    network_prefs_init(NULL, NULL, NULL, NULL);
    register_init(register_changed_callback);
}

void cut_teardown()
{
    register_deinit();
    network_prefs_deinit();

    register_changed_data->check();

    delete register_changed_data;
    register_changed_data = nullptr;

    mock_messages->check();
    mock_os->check();
    mock_dcpd_dbus->check();
    mock_dbus_iface->check();

    mock_messages_singleton = nullptr;
    mock_os_singleton = nullptr;
    mock_dcpd_dbus_singleton = nullptr;
    mock_dbus_iface_singleton = nullptr;

    delete mock_messages;
    delete mock_os;
    delete mock_dcpd_dbus;
    delete mock_dbus_iface;

    mock_messages = nullptr;
    mock_os = nullptr;
    mock_dcpd_dbus = nullptr;
    mock_dbus_iface = nullptr;
}

/*!\test
 * Register 37 cannot be written to.
 */
void test_dcp_register_37_has_no_write_handler()
{
    const auto *reg = register_lookup(37);

    cppcut_assert_not_null(reg);
    cppcut_assert_equal(37U, unsigned(reg->address));
    cut_assert(reg->read_handler != NULL);
    cut_assert(reg->write_handler == NULL);
}

static void do_test_read_image_version(const os_mapped_file_data &config_file,
                                       size_t dest_buffer_size,
                                       const char *expected_build_id,
                                       size_t expected_build_id_size,
                                       const char *expected_warning = nullptr)
{
    char expected_build_id_memory[dest_buffer_size];
    memset(expected_build_id_memory, 0, dest_buffer_size);

    if(expected_build_id_size > 1)
        memcpy(expected_build_id_memory, expected_build_id, expected_build_id_size - 1);

    uint8_t redzone_content[10];
    memset(redzone_content, 0xff, sizeof(redzone_content));

    uint8_t buffer[sizeof(redzone_content) + dest_buffer_size + sizeof(redzone_content)];
    memset(buffer, 0xff, sizeof(buffer));

    auto *reg = register_lookup(37);

    mock_os->expect_os_map_file_to_memory(&config_file, expected_config_filename);
    mock_os->expect_os_unmap_file(&config_file);

    if(expected_warning != nullptr)
        mock_messages->expect_msg_error_formatted(0, LOG_NOTICE, expected_warning);

    cppcut_assert_equal(ssize_t(expected_build_id_size),
                        reg->read_handler(buffer + sizeof(redzone_content),
                                          sizeof(buffer) - 2 * sizeof(redzone_content)));

    cut_assert_equal_memory(redzone_content, sizeof(redzone_content), buffer,
                            sizeof(redzone_content));
    cut_assert_equal_memory(redzone_content, sizeof(redzone_content),
                            buffer + sizeof(redzone_content) + dest_buffer_size,
                            sizeof(redzone_content));
    cut_assert_equal_memory(expected_build_id_memory, dest_buffer_size,
                            buffer + sizeof(redzone_content),
                            dest_buffer_size);
}

/*!\test
 * Realistic test with real-life configuration data.
 */
void test_read_image_version()
{
    static char config_file_buffer[] =
        "ID=strbo\n"
        "NAME=StrBo (T+A Streaming Board)\n"
        "VERSION=1.0.0\n"
        "VERSION_ID=1.0.0\n"
        "PRETTY_NAME=StrBo (T+A Streaming Board) 1.0.0\n"
        "BUILD_ID=20150708122013\n"
        "BUILD_GIT_COMMIT=05f6dcd31134a3d2e9f5d0c8b78a4bab1948a4d5\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_build_id[] = "20150708122013";

    do_test_read_image_version(config_file, 20,
                               expected_build_id, sizeof(expected_build_id));
}

/*!\test
 * Build ID can be read if it appears in the first line of the config file.
 */
void test_read_image_version_with_build_id_in_first_line()
{
    static char config_file_buffer[] =
        "BUILD_ID=20150708122013\n"
        "BUILD_GIT_COMMIT=05f6dcd31134a3d2e9f5d0c8b78a4bab1948a4d5\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_build_id[] = "20150708122013";

    do_test_read_image_version(config_file, 20,
                               expected_build_id, sizeof(expected_build_id));
}

/*!\test
 * Build ID can be read if it appears in the last line of the config file.
 */
void test_read_image_version_with_build_id_in_last_line()
{
    static char config_file_buffer[] =
        "BUILD_GIT_COMMIT=05f6dcd31134a3d2e9f5d0c8b78a4bab1948a4d5\n"
        "BUILD_ID=20150708122013\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_build_id[] = "20150708122013";

    do_test_read_image_version(config_file, 20,
                               expected_build_id, sizeof(expected_build_id));
}

/*!\test
 * Build ID can be read if it appears in the last line of the config file, even
 * if not terminated with a newline character.
 */
void test_read_image_version_with_build_id_in_last_line_without_newline()
{
    static char config_file_buffer[] =
        "BUILD_GIT_COMMIT=05f6dcd31134a3d2e9f5d0c8b78a4bab1948a4d5\n"
        "BUILD_ID=20150708122013";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_build_id[] = "20150708122013";

    do_test_read_image_version(config_file, 20,
                               expected_build_id, sizeof(expected_build_id));
}

/*!\test
 * Very short build IDs are returned correctly.
 */
void test_read_image_version_with_single_character_build_id()
{
    static char config_file_buffer[] = "BUILD_ID=X\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_build_id[] = "X";

    do_test_read_image_version(config_file, 20,
                               expected_build_id, sizeof(expected_build_id));
}

/*!\test
 * The empty build ID is returned correctly.
 */
void test_read_image_version_with_empty_build_id()
{
    static char config_file_buffer[] = "BUILD_ID=\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_build_id[] = "";

    do_test_read_image_version(config_file, 20,
                               expected_build_id, sizeof(expected_build_id));
}

/*!\test
 * No buffer overflow for long build ID vs small buffer.
 */
void test_read_image_version_with_small_buffer()
{
    static char config_file_buffer[] = "BUILD_ID=20150708122013\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_build_id[] = "2015070";

    do_test_read_image_version(config_file, sizeof(expected_build_id),
                               expected_build_id, sizeof(expected_build_id),
                               "Truncating build ID of length 14 to 7 characters");
}

/*!\test
 * No buffer overflow for long build ID vs single byte buffer.
 */
void test_read_image_version_with_very_small_buffer()
{
    static char config_file_buffer[] = "BUILD_ID=20150708122013\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    static const char expected_build_id[] = "";

    do_test_read_image_version(config_file, sizeof(expected_build_id),
                               expected_build_id, sizeof(expected_build_id),
                               "Truncating build ID of length 14 to 0 characters");
}

/*!\test
 * No buffer overflow for long build ID vs no buffer.
 */
void test_read_image_version_with_zero_size_buffer()
{
    static char config_file_buffer[] = "BUILD_ID=20150708122013\n";

    const struct os_mapped_file_data config_file =
    {
        .fd = expected_os_map_file_to_memory_fd,
        .ptr = config_file_buffer,
        .length = sizeof(config_file_buffer) - 1,
    };

    do_test_read_image_version(config_file, 0, NULL, 0,
                               "Cannot copy build ID to zero length buffer");
}

/*!\test
 * Status byte is invalid without explicit internal ready notification.
 */
void test_status_byte_without_ready_notification_is_all_zero()
{
    auto *reg = register_lookup(17);
    uint8_t buffer[2];
    cppcut_assert_equal((ssize_t)sizeof(buffer),
                        reg->read_handler(buffer, sizeof(buffer)));

    static constexpr uint8_t expected_answer[2] = { 0x00, 0x00 };
    cut_assert_equal_memory(expected_answer, sizeof(expected_answer),
                            buffer, sizeof(buffer));
}

/*!\test
 * Status byte OK after explicit internal ready notification.
 */
void test_status_byte_after_ready_notification()
{
    dcpregs_status_set_ready();

    auto *reg = register_lookup(17);
    uint8_t buffer[2];
    cppcut_assert_equal((ssize_t)sizeof(buffer),
                        reg->read_handler(buffer, sizeof(buffer)));

    static constexpr uint8_t expected_answer[2] = { 0x21, 0x00 };
    cut_assert_equal_memory(expected_answer, sizeof(expected_answer),
                            buffer, sizeof(buffer));

    static constexpr std::array<uint8_t, 2> expected_registers = { 17, 50 };
    register_changed_data->check(expected_registers);
}

/*!\test
 * Status byte indicates power off state after explicit internal shutdown
 * notification.
 */
void test_status_byte_after_shutdown_notification()
{
    dcpregs_status_set_ready_to_shutdown();

    auto *reg = register_lookup(17);
    uint8_t buffer[2];
    cppcut_assert_equal((ssize_t)sizeof(buffer),
                        reg->read_handler(buffer, sizeof(buffer)));

    static constexpr uint8_t expected_answer[2] = { 0x21, 0x01 };
    cut_assert_equal_memory(expected_answer, sizeof(expected_answer),
                            buffer, sizeof(buffer));

    register_changed_data->check(17);
}

/*!\test
 * Status byte indicates system error state after corresponding explicit
 * internal notification.
 */
void test_status_byte_after_reboot_required_notification()
{
    dcpregs_status_set_reboot_required();

    auto *reg = register_lookup(17);
    uint8_t buffer[2];
    cppcut_assert_equal((ssize_t)sizeof(buffer),
                        reg->read_handler(buffer, sizeof(buffer)));

    static constexpr uint8_t expected_answer[2] = { 0x24, 0x00 };
    cut_assert_equal_memory(expected_answer, sizeof(expected_answer),
                            buffer, sizeof(buffer));

    register_changed_data->check(17);
}

/*!\test
 * Status byte changes are only pushed to the SPI slave if the corresponding
 * bytes have changed.
 */
void test_status_byte_updates_are_only_sent_if_changed()
{
    dcpregs_status_set_ready();
    static constexpr std::array<uint8_t, 2> expected_regs_for_ready = { 17, 50 };
    register_changed_data->check(expected_regs_for_ready);

    dcpregs_status_set_ready();
    register_changed_data->check();

    dcpregs_status_set_ready_to_shutdown();
    register_changed_data->check(17);

    dcpregs_status_set_ready_to_shutdown();
    register_changed_data->check();

    dcpregs_status_set_reboot_required();
    register_changed_data->check(17);

    dcpregs_status_set_reboot_required();
    register_changed_data->check();
}

static void set_speed_factor_successful_cases(uint8_t subcommand)
{
    const struct dcp_register_t *reg =
        lookup_register_expect_handlers(73, dcpregs_write_73_seek_or_set_speed);
    const double sign_mul = (subcommand == 0xc1) ? 1.0 : -1.0;

    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_set_speed(dbus_dcpd_playback_iface_dummy,
                                                              sign_mul * 4.0);

    const uint8_t buffer_fraction_lower_boundary[] = { subcommand, 0x04, 0x00, };
    cppcut_assert_equal(0, reg->write_handler(buffer_fraction_lower_boundary,
                                              sizeof(buffer_fraction_lower_boundary)));

    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_set_speed(dbus_dcpd_playback_iface_dummy,
                                                              sign_mul * 4.18);

    const uint8_t buffer_generic[] = { subcommand, 0x04, 0x12, };
    cppcut_assert_equal(0, reg->write_handler(buffer_generic, sizeof(buffer_generic)));

    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_set_speed(dbus_dcpd_playback_iface_dummy,
                                                              sign_mul * 4.99);

    const uint8_t buffer_fraction_upper_boundary[] = { subcommand, 0x04, 0x63, };
    cppcut_assert_equal(0, reg->write_handler(buffer_fraction_upper_boundary,
                                              sizeof(buffer_fraction_upper_boundary)));

    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_set_speed(dbus_dcpd_playback_iface_dummy,
                                                              sign_mul * 0.01);

    const uint8_t buffer_absolute_minimum[] = { subcommand, 0x00, 0x01, };
    cppcut_assert_equal(0, reg->write_handler(buffer_absolute_minimum,
                                              sizeof(buffer_absolute_minimum)));

    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_set_speed(dbus_dcpd_playback_iface_dummy,
                                                              sign_mul * 255.99);

    const uint8_t buffer_absolute_maximum[] = { subcommand, 0xff, 0x63, };
    cppcut_assert_equal(0, reg->write_handler(buffer_absolute_maximum,
                                              sizeof(buffer_absolute_maximum)));
}

static void set_speed_factor_wrong_command_format(uint8_t subcommand)
{
    const struct dcp_register_t *reg =
        lookup_register_expect_handlers(73, dcpregs_write_73_seek_or_set_speed);

    /* too long */
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Speed factor length must be 2 (Invalid argument)");

    const uint8_t buffer_too_long[] = { subcommand, 0x04, 0x00, 0x00 };
    cppcut_assert_equal(-1, reg->write_handler(buffer_too_long, sizeof(buffer_too_long)));

    mock_messages->check();

    /* too short */
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Speed factor length must be 2 (Invalid argument)");

    const uint8_t buffer_too_short[] = { subcommand, 0x04 };
    cppcut_assert_equal(-1, reg->write_handler(buffer_too_short, sizeof(buffer_too_short)));
}

static void set_speed_factor_invalid_factor(uint8_t subcommand)
{
    const struct dcp_register_t *reg =
        lookup_register_expect_handlers(73, dcpregs_write_73_seek_or_set_speed);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Speed factor invalid fraction part (Invalid argument)");

    const uint8_t buffer_first_invalid[] = { subcommand, 0x04, 0x64, };
    cppcut_assert_equal(-1, reg->write_handler(buffer_first_invalid, sizeof(buffer_first_invalid)));

    mock_messages->check();

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Speed factor invalid fraction part (Invalid argument)");

    const uint8_t buffer_last_invalid[] = { subcommand, 0x04, 0xff, };
    cppcut_assert_equal(-1, reg->write_handler(buffer_last_invalid, sizeof(buffer_last_invalid)));
}

static void set_speed_factor_zero(uint8_t subcommand)
{
    const struct dcp_register_t *reg =
        lookup_register_expect_handlers(73, dcpregs_write_73_seek_or_set_speed);

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR, "Speed factor too small (Invalid argument)");

    const uint8_t buffer[] = { subcommand, 0x00, 0x00, };
    cppcut_assert_equal(-1, reg->write_handler(buffer, sizeof(buffer)));
}

/*!\test
 * Slave sends command for fast forward.
 */
void test_playback_set_speed_forward()
{
    set_speed_factor_successful_cases(0xc1);
}

/*!\test
 * Slave sends fast forward command with wrong command length.
 */
void test_playback_set_speed_forward_command_has_2_bytes_of_data()
{
    set_speed_factor_wrong_command_format(0xc1);
}

/*!\test
 * Slave sends fast forward command with invalid factor.
 */
void test_playback_set_speed_forward_fraction_part_is_two_digits_decimal()
{
    set_speed_factor_invalid_factor(0xc1);
}

/*!\test
 * Slave sends fast forward command with factor 0.
 */
void test_playback_set_speed_forward_zero_factor_is_invalid()
{
    set_speed_factor_zero(0xc1);
}

/*!\test
 * Slave sends command for fast reverse.
 */
void test_playback_set_speed_reverse()
{
    set_speed_factor_successful_cases(0xc2);
}

/*!\test
 * Slave sends fast reverse command with wrong command length.
 */
void test_playback_set_speed_reverse_command_has_2_bytes_of_data()
{
    set_speed_factor_wrong_command_format(0xc2);
}

/*!\test
 * Slave sends fast reverse command with invalid factor.
 */
void test_playback_set_speed_reverse_fraction_part_is_two_digits_decimal()
{
    set_speed_factor_invalid_factor(0xc2);
}

/*!\test
 * Slave sends fast reverse command with factor 0.
 */
void test_playback_set_speed_reverse_zero_factor_is_invalid()
{
    set_speed_factor_zero(0xc2);
}

/*!\test
 * Reverting to regular speed is done via own subcommand.
 */
void test_playback_regular_speed()
{
    const struct dcp_register_t *reg =
        lookup_register_expect_handlers(73, dcpregs_write_73_seek_or_set_speed);

    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_set_speed(dbus_dcpd_playback_iface_dummy, 0.0);

    static const uint8_t buffer[] = { 0xc3 };
    cppcut_assert_equal(0, reg->write_handler(buffer, sizeof(buffer)));
}

/*!\test
 * Stream seek position is given in milliseconds as 32 bit little-endian value.
 */
void test_playback_stream_seek()
{
    const struct dcp_register_t *reg =
        lookup_register_expect_handlers(73, dcpregs_write_73_seek_or_set_speed);

    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_seek(dbus_dcpd_playback_iface_dummy,
                                                         264781241, "ms");

    static const uint8_t buffer[] = { 0xc4, 0xb9, 0x3d, 0xc8, 0x0f };
    cppcut_assert_equal(0, reg->write_handler(buffer, sizeof(buffer)));
}

/*!\test
 * Stream seek position can be any 32 bit unsigned integer value.
 */
void test_playback_stream_seek_boundaries()
{
    const struct dcp_register_t *reg =
        lookup_register_expect_handlers(73, dcpregs_write_73_seek_or_set_speed);

    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_seek(dbus_dcpd_playback_iface_dummy,
                                                         0, "ms");

    static const uint8_t buffer_min[] = { 0xc4, 0x00, 0x00, 0x00, 0x00 };
    cppcut_assert_equal(0, reg->write_handler(buffer_min, sizeof(buffer_min)));

    mock_dbus_iface->expect_dbus_get_playback_iface(dbus_dcpd_playback_iface_dummy);
    mock_dcpd_dbus->expect_tdbus_dcpd_playback_emit_seek(dbus_dcpd_playback_iface_dummy,
                                                         UINT32_MAX, "ms");

    static const uint8_t buffer_max[] = { 0xc4, 0xff, 0xff, 0xff, 0xff };
    cppcut_assert_equal(0, reg->write_handler(buffer_max, sizeof(buffer_max)));
}

};

/*!@}*/
