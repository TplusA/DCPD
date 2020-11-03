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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <cppcutter.h>
#include <algorithm>

#include "registers.hh"
#include "networkprefs.h"
#include "dcpregs_audiosources.hh"
#include "dcpregs_playstream.hh"
#include "mainloop.hh"

#include "mock_messages.hh"
#include "mock_backtrace.hh"
#include "mock_audiopath_dbus.hh"
#include "mock_dbus_iface.hh"

#include "test_registers_common.hh"

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

#if LOGGED_LOCKS_ENABLED && LOGGED_LOCKS_THREAD_CONTEXTS
thread_local LoggedLock::Context LoggedLock::context;
#endif

MainLoop::Queue MainLoop::detail::queued_work;

/*!
 * \addtogroup registers_tests Unit tests
 */
/*!@{*/

static ssize_t test_os_read(int fd, void *dest, size_t count)
{
    cut_fail("Unexpected call of os_read()");
    return -99999;
}

ssize_t (*os_read)(int fd, void *dest, size_t count) = test_os_read;

#if !LOGGED_LOCKS_ENABLED

namespace spi_registers_audio_sources
{

static MockMessages *mock_messages;
static MockBacktrace *mock_backtrace;
static MockAudiopathDBus *mock_audiopath_dbus;
static MockDBusIface *mock_dbus_iface;

static RegisterChangedData *register_changed_data;

std::unique_ptr<Regs::PlayStream::StreamingRegistersIface> streaming_regs;

static tdbusaupathManager *const dbus_audiopath_manager_iface_dummy =
    reinterpret_cast<tdbusaupathManager *>(0x1cf831e0);

static void register_changed_callback(uint8_t reg_number)
{
    register_changed_data->append(reg_number);
}

class ExpectedSourceData
{
  public:
    const std::string id_;
    const std::string description_;
    const bool is_browsable_;
    const bool is_initially_dead_;

    ExpectedSourceData(const ExpectedSourceData &) = delete;
    ExpectedSourceData(ExpectedSourceData &&) = default;
    ExpectedSourceData &operator=(const ExpectedSourceData &) = delete;

    explicit ExpectedSourceData(std::string &&id, std::string &&description,
                                bool is_browsable,
                                bool is_initially_dead = false):
        id_(std::move(id)),
        description_(std::move(description)),
        is_browsable_(is_browsable),
        is_initially_dead_(is_initially_dead)
    {}

    void serialize_full(std::vector<uint8_t> &out) const
    {
        serialize_base(out);
        out.push_back(compute_status());
    }

    void serialize_full(std::vector<uint8_t> &out, uint8_t status) const
    {
        serialize_base(out);
        out.push_back(status);
    }

    void serialize_update(std::vector<uint8_t> &out) const
    {
        serialize_id(out);
        out.push_back(compute_status());
    }

    void serialize_update(std::vector<uint8_t> &out, uint8_t status) const
    {
        serialize_id(out);
        out.push_back(status);
    }

  private:
    uint8_t compute_status() const
    {
        uint8_t status = 0x80;

        if(is_browsable_)
            status |= uint8_t(1U << 6);

        if(is_initially_dead_)
            status |= uint8_t(0x01 << 0);

        return status;
    }

    void serialize_id(std::vector<uint8_t> &out) const
    {
        std::copy(id_.begin(), id_.end(), std::back_inserter(out));
        out.push_back('\0');
    }

    void serialize_base(std::vector<uint8_t> &out) const
    {
        serialize_id(out);

        std::copy(description_.begin(), description_.end(), std::back_inserter(out));
        out.push_back('\0');
    }
};

static const std::array<ExpectedSourceData, 12> predefined_sources
{
    ExpectedSourceData("strbo.usb",            "USB devices",             true),
    ExpectedSourceData("strbo.upnpcm",         "UPnP media servers",      true),
    ExpectedSourceData("strbo.plainurl",       "TA Control",              false),
    ExpectedSourceData("airable",              "Airable",                 true),
    ExpectedSourceData("airable.radios",       "Airable Internet Radios", true),
    ExpectedSourceData("airable.feeds",        "Airable Podcasts",        true),
    ExpectedSourceData("airable.tidal",        "TIDAL",                   true),
    ExpectedSourceData("airable.deezer",       "Deezer",                  true),
    ExpectedSourceData("airable.qobuz",        "Qobuz",                   true),
    ExpectedSourceData("airable.highresaudio", "HIGHRESAUDIO",            true),
    ExpectedSourceData("roon",                 "Roon Ready",              false, true),
    ExpectedSourceData("",                     "Inactive",                false),
};

void cut_setup()
{
    register_changed_data = new RegisterChangedData;

    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_backtrace = new MockBacktrace;
    cppcut_assert_not_null(mock_backtrace);
    mock_backtrace->init();
    mock_backtrace_singleton = mock_backtrace;

    mock_audiopath_dbus = new MockAudiopathDBus();
    cppcut_assert_not_null(mock_audiopath_dbus);
    mock_audiopath_dbus->init();
    mock_audiopath_dbus_singleton = mock_audiopath_dbus;

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

    network_prefs_init(nullptr, nullptr);
    Regs::init(register_changed_callback, nullptr);
    streaming_regs = Regs::PlayStream::mk_streaming_registers();

    Regs::AudioSources::set_unit_test_mode();
}

void cut_teardown()
{
    Regs::deinit();
    network_prefs_deinit();
    streaming_regs = nullptr;

    register_changed_data->check();

    delete register_changed_data;
    register_changed_data = nullptr;

    mock_messages->check();
    mock_backtrace->check();
    mock_audiopath_dbus->check();
    mock_dbus_iface->check();

    mock_messages_singleton = nullptr;
    mock_backtrace_singleton = nullptr;
    mock_audiopath_dbus_singleton = nullptr;
    mock_dbus_iface_singleton = nullptr;

    delete mock_messages;
    delete mock_backtrace;
    delete mock_audiopath_dbus;
    delete mock_dbus_iface;

    mock_messages = nullptr;
    mock_backtrace = nullptr;
    mock_audiopath_dbus = nullptr;
    mock_dbus_iface = nullptr;
}

static void make_source_available(const char *source_id, const char *player_id,
                                  const char *source_dbusname, const char *source_dbuspath,
                                  uint8_t audio_source_status,
                                  const char *source_description = nullptr,
                                  const std::function<void()> &inject_expectations = nullptr)
{
    const auto found =
        std::find_if(predefined_sources.begin(), predefined_sources.end(),
                     [&source_id] (const ExpectedSourceData &src)
                     {
                         return src.id_ == source_id;
                     });

    cut_assert_true(found != predefined_sources.end());

    if(source_description == nullptr)
        source_description = found->description_.c_str();

    mock_dbus_iface->expect_dbus_get_audiopath_manager_iface(dbus_audiopath_manager_iface_dummy);
    mock_audiopath_dbus->expect_tdbus_aupath_manager_call_get_source_info_sync(
            dbus_audiopath_manager_iface_dummy, source_id,
            source_description, player_id, source_dbusname, source_dbuspath);

    if(inject_expectations != nullptr)
        inject_expectations();

    Regs::AudioSources::source_available(source_id);

    register_changed_data->check(80);

    /* see what's in register 80 */
    std::vector<uint8_t> expected;
    expected.push_back(0x80);
    expected.push_back(0x01);
    found->serialize_update(expected, audio_source_status);

    uint8_t buffer[256];
    std::fill(buffer, buffer + sizeof(buffer), 0xe7);

    cppcut_assert_equal(expected.size(),
                        Regs::lookup(80)->read(buffer, sizeof(buffer)));
    cut_assert_equal_memory(expected.data(), expected.size(),
                            buffer, expected.size());
    cppcut_assert_equal(uint16_t(0xe7), uint16_t(buffer[expected.size()]));
}

/*!\test
 * Our predefined audio sources are available, but marked completely
 * unavailable.
 */
void test_read_out_all_audio_sources_after_initialization()
{
    auto *reg = lookup_register_expect_handlers(80,
                                                Regs::AudioSources::DCP::read_80_get_known_audio_sources,
                                                Regs::AudioSources::DCP::write_80_get_known_audio_sources);

    static const uint8_t subcommand = 0x00;
    reg->write(&subcommand, sizeof(subcommand));
    register_changed_data->check(80);

    std::vector<uint8_t> expected;

    expected.push_back(0x00);  /* subcommand */
    expected.push_back(predefined_sources.size());

    for(const auto &src : predefined_sources)
        src.serialize_full(expected);

    uint8_t buffer[512];
    std::fill(buffer, buffer + sizeof(buffer), 0xe7);

    cppcut_assert_equal(expected.size(), reg->read(buffer, sizeof(buffer)));
    cut_assert_equal_memory(expected.data(), expected.size(),
                            buffer, expected.size());
    cppcut_assert_equal(uint16_t(0xe7), uint16_t(buffer[expected.size()]));
}

static void read_out_all_audio_sources_after_making_airable_available(bool is_online)
{
    make_source_available("airable",              "p", "de.tahifi.Airable", "dbus/airable", 0x42);
    make_source_available("airable.radios",       "p", "de.tahifi.Radios",  "dbus/radios",  0x42);
    make_source_available("airable.feeds",        "p", "de.tahifi.Feeds",   "dbus/feeds",   0x42);
    make_source_available("airable.tidal",        "p", "de.tahifi.Tidal",   "dbus/tidal",   0x44);
    make_source_available("airable.deezer",       "p", "de.tahifi.Deezer",  "dbus/deezer",  0x44);
    make_source_available("airable.qobuz",        "p", "de.tahifi.Qobuz",   "dbus/qobuz",   0x44);
    make_source_available("airable.highresaudio", "p", "de.tahifi.HRAudio", "dbus/hraudio", 0x44);

    auto *reg = lookup_register_expect_handlers(80,
                        Regs::AudioSources::DCP::read_80_get_known_audio_sources,
                        Regs::AudioSources::DCP::write_80_get_known_audio_sources);

    /* read out all audio source information after the audio paths have been
     * made available */
    static const uint8_t subcommand = 0x00;
    reg->write(&subcommand, sizeof(subcommand));
    register_changed_data->check(80);

    std::vector<uint8_t> expected;

    expected.push_back(0x00);  /* subcommand */
    expected.push_back(predefined_sources.size());

    for(const auto &src : predefined_sources)
    {
        if(src.id_.compare(0, 7, "airable") == 0)
        {
            uint8_t status = 1 << 6;

            if(src.id_ == "airable" ||
               src.id_ == "airable.radios" || src.id_ == "airable.feeds")
            {
                status |= uint8_t(0x02);
                status |= uint8_t((is_online ? 0x02 : 0x00) << 4);
            }
            else
            {
                status |= uint8_t(0x04);
                status |= uint8_t((is_online ? 0x01 : 0x00) << 4);
            }

            src.serialize_full(expected, status);
        }
        else
            src.serialize_full(expected);
    }

    uint8_t buffer[512];
    std::fill(buffer, buffer + sizeof(buffer), 0xe7);

    cppcut_assert_equal(expected.size(), reg->read(buffer, sizeof(buffer)));
    cut_assert_equal_memory(expected.data(), expected.size(),
                            buffer, expected.size());
    cppcut_assert_equal(uint16_t(0xe7), uint16_t(buffer[expected.size()]));
}

/*!\test
 * We assume that Airable services have registered, but others have not.
 * Further, we assume we are offline.
 */
void test_read_out_all_audio_sources_after_making_some_sources_available_offline()
{
    read_out_all_audio_sources_after_making_airable_available(false);
}

/*!\test
 * We assume nothing on initialization and do not query the current audio path.
 */
void test_current_audio_source_is_empty_after_initialization()
{
    auto *reg = lookup_register_expect_handlers(81,
                        Regs::AudioSources::DCP::read_81_current_audio_source,
                        Regs::AudioSources::DCP::write_81_current_audio_source);

    uint8_t buffer[32] = {0xc7, 0xc8};
    cppcut_assert_equal(size_t(1), reg->read(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(0x00), buffer[0]);
    cppcut_assert_equal(uint8_t(0xc8), buffer[1]);
}

/*!\test
 * Selection of audio source is not reported back immediately.
 */
void test_selection_of_known_alive_source_reports_selection_asynchronously()
{
    auto *reg = lookup_register_expect_handlers(81,
                        Regs::AudioSources::DCP::read_81_current_audio_source,
                        Regs::AudioSources::DCP::write_81_current_audio_source);

    static const char asrc[] = "strbo.usb";
    static const char player[] = "usb_player";

    make_source_available(asrc, player, "de.tahifi.MySource", "/some/dbus/path", 0x62);

    mock_dbus_iface->expect_dbus_get_audiopath_manager_iface(dbus_audiopath_manager_iface_dummy);
    mock_audiopath_dbus->expect_tdbus_aupath_manager_call_request_source(
            dbus_audiopath_manager_iface_dummy, asrc, player, true, false);

    reg->write(reinterpret_cast<const uint8_t *>(asrc), sizeof(asrc));

    /* source is still empty because successful switch is reported
     * asynchronously */
    uint8_t buffer[32] = {0xc7, 0xc8};
    cppcut_assert_equal(size_t(1), reg->read(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(0x00), buffer[0]);
    cppcut_assert_equal(uint8_t(0xc8), buffer[1]);
}

/*!\test
 * Selection of audio source followed by asynchronous notification.
 */
void test_selection_of_known_alive_source_with_async_notification()
{
    auto *reg = lookup_register_expect_handlers(81,
                        Regs::AudioSources::DCP::read_81_current_audio_source,
                        Regs::AudioSources::DCP::write_81_current_audio_source);

    static const char asrc[] = "strbo.usb";
    static const char player[] = "usb_player";

    make_source_available(asrc, player, "de.tahifi.MySource", "/some/dbus/path", 0x62);

    mock_dbus_iface->expect_dbus_get_audiopath_manager_iface(dbus_audiopath_manager_iface_dummy);
    mock_audiopath_dbus->expect_tdbus_aupath_manager_call_request_source(
            dbus_audiopath_manager_iface_dummy, asrc, player, true, false);

    reg->write(reinterpret_cast<const uint8_t *>(asrc), sizeof(asrc));

    /* this function should be called from a D-Bus handler that monitors audio
     * path changes */
    Regs::AudioSources::selected_source(asrc, false);
    register_changed_data->check(81);

    /* now the register contains our selected audio source ID */
    uint8_t buffer[32] = {0xc7};
    cppcut_assert_equal(sizeof(asrc), reg->read(buffer, sizeof(buffer)));
    cut_assert_equal_memory(asrc, sizeof(asrc), buffer, sizeof(asrc));
}

/*!\test
 * Selection of audio source may be deferred to much later until the audio path
 * is actually usable.
 */
void test_selection_of_known_alive_source_is_done_when_possible()
{
    auto *reg = lookup_register_expect_handlers(81,
                        Regs::AudioSources::DCP::read_81_current_audio_source,
                        Regs::AudioSources::DCP::write_81_current_audio_source);

    static const char asrc[] = "strbo.usb";
    static const char player[] = "usb_player";

    reg->write(reinterpret_cast<const uint8_t *>(asrc), sizeof(asrc));

    /* source is still empty because (1) the audio path (thus the audio source)
     * is not usable yet, and (2) a successful switch of audio path is reported
     * asynchronously */
    uint8_t buffer[32] = {0xc7, 0xc8};
    cppcut_assert_equal(size_t(1), reg->read(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(0x00), buffer[0]);
    cppcut_assert_equal(uint8_t(0xc8), buffer[1]);

    /* path is available now (reported via D-Bus) after both, player and
     * source, have started and registered their parts */
    make_source_available(asrc, player, "de.tahifi.MyUSBSource", "/some/dbus/path", 0x62,
                          "All my USB devices",
                          [] ()
                          {
                              mock_dbus_iface->expect_dbus_get_audiopath_manager_iface(dbus_audiopath_manager_iface_dummy);
                              mock_audiopath_dbus->expect_tdbus_aupath_manager_call_request_source(
                                      dbus_audiopath_manager_iface_dummy, asrc, player, true, false);
                          });

    cppcut_assert_equal(size_t(1), reg->read(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(0x00), buffer[0]);
    cppcut_assert_equal(uint8_t(0xc8), buffer[1]);

    /* audio path has been changed as reported by calling the following
     * function (called from D-Bus handler) */
    Regs::AudioSources::selected_source(asrc, false);
    register_changed_data->check(81);

    cppcut_assert_equal(sizeof(asrc), reg->read(buffer, sizeof(buffer)));
    cut_assert_equal_memory(asrc, sizeof(asrc), buffer, sizeof(asrc));
}

/*!\test
 * Changes of audio source notified by the audio path manager are always
 * forwarded to SPI slave.
 */
void test_unrequested_change_of_known_audio_path_is_propagated_to_spi_slave()
{
    auto *reg = lookup_register_expect_handlers(81,
                        Regs::AudioSources::DCP::read_81_current_audio_source,
                        Regs::AudioSources::DCP::write_81_current_audio_source);

    static const char asrc[] = "roon";

    /* this function should be called from a D-Bus handler that monitors audio
     * path changes */
    Regs::AudioSources::selected_source(asrc, false);
    register_changed_data->check(81);

    /* the register now contains some audio source ID */
    uint8_t buffer[32] = {0xc7};
    cppcut_assert_equal(sizeof(asrc), reg->read(buffer, sizeof(buffer)));
    cut_assert_equal_memory(asrc, sizeof(asrc), buffer, sizeof(asrc));
}

/*!\test
 * Test future compatibility with new audio sources. Don't crash, behave
 * nicely.
 */
void test_unrequested_change_of_unknown_audio_path_is_propagated_to_spi_slave()
{
    auto *reg = lookup_register_expect_handlers(81,
                        Regs::AudioSources::DCP::read_81_current_audio_source,
                        Regs::AudioSources::DCP::write_81_current_audio_source);

    static const char asrc[] = "new_streaming_service";

    /* this function should be called from a D-Bus handler that monitors audio
     * path changes */
    Regs::AudioSources::selected_source(asrc, false);
    register_changed_data->check(81);

    /* the register now contains some audio source ID */
    uint8_t buffer[32] = {0xc7};
    cppcut_assert_equal(sizeof(asrc), reg->read(buffer, sizeof(buffer)));
    cut_assert_equal_memory(asrc, sizeof(asrc), buffer, sizeof(asrc));
}

/*!\test
 * Unusable sources can be selected. They just won't do anything useful.
 */
void test_selection_of_known_unusable_source()
{
    auto *reg = lookup_register_expect_handlers(81,
                        Regs::AudioSources::DCP::read_81_current_audio_source,
                        Regs::AudioSources::DCP::write_81_current_audio_source);

    static const char asrc[] = "strbo.upnpcm";
    reg->write(reinterpret_cast<const uint8_t *>(asrc), sizeof(asrc));

    Regs::AudioSources::selected_source(asrc, false);
    register_changed_data->check(81);

    uint8_t buffer[32] = {0xc7};
    cppcut_assert_equal(sizeof(asrc), reg->read(buffer, sizeof(buffer)));
    cut_assert_equal_memory(asrc, sizeof(asrc), buffer, sizeof(asrc));
}

using RequestSourceResultBundle =
    std::tuple<tdbusaupathManager *, GCancellable *,
               GAsyncReadyCallback, void *,
               MockAudiopathDBus::ManagerRequestSourceResult>;

static void receive_async_result(tdbusaupathManager *proxy,
                                 const gchar *source_id, GCancellable *cancellable,
                                 GAsyncReadyCallback callback, void *user_data,
                                 MockAudiopathDBus::ManagerRequestSourceResult &&result,
                                 RequestSourceResultBundle &bundle)
{
    bundle = std::move(RequestSourceResultBundle(proxy, cancellable,
                                                 callback, user_data,
                                                 std::move(result)));
}

/*!\test
 * Switch request to a source while switching to the same source is ignored.
 * This is for impatient slaves and/or slow audio sources.
 */
void test_quickly_selecting_audio_source_twice_switches_once()
{
    static const char asrc[] = "strbo.usb";
    static const char player[] = "usb_player";

    make_source_available(asrc, player, "usb_source", "/some/dbus/path", 0x62);

    auto *reg = lookup_register_expect_handlers(81,
                        Regs::AudioSources::DCP::read_81_current_audio_source,
                        Regs::AudioSources::DCP::write_81_current_audio_source);

    RequestSourceResultBundle result;

    mock_dbus_iface->expect_dbus_get_audiopath_manager_iface(dbus_audiopath_manager_iface_dummy);
    mock_audiopath_dbus->expect_tdbus_aupath_manager_call_request_source(
            dbus_audiopath_manager_iface_dummy, asrc, player, true,
            std::bind(receive_async_result,
                      std::placeholders::_1, std::placeholders::_2,
                      std::placeholders::_3, std::placeholders::_4,
                      std::placeholders::_5, std::placeholders::_6,
                      std::ref(result)));

    reg->write(reinterpret_cast<const uint8_t *>(asrc), sizeof(asrc));

    cppcut_assert_not_null(std::get<0>(result));
    mock_dbus_iface->check();
    mock_audiopath_dbus->check();

    /* the request for audio source has not finished yet, but here comes yet
     * another request for the same thing; nothing happens */
    reg->write(reinterpret_cast<const uint8_t *>(asrc), sizeof(asrc));

    /* and a few more */
    reg->write(reinterpret_cast<const uint8_t *>(asrc), sizeof(asrc));
    reg->write(reinterpret_cast<const uint8_t *>(asrc), sizeof(asrc));
    reg->write(reinterpret_cast<const uint8_t *>(asrc), sizeof(asrc));
    reg->write(reinterpret_cast<const uint8_t *>(asrc), sizeof(asrc));

    /* finally received the answer for the first request */
    MockAudiopathDBus::aupath_manager_request_source_result(std::get<0>(result),
                                                            std::get<1>(result),
                                                            std::get<2>(result),
                                                            std::get<3>(result),
                                                            std::move(std::get<4>(result)));
}

/*!\test
 * Switch request to a source while switching to another source cancels the
 * first request. This is for impatient users and/or slow or unresponsive audio
 * sources.
 */
void test_quickly_selecting_different_audio_source_during_switch_cancels_first_switch()
{
    static const char asrc_upnp[] = "strbo.upnpcm";
    static const char asrc_usb[]  = "strbo.usb";
    static const char player_upnp[] = "upnp_player";
    static const char player_usb[]  = "usb_player";

    make_source_available(asrc_upnp, player_upnp, "de.tahifi.UPnP", "/dbus/upnp", 0x42);
    make_source_available(asrc_usb,  player_usb,  "de.tahifi.USB",  "/dbus/usb",  0x62);

    auto *reg = lookup_register_expect_handlers(81,
                        Regs::AudioSources::DCP::read_81_current_audio_source,
                        Regs::AudioSources::DCP::write_81_current_audio_source);

    /* request UPnP audio source */
    RequestSourceResultBundle upnp_result;

    mock_dbus_iface->expect_dbus_get_audiopath_manager_iface(dbus_audiopath_manager_iface_dummy);
    mock_audiopath_dbus->expect_tdbus_aupath_manager_call_request_source(
            dbus_audiopath_manager_iface_dummy, asrc_upnp, player_upnp, true,
            std::bind(receive_async_result,
                      std::placeholders::_1, std::placeholders::_2,
                      std::placeholders::_3, std::placeholders::_4,
                      std::placeholders::_5, std::placeholders::_6,
                      std::ref(upnp_result)));

    reg->write(reinterpret_cast<const uint8_t *>(asrc_upnp), sizeof(asrc_upnp));

    cppcut_assert_not_null(std::get<0>(upnp_result));
    mock_dbus_iface->check();
    mock_audiopath_dbus->check();

    /* request USB audio source while selection of UPnP audio source has not
     * finished yet */
    RequestSourceResultBundle usb_result;

    mock_dbus_iface->expect_dbus_get_audiopath_manager_iface(dbus_audiopath_manager_iface_dummy);
    mock_audiopath_dbus->expect_tdbus_aupath_manager_call_request_source(
            dbus_audiopath_manager_iface_dummy, asrc_usb, player_usb, true,
            std::bind(receive_async_result,
                      std::placeholders::_1, std::placeholders::_2,
                      std::placeholders::_3, std::placeholders::_4,
                      std::placeholders::_5, std::placeholders::_6,
                      std::ref(usb_result)));

    reg->write(reinterpret_cast<const uint8_t *>(asrc_usb), sizeof(asrc_usb));

    cppcut_assert_not_null(std::get<0>(usb_result));
    mock_dbus_iface->check();
    mock_audiopath_dbus->check();

    /* finally received the answer for the first request */
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Canceled audio source request");

    MockAudiopathDBus::aupath_manager_request_source_result(std::get<0>(upnp_result),
                                                            std::get<1>(upnp_result),
                                                            std::get<2>(upnp_result),
                                                            std::get<3>(upnp_result),
                                                            std::move(std::get<4>(upnp_result)));

    /* ...and for the second request */
    MockAudiopathDBus::aupath_manager_request_source_result(std::get<0>(usb_result),
                                                            std::get<1>(usb_result),
                                                            std::get<2>(usb_result),
                                                            std::get<3>(usb_result),
                                                            std::move(std::get<4>(usb_result)));

    uint8_t buffer[32] = {0xc7, 0xc8};
    cppcut_assert_equal(size_t(1), reg->read(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(0x00), buffer[0]);
    cppcut_assert_equal(uint8_t(0xc8), buffer[1]);

    /* a bit later, the notification about audio path change */
    Regs::AudioSources::selected_source(asrc_usb, false);
    register_changed_data->check(81);

    cppcut_assert_equal(sizeof(asrc_usb), reg->read(buffer, sizeof(buffer)));
    cut_assert_equal_memory(asrc_usb, sizeof(asrc_usb), buffer, sizeof(asrc_usb));
}

/*!\test
 * Dead sources cannot be selected.
 */
void test_selection_of_known_dead_source_yields_error()
{
    auto *reg = lookup_register_expect_handlers(81,
                        Regs::AudioSources::DCP::read_81_current_audio_source,
                        Regs::AudioSources::DCP::write_81_current_audio_source);

    static const char asrc[] = "roon";
    mock_messages->expect_msg_error_formatted(0, LOG_NOTICE,
                                              "Audio source \"roon\" is dead");
    write_buffer_expect_failure(reg, reinterpret_cast<const uint8_t *>(asrc), sizeof(asrc), -1);

    uint8_t buffer[32] = {0xc7, 0xc8};
    cppcut_assert_equal(size_t(1), reg->read(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(0x00), buffer[0]);
    cppcut_assert_equal(uint8_t(0xc8), buffer[1]);
}

/*!\test
 * Unknown sources cannot be selected.
 */
void test_selection_of_unknown_source_yields_error()
{
    auto *reg = lookup_register_expect_handlers(81,
                        Regs::AudioSources::DCP::read_81_current_audio_source,
                        Regs::AudioSources::DCP::write_81_current_audio_source);

    static const char asrc[] = "doesnotexist";
    mock_messages->expect_msg_error_formatted(0, LOG_NOTICE,
                                              "Audio source \"doesnotexist\" not known");
    write_buffer_expect_failure(reg, reinterpret_cast<const uint8_t *>(asrc), sizeof(asrc), -1);

    uint8_t buffer[32] = {0xc7, 0xc8};
    cppcut_assert_equal(size_t(1), reg->read(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(0x00), buffer[0]);
    cppcut_assert_equal(uint8_t(0xc8), buffer[1]);
}

/*!\test
 * Spurious deselection of audio source is reported as bug.
 */
void test_spurious_deselection_of_audio_source_emits_bug_message()
{
    mock_messages->expect_msg_error(0, LOG_CRIT,
                                    "BUG: Plain URL audio source not selected");
    streaming_regs->audio_source_deselected();
}

/*!\test
 * Selection of idle source right after initialization works.
 */
void test_selection_of_idle_source()
{
    auto *reg = lookup_register_expect_handlers(81,
                        Regs::AudioSources::DCP::read_81_current_audio_source,
                        Regs::AudioSources::DCP::write_81_current_audio_source);

    mock_messages->expect_msg_info("Inactive state requested");
    mock_dbus_iface->expect_dbus_get_audiopath_manager_iface(dbus_audiopath_manager_iface_dummy);
    mock_audiopath_dbus->expect_tdbus_aupath_manager_call_release_path(
            dbus_audiopath_manager_iface_dummy, true);

    const uint8_t empty = 0;
    reg->write(&empty, sizeof(empty));

    /* the register still contains the empty audio source */
    uint8_t buffer[2] = {0x82, 0xeb};
    cppcut_assert_equal(size_t(1), reg->read(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(0x00), buffer[0]);
    cppcut_assert_equal(uint8_t(0xeb), buffer[1]);
}

/*!\test
 * Selection of audio source is not reported back immediately.
 */
void test_selection_of_real_source_followed_by_idle_source()
{
    auto *reg = lookup_register_expect_handlers(81,
                        Regs::AudioSources::DCP::read_81_current_audio_source,
                        Regs::AudioSources::DCP::write_81_current_audio_source);

    static const char asrc[] = "strbo.upnpcm";
    static const char player[] = "upnp_player";

    make_source_available(asrc, player, "de.tahifi.MySource", "/some/dbus/path", 0x42);

    mock_dbus_iface->expect_dbus_get_audiopath_manager_iface(dbus_audiopath_manager_iface_dummy);
    mock_audiopath_dbus->expect_tdbus_aupath_manager_call_request_source(
            dbus_audiopath_manager_iface_dummy, asrc, player, true, false);

    reg->write(reinterpret_cast<const uint8_t *>(asrc), sizeof(asrc));

    /* this function should be called from a D-Bus handler that monitors audio
     * path changes */
    Regs::AudioSources::selected_source(asrc, false);
    register_changed_data->check(81);

    /* now the register contains our selected audio source ID */
    uint8_t buffer[32] = {0x19};
    cppcut_assert_equal(sizeof(asrc), reg->read(buffer, sizeof(buffer)));
    cut_assert_equal_memory(asrc, sizeof(asrc), buffer, sizeof(asrc));

    /* enter idle state */
    mock_messages->expect_msg_info("Inactive state requested");
    mock_dbus_iface->expect_dbus_get_audiopath_manager_iface(dbus_audiopath_manager_iface_dummy);
    mock_audiopath_dbus->expect_tdbus_aupath_manager_call_release_path(
            dbus_audiopath_manager_iface_dummy, true);

    const uint8_t empty = 0;
    reg->write(&empty, sizeof(empty));

    /* this function should be called from a D-Bus handler that monitors audio
     * path changes */
    Regs::AudioSources::selected_source("", false);
    register_changed_data->check(81);

    /* the register contains the empty audio source again */
    buffer[0] = 0xbc;
    buffer[1] = 0xf1;
    cppcut_assert_equal(size_t(1), reg->read(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(0x00), buffer[0]);
    cppcut_assert_equal(uint8_t(0xf1), buffer[1]);
}

/*!\test
 * We first select some proper audio source, then go back to inactive state for
 * the purpose of suspending the appliance.
 *
 * The appliance is supposed to append an appropriate option to the destination
 * source to communicate a reason for the audio source switch.
 */
void test_selection_of_inactive_state_for_suspend()
{
    auto *reg = lookup_register_expect_handlers(81,
                        Regs::AudioSources::DCP::read_81_current_audio_source,
                        Regs::AudioSources::DCP::write_81_current_audio_source);

    static const char asrc[] = "strbo.upnpcm";
    static const char player[] = "upnp_player";

    make_source_available(asrc, player, "de.tahifi.MySource", "/some/dbus/path", 0x42);

    mock_dbus_iface->expect_dbus_get_audiopath_manager_iface(dbus_audiopath_manager_iface_dummy);
    mock_audiopath_dbus->expect_tdbus_aupath_manager_call_request_source(
            dbus_audiopath_manager_iface_dummy, asrc, player, true, false);

    reg->write(reinterpret_cast<const uint8_t *>(asrc), sizeof(asrc));

    /* this function should be called from a D-Bus handler that monitors audio
     * path changes */
    Regs::AudioSources::selected_source(asrc, false);
    register_changed_data->check(81);

    /* now the register contains our selected audio source ID */
    uint8_t buffer[32] = {0x19};
    cppcut_assert_equal(sizeof(asrc), reg->read(buffer, sizeof(buffer)));
    cut_assert_equal_memory(asrc, sizeof(asrc), buffer, sizeof(asrc));

    /* enter idle state */
    mock_messages->expect_msg_info("Inactive state requested");
    mock_dbus_iface->expect_dbus_get_audiopath_manager_iface(dbus_audiopath_manager_iface_dummy);

    GVariantDict dict;
    g_variant_dict_init(&dict, nullptr);
    g_variant_dict_insert_value(&dict, "suspend", g_variant_new_boolean(TRUE));
    auto request_data(GVariantWrapper(g_variant_dict_end(&dict)));

    mock_audiopath_dbus->expect_tdbus_aupath_manager_call_release_path(
            dbus_audiopath_manager_iface_dummy, true, std::move(request_data));

    const char suspend[] = ":suspend";
    reg->write(reinterpret_cast<const uint8_t *>(suspend), sizeof(suspend));

    /* this function should be called from a D-Bus handler that monitors audio
     * path changes */
    Regs::AudioSources::selected_source("", false);
    register_changed_data->check(81);

    /* the register contains the empty audio source again */
    buffer[0] = 0xbc;
    buffer[1] = 0xf1;
    cppcut_assert_equal(size_t(1), reg->read(buffer, sizeof(buffer)));
    cppcut_assert_equal(uint8_t(0x00), buffer[0]);
    cppcut_assert_equal(uint8_t(0xf1), buffer[1]);
}

/*!\test
 * Audio source option string parsing is done properly.
 */
void test_audio_source_request_option_parser()
{
    auto *reg = lookup_register_expect_handlers(81,
                        Regs::AudioSources::DCP::read_81_current_audio_source,
                        Regs::AudioSources::DCP::write_81_current_audio_source);

    static const char asrc[] = "strbo.upnpcm";
    static const char player[] = "upnp_player";

    make_source_available(asrc, player, "de.tahifi.MySource", "/some/dbus/path", 0x42);

    std::string asrc_with_options(asrc);
    asrc_with_options += ":flag,key=value,k=,,,, =space,a=b=c=d,n=m=i,x==,  =   ";
    asrc_with_options += ",\\=,\\=a,a\\=,\\=\\,,\\,\\=";
    asrc_with_options += ",\\=x==,x\\===\\=,y=\\==\\=,\\,a,a\\,,\\,x\\,==";
    asrc_with_options += ",col=:,\\\\,a\\\\=x,t=\\\\";

    GVariantDict dict;
    g_variant_dict_init(&dict, nullptr);

    g_variant_dict_insert_value(&dict, "flag", g_variant_new_boolean(TRUE));
    g_variant_dict_insert_value(&dict, "key",  g_variant_new_string("value"));
    g_variant_dict_insert_value(&dict, "k",    g_variant_new_string(""));
    g_variant_dict_insert_value(&dict, " ",    g_variant_new_string("space"));
    g_variant_dict_insert_value(&dict, "  ",   g_variant_new_string("   "));
    g_variant_dict_insert_value(&dict, "a",    g_variant_new_string("b=c=d"));
    g_variant_dict_insert_value(&dict, "n",    g_variant_new_string("m=i"));
    g_variant_dict_insert_value(&dict, "x",    g_variant_new_string("="));

    g_variant_dict_insert_value(&dict, "=",    g_variant_new_boolean(TRUE));
    g_variant_dict_insert_value(&dict, "=a",   g_variant_new_boolean(TRUE));
    g_variant_dict_insert_value(&dict, "a=",   g_variant_new_boolean(TRUE));
    g_variant_dict_insert_value(&dict, "=,",   g_variant_new_boolean(TRUE));
    g_variant_dict_insert_value(&dict, ",=",   g_variant_new_boolean(TRUE));

    g_variant_dict_insert_value(&dict, "=x",   g_variant_new_string("="));
    g_variant_dict_insert_value(&dict, "x=",   g_variant_new_string("=="));
    g_variant_dict_insert_value(&dict, "y",    g_variant_new_string("==="));
    g_variant_dict_insert_value(&dict, ",a",   g_variant_new_boolean(TRUE));
    g_variant_dict_insert_value(&dict, "a,",   g_variant_new_boolean(TRUE));
    g_variant_dict_insert_value(&dict, ",x,",  g_variant_new_string("="));

    g_variant_dict_insert_value(&dict, "col",  g_variant_new_string(":"));
    g_variant_dict_insert_value(&dict, "\\",   g_variant_new_boolean(TRUE));
    g_variant_dict_insert_value(&dict, "a\\",  g_variant_new_string("x"));
    g_variant_dict_insert_value(&dict, "t",    g_variant_new_string("\\"));

    auto request_data(GVariantWrapper(g_variant_dict_end(&dict)));

    mock_dbus_iface->expect_dbus_get_audiopath_manager_iface(dbus_audiopath_manager_iface_dummy);
    mock_audiopath_dbus->expect_tdbus_aupath_manager_call_request_source(
            dbus_audiopath_manager_iface_dummy, asrc, player, true, nullptr,
            std::move(request_data));

    reg->write(reinterpret_cast<const uint8_t *>(asrc_with_options.c_str()), asrc_with_options.length() + 1);
}

/*!\test
 * Audio source option string parsing can fail.
 */
void test_audio_source_request_option_parser_rejects_malformed_options()
{
    auto *reg = lookup_register_expect_handlers(81,
                        Regs::AudioSources::DCP::read_81_current_audio_source,
                        Regs::AudioSources::DCP::write_81_current_audio_source);

    static const char asrc[] = "strbo.upnpcm";
    static const char player[] = "upnp_player";

    make_source_available(asrc, player, "de.tahifi.MySource", "/some/dbus/path", 0x42);

    static const std::array<const char *const, 7> broken_strings
    {
        ":=x",
        ":,=x",
        ":,a=b,=x",
        ":a=b,=x",
        ":a=b,=x,c",
        ":a=\\",
        ":\\",
    };

    for(const auto &broken : broken_strings)
    {
        std::string asrc_with_options(asrc);
        asrc_with_options += broken;

        mock_messages->expect_msg_error_formatted(EINVAL, LOG_NOTICE,
                "Invalid audio source options (Invalid argument)");

        write_buffer_expect_failure(reg,
                                    reinterpret_cast<const uint8_t *>(asrc_with_options.c_str()),
                                    asrc_with_options.length() + 1, -1);
    }
}

}

#endif /* !LOGGED_LOCKS_ENABLED  */

/*!@}*/
