/*
 * Copyright (C) 2020, 2021, 2022  T+A elektroakustik GmbH & Co. KG
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
#include <memory>

#include "registers.hh"
#include "networkprefs.h"
#include "dcpregs_playstream.hh"
#include "mainloop.hh"
#include "stream_id.hh"

#include "mock_messages.hh"
#include "mock_backtrace.hh"
#include "mock_streamplayer_dbus.hh"
#include "mock_artcache_dbus.hh"
#include "mock_dcpd_dbus.hh"
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

namespace spi_registers_play_app_stream
{

static MockMessages *mock_messages;
static MockBacktrace *mock_backtrace;
static MockStreamplayerDBus *mock_streamplayer_dbus;
static MockArtCacheDBus *mock_artcache_dbus;
static MockDcpdDBus *mock_dcpd_dbus;
static MockAudiopathDBus *mock_audiopath_dbus;
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

static tdbusaupathManager *const dbus_audiopath_manager_iface_dummy =
    reinterpret_cast<tdbusaupathManager *>(0x9ccb816a);

using OurStream = ::ID::SourcedStream<STREAM_ID_SOURCE_APP>;

std::unique_ptr<Regs::PlayStream::StreamingRegistersIface> streaming_regs;
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

    mock_backtrace = new MockBacktrace;
    cppcut_assert_not_null(mock_backtrace);
    mock_backtrace->init();
    mock_backtrace_singleton = mock_backtrace;

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
    Regs::PlayStream::DCP::init(*streaming_regs);
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
    mock_streamplayer_dbus->check();
    mock_artcache_dbus->check();
    mock_dcpd_dbus->check();
    mock_audiopath_dbus->check();
    mock_dbus_iface->check();

    mock_messages_singleton = nullptr;
    mock_backtrace_singleton = nullptr;
    mock_streamplayer_dbus_singleton = nullptr;
    mock_artcache_dbus_singleton = nullptr;
    mock_dcpd_dbus_singleton = nullptr;
    mock_audiopath_dbus_singleton = nullptr;
    mock_dbus_iface_singleton = nullptr;

    delete mock_messages;
    delete mock_backtrace;
    delete mock_streamplayer_dbus;
    delete mock_artcache_dbus;
    delete mock_dcpd_dbus;
    delete mock_audiopath_dbus;
    delete mock_dbus_iface;

    mock_messages = nullptr;
    mock_backtrace = nullptr;
    mock_streamplayer_dbus = nullptr;
    mock_artcache_dbus = nullptr;
    mock_dcpd_dbus = nullptr;
    mock_audiopath_dbus = nullptr;
    mock_dbus_iface = nullptr;
}

enum class SetTitleAndURLFlowAssumptions
{
    DESELECTED__STOPPED__KEEP_DESELECTED,
    DESELECTED__PLAYING__KEEP_DESELECTED,
    DESELECTED__PLAYING__SELECT,
    DESELECTED__SELECT,
    SELECTED__STOPPED__KEEP_SELECTED,
    SELECTED__PLAY_REQUESTED__KEEP_SELECTED,
    SELECTED__PLAYING__KEEP_SELECTED,
};

enum class SetTitleAndURLSystemAssumptions
{
    IMMEDIATE_RESPONSE,
    IMMEDIATE_AUDIO_SOURCE_SELECTION,
    IMMEDIATE_NOW_PLAYING_STATUS,
    NO_RESPONSE,
};

static constexpr const char *const audio_source_id = "strbo.plainurl";

static void set_stream_meta_data_dump_expectations(const std::string &prefix,
                                                   const std::string &artist,
                                                   const std::string &album,
                                                   const std::string &title)
{
    mock_messages->expect_msg_is_verbose(true, MESSAGE_LEVEL_NORMAL);
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_NORMAL, (prefix + " artist: \"" + artist + "\"").c_str());
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_NORMAL, (prefix + " album : \"" + album + "\"").c_str());
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_NORMAL, (prefix + " title : \"" + title + '"').c_str());
}

static void set_start_title(const std::string expected_artist,
                            const std::string expected_album,
                            const std::string expected_title,
                            const uint8_t *title, size_t length,
                            SetTitleAndURLFlowAssumptions flow_assumptions,
                            SetTitleAndURLSystemAssumptions system_assumptions)
{
    switch(flow_assumptions)
    {
      case SetTitleAndURLFlowAssumptions::DESELECTED__SELECT:
      case SetTitleAndURLFlowAssumptions::DESELECTED__PLAYING__SELECT:
        /* request plain URL audio source */
        mock_dbus_iface->expect_dbus_get_audiopath_manager_iface(dbus_audiopath_manager_iface_dummy);
        mock_audiopath_dbus->expect_tdbus_aupath_manager_call_request_source(dbus_audiopath_manager_iface_dummy, audio_source_id);
        break;

      case SetTitleAndURLFlowAssumptions::DESELECTED__STOPPED__KEEP_DESELECTED:
      case SetTitleAndURLFlowAssumptions::SELECTED__STOPPED__KEEP_SELECTED:
      case SetTitleAndURLFlowAssumptions::SELECTED__PLAY_REQUESTED__KEEP_SELECTED:
      case SetTitleAndURLFlowAssumptions::DESELECTED__PLAYING__KEEP_DESELECTED:
      case SetTitleAndURLFlowAssumptions::SELECTED__PLAYING__KEEP_SELECTED:
        break;
    }

    set_stream_meta_data_dump_expectations("First stream meta data (reg 78)",
                                           expected_artist, expected_album, expected_title);

    const auto *const reg = Regs::lookup(78);

    reg->write(title, length);

    mock_dbus_iface->check();
    mock_audiopath_dbus->check();
    mock_messages->check();

    switch(system_assumptions)
    {
      case SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE:
      case SetTitleAndURLSystemAssumptions::IMMEDIATE_AUDIO_SOURCE_SELECTION:
        /* audio source selection immediately acknowledged */
        streaming_regs->audio_source_selected();
        break;

      case SetTitleAndURLSystemAssumptions::IMMEDIATE_NOW_PLAYING_STATUS:
      case SetTitleAndURLSystemAssumptions::NO_RESPONSE:
        break;
    }

    mock_messages->check();
}

static void set_start_title(const std::string expected_artist,
                            const std::string expected_album,
                            const std::string expected_title,
                            const std::string title,
                            SetTitleAndURLFlowAssumptions flow_assumptions,
                            SetTitleAndURLSystemAssumptions system_assumptions)
{
    set_start_title(expected_artist, expected_album, expected_title,
                    reinterpret_cast<const uint8_t *>(title.c_str()),
                    title.length(), flow_assumptions, system_assumptions);
}

static void set_start_title(const std::string title,
                            SetTitleAndURLFlowAssumptions flow_assumptions,
                            SetTitleAndURLSystemAssumptions system_assumptions)
{
    set_start_title("", "", title,
                    reinterpret_cast<const uint8_t *>(title.c_str()),
                    title.length(), flow_assumptions, system_assumptions);
}

static void set_next_title(const std::string title)
{
    set_stream_meta_data_dump_expectations("Next stream meta data (reg 238)",
                                           "", "", title);
    const auto *const reg = Regs::lookup(238);
    reg->write(reinterpret_cast<const uint8_t *>(title.c_str()), title.length());
}

static GVariantWrapper hash_to_variant(const MD5::Hash &hash)
{
    return GVariantWrapper(g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE,
                                                     hash.data(), hash.size(),
                                                     sizeof(hash[0])));
}

static GVariant *
to_stream_meta_data(const std::string &artist, const std::string &album,
                    const std::string &title, const std::string &alttrack)
{
    GVariantBuilder builder;
    g_variant_builder_init(&builder, G_VARIANT_TYPE("a(ss)"));
    g_variant_builder_add(&builder, "(ss)", "artist", artist.c_str());
    g_variant_builder_add(&builder, "(ss)", "album", album.c_str());
    g_variant_builder_add(&builder, "(ss)", "title", title.c_str());
    g_variant_builder_add(&builder, "(ss)", "x-drcpd-title", alttrack.c_str());
    return g_variant_builder_end(&builder);
}

static void set_start_playing_expectations(const std::string expected_artist,
                                           const std::string expected_album,
                                           const std::string expected_title,
                                           const std::string expected_alttrack,
                                           const std::string url,
                                           const OurStream stream_id,
                                           const MD5::Hash &hash,
                                           SetTitleAndURLFlowAssumptions flow_assumptions,
                                           SetTitleAndURLSystemAssumptions system_assumptions)
{
    bool assume_already_playing = false;
    bool expecting_start_playing_command = false;
    bool expecting_play_view_activation = false;

    switch(flow_assumptions)
    {
      case SetTitleAndURLFlowAssumptions::DESELECTED__STOPPED__KEEP_DESELECTED:
        break;

      case SetTitleAndURLFlowAssumptions::DESELECTED__SELECT:
      case SetTitleAndURLFlowAssumptions::SELECTED__STOPPED__KEEP_SELECTED:
      case SetTitleAndURLFlowAssumptions::SELECTED__PLAY_REQUESTED__KEEP_SELECTED:
        switch(system_assumptions)
        {
          case SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE:
          case SetTitleAndURLSystemAssumptions::IMMEDIATE_AUDIO_SOURCE_SELECTION:
            expecting_start_playing_command = true;
            break;

          case SetTitleAndURLSystemAssumptions::IMMEDIATE_NOW_PLAYING_STATUS:
          case SetTitleAndURLSystemAssumptions::NO_RESPONSE:
            break;
        }

        break;

      case SetTitleAndURLFlowAssumptions::DESELECTED__PLAYING__KEEP_DESELECTED:
      case SetTitleAndURLFlowAssumptions::DESELECTED__PLAYING__SELECT:
      case SetTitleAndURLFlowAssumptions::SELECTED__PLAYING__KEEP_SELECTED:
        assume_already_playing = true;
        break;
    }

    switch(flow_assumptions)
    {
      case SetTitleAndURLFlowAssumptions::DESELECTED__STOPPED__KEEP_DESELECTED:
      case SetTitleAndURLFlowAssumptions::SELECTED__STOPPED__KEEP_SELECTED:
      case SetTitleAndURLFlowAssumptions::DESELECTED__PLAYING__KEEP_DESELECTED:
        break;

      case SetTitleAndURLFlowAssumptions::DESELECTED__SELECT:
      case SetTitleAndURLFlowAssumptions::SELECTED__PLAY_REQUESTED__KEEP_SELECTED:
      case SetTitleAndURLFlowAssumptions::DESELECTED__PLAYING__SELECT:
      case SetTitleAndURLFlowAssumptions::SELECTED__PLAYING__KEEP_SELECTED:
        std::string expected_message("First stream URL (reg 79)");
        expected_message += ": \"";
        expected_message += url;
        expected_message += '"';
        mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_NORMAL, expected_message.c_str());
        break;
    }

    switch(system_assumptions)
    {
      case SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE:
      case SetTitleAndURLSystemAssumptions::IMMEDIATE_AUDIO_SOURCE_SELECTION:
      case SetTitleAndURLSystemAssumptions::IMMEDIATE_NOW_PLAYING_STATUS:
        mock_dbus_iface->expect_dbus_get_streamplayer_urlfifo_iface(
            dbus_streamplayer_urlfifo_iface_dummy);
        mock_streamplayer_dbus->expect_tdbus_splay_urlfifo_call_push_sync(
            TRUE, dbus_streamplayer_urlfifo_iface_dummy,
            stream_id.get().get_raw_id(), url.c_str(), hash,
            0, "ms", 0, "ms", -2,
            to_stream_meta_data(expected_artist, expected_album,
                                expected_title, expected_alttrack),
            FALSE, assume_already_playing);

        expecting_play_view_activation = true;

        break;

      case SetTitleAndURLSystemAssumptions::NO_RESPONSE:
        break;
    }

    if(expecting_start_playing_command)
    {
        mock_dbus_iface->expect_dbus_get_streamplayer_playback_iface(
            dbus_streamplayer_playback_iface_dummy);
        mock_streamplayer_dbus->expect_tdbus_splay_playback_call_start_sync(
            TRUE, dbus_streamplayer_playback_iface_dummy, "URL written to register 79");
    }

    if(expecting_play_view_activation)
    {
        mock_dbus_iface->expect_dbus_get_views_iface(dbus_dcpd_views_iface_dummy);
        mock_dcpd_dbus->expect_tdbus_dcpd_views_emit_open(dbus_dcpd_views_iface_dummy, "Play");
    }
}

static void set_start_url(const std::string expected_artist,
                          const std::string expected_album,
                          const std::string expected_title,
                          const std::string expected_alttrack,
                          const std::string url,
                          const OurStream stream_id,
                          SetTitleAndURLFlowAssumptions flow_assumptions,
                          SetTitleAndURLSystemAssumptions system_assumptions,
                          GVariantWrapper *expected_stream_key)
{
    MD5::Context ctx;
    MD5::init(ctx);
    MD5::update(ctx, reinterpret_cast<const uint8_t *>(url.c_str()), url.length());
    MD5::Hash hash;
    MD5::finish(ctx, hash);

    if(expected_stream_key != nullptr)
        *expected_stream_key = std::move(hash_to_variant(hash));

    const auto *const reg = Regs::lookup(79);

    set_start_playing_expectations(expected_artist, expected_album,
                                   expected_title, expected_alttrack,
                                   url, stream_id, hash,
                                   flow_assumptions, system_assumptions);

    reg->write(reinterpret_cast<const uint8_t *>(url.c_str()), url.length());

    uint8_t buffer[8];
    cppcut_assert_equal(size_t(0), reg->read(buffer, sizeof(buffer)));

    mock_dbus_iface->check();
    mock_dcpd_dbus->check();
    mock_streamplayer_dbus->check();
    mock_messages->check();
}

static void set_start_meta_data_and_url(const std::string meta_data,
                                        const std::string url,
                                        const std::string expected_artist,
                                        const std::string expected_album,
                                        const std::string expected_title,
                                        const OurStream stream_id,
                                        SetTitleAndURLFlowAssumptions flow_assumptions,
                                        SetTitleAndURLSystemAssumptions system_assumptions,
                                        GVariantWrapper *expected_stream_key)
{
    set_start_title(expected_artist, expected_album, expected_title, meta_data,
                    flow_assumptions, system_assumptions);
    set_start_url(expected_artist, expected_album, expected_title, meta_data,
                  url, stream_id, flow_assumptions, system_assumptions,
                  expected_stream_key);
}

static void set_start_meta_data_and_url(const uint8_t *meta_data, size_t meta_data_length,
                                        const std::string url,
                                        const std::string expected_artist,
                                        const std::string expected_album,
                                        const std::string expected_title,
                                        const OurStream stream_id,
                                        SetTitleAndURLFlowAssumptions flow_assumptions,
                                        SetTitleAndURLSystemAssumptions system_assumptions,
                                        GVariantWrapper *expected_stream_key)
{
    set_start_title(expected_artist, expected_album, expected_title,
                    meta_data, meta_data_length,
                    flow_assumptions, system_assumptions);
    set_start_url(expected_artist, expected_album, expected_title,
                  std::string(reinterpret_cast<const char *>(meta_data),
                              meta_data_length),
                  url, stream_id, flow_assumptions, system_assumptions,
                  expected_stream_key);
}

static void set_start_title_and_url(const std::string title, const std::string url,
                                    const OurStream stream_id,
                                    SetTitleAndURLFlowAssumptions flow_assumptions,
                                    SetTitleAndURLSystemAssumptions system_assumptions,
                                    GVariantWrapper *expected_stream_key)
{
    set_start_title(title, flow_assumptions, system_assumptions);
    set_start_url("", "", title, title, url, stream_id,
                  flow_assumptions, system_assumptions, expected_stream_key);
}

static void set_next_url(const std::string title, const std::string url,
                         const OurStream stream_id,
                         SetTitleAndURLFlowAssumptions flow_assumptions,
                         SetTitleAndURLSystemAssumptions system_assumptions,
                         GVariantWrapper *expected_stream_key,
                         bool app_is_too_fast)
{
    std::string expected_message("Next stream URL (reg 239)");
    expected_message += ": \"";
    expected_message += url;
    expected_message += '"';
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_NORMAL, expected_message.c_str());

    const auto *const reg = Regs::lookup(239);

    switch(flow_assumptions)
    {
      case SetTitleAndURLFlowAssumptions::SELECTED__STOPPED__KEEP_SELECTED:
      case SetTitleAndURLFlowAssumptions::SELECTED__PLAY_REQUESTED__KEEP_SELECTED:
      case SetTitleAndURLFlowAssumptions::SELECTED__PLAYING__KEEP_SELECTED:
        {
            MD5::Context ctx;
            MD5::init(ctx);
            MD5::update(ctx, reinterpret_cast<const uint8_t *>(url.c_str()), url.length());
            MD5::Hash hash;
            MD5::finish(ctx, hash);

            if(expected_stream_key != nullptr)
                *expected_stream_key = std::move(hash_to_variant(hash));

            mock_dbus_iface->expect_dbus_get_streamplayer_urlfifo_iface(dbus_streamplayer_urlfifo_iface_dummy);
            mock_streamplayer_dbus->expect_tdbus_splay_urlfifo_call_push_sync(
                TRUE, dbus_streamplayer_urlfifo_iface_dummy,
                stream_id.get().get_raw_id(), url.c_str(), hash,
                0, "ms", 0, "ms", 0,
                to_stream_meta_data("", "", title, title),
                FALSE,
                flow_assumptions == SetTitleAndURLFlowAssumptions::SELECTED__PLAYING__KEEP_SELECTED);

            if(flow_assumptions != SetTitleAndURLFlowAssumptions::SELECTED__PLAYING__KEEP_SELECTED)
            {
                mock_dbus_iface->expect_dbus_get_streamplayer_playback_iface(dbus_streamplayer_playback_iface_dummy);
                mock_streamplayer_dbus->expect_tdbus_splay_playback_call_start_sync(
                    TRUE, dbus_streamplayer_playback_iface_dummy, "URL written to register 79");
            }

            if(!app_is_too_fast)
            {
                std::ostringstream os;
                os << "Pushed next stream " << stream_id.get().get_raw_id();
                mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
                                                          os.str().c_str());
            }
        }

        break;

      case SetTitleAndURLFlowAssumptions::DESELECTED__STOPPED__KEEP_DESELECTED:
      case SetTitleAndURLFlowAssumptions::DESELECTED__SELECT:
      case SetTitleAndURLFlowAssumptions::DESELECTED__PLAYING__KEEP_DESELECTED:
      case SetTitleAndURLFlowAssumptions::DESELECTED__PLAYING__SELECT:
        mock_messages->expect_msg_error(0, LOG_CRIT,
                "BUG: Attempted to set next stream without prior audio source selection");

        if(expected_stream_key != nullptr)
            expected_stream_key->release();

        break;
    }

    reg->write(reinterpret_cast<const uint8_t *>(url.c_str()), url.length());

    mock_messages->check();
}

static void set_next_title_and_url(const std::string title, const std::string url,
                                   const OurStream stream_id,
                                   SetTitleAndURLFlowAssumptions flow_assumptions,
                                   SetTitleAndURLSystemAssumptions system_assumptions,
                                   GVariantWrapper *expected_stream_key,
                                   bool app_is_too_fast = false)
{
    set_next_title(title);
    set_next_url(title, url, stream_id,
                 flow_assumptions, system_assumptions, expected_stream_key,
                 app_is_too_fast);
}

static void expect_current_title(const std::string &expected_title)
{
    const auto *const reg = Regs::lookup(75);

    char buffer[150];
    const size_t len = reg->read((uint8_t *)buffer, sizeof(buffer));
    cppcut_assert_operator(sizeof(buffer), >, len);
    buffer[len] = '\0';

    cppcut_assert_equal(expected_title.c_str(), buffer);
}

static void expect_current_url(const std::string &expected_url)
{
    const auto *const reg = Regs::lookup(76);

    char buffer[600];
    const size_t len = reg->read((uint8_t *)buffer, sizeof(buffer));
    cppcut_assert_operator(sizeof(buffer), >, len);
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
    const auto *const reg = Regs::lookup(239);

    uint8_t buffer[16];
    memset(buffer, UINT8_MAX, sizeof(buffer));
    const size_t len = reg->read((uint8_t *)buffer, sizeof(buffer));
    cppcut_assert_equal(size_t(0), len);

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
    if(expected_title == nullptr)
        expected_title = "";

    if(expected_url == nullptr)
        expected_url = "";

    char buffer[512];
    snprintf(buffer, sizeof(buffer),
             "Received explicit title and URL information for stream %u",
             stream_id.get_raw_id());

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG, buffer);

    if(expecting_direct_slave_notification)
        mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");

    streaming_regs->set_title_and_url(stream_id, expected_title, expected_url);
}

static void stop_stream()
{
    const auto *const reg = Regs::lookup(79);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_NORMAL,
                                              "First stream URL (reg 79): <empty>");
    mock_dbus_iface->expect_dbus_get_streamplayer_playback_iface(dbus_streamplayer_playback_iface_dummy);
    mock_streamplayer_dbus->expect_tdbus_splay_playback_call_stop_sync(
            TRUE, dbus_streamplayer_playback_iface_dummy,
            "empty URL written to reg 79");

    static const uint8_t zero = 0;
    reg->write(&zero, sizeof(zero));
}

/*!\test
 * App starts single stream with plain title information.
 */
void test_start_stream()
{
    set_start_title_and_url("Test stream", "http://app-provided.url.org/stream.flac",
                            OurStream::make(),
                            SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                            SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                            nullptr);

    register_changed_data->check();
    expect_current_title_and_url("", "");
}

/*!\test
 * App starts single stream with plain title information, then gets stopped
 * because another audio source is selected.
 *
 * This is the regular case: stop notification is received from player before
 * the audio source is deselected. The SPI slave will be notified through
 * registers 75, 76, and 79.
 *
 * Our audio source manager should take care of keeping this order.
 */
void test_start_stream_stop_stream_and_deselect_audio_source()
{
    set_start_title_and_url("Test stream", "http://app-provided.url.org/stream.flac",
                            OurStream::make(),
                            SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                            SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                            nullptr);

    register_changed_data->check();
    mock_messages->check();
    expect_current_title_and_url("", "");

    mock_messages->expect_msg_info_formatted("Next app stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG,
                                    "Send title and URL to SPI slave");
    GVariantWrapper skey;
    streaming_regs->start_notification(OurStream::make().get(), "",
                                       GVariantWrapper::move(skey));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    mock_messages->check();
    expect_current_title_and_url("Test stream", "http://app-provided.url.org/stream.flac");

    mock_messages->expect_msg_info_formatted(
            "Stream player stopped playing app stream 257 (external cause)");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG,
                                    "Send title and URL to SPI slave");
    streaming_regs->stop_notification(OurStream::make().get());
    register_changed_data->check(std::array<uint8_t, 3>{79, 75, 76});

    streaming_regs->audio_source_deselected();
}

/*!\test
 * App tries to start single stream with plain title information, then gets
 * stopped quickly because another audio source is selected.
 *
 * This is another regular, yet uncommon case: start notification is never
 * received from player because audio source deselection comes very quickly,
 * before the stream player had a chance to actually start playing. The SPI
 * slave will not see registers 75 and 76 updates because nothing has ever
 * changed in the meantime; register 79, however, will be sent.
 */
void test_try_start_stream_and_quickly_deselect_audio_source()
{
    set_start_title_and_url("Test stream", "http://app-provided.url.org/stream.flac",
                            OurStream::make(),
                            SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                            SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                            nullptr);

    register_changed_data->check();
    mock_messages->check();
    expect_current_title_and_url("", "");

    mock_messages->expect_msg_info_formatted(
            "Stream player stopped playing app stream 257 (external cause)");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG,
                                    "Suppress sending title and URL to SPI slave");
    streaming_regs->stop_notification(OurStream::make().get());
    register_changed_data->check(std::array<uint8_t, 1>{79});

    streaming_regs->audio_source_deselected();
}

/*!\test
 * App starts single stream with plain title information, then audio source is
 * deselected before stop notification from player is received.
 *
 * This is a special case which frequently occurs in practice when switching
 * away from plain URL to another source while a stream is playing. The stop
 * notification from the player is received only after the plain URL source has
 * been deselected.
 */
void test_start_stream_and_deselect_audio_source_with_correct_stop_notification()
{
    set_start_title_and_url("Test stream", "http://app-provided.url.org/stream.flac",
                            OurStream::make(),
                            SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                            SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                            nullptr);
    register_changed_data->check();

    mock_messages->expect_msg_info_formatted("Next app stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    GVariantWrapper skey;
    streaming_regs->start_notification(OurStream::make().get(), "",
                                       GVariantWrapper::move(skey));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_current_title_and_url("Test stream", "http://app-provided.url.org/stream.flac");

    streaming_regs->audio_source_deselected();

    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    streaming_regs->stop_notification(OurStream::make().get());
    register_changed_data->check(std::array<uint8_t, 2>{75, 76});
    expect_current_title_and_url("", "");
}

/*!\test
 * See #test_start_stream_and_deselect_audio_source_with_correct_stop_notification().
 *
 * We expect a BUG log message in case a stop notification is received for an
 * unexpected stream ID.
 */
void test_start_stream_and_deselect_audio_source_with_unexpected_stop_notification()
{
    set_start_title_and_url("Test stream", "http://app-provided.url.org/stream.flac",
                            OurStream::make(),
                            SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                            SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                            nullptr);
    register_changed_data->check();

    mock_messages->expect_msg_info_formatted("Next app stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    GVariantWrapper skey;
    streaming_regs->start_notification(OurStream::make().get(), "",
                                       GVariantWrapper::move(skey));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_current_title_and_url("Test stream", "http://app-provided.url.org/stream.flac");

    streaming_regs->audio_source_deselected();

    mock_messages->expect_msg_error_formatted(0, LOG_CRIT,
        "BUG: App stream 271 stopped in unexpected state DESELECTED");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    streaming_regs->stop_notification(OurStream::make(15).get());
    register_changed_data->check(std::array<uint8_t, 2>{75, 76});
    expect_current_title_and_url("", "");
}

/*!\test
 * The plain URL audio source is selected, nothing is played, then another
 * audio source is selected.
 *
 * Very standard situation. No registers will be harmed.
 */
void test_select_plain_url_audio_source_then_deselect_audio_source()
{
    set_start_title("Test stream",
                    SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                    SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE);
    streaming_regs->audio_source_deselected();
}

/*!\test
 * App starts single stream with structured meta data information.
 *
 * This test makes sure that the meta data tokenizer works correctly for
 * simple, expected inputs.
 */
void test_start_stream_with_meta_data()
{
    set_start_meta_data_and_url("The title\x1d""By some artist\x1dOn that album",
                                "http://app-provided.url.org/stream.aac",
                                "By some artist", "On that album", "The title",
                                OurStream::make(),
                                SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                                SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                                nullptr);

    expect_current_title_and_url("", "");
}

/*!\test
 * App starts single stream with structured meta data information.
 *
 * This test makes sure that the meta data tokenizer works correctly for
 * unusual inputs.
 */
void test_start_stream_with_unterminated_meta_data()
{
    static const uint8_t evil[] = { 'T', 'i', 't', 'l', 'e', 0x1d, };

    set_start_meta_data_and_url(evil, sizeof(evil),
                                "http://app-provided.url.org/stream.aac",
                                "", "", "Title",
                                OurStream::make(),
                                SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                                SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                                nullptr);

    expect_current_title_and_url("", "");
}

/*!\test
 * App starts single stream with partial structured meta data information.
 *
 * This test makes sure that the meta data tokenizer works correctly for
 * partial inputs.
 */
void test_start_stream_with_partial_meta_data()
{
    set_start_meta_data_and_url("The title\x1d""By some artist on that album",
                                "http://app-provided.url.org/stream.aac",
                                "By some artist on that album", "", "The title",
                                OurStream::make(),
                                SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                                SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                                nullptr);

    expect_current_title_and_url("", "");
}

/*!\test
 * App starts single stream with too many meta data information.
 *
 * This test makes sure that the meta data tokenizer works correctly for long
 * inputs with trailing junk.
 */
void test_start_stream_with_too_many_meta_data()
{
    set_start_meta_data_and_url("The title\x1d""By some artist\x1dOn that album\x1dThat I like",
                                "http://app-provided.url.org/stream.aac",
                                "By some artist", "On that album", "The title",
                                OurStream::make(),
                                SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                                SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                                nullptr);

    expect_current_title_and_url("", "");
}

/*!\test
 * App starts single stream with too many meta data information.
 *
 * This test makes sure that the meta data tokenizer works correctly for even
 * longer inputs with even more trailing junk.
 */
void test_start_stream_with_way_too_many_meta_data()
{
    set_start_meta_data_and_url("The title\x1d""By some artist\x1dOn that album\x1dThat\x1dI\x1dlike",
                                "http://app-provided.url.org/stream.aac",
                                "By some artist", "On that album", "The title",
                                OurStream::make(),
                                SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                                SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                                nullptr);

    expect_current_title_and_url("", "");
}

/*!\test
 * App starts single stream with title, but no other information
 *
 * Regular case with just the title filled in.
 */
void test_start_stream_with_title_name()
{
    set_start_meta_data_and_url("The Title\x1d\x1d",
                                "http://app-provided.url.org/stream.aac",
                                "", "", "The Title",
                                OurStream::make(),
                                SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                                SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                                nullptr);

    expect_current_title_and_url("", "");
}

/*!\test
 * App starts single stream with artist, but no other information
 *
 * Regular case with just the artist name filled in.
 */
void test_start_stream_with_artist_name()
{
    set_start_meta_data_and_url("\x1dThe Artist\x1d",
                                "http://app-provided.url.org/stream.aac",
                                "The Artist", "", "",
                                OurStream::make(),
                                SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                                SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                                nullptr);

    expect_current_title_and_url("", "");
}

/*!\test
 * App starts single stream with album, but no other information
 *
 * Regular case with just the album name filled in.
 */
void test_start_stream_with_album_name()
{
    set_start_meta_data_and_url("\x1d\x1dThe Album",
                                "http://app-provided.url.org/stream.aac",
                                "", "The Album", "",
                                OurStream::make(),
                                SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                                SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                                nullptr);

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
                            stream_id_first,
                            SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                            SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                            &skey_first);
    register_changed_data->check();

    mock_messages->expect_msg_info_formatted("Next app stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    GVariantWrapper hash_first;
    expect_cover_art_notification(skey_first, GVariantWrapper(), cached_image_first, &hash_first);
    streaming_regs->start_notification(stream_id_first.get(), "",
                                       GVariantWrapper::move(skey_first));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("First", "http://app-provided.url.org/first.flac");

    const auto stream_id_second(++next_stream_id);
    GVariantWrapper skey_second;
    set_start_title_and_url("Second", "http://app-provided.url.org/second.flac",
                            stream_id_second,
                            SetTitleAndURLFlowAssumptions::SELECTED__PLAYING__KEEP_SELECTED,
                            SetTitleAndURLSystemAssumptions::IMMEDIATE_NOW_PLAYING_STATUS,
                            &skey_second);
    register_changed_data->check();
    expect_current_title_and_url("First", "http://app-provided.url.org/first.flac");

    mock_messages->expect_msg_info_formatted("Next app stream 258");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_cover_art_notification(skey_second, hash_first, cached_image_second);
    streaming_regs->start_notification(stream_id_second.get(), "",
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
                            stream_id_first,
                            SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                            SetTitleAndURLSystemAssumptions::IMMEDIATE_AUDIO_SOURCE_SELECTION,
                            &skey_first);
    register_changed_data->check();

    const auto stream_id_second(++next_stream_id);
    GVariantWrapper skey_second;
    set_start_title_and_url("Second", "http://app-provided.url.org/second.flac",
                            stream_id_second,
                            SetTitleAndURLFlowAssumptions::SELECTED__PLAY_REQUESTED__KEEP_SELECTED,
                            SetTitleAndURLSystemAssumptions::IMMEDIATE_NOW_PLAYING_STATUS,
                            &skey_second);
    register_changed_data->check();
    expect_current_title_and_url("", "");

    mock_messages->expect_msg_info_formatted("App stream 257 started, but we are waiting for 258");
    expect_empty_cover_art_notification(skey_first);
    streaming_regs->start_notification(stream_id_first.get(), "",
                                       GVariantWrapper::move(skey_first));
    register_changed_data->check(std::array<uint8_t, 1>{210});
    mock_messages->check();
    expect_current_title_and_url("", "");

    mock_messages->expect_msg_info_formatted("Next app stream 258");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_second);
    streaming_regs->start_notification(stream_id_second.get(), "",
                                       GVariantWrapper::move(skey_second));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("Second", "http://app-provided.url.org/second.flac");
}

/*!\test
 * App starts stream while another source is playing.
 *
 * An audio source selection step is done so that we are allowed to use the
 * player.
 */
void test_app_can_start_stream_while_other_source_is_playing()
{
    GVariantWrapper dummy_stream_key;
    expect_empty_cover_art_notification(dummy_stream_key);
    streaming_regs->start_notification(ID::Stream::make_for_source(STREAM_ID_SOURCE_UI), "",
                                       GVariantWrapper::move(dummy_stream_key));
    register_changed_data->check({210});
    expect_current_title_and_url("", "");

    const auto stream_id(OurStream::make());
    GVariantWrapper skey;
    set_start_title_and_url("Stream", "http://app-provided.url.org/stream.flac",
                            stream_id,
                            SetTitleAndURLFlowAssumptions::DESELECTED__PLAYING__SELECT,
                            SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                            &skey);
    register_changed_data->check();

    mock_messages->expect_msg_info_formatted("Next app stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey);
    streaming_regs->start_notification(stream_id.get(), "",
                                       GVariantWrapper::move(skey));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("Stream", "http://app-provided.url.org/stream.flac");
}

/*!\test
 * Non-app source starts playing while plain URL audio source is selected,
 * hijacking the audio source (variant 1).
 *
 * UI sends title and URL after start notification in this test case. This
 * leads to a short glitch which could only be avoided by keeping outdated
 * information in registers 75/76. We chose not to.
 *
 * This is a special case which should never occur in practice as long as the
 * audio source management is correctly implemented and used.
 */
void test_non_app_stream_starts_while_plain_url_is_active_with_early_start_notification()
{
    const auto stream_id(OurStream::make());
    GVariantWrapper skey;
    set_start_title_and_url("Stream", "http://app-provided.url.org/stream.flac",
                            stream_id,
                            SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                            SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                            &skey);
    register_changed_data->check();

    mock_messages->expect_msg_info_formatted("Next app stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey);
    streaming_regs->start_notification(stream_id.get(), "",
                                       GVariantWrapper::move(skey));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("Stream", "http://app-provided.url.org/stream.flac");

    mock_messages->expect_msg_error_formatted(0, LOG_CRIT,
        "BUG: Non-app stream 129 started while plain URL player is selected");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    const auto bad_stream_id(ID::Stream::make_for_source(STREAM_ID_SOURCE_UI));
    GVariantWrapper dummy_stream_key;
    expect_empty_cover_art_notification(dummy_stream_key);
    streaming_regs->start_notification(bad_stream_id, "",
                                       GVariantWrapper::move(dummy_stream_key));
    register_changed_data->check(std::array<uint8_t, 4>{79, 75, 76, 210});
    expect_current_title_and_url("", "");

    send_title_and_url(bad_stream_id, "UI stream", "http://ui-provided.url.org/loud.flac", true);
    register_changed_data->check(std::array<uint8_t, 2>{75, 76});
    expect_current_title_and_url("UI stream", "http://ui-provided.url.org/loud.flac");
}

/*!\test
 * Non-app source starts playing while plain URL audio source is selected,
 * hijacking the audio source (variant 2).
 *
 * UI sends title and URL before start notification in this test case.
 */
void test_non_app_stream_starts_while_plain_url_is_active_with_late_start_notification()
{
    const auto stream_id(OurStream::make());
    GVariantWrapper skey;
    set_start_title_and_url("Stream", "http://app-provided.url.org/stream.flac",
                            stream_id,
                            SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                            SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                            &skey);
    register_changed_data->check();

    mock_messages->expect_msg_info_formatted("Next app stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey);
    streaming_regs->start_notification(stream_id.get(), "",
                                       GVariantWrapper::move(skey));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("Stream", "http://app-provided.url.org/stream.flac");

    const auto bad_stream_id(ID::Stream::make_for_source(STREAM_ID_SOURCE_UI));
    send_title_and_url(bad_stream_id, "UI stream", "http://ui-provided.url.org/loud.flac", false);
    register_changed_data->check();

    mock_messages->expect_msg_error_formatted(0, LOG_CRIT,
        "BUG: Non-app stream 129 started while plain URL player is selected");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    GVariantWrapper dummy_stream_key;
    expect_empty_cover_art_notification(dummy_stream_key);
    streaming_regs->start_notification(bad_stream_id, "",
                                       GVariantWrapper::move(dummy_stream_key));
    register_changed_data->check(std::array<uint8_t, 4>{79, 75, 76, 210});
    expect_current_title_and_url("UI stream", "http://ui-provided.url.org/loud.flac");
}

static void start_stop_single_stream(bool with_notifications)
{
    const auto stream_id(OurStream::make());
    GVariantWrapper skey;
    set_start_title_and_url("Stream", "http://app-provided.url.org/stream.flac",
                            stream_id,
                            SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                            SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                            &skey);
    register_changed_data->check();
    mock_messages->check();

    if(with_notifications)
    {
        mock_messages->expect_msg_info_formatted("Next app stream 257");
        mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
        expect_empty_cover_art_notification(skey);
        streaming_regs->start_notification(stream_id.get(), "",
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
        mock_messages->expect_msg_info_formatted(
                "Stream player stopped playing app stream 257 (requested)");
        mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
        streaming_regs->stop_notification(stream_id.get());
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
    mock_messages->expect_msg_error_formatted(0, LOG_CRIT,
        "BUG: App stream 257 started in unexpected state STOPPED_REQUESTED");
    register_changed_data->check();
    GVariantWrapper dummy_stream_key;
    expect_empty_cover_art_notification(dummy_stream_key);
    streaming_regs->start_notification(OurStream::make().get(), "",
                                       GVariantWrapper::move(dummy_stream_key));
    register_changed_data->check(std::array<uint8_t, 1>{210});
    expect_current_title_and_url("", "");

    mock_messages->expect_msg_info_formatted(
            "Stream player stopped playing app stream 257 (requested)");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG,
                                    "Suppress sending title and URL to SPI slave");
    streaming_regs->stop_notification(OurStream::make().get());
    register_changed_data->check(std::array<uint8_t, 1>{79});
    expect_current_title_and_url("", "");
}

/*!\test
 * App starts single stream, but it fails.
 */
void test_start_single_stream_failure()
{
    const auto stream_id(OurStream::make());
    GVariantWrapper skey;
    set_start_title_and_url("Stream", "http://app-provided.url.org/stream.flac",
                            stream_id,
                            SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                            SetTitleAndURLSystemAssumptions::IMMEDIATE_AUDIO_SOURCE_SELECTION,
                            &skey);


    register_changed_data->check();
    mock_messages->check();

    mock_messages->expect_msg_error_formatted(
            0, LOG_NOTICE, "Stream 257 stopped with error: io.unavailable");
    mock_messages->expect_msg_info_formatted(
            "Stream player stopped playing app stream 257 (failure)");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG,
                                    "Suppress sending title and URL to SPI slave");
    streaming_regs->stop_notification(stream_id.get(), "io.unavailable", {});
    register_changed_data->check(std::array<uint8_t, 1>{79});
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
    streaming_regs->start_notification(stream_id, "",
                                       GVariantWrapper::move(dummy_stream_key));

    register_changed_data->check({210});
    mock_messages->check();
    expect_current_title_and_url("", "");

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
             "Received explicit title and URL information for stream 129");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");

    streaming_regs->set_title_and_url(stream_id, "My stream", url);

    register_changed_data->check(std::array<uint8_t, 2>{75, 76});
    mock_messages->check();
    expect_current_title_and_url("My stream", url);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
             "Received explicit title and URL information for stream 129");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send only new title to SPI slave");

    streaming_regs->set_title_and_url(stream_id, "Other title", url);

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
    streaming_regs->start_notification(stream_id, "",
                                       GVariantWrapper::move(dummy_stream_key));

    register_changed_data->check({210});
    mock_messages->check();
    expect_current_title_and_url("", "");

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
             "Received explicit title and URL information for stream 129");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG,
                                    "Send title and URL to SPI slave");

    streaming_regs->set_title_and_url(stream_id, title, url);

    register_changed_data->check(std::array<uint8_t, 2>{75, 76});
    mock_messages->check();
    expect_current_title_and_url(title, url);

    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG,
             "Received explicit title and URL information for stream 129");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG,
                                    "Suppress sending title and URL to SPI slave");

    streaming_regs->set_title_and_url(stream_id, title, url);

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
                            stream_id_first,
                            SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                            SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                            &skey_first);
    register_changed_data->check();
    expect_current_title_and_url("", "");

    mock_messages->expect_msg_info_formatted("Next app stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_first);
    streaming_regs->start_notification(stream_id_first.get(), "",
                                       GVariantWrapper::move(skey_first));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    mock_messages->check();
    expect_next_url_empty();
    expect_current_title_and_url("First FLAC", "http://app-provided.url.org/first.flac");

    const auto stream_id_second(++next_stream_id);
    GVariantWrapper skey_second;
    set_next_title_and_url("Second FLAC", "http://app-provided.url.org/second.flac",
                           stream_id_second,
                           SetTitleAndURLFlowAssumptions::SELECTED__PLAYING__KEEP_SELECTED,
                           SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                           &skey_second);

    mock_messages->expect_msg_info_formatted("Next app stream 258");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_second);
    streaming_regs->start_notification(stream_id_second.get(), "",
                                       GVariantWrapper::move(skey_second));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    mock_messages->check();
    expect_next_url_empty();
    expect_current_title_and_url("Second FLAC", "http://app-provided.url.org/second.flac");

    /* after a while, the stream may finish */
    mock_messages->expect_msg_info_formatted(
            "Stream player stopped playing app stream 258 (external cause)");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    streaming_regs->stop_notification(stream_id_second.get());
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
                            stream_id_first,
                            SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                            SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                            &skey);
    register_changed_data->check();
    expect_current_title_and_url("", "");

    /* first track starts playing */
    mock_messages->expect_msg_info_formatted("Next app stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey);
    streaming_regs->start_notification(stream_id_first.get(), "",
                                       GVariantWrapper::move(skey));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url(title_and_url[0].first, title_and_url[0].second);

    for(size_t i = 1; i < title_and_url.size(); ++i)
    {
        const std::pair<const char *, const char *> &pair(title_and_url[i]);

        /* queue next track */
        const auto stream_id(++next_stream_id);
        set_next_title_and_url(pair.first, pair.second, stream_id,
                               SetTitleAndURLFlowAssumptions::SELECTED__PLAYING__KEEP_SELECTED,
                               SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                               &skey);
        register_changed_data->check();

        /* next track starts playing */
        char buffer[64];
        snprintf(buffer, sizeof(buffer),
                 "Next app stream %u", stream_id.get().get_raw_id());
        mock_messages->expect_msg_info_formatted(buffer);
        mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
        expect_empty_cover_art_notification(skey);
        streaming_regs->start_notification(stream_id.get(), "",
                                           GVariantWrapper::move(skey));
        register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
        mock_messages->check();
        expect_next_url_empty();
        expect_current_title_and_url(pair.first, pair.second);
    }

    /* after a while, the last stream finishes playing */
    mock_messages->expect_msg_info_formatted(
            "Stream player stopped playing app stream 261 (external cause)");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    streaming_regs->stop_notification(next_stream_id.get());
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
                            stream_id_first,
                            SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                            SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                            &skey_first);
    register_changed_data->check();
    expect_current_title_and_url("", "");

    const auto stream_id_second(++next_stream_id);
    GVariantWrapper skey_second;
    set_next_title_and_url("Second FLAC", "http://app-provided.url.org/second.flac",
                           stream_id_second,
                           SetTitleAndURLFlowAssumptions::SELECTED__PLAYING__KEEP_SELECTED,
                           SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                           &skey_second, true);
    register_changed_data->check();
    expect_current_title_and_url("", "");

    mock_messages->expect_msg_info_formatted("Next app stream 257");
    mock_messages->expect_msg_vinfo_formatted(MESSAGE_LEVEL_DIAG, "Pushed next stream 258");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_first);
    streaming_regs->start_notification(stream_id_first.get(), "",
                                       GVariantWrapper::move(skey_first));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("First FLAC", "http://app-provided.url.org/first.flac");

    mock_messages->expect_msg_info_formatted("Next app stream 258");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_second);
    streaming_regs->start_notification(stream_id_second.get(), "",
                                       GVariantWrapper::move(skey_second));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("Second FLAC", "http://app-provided.url.org/second.flac");
}

/*!\test
 * App starts stream and tries to queue another stream just after the first
 * stream ended.
 *
 * The second stream is played because we are still on plain URL audio source.
 */
void test_queue_next_after_stop_notification_is_not_ignored()
{
    auto next_stream_id(OurStream::make());

    const auto stream_id_first(next_stream_id);
    GVariantWrapper skey_first;
    set_start_title_and_url("First FLAC", "http://app-provided.url.org/first.flac",
                            stream_id_first,
                            SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                            SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                            &skey_first);
    register_changed_data->check();
    expect_current_title_and_url("", "");

    mock_messages->expect_msg_info_formatted("Next app stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_first);
    streaming_regs->start_notification(stream_id_first.get(), "",
                                       GVariantWrapper::move(skey_first));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("First FLAC", "http://app-provided.url.org/first.flac");

    /* the stream finishes... */
    mock_messages->expect_msg_info_formatted(
            "Stream player stopped playing app stream 257 (external cause)");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    streaming_regs->stop_notification(stream_id_first.get());
    register_changed_data->check(std::array<uint8_t, 3>{79, 75, 76});
    expect_current_title_and_url("", "");

    /* ...but the slave sends another stream just in that moment */
    const auto stream_id_second(++next_stream_id);
    set_next_title_and_url("Second FLAC", "http://app-provided.url.org/second.flac",
                           stream_id_second,
                           SetTitleAndURLFlowAssumptions::SELECTED__STOPPED__KEEP_SELECTED,
                           SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                           nullptr);
    expect_current_title_and_url("", "");
}

/*!\test
 * App must start first stream before trying to queue next.
 */
void test_queue_next_with_prior_start_is_ignored()
{
    set_next_title_and_url("Stream", "http://app-provided.url.org/stream.flac",
                           OurStream::make(),
                           SetTitleAndURLFlowAssumptions::DESELECTED__STOPPED__KEEP_DESELECTED,
                           SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                           nullptr);
    expect_current_title_and_url("", "");
}

/*!\test
 * App must start first stream before trying to queue next also if streamplayer
 * is already playing.
 */
void test_queue_next_with_prior_start_by_us_is_ignored()
{
    set_next_title_and_url("Stream", "http://app-provided.url.org/stream.flac",
                           OurStream::make(),
                           SetTitleAndURLFlowAssumptions::DESELECTED__PLAYING__KEEP_DESELECTED,
                           SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                           nullptr);
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
                            stream_id_first,
                            SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                            SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                            &skey_first);
    register_changed_data->check();
    expect_current_title_and_url("", "");

    mock_messages->expect_msg_info_formatted("Next app stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_first);
    streaming_regs->start_notification(stream_id_first.get(), "",
                                       GVariantWrapper::move(skey_first));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("Playing stream", "http://app-provided.url.org/first.mp3");

    const auto stream_id_second(++next_stream_id);
    set_next_title_and_url("Stream 2", "http://app-provided.url.org/2.mp3",
                           stream_id_second,
                           SetTitleAndURLFlowAssumptions::SELECTED__PLAYING__KEEP_SELECTED,
                           SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                           nullptr);
    register_changed_data->check();
    expect_current_title_and_url("Playing stream", "http://app-provided.url.org/first.mp3");

    const auto stream_id_third(++next_stream_id);
    set_next_title_and_url("Stream 3", "http://app-provided.url.org/3.mp3",
                           stream_id_third,
                           SetTitleAndURLFlowAssumptions::SELECTED__PLAYING__KEEP_SELECTED,
                           SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                           nullptr);
    register_changed_data->check();
    expect_current_title_and_url("Playing stream", "http://app-provided.url.org/first.mp3");

    const auto stream_id_fourth(++next_stream_id);
    GVariantWrapper skey_fourth;
    set_next_title_and_url("Stream 4", "http://app-provided.url.org/4.mp3",
                           stream_id_fourth,
                           SetTitleAndURLFlowAssumptions::SELECTED__PLAYING__KEEP_SELECTED,
                           SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                           &skey_fourth);
    register_changed_data->check();
    expect_current_title_and_url("Playing stream", "http://app-provided.url.org/first.mp3");

    mock_messages->check();

    mock_messages->expect_msg_info_formatted("Next app stream 260");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_fourth);
    streaming_regs->start_notification(stream_id_fourth.get(), "",
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
                            stream_id_first,
                            SetTitleAndURLFlowAssumptions::DESELECTED__SELECT,
                            SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                            &skey_first);
    register_changed_data->check();
    expect_current_title_and_url("", "");

    mock_messages->expect_msg_info_formatted("Next app stream 257");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_first);
    streaming_regs->start_notification(stream_id_first.get(), "",
                                       GVariantWrapper::move(skey_first));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    mock_messages->check();
    expect_next_url_empty();
    expect_current_title_and_url("First FLAC", "http://app-provided.url.org/first.flac");

    const auto stream_id_second(++next_stream_id);
    GVariantWrapper skey_second;
    set_next_title_and_url("Second FLAC", "http://app-provided.url.org/second.flac",
                           stream_id_second,
                           SetTitleAndURLFlowAssumptions::SELECTED__PLAYING__KEEP_SELECTED,
                           SetTitleAndURLSystemAssumptions::IMMEDIATE_RESPONSE,
                           &skey_second);
    expect_current_title_and_url("First FLAC", "http://app-provided.url.org/first.flac");

    /* the pause signal itself is caught, but ignored by dcpd; however,
     * starting the same stream is treated as continue from pause */
    mock_messages->expect_msg_info_formatted("Continue with app stream 257");
    expect_empty_cover_art_notification(skey_first);
    streaming_regs->start_notification(stream_id_first.get(), "",
                                       GVariantWrapper::move(skey_first));
    expect_current_title_and_url("First FLAC", "http://app-provided.url.org/first.flac");
    register_changed_data->check();

    /* also works a second time */
    mock_messages->expect_msg_info_formatted("Continue with app stream 257");
    expect_empty_cover_art_notification(skey_first);
    streaming_regs->start_notification(stream_id_first.get(), "",
                                       GVariantWrapper::move(skey_first));
    expect_current_title_and_url("First FLAC", "http://app-provided.url.org/first.flac");
    register_changed_data->check();

    /* now assume the next stream has started */
    mock_messages->expect_msg_info_formatted("Next app stream 258");
    mock_messages->expect_msg_vinfo(MESSAGE_LEVEL_DIAG, "Send title and URL to SPI slave");
    expect_empty_cover_art_notification(skey_second);
    streaming_regs->start_notification(stream_id_second.get(), "",
                                       GVariantWrapper::move(skey_second));
    register_changed_data->check(std::array<uint8_t, 4>{239, 75, 76, 210});
    expect_next_url_empty();
    expect_current_title_and_url("Second FLAC", "http://app-provided.url.org/second.flac");
}

}

#endif /* !LOGGED_LOCKS_ENABLED  */

/*!@}*/
