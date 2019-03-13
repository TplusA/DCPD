/*
 * Copyright (C) 2019  T+A elektroakustik GmbH & Co. KG
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

#include <doctest.h>

#include "plainplayer.hh"

#include "mock_messages.hh"

TEST_SUITE_BEGIN("Plain URL player");

/*!
 * Set up player with deselected plain URL audio source.
 */
class Fixture
{
  protected:
    std::unique_ptr<Regs::PlayStream::PlainPlayer> player;
    std::unique_ptr<MockMessages::Mock> mock_messages;

  public:
    explicit Fixture():
        player(Regs::PlayStream::make_player()),
        mock_messages(std::make_unique<MockMessages::Mock>())
    {
        MockMessages::singleton = mock_messages.get();
    }

    virtual ~Fixture()
    {
        try
        {
            mock_messages->done();
        }
        catch(...)
        {
            /* no throwing from dtors */
        }

        MockMessages::singleton = nullptr;
    }

    /* activate player and tell it that the audio source has been selected */
    void activate_player()
    {
        player->activate([] () {});
        player->notifications().audio_source_selected();
    }
};

TEST_CASE_FIXTURE(Fixture,
                  "Player activation selects the plain URL audio source")
{
    CHECK_FALSE(player->is_active());
    bool requested = false;
    player->activate([&requested] () { requested = true; });
    CHECK(requested);
    CHECK(player->is_active());
}

TEST_CASE_FIXTURE(Fixture,
                  "Second player activation has no effect")
{
    bool requested = false;
    player->activate([&requested] () { requested = true; });
    CHECK(requested);

    requested = false;
    player->activate([&requested] () { requested = true; });
    CHECK_FALSE(requested);
}

TEST_CASE_FIXTURE(Fixture,
                  "Playback cannot start without prior audio source selection")
{
    bool has_started = false;
    const auto not_called =
        [&has_started] (const auto &, auto, bool is_first, bool is_start_requested)
        {
            has_started = true;
            return true;
        };
    expect<MockMessages::MsgError>(mock_messages, 0, LOG_CRIT,
        "BUG: Attempted to start playback without prior audio source selection",
        false);
    CHECK_FALSE(player->start(Regs::PlayStream::StreamInfo("artist", "album",
                                                           "title", "alttrack", "url"),
                              not_called));
    CHECK_FALSE(has_started);
}

TEST_CASE_FIXTURE(Fixture,
                  "Cannot push next stream without prior audio source selection")
{
    expect<MockMessages::MsgError>(mock_messages, 0, LOG_CRIT,
        "BUG: Attempted to set next stream without prior audio source selection",
        false);
    CHECK_FALSE(player->next(Regs::PlayStream::StreamInfo("artist", "album",
                                                          "title", "alttrack", "url")));
}

TEST_CASE_FIXTURE(Fixture,
                  "Playback cannot stop without prior audio source selection")
{
    bool stopped = false;
    const auto not_called = [&stopped] () { stopped = true; return true; };
    CHECK_FALSE(player->stop(not_called));
    CHECK_FALSE(stopped);
}

static bool compare(const Regs::PlayStream::StreamInfo &stream,
                    const Regs::PlayStream::StreamInfo &expected)
{
    CHECK(stream.artist_ == expected.artist_);
    CHECK(stream.album_ == expected.album_);
    CHECK(stream.title_ == expected.title_);
    CHECK(stream.url_ == expected.url_);
    return true;
}

TEST_CASE_FIXTURE(Fixture,
                  "Player can be activated and deactivated")
{
    CHECK_FALSE(player->is_active());
    activate_player();
    CHECK(player->is_active());
    player->notifications().audio_source_deselected();
    CHECK_FALSE(player->is_active());
}

TEST_CASE_FIXTURE(Fixture,
                  "Start playback sends stream information to player")
{
    static const Regs::PlayStream::StreamInfo expected_info(
            "artist", "album", "title", "alttrack", "url now");

    player->activate([] () {});
    player->notifications().audio_source_selected();

    bool has_started = false;
    auto id(Regs::PlayStream::PlainPlayer::StreamID::make_invalid());
    bool was_first;
    bool was_start_requested;
    CHECK(player->start(Regs::PlayStream::StreamInfo("artist", "album",
                                                     "title", "alttrack",
                                                     "url now"),
                        [&has_started, &id, &was_first, &was_start_requested]
                        (const auto &stream, auto stream_id,
                         bool is_first, bool is_start_requested)
                        {
                            id = stream_id;
                            was_first = is_first;
                            was_start_requested = is_start_requested;
                            has_started = true;
                            return compare(stream, expected_info);
                        }));
    REQUIRE(has_started);
    CHECK(was_first);
    CHECK_FALSE(was_start_requested);
}

TEST_CASE_FIXTURE(Fixture,
                  "Start playback can be issued multiple times quickly")
{
    static const Regs::PlayStream::StreamInfo expected_info_1(
            "artist_1", "album_1", "title_1", "alttrack_1", "url now_1");
    static const Regs::PlayStream::StreamInfo expected_info_2(
            "artist_2", "album_2", "title_2", "alttrack_2", "url now_2");

    player->activate([] () {});
    player->notifications().audio_source_selected();

    /* start for the first time */
    bool has_started_1 = false;
    auto id_1(Regs::PlayStream::PlainPlayer::StreamID::make_invalid());
    bool was_first_1;
    bool was_start_requested_1;
    CHECK(player->start(Regs::PlayStream::StreamInfo("artist_1", "album_1",
                                                     "title_1", "alttrack_1",
                                                     "url now_1"),
                        [&has_started_1, &id_1, &was_first_1, &was_start_requested_1]
                        (const auto &stream, auto stream_id,
                         bool is_first, bool is_start_requested)
                        {
                            id_1 = stream_id;
                            was_first_1 = is_first;
                            was_start_requested_1 = is_start_requested;
                            has_started_1 = true;
                            return compare(stream, expected_info_1);
                        }));
    REQUIRE(has_started_1);
    CHECK(was_first_1);
    CHECK_FALSE(was_start_requested_1);

    /* start for the second time before start notification has arrived */
    bool has_started_2 = false;
    auto id_2(Regs::PlayStream::PlainPlayer::StreamID::make_invalid());
    bool was_first_2;
    bool was_start_requested_2;
    CHECK(player->start(Regs::PlayStream::StreamInfo("artist_2", "album_2",
                                                     "title_2", "alttrack_2",
                                                     "url now_2"),
                        [&has_started_2, &id_2, &was_first_2, &was_start_requested_2]
                        (const auto &stream, auto stream_id,
                         bool is_first, bool is_start_requested)
                        {
                            id_2 = stream_id;
                            was_first_2 = is_first;
                            was_start_requested_2 = is_start_requested;
                            has_started_2 = true;
                            return compare(stream, expected_info_2);
                        }));
    REQUIRE(has_started_2);
    CHECK(was_first_2);
    CHECK(was_start_requested_2);

    /* second track plays, first went down the drain */
    expect<MockMessages::MsgInfo>(mock_messages, "Next app stream 258", false);
    CHECK(player->notifications().started(id_2) == Regs::PlayStream::PlainPlayerNotifications::StartResult::STARTED);
    REQUIRE(player->get_current_stream_info().is_known());
    CHECK(player->get_current_stream_info()->artist_ == "artist_2");
}

TEST_CASE_FIXTURE(Fixture,
                  "Start playback with pending audio source selection sends stream information to player on source selection completion")
{
    static const Regs::PlayStream::StreamInfo expected_info(
            "artist", "album", "title", "alttrack", "url later");

    player->activate([] () {});
    bool has_started = false;
    auto id(Regs::PlayStream::PlainPlayer::StreamID::make_invalid());
    bool was_first;
    bool was_start_requested;
    CHECK(player->start(Regs::PlayStream::StreamInfo("artist", "album",
                                                     "title", "alttrack",
                                                     "url later"),
                        [&has_started, &id, &was_first, &was_start_requested]
                        (const auto &stream, auto stream_id,
                         bool is_first, bool is_start_requested)
                        {
                            id = stream_id;
                            was_first = is_first;
                            was_start_requested = is_start_requested;
                            has_started = true;
                            return compare(stream, expected_info);
                        }));
    CHECK_FALSE(has_started);

    player->notifications().audio_source_selected();
    REQUIRE(has_started);
    CHECK(was_first);
    CHECK_FALSE(was_start_requested);
}

TEST_CASE_FIXTURE(Fixture,
                  "Start notification for same stream is treated as resume from pause")
{
    player->activate([] () {});
    player->notifications().audio_source_selected();

    auto id(Regs::PlayStream::PlainPlayer::StreamID::make_invalid());
    CHECK(player->start(Regs::PlayStream::StreamInfo("a", "b", "c", "d", "e"),
                        [&id]
                        (const auto &stream, auto stream_id,
                         bool is_first, bool is_start_requested)
                        {
                            id = stream_id;
                            return true;
                        }));
    REQUIRE(id.get().is_valid());

    expect<MockMessages::MsgInfo>(mock_messages, "Next app stream 257", false);
    CHECK(player->notifications().started(id) == Regs::PlayStream::PlainPlayerNotifications::StartResult::STARTED);
    CHECK(player->notifications().started(id) == Regs::PlayStream::PlainPlayerNotifications::StartResult::CONTINUE_FROM_PAUSE);
}

TEST_CASE_FIXTURE(Fixture,
                  "Next stream is pushed to player queue when available")
{
    activate_player();

    std::string pushed_artist;
    bool was_first = false;
    bool was_start_requested = false;
    auto pushed_id(Regs::PlayStream::PlainPlayer::StreamID::make_invalid());

    CHECK(player->start(Regs::PlayStream::StreamInfo("a", "b", "c", "d", "e"),
                        [&pushed_artist, &pushed_id, &was_first, &was_start_requested]
                        (const auto &stream, auto stream_id,
                         bool is_first, bool is_start_requested)
                        {
                            pushed_id = stream_id;
                            pushed_artist = stream.artist_;
                            was_first = is_first;
                            was_start_requested = is_start_requested;
                            return true;
                        }));
    CHECK(pushed_artist == "a");
    CHECK(was_first);
    CHECK_FALSE(was_start_requested);
    CHECK(pushed_id.get().is_valid());
    auto current_id(pushed_id);

    expect<MockMessages::MsgInfo>(mock_messages, "Next app stream 257", false);
    CHECK(player->notifications().started(pushed_id) == Regs::PlayStream::PlainPlayerNotifications::StartResult::STARTED);
    mock_messages->done();

    CHECK(player->next(Regs::PlayStream::StreamInfo("f", "g", "h", "i", "j")));
    CHECK(pushed_artist == "f");
    CHECK_FALSE(was_first);
    CHECK_FALSE(was_start_requested);
    CHECK(pushed_id.get().is_valid());
    ++current_id;
    CHECK(current_id == pushed_id);

    expect<MockMessages::MsgInfo>(mock_messages, "Next app stream 258", false);
    CHECK(player->notifications().started(pushed_id) == Regs::PlayStream::PlainPlayerNotifications::StartResult::PLAYING_ON);
    mock_messages->done();

    CHECK(pushed_artist == "f");
    CHECK(current_id == pushed_id);
}

TEST_CASE_FIXTURE(Fixture,
                  "Push of next stream to player is deferred if first stream is not playing yet")
{
    activate_player();

    std::string pushed_artist;
    bool was_first = false;
    bool was_start_requested = false;
    auto pushed_id(Regs::PlayStream::PlainPlayer::StreamID::make_invalid());

    CHECK(player->start(Regs::PlayStream::StreamInfo("a", "b", "c", "d", "e"),
                        [&pushed_artist, &pushed_id, &was_first, &was_start_requested]
                        (const auto &stream, auto stream_id,
                         bool is_first, bool is_start_requested)
                        {
                            pushed_id = stream_id;
                            pushed_artist = stream.artist_;
                            was_first = is_first;
                            was_start_requested = is_start_requested;
                            return true;
                        }));
    CHECK(pushed_artist == "a");
    CHECK(was_first);
    CHECK_FALSE(was_start_requested);
    CHECK(pushed_id.get().is_valid());
    auto current_id(pushed_id);

    CHECK(player->next(Regs::PlayStream::StreamInfo("f", "g", "h", "i", "j")));
    CHECK(pushed_artist == "a");

    expect<MockMessages::MsgInfo>(mock_messages, "Next app stream 257", false);
    CHECK(player->notifications().started(current_id) == Regs::PlayStream::PlainPlayerNotifications::StartResult::STARTED);
    mock_messages->done();

    CHECK(pushed_artist == "f");
    CHECK_FALSE(was_first);
    CHECK_FALSE(was_start_requested);
    CHECK(pushed_id.get().is_valid());
    ++current_id;
    CHECK(current_id == pushed_id);

    expect<MockMessages::MsgInfo>(mock_messages, "Next app stream 258", false);
    CHECK(player->notifications().started(pushed_id) == Regs::PlayStream::PlainPlayerNotifications::StartResult::PLAYING_ON);
    mock_messages->done();

    CHECK(pushed_artist == "f");
    CHECK(current_id == pushed_id);
}

TEST_CASE_FIXTURE(Fixture,
                  "Pushing next stream quickly replaces previously pushed streams")
{
    activate_player();

    std::string pushed_artist;
    bool was_first = false;
    bool was_start_requested = false;
    auto pushed_id(Regs::PlayStream::PlainPlayer::StreamID::make_invalid());

    CHECK(player->start(Regs::PlayStream::StreamInfo("a", "b", "c", "d", "e"),
                        [&pushed_artist, &pushed_id, &was_first, &was_start_requested]
                        (const auto &stream, auto stream_id,
                         bool is_first, bool is_start_requested)
                        {
                            pushed_id = stream_id;
                            pushed_artist = stream.artist_;
                            was_first = is_first;
                            was_start_requested = is_start_requested;
                            return true;
                        }));
    CHECK(pushed_artist == "a");
    CHECK(was_first);
    CHECK_FALSE(was_start_requested);
    CHECK(pushed_id.get().is_valid());
    auto current_id(pushed_id);

    CHECK(player->next(Regs::PlayStream::StreamInfo("f", "g", "h", "i", "j")));
    CHECK(pushed_artist == "a");

    CHECK(player->next(Regs::PlayStream::StreamInfo("k", "l", "m", "n", "o")));
    CHECK(pushed_artist == "a");

    expect<MockMessages::MsgInfo>(mock_messages, "Next app stream 257", false);
    CHECK(player->notifications().started(current_id) == Regs::PlayStream::PlainPlayerNotifications::StartResult::STARTED);
    mock_messages->done();

    CHECK(pushed_artist == "k");
    CHECK_FALSE(was_first);
    CHECK_FALSE(was_start_requested);
    CHECK(pushed_id.get().is_valid());
    ++current_id;
    CHECK(current_id == pushed_id);

    expect<MockMessages::MsgInfo>(mock_messages, "Next app stream 258", false);
    CHECK(player->notifications().started(pushed_id) == Regs::PlayStream::PlainPlayerNotifications::StartResult::PLAYING_ON);
    mock_messages->done();

    CHECK(pushed_artist == "k");
    CHECK(current_id == pushed_id);
}

/*
 * This test demonstrates that follow-up streams are accepted if the currently
 * playing stream stops for some reason which has not been intended by the user
 * (corrupted stream data, network failure, wrong time information).
 */
TEST_CASE_FIXTURE(Fixture,
                  "Pushing next stream late after stopped/aborted first stream works")
{
    activate_player();

    bool was_first = false;
    bool was_start_requested = false;
    auto pushed_id(Regs::PlayStream::PlainPlayer::StreamID::make_invalid());

    CHECK(player->start(Regs::PlayStream::StreamInfo("a1", "b1", "c1", "d1", "e1"),
                        [&pushed_id, &was_first, &was_start_requested]
                        (const auto &stream, auto stream_id,
                         bool is_first, bool is_start_requested)
                        {
                            pushed_id = stream_id;
                            was_first = is_first;
                            was_start_requested = is_start_requested;
                            return true;
                        }));
    CHECK(was_first);
    CHECK_FALSE(was_start_requested);
    CHECK(pushed_id.get().is_valid());
    auto current_id(pushed_id);

    expect<MockMessages::MsgInfo>(mock_messages, "Next app stream 257", false);
    CHECK(player->notifications().started(current_id) == Regs::PlayStream::PlainPlayerNotifications::StartResult::STARTED);
    mock_messages->done();
    REQUIRE(player->get_current_stream_info().is_known());
    CHECK(player->get_current_stream_info()->artist_ == "a1");

    /* stream stopped without explicit stop request from user */
    CHECK(player->notifications().stopped() == Regs::PlayStream::PlainPlayerNotifications::StopResult::STOPPED_EXTERNALLY);
    CHECK_FALSE(player->get_current_stream_info().is_known());

    /* we are late, but we can still continue with playing the next stream */
    CHECK(player->next(Regs::PlayStream::StreamInfo("a2", "b2", "c2", "d2", "e2")));
    CHECK_FALSE(was_first);
    CHECK_FALSE(was_start_requested);
    ++current_id;
    CHECK(current_id == pushed_id);

    CHECK_FALSE(player->get_current_stream_info().is_known());
    expect<MockMessages::MsgInfo>(mock_messages, "Next app stream 258", false);
    CHECK(player->notifications().started(current_id) == Regs::PlayStream::PlainPlayerNotifications::StartResult::PLAYING_ON);
    mock_messages->done();
    CHECK(current_id == pushed_id);
    REQUIRE(player->get_current_stream_info().is_known());
    CHECK(player->get_current_stream_info()->artist_ == "a2");
}

TEST_CASE_FIXTURE(Fixture, "Playing a list of four tracks")
{
    activate_player();
    CHECK_FALSE(player->get_current_stream_info().is_known());

    bool was_first = false;
    bool was_start_requested = false;
    auto pushed_id(Regs::PlayStream::PlainPlayer::StreamID::make_invalid());

    CHECK(player->start(Regs::PlayStream::StreamInfo("a1", "b1", "c1", "d1", "e1"),
                        [&pushed_id, &was_first, &was_start_requested]
                        (const auto &stream, auto stream_id,
                         bool is_first, bool is_start_requested)
                        {
                            pushed_id = stream_id;
                            was_first = is_first;
                            was_start_requested = is_start_requested;
                            return true;
                        }));
    CHECK(was_first);
    CHECK_FALSE(was_start_requested);
    CHECK(pushed_id.get().is_valid());
    auto current_id(pushed_id);
    REQUIRE(player->get_current_stream_info().is_known());
    CHECK(player->get_current_stream_info()->artist_ == "a1");

    expect<MockMessages::MsgInfo>(mock_messages, "Next app stream 257", false);
    CHECK(player->notifications().started(current_id) == Regs::PlayStream::PlainPlayerNotifications::StartResult::STARTED);
    mock_messages->done();
    CHECK(current_id == pushed_id);
    REQUIRE(player->get_current_stream_info().is_known());
    CHECK(player->get_current_stream_info()->artist_ == "a1");

    CHECK(player->next(Regs::PlayStream::StreamInfo("a2", "b2", "c2", "d2", "e2")));
    CHECK_FALSE(was_first);
    CHECK_FALSE(was_start_requested);
    ++current_id;
    CHECK(current_id == pushed_id);
    REQUIRE(player->get_current_stream_info().is_known());
    CHECK(player->get_current_stream_info()->artist_ == "a1");
    expect<MockMessages::MsgInfo>(mock_messages, "Next app stream 258", false);
    CHECK(player->notifications().started(current_id) == Regs::PlayStream::PlainPlayerNotifications::StartResult::PLAYING_ON);
    mock_messages->done();
    CHECK(current_id == pushed_id);
    REQUIRE(player->get_current_stream_info().is_known());
    CHECK(player->get_current_stream_info()->artist_ == "a2");

    CHECK(player->next(Regs::PlayStream::StreamInfo("a3", "b3", "c3", "d3", "e3")));
    CHECK_FALSE(was_first);
    CHECK_FALSE(was_start_requested);
    ++current_id;
    CHECK(current_id == pushed_id);
    REQUIRE(player->get_current_stream_info().is_known());
    CHECK(player->get_current_stream_info()->artist_ == "a2");
    expect<MockMessages::MsgInfo>(mock_messages, "Next app stream 259", false);
    CHECK(player->notifications().started(current_id) == Regs::PlayStream::PlainPlayerNotifications::StartResult::PLAYING_ON);
    mock_messages->done();
    CHECK(current_id == pushed_id);
    REQUIRE(player->get_current_stream_info().is_known());
    CHECK(player->get_current_stream_info()->artist_ == "a3");

    CHECK(player->next(Regs::PlayStream::StreamInfo("a4", "b4", "c4", "d4", "e4")));
    CHECK_FALSE(was_first);
    CHECK_FALSE(was_start_requested);
    ++current_id;
    CHECK(current_id == pushed_id);
    REQUIRE(player->get_current_stream_info().is_known());
    CHECK(player->get_current_stream_info()->artist_ == "a3");
    expect<MockMessages::MsgInfo>(mock_messages, "Next app stream 260", false);
    CHECK(player->notifications().started(current_id) == Regs::PlayStream::PlainPlayerNotifications::StartResult::PLAYING_ON);
    mock_messages->done();
    CHECK(current_id == pushed_id);
    REQUIRE(player->get_current_stream_info().is_known());
    CHECK(player->get_current_stream_info()->artist_ == "a4");

    CHECK(player->notifications().stopped() == Regs::PlayStream::PlainPlayerNotifications::StopResult::STOPPED_EXTERNALLY);
    CHECK(current_id == pushed_id);
    CHECK_FALSE(player->get_current_stream_info().is_known());
}

TEST_CASE_FIXTURE(Fixture,
                  "Next track is not accepted after explicit stop command from user (player stops quickly)")
{
    activate_player();

    bool was_first = false;
    bool was_start_requested = false;
    auto pushed_id(Regs::PlayStream::PlainPlayer::StreamID::make_invalid());

    CHECK(player->start(Regs::PlayStream::StreamInfo("a1", "b1", "c1", "d1", "e1"),
                        [&pushed_id, &was_first, &was_start_requested]
                        (const auto &stream, auto stream_id,
                         bool is_first, bool is_start_requested)
                        {
                            pushed_id = stream_id;
                            was_first = is_first;
                            was_start_requested = is_start_requested;
                            return true;
                        }));
    CHECK(was_first);
    CHECK_FALSE(was_start_requested);
    CHECK(pushed_id.get().is_valid());
    auto current_id(pushed_id);

    expect<MockMessages::MsgInfo>(mock_messages, "Next app stream 257", false);
    CHECK(player->notifications().started(current_id) == Regs::PlayStream::PlainPlayerNotifications::StartResult::STARTED);
    mock_messages->done();
    REQUIRE(player->get_current_stream_info().is_known());
    CHECK(player->get_current_stream_info()->artist_ == "a1");

    bool was_called = false;
    CHECK(player->stop([&was_called] () { was_called = true; return true; }));
    CHECK(was_called);

    /* stream stopped after explicit stop request from user */
    CHECK(player->notifications().stopped() == Regs::PlayStream::PlainPlayerNotifications::StopResult::STOPPED_AS_REQUESTED);
    CHECK_FALSE(player->get_current_stream_info().is_known());

    /* no luck... */
    expect<MockMessages::MsgError>(mock_messages, 0, LOG_CRIT,
        "BUG: Attempted to set next stream while stopped", false);
    CHECK_FALSE(player->next(Regs::PlayStream::StreamInfo("a2", "b2", "c2", "d2", "e2")));
    CHECK(current_id == pushed_id);
    CHECK_FALSE(player->get_current_stream_info().is_known());
}

TEST_CASE_FIXTURE(Fixture,
                  "Next track is not accepted after explicit stop command from user (player stops late)")
{
    activate_player();

    bool was_first = false;
    bool was_start_requested = false;
    auto pushed_id(Regs::PlayStream::PlainPlayer::StreamID::make_invalid());

    CHECK(player->start(Regs::PlayStream::StreamInfo("a1", "b1", "c1", "d1", "e1"),
                        [&pushed_id, &was_first, &was_start_requested]
                        (const auto &stream, auto stream_id,
                         bool is_first, bool is_start_requested)
                        {
                            pushed_id = stream_id;
                            was_first = is_first;
                            was_start_requested = is_start_requested;
                            return true;
                        }));
    CHECK(was_first);
    CHECK_FALSE(was_start_requested);
    CHECK(pushed_id.get().is_valid());
    auto current_id(pushed_id);

    expect<MockMessages::MsgInfo>(mock_messages, "Next app stream 257", false);
    CHECK(player->notifications().started(current_id) == Regs::PlayStream::PlainPlayerNotifications::StartResult::STARTED);
    mock_messages->done();
    REQUIRE(player->get_current_stream_info().is_known());
    CHECK(player->get_current_stream_info()->artist_ == "a1");

    bool was_called = false;
    CHECK(player->stop([&was_called] () { was_called = true; return true; }));
    CHECK(was_called);

    /* no luck, already stopping... */
    expect<MockMessages::MsgError>(mock_messages, 0, LOG_CRIT,
        "BUG: Attempted to set next stream while stopped requested",
        false);
    CHECK_FALSE(player->next(Regs::PlayStream::StreamInfo("a2", "b2", "c2", "d2", "e2")));
    CHECK(current_id == pushed_id);
    REQUIRE(player->get_current_stream_info().is_known());
    CHECK(player->get_current_stream_info()->artist_ == "a1");

    /* stream stopped after explicit stop request from user */
    CHECK(player->notifications().stopped() == Regs::PlayStream::PlainPlayerNotifications::StopResult::STOPPED_AS_REQUESTED);
    CHECK_FALSE(player->get_current_stream_info().is_known());
}

TEST_CASE_FIXTURE(Fixture,
                  "Notification about stopped stream while deselected causes log entry")
{
    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_CRIT,
            "BUG: App stream stopped in unexpected state DESELECTED", false);
    CHECK(player->notifications().stopped() == Regs::PlayStream::PlainPlayerNotifications::StopResult::WRONG_STATE);
}

TEST_CASE_FIXTURE(Fixture,
                  "Notification about stopped stream while stopped is OK")
{
    activate_player();

    CHECK(player->notifications().stopped() == Regs::PlayStream::PlainPlayerNotifications::StopResult::ALREADY_STOPPED);
}

TEST_CASE_FIXTURE(Fixture,
                  "Notification about started stream while deselected causes log entry")
{
    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_CRIT,
            "BUG: App stream 257 started in unexpected state DESELECTED", false);
    CHECK(player->notifications().started(Regs::PlayStream::PlainPlayer::StreamID::make()) == Regs::PlayStream::PlainPlayerNotifications::StartResult::WRONG_STATE);
}

TEST_CASE_FIXTURE(Fixture,
                  "Notification about started stream while stopped causes log entry")
{
    activate_player();

    expect<MockMessages::MsgError>(
            mock_messages, 0, LOG_CRIT,
            "BUG: App stream 261 started in unexpected state STOPPED", false);
    CHECK(player->notifications().started(Regs::PlayStream::PlainPlayer::StreamID::make(5)) == Regs::PlayStream::PlainPlayerNotifications::StartResult::WRONG_STATE);
}

TEST_SUITE_END();
