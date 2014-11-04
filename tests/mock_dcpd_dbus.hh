#ifndef MOCK_DCPD_DBUS_HH
#define MOCK_DCPD_DBUS_HH

#include "dcpd_dbus.h"
#include "mock_expectation.hh"

class MockDcpdDBus
{
  public:
    MockDcpdDBus(const MockDcpdDBus &) = delete;
    MockDcpdDBus &operator=(const MockDcpdDBus &) = delete;

    class Expectation;
    typedef MockExpectationsTemplate<Expectation> MockExpectations;
    MockExpectations *expectations_;

    bool ignore_all_;

    explicit MockDcpdDBus();
    ~MockDcpdDBus();

    void init();
    void check() const;

    void expect_tdbus_dcpd_playback_emit_start(tdbusdcpdPlayback *object);
    void expect_tdbus_dcpd_playback_emit_stop(tdbusdcpdPlayback *object);
    void expect_tdbus_dcpd_playback_emit_pause(tdbusdcpdPlayback *object);
    void expect_tdbus_dcpd_playback_emit_next(tdbusdcpdPlayback *object);
    void expect_tdbus_dcpd_playback_emit_previous(tdbusdcpdPlayback *object);
    void expect_tdbus_dcpd_playback_emit_fast_forward(tdbusdcpdPlayback *object);
    void expect_tdbus_dcpd_playback_emit_fast_rewind(tdbusdcpdPlayback *object);
    void expect_tdbus_dcpd_playback_emit_fast_wind_stop(tdbusdcpdPlayback *object);
    void expect_tdbus_dcpd_playback_emit_fast_wind_set_factor(tdbusdcpdPlayback *object, gdouble arg_speed);
    void expect_tdbus_dcpd_playback_emit_repeat_mode_toggle(tdbusdcpdPlayback *object);
    void expect_tdbus_dcpd_playback_emit_shuffle_mode_toggle(tdbusdcpdPlayback *object);
    void expect_tdbus_dcpd_views_emit_open(tdbusdcpdViews *object, const gchar *arg_view_name);
    void expect_tdbus_dcpd_views_emit_toggle(tdbusdcpdViews *object, const gchar *arg_view_name_back, const gchar *arg_view_name_forth);
    void expect_tdbus_dcpd_list_navigation_emit_level_up(tdbusdcpdListNavigation *object);
    void expect_tdbus_dcpd_list_navigation_emit_level_down(tdbusdcpdListNavigation *object);
    void expect_tdbus_dcpd_list_navigation_emit_move_lines(tdbusdcpdListNavigation *object, gint arg_count);
    void expect_tdbus_dcpd_list_navigation_emit_move_pages(tdbusdcpdListNavigation *object, gint arg_count);
    void expect_tdbus_dcpd_list_item_emit_add_to_list(tdbusdcpdListItem *object, const gchar *arg_category, guint16 arg_index);
    void expect_tdbus_dcpd_list_item_emit_remove_from_list(tdbusdcpdListItem *object, const gchar *arg_category, guint16 arg_index);
};

extern MockDcpdDBus *mock_dcpd_dbus_singleton;

#endif /* !MOCK_DCPD_DBUS_HH */
