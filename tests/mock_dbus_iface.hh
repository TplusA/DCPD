#ifndef MOCK_DBUS_IFACE_HH
#define MOCK_DBUS_IFACE_HH

#include "dbus_iface_deep.h"
#include "mock_expectation.hh"

class MockDBusIface
{
  public:
    MockDBusIface(const MockDBusIface &) = delete;
    MockDBusIface &operator=(const MockDBusIface &) = delete;

    class Expectation;
    typedef MockExpectationsTemplate<Expectation> MockExpectations;
    MockExpectations *expectations_;

    bool ignore_all_;

    explicit MockDBusIface();
    ~MockDBusIface();

    void init();
    void check() const;

    void expect_dbus_setup(int ret, bool connect_to_session_bus);
    void expect_dbus_shutdown(void);

    void expect_dbus_get_playback_iface(tdbusdcpdPlayback *);
    void expect_dbus_get_views_iface(tdbusdcpdViews *);
    void expect_dbus_get_list_navigation_iface(tdbusdcpdListNavigation *);
    void expect_dbus_get_list_item_iface(tdbusdcpdListItem *);
};

extern MockDBusIface *mock_dbus_iface_singleton;

#endif /* !MOCK_DBUS_IFACE_HH */
