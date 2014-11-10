if WITH_CUTTER
TESTS = run_test.sh

if WITH_VALGRIND
TESTS += valgrind.sh
endif

AM_TESTS_ENVIRONMENT = CUTTER="$(CUTTER)" XSLTPROC="$(XSLTPROC)" VALGRIND="$(VALGRIND)"

AM_LDFLAGS = -module -rpath $(libdir) -avoid-version -no-undefined

AM_CPPFLAGS = $(CUTTER_CFLAGS)
AM_CPPFLAGS += -I$(top_srcdir)

AM_CFLAGS = $(CWARNINGS)

AM_CXXFLAGS = $(CXXWARNINGS)

LIBS += $(CPPCUTTER_LIBS)

check_LTLIBRARIES = test_dynamic_buffer.la test_registers.la test_drcpdcomm.la

test_dynamic_buffer_la_SOURCES = test_dynamic_buffer.c
test_dynamic_buffer_la_LIBADD = ../libdynamic_buffer.la
test_dynamic_buffer_la_CFLAGS = $(AM_CFLAGS)

test_registers_la_SOURCES = \
    test_registers.cc \
    mock_dcpd_dbus.hh mock_dcpd_dbus.cc \
    mock_dbus_iface.hh mock_dbus_iface.cc \
    mock_messages.hh mock_messages.cc \
    mock_expectation.hh
test_registers_la_LIBADD = ../libregisters.la ../libdynamic_buffer.la
test_registers_la_CFLAGS = $(AM_CFLAGS) $(DCPD_DEPENDENCIES_CFLAGS)
test_registers_la_CXXFLAGS = $(CXXRELAXEDWARNINGS) $(DCPD_DEPENDENCIES_CFLAGS)

test_drcpdcomm_la_SOURCES = \
    test_drcp_communication.cc \
    mock_named_pipe.hh mock_named_pipe.cc \
    mock_messages.hh mock_messages.cc \
    mock_expectation.hh
test_drcpdcomm_la_LIBADD = ../libdrcpdcomm.la ../libdynamic_buffer.la
test_drcpdcomm_la_CFLAGS = $(AM_CFLAGS)
test_drcpdcomm_la_CXXFLAGS = $(AM_CXXFLAGS)

CLEANFILES = test_report.xml test_report_junit.xml valgrind.xml

EXTRA_DIST = cutter2junit.xslt
EXTRA_DIST += cutter-1_2_4.supp cutter-children-1_2_4.supp
endif
