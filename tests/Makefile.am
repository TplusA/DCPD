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

LIBS += $(CUTTER_LIBS)

check_LTLIBRARIES = test_dynamic_buffer.la test_registers.la

test_dynamic_buffer_la_SOURCES = test_dynamic_buffer.c
test_dynamic_buffer_la_LIBADD = ../libdynamic_buffer.la
test_dynamic_buffer_la_CFLAGS = $(AM_CFLAGS)

test_registers_la_SOURCES = test_registers.cc mock_dcpd_dbus.hh mock_dcpd_dbus.cc mock_expectation.hh
test_registers_la_LIBADD = ../libregisters.la
test_registers_la_CFLAGS = $(AM_CFLAGS) $(DCPD_DEPENDENCIES_CFLAGS)
test_registers_la_CXXFLAGS = $(CXXRELAXEDWARNINGS) $(DCPD_DEPENDENCIES_CFLAGS)

CLEANFILES = test_report.xml test_report_junit.xml valgrind.xml

EXTRA_DIST = cutter2junit.xslt
EXTRA_DIST += cutter-1_2_4.supp cutter-children-1_2_4.supp
endif
