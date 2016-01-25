#
# Copyright (C) 2015, 2016  T+A elektroakustik GmbH & Co. KG
#
# This file is part of DCPD.
#
# DCPD is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 3 as
# published by the Free Software Foundation.
#
# DCPD is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with DCPD.  If not, see <http://www.gnu.org/licenses/>.
#

if WITH_CUTTER
TESTS = run_test.sh

if WITH_VALGRIND
TESTS += valgrind.sh
endif

AM_TESTS_ENVIRONMENT = CUTTER="$(CUTTER)" XSLTPROC="$(XSLTPROC)" VALGRIND="$(VALGRIND)"

AM_LDFLAGS = -module -rpath $(libdir) -avoid-version -no-undefined

AM_CPPFLAGS = $(CPPCUTTER_CFLAGS)
AM_CPPFLAGS += -I$(top_srcdir)/src -I$(top_builddir)/src
AM_CPPFLAGS += -I$(top_srcdir)/dbus_interfaces

AM_CFLAGS = $(CWARNINGS)

AM_CXXFLAGS = $(CXXWARNINGS)

LIBS += $(CPPCUTTER_LIBS)

check_LTLIBRARIES = \
    test_dynamic_buffer.la \
    test_registers.la \
    test_drcpdcomm.la \
    test_transactions.la \
    test_xmodem.la \
    test_network_dispatcher.la

test_dynamic_buffer_la_SOURCES = test_dynamic_buffer.c
test_dynamic_buffer_la_LIBADD = $(top_builddir)/src/libdynamic_buffer.la
test_dynamic_buffer_la_CFLAGS = $(AM_CFLAGS)

test_registers_la_SOURCES = \
    test_registers.cc \
    ../src/dcpregs_filetransfer_priv.h \
    ../src/stream_id.h ../src/stream_id.hh \
    mock_dcpd_dbus.hh mock_dcpd_dbus.cc \
    mock_dbus_iface.hh mock_dbus_iface.cc \
    mock_file_transfer_dbus.hh mock_file_transfer_dbus.cc \
    mock_streamplayer_dbus.hh mock_streamplayer_dbus.cc \
    mock_logind_manager_dbus.hh mock_logind_manager_dbus.cc \
    mock_connman.hh mock_connman.cc \
    mock_os.hh mock_os.cc \
    mock_messages.hh mock_messages.cc \
    mock_expectation.hh
test_registers_la_LIBADD = \
    $(top_builddir)/src/libregisters.la \
    $(top_builddir)/src/libshutdown_guard.la \
    $(top_builddir)/src/libdynamic_buffer.la \
    $(top_builddir)/src/libinifile.la \
    $(top_builddir)/src/libxmodem.la
test_registers_la_CFLAGS = $(AM_CFLAGS) $(DCPD_DEPENDENCIES_CFLAGS)
test_registers_la_CXXFLAGS = $(CXXRELAXEDWARNINGS) $(DCPD_DEPENDENCIES_CFLAGS)

test_drcpdcomm_la_SOURCES = \
    test_drcp_communication.cc \
    mock_os.hh mock_os.cc \
    mock_messages.hh mock_messages.cc \
    mock_expectation.hh
test_drcpdcomm_la_LIBADD = $(top_builddir)/src/libdrcpdcomm.la $(top_builddir)/src/libdynamic_buffer.la
test_drcpdcomm_la_CFLAGS = $(AM_CFLAGS)
test_drcpdcomm_la_CXXFLAGS = $(AM_CXXFLAGS)

test_transactions_la_SOURCES = \
    test_transactions.cc \
    mock_dcpd_dbus.hh mock_dcpd_dbus.cc \
    mock_connman.hh mock_connman.cc \
    mock_logind_manager_dbus.hh mock_logind_manager_dbus.cc \
    mock_os.hh mock_os.cc \
    mock_messages.hh mock_messages.cc \
    mock_expectation.hh
test_transactions_la_LIBADD = \
    $(top_builddir)/src/libtransactions.la \
    $(top_builddir)/src/libregisters.la \
    $(top_builddir)/src/libshutdown_guard.la \
    $(top_builddir)/src/libdynamic_buffer.la
test_transactions_la_CFLAGS = $(AM_CFLAGS) $(DCPD_DEPENDENCIES_CFLAGS)
test_transactions_la_CXXFLAGS = $(AM_CXXFLAGS) $(DCPD_DEPENDENCIES_CFLAGS)

test_xmodem_la_SOURCES = \
    test_xmodem.cc \
    ../src/xmodem.h ../src/crc16.h \
    mock_expectation.hh
test_xmodem_la_LIBADD = $(top_builddir)/src/libxmodem.la
test_xmodem_la_CFLAGS = $(AM_CFLAGS)
test_xmodem_la_CXXFLAGS = $(AM_CXXFLAGS)

test_network_dispatcher_la_SOURCES = \
    test_network_dispatcher.cc \
    ../src/network_dispatcher.h \
    mock_os.hh mock_os.cc \
    mock_messages.hh mock_messages.cc \
    mock_expectation.hh
test_network_dispatcher_la_LIBADD = $(top_builddir)/src/libnetwork_dispatcher.la
test_network_dispatcher_la_CFLAGS = $(AM_CFLAGS)
test_network_dispatcher_la_CXXFLAGS = $(AM_CXXFLAGS)

CLEANFILES = test_report.xml test_report_junit.xml valgrind.xml

EXTRA_DIST = cutter2junit.xslt
EXTRA_DIST += cutter-1_2_4.supp

check-local: check-TESTS
	@if $(GREP) -w cutter $(TEST_LOGS); then \
	    echo "Unit tests failed (check log)"; \
	    exit 1; \
	fi
endif
