#
# Copyright (C) 2015--2020  T+A elektroakustik GmbH & Co. KG
#
# This file is part of DCPD.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA  02110-1301, USA.
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
    test_registers.la \
    test_drcpdcomm.la \
    test_transactions.la \
    test_xmodem.la \
    test_networkprefs.la \
    test_network_dispatcher.la \
    test_applink.la

test_applink_la_SOURCES = \
    test_applink.cc \
    mock_os.hh mock_os.cc \
    mock_network.hh mock_network.cc \
    mock_dbus_iface.hh mock_dbus_iface.cc \
    mock_airable_dbus.hh mock_airable_dbus.cc \
    mock_credentials_dbus.hh mock_credentials_dbus.cc \
    mock_messages.hh mock_messages.cc \
    mock_backtrace.hh mock_backtrace.cc
test_applink_la_LIBADD = \
    $(top_builddir)/src/libapplink.la \
    $(top_builddir)/src/libnetwork_dispatcher.la
test_applink_la_CFLAGS = $(AM_CFLAGS) $(DCPD_DEPENDENCIES_CFLAGS)
test_applink_la_CXXFLAGS = $(AM_CXXFLAGS) $(DCPD_DEPENDENCIES_CFLAGS)

test_registers_la_SOURCES = \
    test_registers.cc \
    ../src/dcpregs_filetransfer_priv.h \
    ../src/stream_id.h ../src/stream_id.hh \
    mock_dcpd_dbus.hh mock_dcpd_dbus.cc \
    mock_dbus_iface.hh mock_dbus_iface.cc \
    mock_file_transfer_dbus.hh mock_file_transfer_dbus.cc \
    mock_streamplayer_dbus.hh mock_streamplayer_dbus.cc \
    mock_credentials_dbus.hh mock_credentials_dbus.cc \
    mock_airable_dbus.hh mock_airable_dbus.cc \
    mock_artcache_dbus.hh mock_artcache_dbus.cc \
    mock_audiopath_dbus.hh mock_audiopath_dbus.cc \
    mock_logind_manager_dbus.hh mock_logind_manager_dbus.cc \
    mock_connman.hh mock_connman.cc \
    mock_os.hh mock_os.cc \
    mock_messages.hh mock_messages.cc \
    mock_backtrace.hh mock_backtrace.cc \
    mock_expectation.hh
test_registers_la_LIBADD = \
    $(top_builddir)/src/libregisters.la \
    $(top_builddir)/src/libplainplayer.la \
    $(top_builddir)/src/libshutdown_guard.la \
    $(top_builddir)/src/libnetworkprefs.la \
    $(top_builddir)/src/libservicelist.la \
    $(top_builddir)/src/libconnman_service.la \
    $(top_builddir)/src/libconnman_technology_registry.la \
    $(top_builddir)/src/libinifile.la \
    $(top_builddir)/src/libxmodem.la
test_registers_la_CFLAGS = $(AM_CFLAGS) $(DCPD_DEPENDENCIES_CFLAGS)
test_registers_la_CXXFLAGS = $(CXXRELAXEDWARNINGS) $(DCPD_DEPENDENCIES_CFLAGS)

test_drcpdcomm_la_SOURCES = \
    test_drcp_communication.cc \
    mock_os.hh mock_os.cc \
    mock_messages.hh mock_messages.cc \
    mock_expectation.hh
test_drcpdcomm_la_LIBADD = $(top_builddir)/src/libdrcpdcomm.la
test_drcpdcomm_la_CFLAGS = $(AM_CFLAGS)
test_drcpdcomm_la_CXXFLAGS = $(AM_CXXFLAGS)

test_transactions_la_SOURCES = \
    test_transactions.cc \
    mock_dcpd_dbus.hh mock_dcpd_dbus.cc \
    mock_logind_manager_dbus.hh mock_logind_manager_dbus.cc \
    mock_os.hh mock_os.cc \
    mock_messages.hh mock_messages.cc \
    mock_backtrace.hh mock_backtrace.cc \
    mock_expectation.hh
test_transactions_la_LIBADD = \
    $(top_builddir)/src/libtransactions.la \
    $(top_builddir)/src/libconfigproxy.la \
    $(top_builddir)/src/libregisters.la \
    $(top_builddir)/src/libplainplayer.la \
    $(top_builddir)/src/libservicelist.la \
    $(top_builddir)/src/libconnman_service.la \
    $(top_builddir)/src/libconnman_technology_registry.la \
    $(top_builddir)/src/libnetworkprefs.la \
    $(top_builddir)/src/libshutdown_guard.la
test_transactions_la_CFLAGS = $(AM_CFLAGS) $(DCPD_DEPENDENCIES_CFLAGS)
test_transactions_la_CXXFLAGS = $(AM_CXXFLAGS) $(DCPD_DEPENDENCIES_CFLAGS)

test_xmodem_la_SOURCES = \
    test_xmodem.cc \
    ../src/xmodem.h ../src/crc16.h \
    mock_expectation.hh
test_xmodem_la_LIBADD = $(top_builddir)/src/libxmodem.la
test_xmodem_la_CFLAGS = $(AM_CFLAGS)
test_xmodem_la_CXXFLAGS = $(AM_CXXFLAGS)

test_networkprefs_la_SOURCES = \
    test_networkprefs.cc \
    ../src/networkprefs.h \
    mock_os.hh mock_os.cc \
    mock_messages.hh mock_messages.cc \
    mock_expectation.hh
test_networkprefs_la_LIBADD = \
    $(top_builddir)/src/libnetworkprefs.la \
    $(top_builddir)/src/libservicelist.la \
    $(top_builddir)/src/libconnman_service.la \
    $(top_builddir)/src/libinifile.la
test_networkprefs_la_CFLAGS = $(AM_CFLAGS)
test_networkprefs_la_CXXFLAGS = $(AM_CXXFLAGS)

test_network_dispatcher_la_SOURCES = \
    test_network_dispatcher.cc \
    ../src/network_dispatcher.hh \
    mock_os.hh mock_os.cc \
    mock_messages.hh mock_messages.cc \
    mock_backtrace.hh mock_backtrace.cc \
    mock_expectation.hh
test_network_dispatcher_la_LIBADD = \
    $(top_builddir)/src/libnetwork_dispatcher.la \
    $(top_builddir)/src/libnetwork.la
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
