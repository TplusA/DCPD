#
# Copyright (C) 2018, 2019, 2020  T+A elektroakustik GmbH & Co. KG
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

if WITH_DOCTEST
check_PROGRAMS = \
    test_connman_service \
    test_connman_property_cache \
    test_access_point \
    test_plainplayer \
    test_aupal_parser \
    test_registers_system_update

TESTS = run_tests.sh

if WITH_VALGRIND
AM_TESTS_ENVIRONMENT = VALGRIND="$(VALGRIND)"
TESTS += valgrind.sh
endif

EXTRA_DIST = run_tests.sh valgrind.sh
CLEANFILES = *.junit.xml *.valgrind.xml

AM_CPPFLAGS = -DDOCTEST_CONFIG_TREAT_CHAR_STAR_AS_STRING
AM_CPPFLAGS += -I$(top_srcdir)/src -I$(top_builddir)/src
AM_CPPFLAGS += -I$(top_srcdir)/dbus_interfaces
AM_CFLAGS = $(CWARNINGS)
AM_CXXFLAGS = $(CXXWARNINGS)

noinst_LTLIBRARIES = libtestrunner.la

libtestrunner_la_SOURCES = testrunner.cc

test_connman_service_SOURCES = \
    test_connman_service.cc \
    mock_os.hh mock_os.cc \
    mock_messages.hh mock_messages.cc \
    mock_expectation.hh
test_connman_service_LDADD = \
    libtestrunner.la \
    $(top_builddir)/src/libconnman_service.la
test_connman_service_CPPFLAGS = $(AM_CPPFLAGS)
test_connman_service_CXXFLAGS = $(AM_CXXFLAGS)

test_connman_property_cache_SOURCES = test_connman_property_cache.cc
test_connman_property_cache_LDADD = libtestrunner.la
test_connman_property_cache_CPPFLAGS = $(AM_CPPFLAGS)
test_connman_property_cache_CXXFLAGS = $(AM_CXXFLAGS)

test_access_point_SOURCES = \
    test_access_point.cc \
    mock_messages.hh mock_messages.cc \
    mock_backtrace.hh mock_backtrace.cc \
    mock_connman_technology_registry.hh mock_connman_technology_registry.cc \
    mock_os.hh mock_os.cc \
    mock_expectation.hh
test_access_point_LDADD = \
    libtestrunner.la \
    $(top_builddir)/src/libaccesspoint.la \
    $(top_builddir)/src/libservicelist.la \
    $(top_builddir)/src/libconnman_service.la
test_access_point_CPPFLAGS = $(AM_CPPFLAGS)
test_access_point_CXXFLAGS = $(AM_CXXFLAGS)

test_aupal_parser_SOURCES = \
    test_aupal_parser.cc
test_aupal_parser_LDADD = \
    libtestrunner.la \
    $(top_builddir)/src/libaudiopath_minidsl.la
test_aupal_parser_CPPFLAGS = $(AM_CPPFLAGS)
test_aupal_parser_CXXFLAGS = $(AM_CXXFLAGS)

test_plainplayer_SOURCES = \
    test_plainplayer.cc \
    mock_messages.hh mock_messages.cc \
    mock_backtrace.hh mock_backtrace.cc \
    mock_os.hh mock_os.cc \
    mock_expectation.hh
test_plainplayer_LDADD = \
    libtestrunner.la \
    $(top_builddir)/src/libplainplayer.la
test_plainplayer_CPPFLAGS = $(AM_CPPFLAGS)
test_plainplayer_CXXFLAGS = $(AM_CXXFLAGS)

test_registers_system_update_SOURCES = \
    test_registers_system_update.cc \
    mock_messages.hh mock_messages.cc \
    mock_expectation.hh
test_registers_system_update_LDADD = \
    libtestrunner.la \
    $(top_builddir)/src/libregisters.la \
    $(top_builddir)/src/librest_api_light.la
test_registers_system_update_CPPFLAGS = $(AM_CPPFLAGS)
test_registers_system_update_CXXFLAGS = $(AM_CXXFLAGS)

doctest: $(check_PROGRAMS)
	for p in $(check_PROGRAMS); do \
	    if ./$$p $(DOCTEST_EXTRA_OPTIONS); then :; \
	    else \
	        echo "*****"; \
	        echo "***** Running $$p again in gdb due to failures"; \
	        echo "*****"; \
	        gdb -ex run --args ./$$p $(DOCTEST_EXTRA_OPTIONS); \
	    fi; \
	done

doctest-valgrind: $(check_PROGRAMS)
	for p in $(check_PROGRAMS); do $(VALGRIND) --leak-check=full --show-reachable=yes --error-limit=no ./$$p $(DOCTEST_EXTRA_OPTIONS); done
endif
