#
# Copyright (C) 2018  T+A elektroakustik GmbH & Co. KG
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

if WITH_DOCTEST
check_PROGRAMS = test_connman_service

TESTS = $(check_PROGRAMS)

AM_CPPFLAGS = -DDOCTEST_CONFIG_TREAT_CHAR_STAR_AS_STRING
AM_CPPFLAGS += -I$(top_srcdir)/src -I$(top_builddir)/src
AM_CPPFLAGS += -I$(top_srcdir)/dbus_interfaces
AM_CFLAGS = $(CWARNINGS)
AM_CXXFLAGS = $(CXXWARNINGS)

noinst_LTLIBRARIES = libtestrunner.la

libtestrunner_la_SOURCES = testrunner.cc

test_connman_service_SOURCES = test_connman_service.cc
test_connman_service_LDADD = \
    libtestrunner.la \
    $(top_builddir)/src/libconnman_service.la
test_connman_service_CPPFLAGS = $(AM_CPPFLAGS)
test_connman_service_CXXFLAGS = $(AM_CXXFLAGS)

doctest: $(check_PROGRAMS)
	for p in $(check_PROGRAMS); do ./$$p $(DOCTEST_EXTRA_OPTIONS); done
endif
