#
# Copyright (C) 2015  T+A elektroakustik GmbH & Co. KG
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

ACLOCAL_AMFLAGS = -I ../m4

bin_PROGRAMS = dcpd

dcpd_SOURCES = \
    dcpd.c os.c os.h registers.h registers_priv.h named_pipe.c named_pipe.h \
    network.c network.h \
    transactions.h dcpdefs.h messages.c messages.h \
    dynamic_buffer.h drcp.h drcp_command_codes.h \
    dcpregs_drcp.h dcpregs_networking.h \
    connman.c connman.h \
    dbus_iface.c dbus_iface.h dbus_iface_deep.h dbus_handlers.h

AM_CFLAGS = $(CWARNINGS)

AM_CPPFLAGS = $(DCPD_DEPENDENCIES_CFLAGS)

noinst_LTLIBRARIES = \
    libtransactions.la \
    libdynamic_buffer.la \
    libregisters.la \
    libinifile.la \
    libdrcpdcomm.la \
    libdbus_handlers.la \
    libdcpd_dbus.la \
    libconnman_dbus.la

dcpd_LDADD = $(noinst_LTLIBRARIES) $(DCPD_DEPENDENCIES_LIBS)

dcpd_LDFLAGS = $(LTLIBINTL)

libdynamic_buffer_la_SOURCES = dynamic_buffer.c dynamic_buffer.h
libdynamic_buffer_la_CFLAGS = $(AM_CFLAGS)

libregisters_la_SOURCES = \
    registers.c registers.h registers_priv.h \
    dcpregs_drcp.c dcpregs_drcp.h \
    dcpregs_networking.c dcpregs_networking.h \
    drcp_command_codes.h messages.h
libregisters_la_CFLAGS = $(AM_CFLAGS)

libinifile_la_SOURCES = inifile.c inifile.h
libinifile_la_CFLAGS = $(AM_CFLAGS)

libdbus_handlers_la_SOURCES = dbus_handlers.c dbus_handlers.h dcpregs_networking.h
libdbus_handlers_la_CFLAGS = $(AM_CFLAGS)

nodist_libdcpd_dbus_la_SOURCES = dcpd_dbus.c dcpd_dbus.h
libdcpd_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_libconnman_dbus_la_SOURCES = connman_dbus.c connman_dbus.h
libconnman_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

libdrcpdcomm_la_SOURCES = drcp.c drcp.h named_pipe.h dynamic_buffer.h messages.h
libdrcpdcomm_la_CFLAGS = $(AM_CFLAGS)

libtransactions_la_SOURCES = \
    transactions.c transactions.h os.h \
    dynamic_buffer.h registers.h named_pipe.h dcpdefs.h messages.h
libtransactions_la_CFLAGS = $(AM_CFLAGS)

BUILT_SOURCES = \
    $(nodist_libdcpd_dbus_la_SOURCES) \
    de_tahifi_dcpd.h \
    de_tahifi_dcpd.md \
    dcpd_dbus.stamp \
    $(nodist_libconnman_dbus_la_SOURCES) \
    net_connman.h \
    net_connman.md \
    connman_dbus.stamp

CLEANFILES = $(BUILT_SOURCES)

DBUS_IFACES = $(top_srcdir)/dbus_interfaces

de_tahifi_dcpd.h: dcpd_dbus.stamp
de_tahifi_dcpd.md: dcpd_dbus.stamp
dcpd_dbus.c: dcpd_dbus.stamp
dcpd_dbus.h: dcpd_dbus.stamp
dcpd_dbus.stamp: $(DBUS_IFACES)/de_tahifi_dcpd.xml
	$(GDBUS_CODEGEN) --generate-c-code=dcpd_dbus --c-namespace tdbus_dcpd --interface-prefix de.tahifi.Dcpd. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o de_tahifi_dcpd.md -H de_tahifi_dcpd.h -c tdbus_dcpd -s de.tahifi.Dcpd. -n "$(PACKAGE_NAME)"
	touch $@

net_connman.h: connman_dbus.stamp
net_connman.md: connman_dbus.stamp
connman_dbus.c: connman_dbus.stamp
connman_dbus.h: connman_dbus.stamp
connman_dbus.stamp: $(DBUS_IFACES)/net_connman.xml
	$(GDBUS_CODEGEN) --generate-c-code=connman_dbus --c-namespace tdbus_connman --interface-prefix net.connman. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o net_connman.md -H net_connman.h -c tdbus_connman -s net.connman. -n "$(PACKAGE_NAME)"
	touch $@
