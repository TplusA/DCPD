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

ACLOCAL_AMFLAGS = -I ../m4

bin_PROGRAMS = dcpd

dcpd_SOURCES = \
    dcpd.c os.c os.h registers.h registers_priv.h named_pipe.c named_pipe.h \
    dcp_over_tcp.c dcp_over_tcp.h \
    smartphone_app.c smartphone_app.h \
    applink.h applink_variables.h \
    network.h \
    transactions.h dcpdefs.h messages.c messages.h \
    dynamic_buffer.h drcp.h drcp_command_codes.h \
    dcpregs_drcp.h dcpregs_networkconfig.h dcpregs_wlansurvey.h \
    dcpregs_filetransfer.h dcpregs_filetransfer_priv.h \
    dcpregs_tcptunnel.h dcpregs_playstream.h dcpregs_status.h \
    connman.c connman_iter.c connman_scan.c connman.h \
    connman_common.c connman_common.h \
    dbus_common.c dbus_common.h \
    dbus_iface.c dbus_iface.h dbus_iface_deep.h dbus_handlers.h

DBUS_IFACES = $(top_srcdir)/dbus_interfaces

AM_CFLAGS = $(CWARNINGS)

AM_CPPFLAGS = $(DCPD_DEPENDENCIES_CFLAGS)
AM_CPPFLAGS += -I$(DBUS_IFACES)

noinst_LTLIBRARIES = \
    libtransactions.la \
    libdynamic_buffer.la \
    libregisters.la \
    libinifile.la \
    libapplink.la \
    libdrcpdcomm.la \
    libxmodem.la \
    libnetwork_dispatcher.la \
    libshutdown_guard.la \
    libdbus_handlers.la \
    libdcpd_dbus.la \
    libdbusdl_dbus.la \
    libstreamplayer_dbus.la \
    libairable_dbus.la \
    libcredentials_dbus.la \
    libconnman_dbus.la \
    liblogind_dbus.la

dcpd_LDADD = $(noinst_LTLIBRARIES) $(DCPD_DEPENDENCIES_LIBS)

libdynamic_buffer_la_SOURCES = \
    dynamic_buffer.c dynamic_buffer.h \
    dynamic_buffer_util.c dynamic_buffer_util.h
libdynamic_buffer_la_CFLAGS = $(AM_CFLAGS)

libregisters_la_SOURCES = \
    registers.c registers.h registers_priv.h \
    dcpregs_drcp.c dcpregs_drcp.h \
    dcpregs_networkconfig.c dcpregs_networkconfig.h \
    dcpregs_wlansurvey.c dcpregs_wlansurvey.h \
    dcpregs_filetransfer.c dcpregs_filetransfer.h dcpregs_filetransfer_priv.h \
    dcpregs_tcptunnel.c dcpregs_tcptunnel.h \
    dcpregs_playstream.c dcpregs_playstream.h \
    dcpregs_status.h \
    dbusdl_dbus.h \
    stream_id.h \
    shutdown_guard.h \
    $(DBUS_IFACES)/de_tahifi_lists_errors.h \
    drcp_command_codes.h messages.h
libregisters_la_CFLAGS = $(AM_CFLAGS)

libinifile_la_SOURCES = inifile.c inifile.h
libinifile_la_CFLAGS = $(AM_CFLAGS)

libapplink_la_SOURCES = \
    applink.c applink.h \
    applink_variables.c applink_variables.h \
    dynamic_buffer.h dynamic_buffer_util.h
libapplink_la_CFLAGS = $(AM_CFLAGS)

libdbus_handlers_la_SOURCES = \
    dbus_handlers.c dbus_handlers.h \
    dcpregs_networkconfig.h \
    dcpregs_wlansurvey.h \
    dcpregs_filetransfer.h \
    dcpregs_playstream.h \
    dcpregs_status.h
libdbus_handlers_la_CFLAGS = $(AM_CFLAGS)

nodist_libdcpd_dbus_la_SOURCES = dcpd_dbus.c dcpd_dbus.h
libdcpd_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_libconnman_dbus_la_SOURCES = connman_dbus.c connman_dbus.h
libconnman_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_liblogind_dbus_la_SOURCES = logind_dbus.c logind_dbus.h
liblogind_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_libdbusdl_dbus_la_SOURCES = dbusdl_dbus.c dbusdl_dbus.h
libdbusdl_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_libstreamplayer_dbus_la_SOURCES = streamplayer_dbus.c streamplayer_dbus.h
libstreamplayer_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_libairable_dbus_la_SOURCES = airable_dbus.c airable_dbus.h
libairable_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_libcredentials_dbus_la_SOURCES = credentials_dbus.c credentials_dbus.h
libcredentials_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

libdrcpdcomm_la_SOURCES = \
    drcp.c drcp.h \
    named_pipe.h \
    dynamic_buffer.h dynamic_buffer_util.h \
    messages.h
libdrcpdcomm_la_CFLAGS = $(AM_CFLAGS)

libtransactions_la_SOURCES = \
    transactions.c transactions.h os.h \
    dynamic_buffer.h registers.h named_pipe.h dcpdefs.h messages.h
libtransactions_la_CFLAGS = $(AM_CFLAGS)

libxmodem_la_SOURCES = xmodem.c xmodem.h crc16.h os.h
libxmodem_la_CFLAGS = $(AM_CFLAGS)

libnetwork_dispatcher_la_SOURCES = \
    network_dispatcher.c network_dispatcher.h \
    network.c network.h \
    messages.h
libnetwork_dispatcher_la_CFLAGS = $(AM_CFLAGS)

libshutdown_guard_la_SOURCES = \
    shutdown_guard.c shutdown_guard.h \
    messages.h
libshutdown_guard_la_CFLAGS = $(AM_CFLAGS)

BUILT_SOURCES = \
    $(nodist_libdcpd_dbus_la_SOURCES) \
    de_tahifi_dcpd.h \
    de_tahifi_dcpd.md \
    dcpd_dbus.stamp \
    $(nodist_libdbusdl_dbus_la_SOURCES) \
    de_tahifi_dbusdl.h \
    de_tahifi_dbusdl.md \
    dbusdl_dbus.stamp \
    $(nodist_libstreamplayer_dbus_la_SOURCES) \
    de_tahifi_streamplayer.h \
    de_tahifi_streamplayer.md \
    streamplayer_dbus.stamp \
    $(nodist_libairable_dbus_la_SOURCES) \
    de_tahifi_airable.h \
    de_tahifi_airable.md \
    airable_dbus.stamp \
    $(nodist_libcredentials_dbus_la_SOURCES) \
    de_tahifi_credentials.h \
    de_tahifi_credentials.md \
    credentials_dbus.stamp \
    $(nodist_libconnman_dbus_la_SOURCES) \
    net_connman.h \
    net_connman.md \
    connman_dbus.stamp \
    $(nodist_liblogind_dbus_la_SOURCES) \
    org_freedesktop_logind.h \
    org_freedesktop_logind.md \
    logind_dbus.stamp

CLEANFILES = $(BUILT_SOURCES)

de_tahifi_dcpd.h: dcpd_dbus.stamp
de_tahifi_dcpd.md: dcpd_dbus.stamp
dcpd_dbus.c: dcpd_dbus.stamp
dcpd_dbus.h: dcpd_dbus.stamp
dcpd_dbus.stamp: $(DBUS_IFACES)/de_tahifi_dcpd.xml
	$(GDBUS_CODEGEN) --generate-c-code=dcpd_dbus --c-namespace tdbus_dcpd --interface-prefix de.tahifi.Dcpd. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o de_tahifi_dcpd.md -H de_tahifi_dcpd.h -c tdbus_dcpd -s de.tahifi.Dcpd. -n "$(PACKAGE_NAME)"
	touch $@

de_tahifi_dbusdl.h: dbusdl_dbus.stamp
de_tahifi_dbusdl.md: dbusdl_dbus.stamp
dbusdl_dbus.c: dbusdl_dbus.stamp
dbusdl_dbus.h: dbusdl_dbus.stamp
dbusdl_dbus.stamp: $(DBUS_IFACES)/de_tahifi_filetransfer.xml
	$(GDBUS_CODEGEN) --generate-c-code=dbusdl_dbus --c-namespace tdbus --interface-prefix de.tahifi. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o de_tahifi_dbusdl.md -H de_tahifi_dbusdl.h -c tdbus -s de.tahifi. -n "$(PACKAGE_NAME)"
	touch $@

de_tahifi_streamplayer.h: streamplayer_dbus.stamp
de_tahifi_streamplayer.md: streamplayer_dbus.stamp
streamplayer_dbus.c: streamplayer_dbus.stamp
streamplayer_dbus.h: streamplayer_dbus.stamp
streamplayer_dbus.stamp: $(DBUS_IFACES)/de_tahifi_streamplayer.xml
	$(GDBUS_CODEGEN) --generate-c-code=streamplayer_dbus --c-namespace tdbus_splay --interface-prefix de.tahifi.Streamplayer. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o de_tahifi_streamplayer.md -H de_tahifi_streamplayer.h -c tdbus_splay -s de.tahifi.Streamplayer. -n 'Streamplayer'
	touch $@

de_tahifi_airable.h: airable_dbus.stamp
de_tahifi_airable.md: airable_dbus.stamp
airable_dbus.c: airable_dbus.stamp
airable_dbus.h: airable_dbus.stamp
airable_dbus.stamp: $(DBUS_IFACES)/de_tahifi_airable.xml
	$(GDBUS_CODEGEN) --generate-c-code=airable_dbus --c-namespace tdbus --interface-prefix de.tahifi. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o de_tahifi_airable.md -H de_tahifi_airable.h -c tdbus -s de.tahifi. -n "$(PACKAGE_NAME) (Airable HTTP session security)"
	touch $@

de_tahifi_credentials.h: credentials_dbus.stamp
de_tahifi_credentials.md: credentials_dbus.stamp
credentials_dbus.c: credentials_dbus.stamp
credentials_dbus.h: credentials_dbus.stamp
credentials_dbus.stamp: $(DBUS_IFACES)/de_tahifi_credentials.xml
	$(GDBUS_CODEGEN) --generate-c-code=credentials_dbus --c-namespace tdbus_credentials --interface-prefix de.tahifi.Credentials. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o de_tahifi_credentials.md -H de_tahifi_credentials.h -c tdbus_credentials -s de.tahifi.Credentials. -n "$(PACKAGE_NAME) (passing credentials around)"
	touch $@

net_connman.h: connman_dbus.stamp
net_connman.md: connman_dbus.stamp
connman_dbus.c: connman_dbus.stamp
connman_dbus.h: connman_dbus.stamp
connman_dbus.stamp: $(DBUS_IFACES)/net_connman.xml
	$(GDBUS_CODEGEN) --generate-c-code=connman_dbus --c-namespace tdbus_connman --interface-prefix net.connman. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o net_connman.md -H net_connman.h -c tdbus_connman -s net.connman. -n "$(PACKAGE_NAME)"
	touch $@

org_freedesktop_logind.h: logind_dbus.stamp
org_freedesktop_logind.md: logind_dbus.stamp
logind_dbus.c: logind_dbus.stamp
logind_dbus.h: logind_dbus.stamp
logind_dbus.stamp: $(DBUS_IFACES)/org_freedesktop_login1.xml
	$(GDBUS_CODEGEN) --generate-c-code=logind_dbus --c-namespace tdbus_logind --interface-prefix org.freedesktop.login1. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o org_freedesktop_logind.md -H org_freedesktop_logind.h -c tdbus_logind -s org.freedesktop.login1. -n "$(PACKAGE_NAME)"
	touch $@
