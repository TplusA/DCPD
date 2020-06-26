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

ACLOCAL_AMFLAGS = -I ../m4

bin_PROGRAMS = dcpd

dcpd_SOURCES = \
    dcpd.cc os.c os.h os.hh named_pipe.c named_pipe.h \
    registers.hh registers_priv.hh register_response_writer.hh \
    dcp_over_tcp.c dcp_over_tcp.h mainloop.hh logged_lock.hh \
    smartphone_app_send.cc smartphone_app_send.hh smartphone_app.hh \
    actor_id.h \
    applink.hh applink_variables.hh \
    network.h network_status_bits.h \
    accesspoint_manager.hh accesspoint.hh \
    transactions.hh dcpdefs.h \
    messages.c messages.h messages_glib.c messages_glib.h \
    backtrace.c backtrace.h \
    drcp.hh drcp_command_codes.h \
    dcpregs_drcp.hh dcpregs_networkconfig.hh dcpregs_wlansurvey.hh \
    dcpregs_filetransfer.hh dcpregs_filetransfer_priv.h \
    dcpregs_tcptunnel.hh dcpregs_playstream.hh dcpregs_stream_speed.hh dcpregs_status.hh \
    dcpregs_upnpname.hh dcpregs_upnpserver.hh dcpregs_audiosources.hh dcpregs_volume.hh \
    dcpregs_searchparameters.hh dcpregs_appliance.hh dcpregs_internationalization.hh \
    dcpregs_accesspoint.hh dcpregs_datetime.hh dcpregs_audiopaths.hh \
    dcpregs_system_update.hh \
    audiopath_minidsl.hh json.hh \
    connman_iter.c connman_iter.h connman_scan.cc connman_scan.hh \
    connman_common.c connman_common.h \
    connman_service.hh connman_service_list.hh maybe.hh \
    connman_address.hh \
    connman_technology_registry.hh connman_property_cache.hh \
    network_device.hh network_device_list.hh \
    stream_id.h stream_id.hh plainplayer.hh coverart.hh gvariantwrapper.hh md5.hh \
    dbus_common.c dbus_common.h \
    dbus_iface.cc dbus_iface.hh dbus_iface_deep.h \
    dbus_handlers.h dbus_handlers_connman_agent.hh connman_agent.h \
    dbus_handlers_connman_manager.hh \
    configuration.cc configuration.hh configuration_base.hh configuration_changed.hh \
    configuration_settings.hh inifile.h \
    configuration_dcpd.cc configuration_dcpd.hh configuration_dcpd.h \
    configproxy.h \
    networkprefs.h

DBUS_IFACES = $(top_srcdir)/dbus_interfaces

AM_CFLAGS = $(CWARNINGS)

AM_CXXFLAGS = $(CXXWARNINGS)

AM_CPPFLAGS = $(DCPD_DEPENDENCIES_CFLAGS)
AM_CPPFLAGS += -I$(DBUS_IFACES)

noinst_LTLIBRARIES = \
    libtransactions.la \
    libdbus_handlers.la \
    libregisters.la \
    libnetworkprefs.la \
    libinifile.la \
    libapplink.la \
    libaudiopath_minidsl.la \
    libdrcpdcomm.la \
    libxmodem.la \
    libnetwork.la \
    libnetwork_dispatcher.la \
    libshutdown_guard.la \
    libdcpd_dbus.la \
    libdbusdl_dbus.la \
    libstreamplayer_dbus.la \
    libaudiopath_dbus.la \
    libmixer_dbus.la \
    libartcache_dbus.la \
    libairable_dbus.la \
    libcredentials_dbus.la \
    libgerbera_dbus.la \
    libconfigproxy.la \
    libconfiguration_dbus.la \
    libappliance_dbus.la \
    libservicelist.la \
    libconnman_service.la \
    libconnman_technology_registry.la \
    libconnman_dbus.la \
    libaccesspoint.la \
    libplainplayer.la \
    librest_api.la \
    librest_api_light.la \
    liblogind_dbus.la \
    libsystemd_dbus.la \
    libjsonio_dbus.la \
    libdebug_dbus.la

dcpd_LDADD = $(noinst_LTLIBRARIES) $(DCPD_DEPENDENCIES_LIBS)

libregisters_la_SOURCES = \
    registers.cc registers.hh registers_priv.hh register_response_writer.hh \
    register_push_queue.hh \
    string_trim.hh \
    dcpregs_drcp.cc dcpregs_drcp.hh \
    dcpregs_protolevel.cc dcpregs_protolevel.hh \
    dcpregs_appliance.cc dcpregs_appliance.hh \
    dcpregs_internationalization.cc dcpregs_internationalization.hh \
    dcpregs_networkconfig.cc dcpregs_networkconfig.hh \
    dcpregs_upnpname.cc dcpregs_upnpname.hh \
    dcpregs_upnpserver.cc dcpregs_upnpserver.hh \
    dcpregs_wlansurvey.cc dcpregs_wlansurvey.hh \
    dcpregs_accesspoint.cc dcpregs_accesspoint.hh \
    dcpregs_filetransfer.cc dcpregs_filetransfer.hh dcpregs_filetransfer_priv.h \
    dcpregs_tcptunnel.cc dcpregs_tcptunnel.hh \
    dcpregs_audiosources.cc dcpregs_audiosources.hh \
    dcpregs_audiopaths.cc dcpregs_audiopaths.hh \
    dcpregs_playstream.cc dcpregs_playstream.hh \
    dcpregs_stream_speed.cc dcpregs_stream_speed.hh \
    dcpregs_mediaservices.cc dcpregs_mediaservices.hh \
    dcpregs_searchparameters.cc dcpregs_searchparameters.hh \
    dcpregs_datetime.cc dcpregs_datetime.hh \
    dcpregs_system_update.cc dcpregs_system_update.hh dcpregs_system_update_json.hh \
    dcpregs_status.hh \
    volume_control.cc volume_control.hh dcpregs_volume.hh fixpoint.hh \
    dbus_handlers_connman_manager.hh networkprefs.h \
    connman_service.hh connman_service_list.hh connman_address.hh maybe.hh\
    network_device.hh network_device_list.hh \
    network_config_request.hh \
    de_tahifi_filetransfer.h \
    stream_id.h \
    coverart.cc coverart.hh md5.cc md5.hh \
    gvariantwrapper.cc gvariantwrapper.hh \
    actor_id.h \
    shutdown_guard.h \
    $(DBUS_IFACES)/de_tahifi_lists_errors.h \
    drcp_command_codes.h messages.h
nodist_libregisters_la_SOURCES = do_update_sh.h
libregisters_la_CFLAGS = $(AM_CFLAGS)
libregisters_la_CXXFLAGS = $(AM_CXXFLAGS)

librest_api_light_la_SOURCES = rest_api.cc rest_api.hh
librest_api_light_la_CFLAGS = $(AM_CFLAGS)
librest_api_light_la_CXXFLAGS = $(AM_CXXFLAGS)

librest_api_la_SOURCES = rest_api.cc rest_api_curl.cc rest_api.hh
librest_api_la_CFLAGS = $(AM_CFLAGS)
librest_api_la_CXXFLAGS = $(AM_CXXFLAGS)

libservicelist_la_SOURCES = \
    connman_service_list.cc connman_service_list.hh \
    connman_service.hh connman_address.hh maybe.hh \
    network_device_list.cc network_device.hh network_device_list.hh \
    network_netlink.cc network_netlink.hh \
    messages.h
libservicelist_la_CFLAGS = $(AM_CFLAGS)
libservicelist_la_CXXFLAGS = $(AM_CXXFLAGS)

libconnman_service_la_SOURCES = connman_service.cc connman_service.hh
libconnman_service_la_CFLAGS = $(AM_CFLAGS)
libconnman_service_la_CXXFLAGS = $(AM_CXXFLAGS)

libconnman_technology_registry_la_SOURCES = \
    connman_technology_registry.cc connman_technology_registry.hh
libconnman_technology_registry_la_CFLAGS = $(AM_CFLAGS)
libconnman_technology_registry_la_CXXFLAGS = $(AM_CXXFLAGS)

libinifile_la_SOURCES = inifile.c inifile.h
libinifile_la_CFLAGS = $(AM_CFLAGS)
libinifile_la_CXXFLAGS = $(AM_CXXFLAGS)

libconfigproxy_la_SOURCES = configproxy.c configproxy.h
libconfigproxy_la_CFLAGS = $(AM_CFLAGS)
libconfigproxy_la_CXXFLAGS = $(AM_CXXFLAGS)

libnetworkprefs_la_SOURCES = networkprefs.cc networkprefs.h inifile.h guard.hh
libnetworkprefs_la_CFLAGS = $(AM_CFLAGS)
libnetworkprefs_la_CXXFLAGS = $(AM_CXXFLAGS)

libapplink_la_SOURCES = \
    applink.cc applink.hh \
    applink_variables.cc applink_variables.hh \
    smartphone_app.cc smartphone_app.hh
libapplink_la_CFLAGS = $(AM_CFLAGS)
libapplink_la_CXXFLAGS = $(AM_CXXFLAGS)

libaudiopath_minidsl_la_SOURCES = \
    audiopath_minidsl.cc audiopath_minidsl.hh json.hh
libaudiopath_minidsl_la_CFLAGS = $(AM_CFLAGS)
libaudiopath_minidsl_la_CXXFLAGS = $(AM_CXXFLAGS)

libdbus_handlers_la_SOURCES = \
    dbus_handlers.cc dbus_handlers.h \
    dbus_handlers_connman_agent.cc dbus_handlers_connman_agent.hh connman_agent.h \
    dbus_handlers_connman_manager.cc dbus_handlers_connman_manager.hh \
    network_config_to_json.cc network_config_to_json.hh \
    networkprefs.h \
    net_connman.h \
    actor_id.h \
    dcpregs_networkconfig.hh \
    dcpregs_upnpname.hh \
    dcpregs_wlansurvey.hh \
    dcpregs_filetransfer.hh \
    dcpregs_audiosources.hh \
    dcpregs_playstream.hh \
    dcpregs_stream_speed.hh \
    dcpregs_status.hh
libdbus_handlers_la_CFLAGS = $(AM_CFLAGS)
libdbus_handlers_la_CXXFLAGS = $(AM_CXXFLAGS)

libaccesspoint_la_SOURCES = \
    accesspoint.cc accesspoint.hh \
    accesspoint_manager.cc accesspoint_manager.hh
libaccesspoint_la_CXXFLAGS = $(AM_CXXFLAGS)

libplainplayer_la_SOURCES = plainplayer.cc plainplayer.hh
libplainplayer_la_CXXFLAGS = $(AM_CXXFLAGS)

nodist_libdcpd_dbus_la_SOURCES = de_tahifi_dcpd.c de_tahifi_dcpd.h
libdcpd_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_libconnman_dbus_la_SOURCES = net_connman.c net_connman.h
libconnman_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_liblogind_dbus_la_SOURCES = org_freedesktop_login1.c org_freedesktop_login1.h
liblogind_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_libsystemd_dbus_la_SOURCES = org_freedesktop_systemd1.c org_freedesktop_systemd1.h
libsystemd_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_libdbusdl_dbus_la_SOURCES = de_tahifi_filetransfer.c de_tahifi_filetransfer.h
libdbusdl_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_libstreamplayer_dbus_la_SOURCES = de_tahifi_streamplayer.c de_tahifi_streamplayer.h
libstreamplayer_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_libaudiopath_dbus_la_SOURCES = de_tahifi_audiopath.c de_tahifi_audiopath.h
libaudiopath_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_libmixer_dbus_la_SOURCES = de_tahifi_mixer.c de_tahifi_mixer.h
libmixer_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_libartcache_dbus_la_SOURCES = de_tahifi_artcache.c de_tahifi_artcache.h
libartcache_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_libairable_dbus_la_SOURCES = de_tahifi_airable.c de_tahifi_airable.h
libairable_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_libcredentials_dbus_la_SOURCES = de_tahifi_credentials.c de_tahifi_credentials.h
libcredentials_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_libgerbera_dbus_la_SOURCES = io_gerbera.c io_gerbera.h
libgerbera_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_libconfiguration_dbus_la_SOURCES = de_tahifi_configuration.c de_tahifi_configuration.h
libconfiguration_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_libappliance_dbus_la_SOURCES = de_tahifi_appliance.c de_tahifi_appliance.h
libappliance_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_libjsonio_dbus_la_SOURCES = de_tahifi_jsonio.c de_tahifi_jsonio.h
libjsonio_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

nodist_libdebug_dbus_la_SOURCES = de_tahifi_debug.c de_tahifi_debug.h
libdebug_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

libdrcpdcomm_la_SOURCES = \
    drcp.cc drcp.hh \
    named_pipe.h \
    messages.h
libdrcpdcomm_la_CFLAGS = $(AM_CFLAGS)
libdrcpdcomm_la_CXXFLAGS = $(AM_CXXFLAGS)

libtransactions_la_SOURCES = \
    transactions.cc transactions.hh os.h \
    hexdump.c hexdump.h \
    registers.hh named_pipe.h dcpdefs.h messages.h
libtransactions_la_CFLAGS = $(AM_CFLAGS)
libtransactions_la_CXXFLAGS = $(AM_CXXFLAGS)

libxmodem_la_SOURCES = xmodem.c xmodem.h crc16.h os.h
libxmodem_la_CFLAGS = $(AM_CFLAGS)
libxmodem_la_CXXFLAGS = $(AM_CXXFLAGS)

libnetwork_la_SOURCES = \
    network.c network.h \
    messages.h
libnetwork_la_CFLAGS = $(AM_CFLAGS)
libnetwork_la_CXXFLAGS = $(AM_CXXFLAGS)

libnetwork_dispatcher_la_SOURCES = \
    network_dispatcher.cc network_dispatcher.hh \
    network.h messages.h
libnetwork_dispatcher_la_CFLAGS = $(AM_CFLAGS)
libnetwork_dispatcher_la_CXXFLAGS = $(AM_CXXFLAGS)

libshutdown_guard_la_SOURCES = \
    shutdown_guard.c shutdown_guard.h \
    messages.h
libshutdown_guard_la_CFLAGS = $(AM_CFLAGS)
libshutdown_guard_la_CXXFLAGS = $(AM_CXXFLAGS)

BUILT_SOURCES = \
    $(nodist_libdcpd_dbus_la_SOURCES) \
    de_tahifi_dcpd-doc.h \
    de_tahifi_dcpd-doc.md \
    de_tahifi_dcpd.stamp \
    $(nodist_libdbusdl_dbus_la_SOURCES) \
    de_tahifi_filetransfer-doc.h \
    de_tahifi_filetransfer-doc.md \
    de_tahifi_filetransfer.stamp \
    $(nodist_libstreamplayer_dbus_la_SOURCES) \
    de_tahifi_streamplayer-doc.h \
    de_tahifi_streamplayer-doc.md \
    de_tahifi_streamplayer.stamp \
    $(nodist_libaudiopath_dbus_la_SOURCES) \
    de_tahifi_audiopath-doc.h \
    de_tahifi_audiopath-doc.md \
    de_tahifi_audiopath.stamp \
    $(nodist_libmixer_dbus_la_SOURCES) \
    de_tahifi_mixer-doc.h \
    de_tahifi_mixer-doc.md \
    de_tahifi_mixer.stamp \
    $(nodist_libartcache_dbus_la_SOURCES) \
    de_tahifi_artcache-doc.h \
    de_tahifi_artcache-doc.md \
    de_tahifi_artcache.stamp \
    $(nodist_libairable_dbus_la_SOURCES) \
    de_tahifi_airable-doc.h \
    de_tahifi_airable-doc.md \
    de_tahifi_airable.stamp \
    $(nodist_libcredentials_dbus_la_SOURCES) \
    de_tahifi_credentials-doc.h \
    de_tahifi_credentials-doc.md \
    de_tahifi_credentials.stamp \
    $(nodist_libgerbera_dbus_la_SOURCES) \
    io_gerbera-doc.h \
    io_gerbera-doc.md \
    io_gerbera.stamp \
    $(nodist_libconfiguration_dbus_la_SOURCES) \
    de_tahifi_configuration-doc.h \
    de_tahifi_configuration-doc.md \
    de_tahifi_configuration.stamp \
    $(nodist_libappliance_dbus_la_SOURCES) \
    de_tahifi_appliance-doc.h \
    de_tahifi_appliance-doc.md \
    de_tahifi_appliance.stamp \
    $(nodist_libconnman_dbus_la_SOURCES) \
    net_connman-doc.h \
    net_connman-doc.md \
    net_connman.stamp \
    $(nodist_liblogind_dbus_la_SOURCES) \
    org_freedesktop_login1-doc.h \
    org_freedesktop_login1-doc.md \
    org_freedesktop_login1.stamp \
    $(nodist_libsystemd_dbus_la_SOURCES) \
    org_freedesktop_systemd1-doc.h \
    org_freedesktop_systemd1-doc.md \
    org_freedesktop_systemd1.stamp \
    $(nodist_libjsonio_dbus_la_SOURCES) \
    de_tahifi_jsonio-doc.h \
    de_tahifi_jsonio-doc.md \
    de_tahifi_jsonio.stamp \
    $(nodist_libdebug_dbus_la_SOURCES) \
    de_tahifi_debug-doc.h \
    de_tahifi_debug-doc.md \
    de_tahifi_debug.stamp \
    $(nodist_libregisters_la_SOURCES)

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST = do_update.sh

de_tahifi_dcpd-doc.h: de_tahifi_dcpd.stamp
de_tahifi_dcpd-doc.md: de_tahifi_dcpd.stamp
de_tahifi_dcpd.c: de_tahifi_dcpd.stamp
de_tahifi_dcpd.h: de_tahifi_dcpd.stamp
de_tahifi_dcpd.stamp: $(DBUS_IFACES)/de_tahifi_dcpd.xml
	$(GDBUS_CODEGEN) --generate-c-code=de_tahifi_dcpd --c-namespace tdbus_dcpd --interface-prefix de.tahifi.Dcpd. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o de_tahifi_dcpd-doc.md -H de_tahifi_dcpd-doc.h -c tdbus_dcpd -s de.tahifi.Dcpd. -n "$(PACKAGE_NAME)"
	touch $@

de_tahifi_filetransfer-doc.h: de_tahifi_filetransfer.stamp
de_tahifi_filetransfer-doc.md: de_tahifi_filetransfer.stamp
de_tahifi_filetransfer.c: de_tahifi_filetransfer.stamp
de_tahifi_filetransfer.h: de_tahifi_filetransfer.stamp
de_tahifi_filetransfer.stamp: $(DBUS_IFACES)/de_tahifi_filetransfer.xml
	$(GDBUS_CODEGEN) --generate-c-code=de_tahifi_filetransfer --c-namespace tdbus --interface-prefix de.tahifi. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o de_tahifi_filetransfer-doc.md -H de_tahifi_filetransfer-doc.h -c tdbus -s de.tahifi. -n "File Download"
	touch $@

de_tahifi_streamplayer-doc.h: de_tahifi_streamplayer.stamp
de_tahifi_streamplayer-doc.md: de_tahifi_streamplayer.stamp
de_tahifi_streamplayer.c: de_tahifi_streamplayer.stamp
de_tahifi_streamplayer.h: de_tahifi_streamplayer.stamp
de_tahifi_streamplayer.stamp: $(DBUS_IFACES)/de_tahifi_streamplayer.xml
	$(GDBUS_CODEGEN) --generate-c-code=de_tahifi_streamplayer --c-namespace tdbus_splay --interface-prefix de.tahifi.Streamplayer. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o de_tahifi_streamplayer-doc.md -H de_tahifi_streamplayer-doc.h -c tdbus_splay -s de.tahifi.Streamplayer. -n 'Stream Player'
	touch $@

de_tahifi_audiopath-doc.h: de_tahifi_audiopath.stamp
de_tahifi_audiopath-doc.md: de_tahifi_audiopath.stamp
de_tahifi_audiopath.c: de_tahifi_audiopath.stamp
de_tahifi_audiopath.h: de_tahifi_audiopath.stamp
de_tahifi_audiopath.stamp: $(DBUS_IFACES)/de_tahifi_audiopath.xml
	$(GDBUS_CODEGEN) --generate-c-code=de_tahifi_audiopath --c-namespace tdbus_aupath --interface-prefix de.tahifi.AudioPath. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o de_tahifi_audiopath-doc.md -H de_tahifi_audiopath-doc.h -c tdbus_aupath -s de.tahifi.AudioPath. -n 'Audio Paths'
	touch $@

de_tahifi_mixer-doc.h: de_tahifi_mixer.stamp
de_tahifi_mixer-doc.md: de_tahifi_mixer.stamp
de_tahifi_mixer.c: de_tahifi_mixer.stamp
de_tahifi_mixer.h: de_tahifi_mixer.stamp
de_tahifi_mixer.stamp: $(DBUS_IFACES)/de_tahifi_mixer.xml
	$(GDBUS_CODEGEN) --generate-c-code=de_tahifi_mixer --c-namespace tdbus_mixer --interface-prefix de.tahifi.Mixer. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o de_tahifi_mixer-doc.md -H de_tahifi_mixer-doc.h -c tdbus_mixer -s de.tahifi.Mixer. -n 'Volume Control'
	touch $@

de_tahifi_artcache-doc.h: de_tahifi_artcache.stamp
de_tahifi_artcache-doc.md: de_tahifi_artcache.stamp
de_tahifi_artcache.c: de_tahifi_artcache.stamp
de_tahifi_artcache.h: de_tahifi_artcache.stamp
de_tahifi_artcache.stamp: $(DBUS_IFACES)/de_tahifi_artcache.xml
	$(GDBUS_CODEGEN) --generate-c-code=de_tahifi_artcache --c-namespace tdbus_artcache --interface-prefix de.tahifi.ArtCache. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o de_tahifi_artcache-doc.md -H de_tahifi_artcache-doc.h -c tdbus_artcache -s de.tahifi.ArtCache. -n "Cover Art"
	touch $@

de_tahifi_airable-doc.h: de_tahifi_airable.stamp
de_tahifi_airable-doc.md: de_tahifi_airable.stamp
de_tahifi_airable.c: de_tahifi_airable.stamp
de_tahifi_airable.h: de_tahifi_airable.stamp
de_tahifi_airable.stamp: $(DBUS_IFACES)/de_tahifi_airable.xml
	$(GDBUS_CODEGEN) --generate-c-code=de_tahifi_airable --c-namespace tdbus --interface-prefix de.tahifi. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o de_tahifi_airable-doc.md -H de_tahifi_airable-doc.h -c tdbus -s de.tahifi. -n "Airable"
	touch $@

de_tahifi_credentials-doc.h: de_tahifi_credentials.stamp
de_tahifi_credentials-doc.md: de_tahifi_credentials.stamp
de_tahifi_credentials.c: de_tahifi_credentials.stamp
de_tahifi_credentials.h: de_tahifi_credentials.stamp
de_tahifi_credentials.stamp: $(DBUS_IFACES)/de_tahifi_credentials.xml
	$(GDBUS_CODEGEN) --generate-c-code=de_tahifi_credentials --c-namespace tdbus_credentials --interface-prefix de.tahifi.Credentials. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o de_tahifi_credentials-doc.md -H de_tahifi_credentials-doc.h -c tdbus_credentials -s de.tahifi.Credentials. -n "Passing Credentials Around"
	touch $@

io_gerbera-doc.h: io_gerbera.stamp
io_gerbera-doc.md: io_gerbera.stamp
io_gerbera.c: io_gerbera.stamp
io_gerbera.h: io_gerbera.stamp
io_gerbera.stamp: $(DBUS_IFACES)/io_gerbera.xml
	$(GDBUS_CODEGEN) --generate-c-code=io_gerbera --c-namespace tdbus --interface-prefix io. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o io_gerbera-doc.md -H io_gerbera-doc.h -c tdbus -s io. -n "Gerbera UPnP server"
	touch $@

de_tahifi_configuration-doc.h: de_tahifi_configuration.stamp
de_tahifi_configuration-doc.md: de_tahifi_configuration.stamp
de_tahifi_configuration.c: de_tahifi_configuration.stamp
de_tahifi_configuration.h: de_tahifi_configuration.stamp
de_tahifi_configuration.stamp: $(DBUS_IFACES)/de_tahifi_configuration.xml
	$(GDBUS_CODEGEN) --generate-c-code=de_tahifi_configuration --c-namespace tdbus --interface-prefix de.tahifi. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o de_tahifi_configuration-doc.md -H de_tahifi_configuration-doc.h -c tdbus -s de.tahifi. -n "Configuration Management"
	touch $@

de_tahifi_appliance-doc.h: de_tahifi_appliance.stamp
de_tahifi_appliance-doc.md: de_tahifi_appliance.stamp
de_tahifi_appliance.c: de_tahifi_appliance.stamp
de_tahifi_appliance.h: de_tahifi_appliance.stamp
de_tahifi_appliance.stamp: $(DBUS_IFACES)/de_tahifi_appliance.xml
	$(GDBUS_CODEGEN) --generate-c-code=de_tahifi_appliance --c-namespace tdbus_appliance --interface-prefix de.tahifi.Appliance. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o de_tahifi_appliance-doc.md -H de_tahifi_appliance-doc.h -c tdbus_appliance -s de.tahifi.Appliance. -n "Appliance State and Control"
	touch $@

de_tahifi_jsonio-doc.h: de_tahifi_jsonio.stamp
de_tahifi_jsonio-doc.md: de_tahifi_jsonio.stamp
de_tahifi_jsonio.c: de_tahifi_jsonio.stamp
de_tahifi_jsonio.h: de_tahifi_jsonio.stamp
de_tahifi_jsonio.stamp: $(DBUS_IFACES)/de_tahifi_jsonio.xml
	$(GDBUS_CODEGEN) --generate-c-code=de_tahifi_jsonio --c-namespace tdbus --interface-prefix de.tahifi. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o de_tahifi_jsonio-doc.md -H de_tahifi_jsonio-doc.h -c tdbus -s de.tahifi. -n "JSON Object Exchange"
	touch $@

de_tahifi_debug-doc.h: de_tahifi_debug.stamp
de_tahifi_debug-doc.md: de_tahifi_debug.stamp
de_tahifi_debug.c: de_tahifi_debug.stamp
de_tahifi_debug.h: de_tahifi_debug.stamp
de_tahifi_debug.stamp: $(DBUS_IFACES)/de_tahifi_debug.xml
	$(GDBUS_CODEGEN) --generate-c-code=de_tahifi_debug --c-namespace tdbus_debug --interface-prefix de.tahifi.Debug. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o de_tahifi_debug-doc.md -H de_tahifi_debug-doc.h -c tdbus_debug -s de.tahifi.Debug. -n "Debug Levels"
	touch $@

net_connman-doc.h: net_connman.stamp
net_connman-doc.md: net_connman.stamp
net_connman.c: net_connman.stamp
net_connman.h: net_connman.stamp
net_connman.stamp: $(DBUS_IFACES)/net_connman.xml
	$(GDBUS_CODEGEN) --generate-c-code=net_connman --c-namespace tdbus_connman --interface-prefix net.connman. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o net_connman-doc.md -H net_connman-doc.h -c tdbus_connman -s net.connman. -n "ConnMan Integration"
	touch $@

org_freedesktop_login1-doc.h: org_freedesktop_login1.stamp
org_freedesktop_login1-doc.md: org_freedesktop_login1.stamp
org_freedesktop_login1.c: org_freedesktop_login1.stamp
org_freedesktop_login1.h: org_freedesktop_login1.stamp
org_freedesktop_login1.stamp: $(DBUS_IFACES)/org_freedesktop_login1.xml
	$(GDBUS_CODEGEN) --generate-c-code=org_freedesktop_login1 --c-namespace tdbus_logind --interface-prefix org.freedesktop.login1. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o org_freedesktop_login1-doc.md -H org_freedesktop_login1-doc.h -c tdbus_logind -s org.freedesktop.login1. -n "Shutdown via Systemd"
	touch $@

org_freedesktop_systemd1-doc.h: org_freedesktop_systemd1.stamp
org_freedesktop_systemd1-doc.md: org_freedesktop_systemd1.stamp
org_freedesktop_systemd1.c: org_freedesktop_systemd1.stamp
org_freedesktop_systemd1.h: org_freedesktop_systemd1.stamp
org_freedesktop_systemd1.stamp: $(DBUS_IFACES)/org_freedesktop_systemd1.xml
	$(GDBUS_CODEGEN) --generate-c-code=org_freedesktop_systemd1 --c-namespace tdbus_systemd --interface-prefix org.freedesktop.systemd1. $<
	$(DBUS_IFACES)/extract_documentation.py -i $< -o org_freedesktop_systemd1-doc.md -H org_freedesktop_systemd1-doc.h -c tdbus_systemd -s org.freedesktop.systemd1. -n "Systemd Manager"
	touch $@

do_update_sh.h: do_update.sh
	echo 'static const uint8_t shell_script_content[] =' >$@
	echo '{' >>$@
	od -An -tx1 -v <$^ | sed 's/ / 0x/g;s/^ //;s/ /, /g;s/$$/,/' >>$@
	echo '};' >>$@
