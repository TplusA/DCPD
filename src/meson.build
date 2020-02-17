#
# Copyright (C) 2019  T+A elektroakustik GmbH & Co. KG
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

configure_file(input: '../config.h.meson', output: 'config.h',
               configuration: config_data)

gnome = import('gnome')

dbus_docs = []

dcpd_dbus_src = gnome.gdbus_codegen('de_tahifi_dcpd',
    sources: '../dbus_interfaces/de_tahifi_dcpd.xml',
    interface_prefix: 'de.tahifi.Dcpd.',
    namespace: 'tdbus_dcpd')
dcpd_dbus_lib = static_library('dcpd_dbus',
    dcpd_dbus_src, dependencies: glib_deps, c_args: relaxed_dbus_warnings)
dcpd_dbus_dep = declare_dependency(link_with: dcpd_dbus_lib)
dbus_docs += custom_target('de_tahifi_dcpd_docs',
    input: '../dbus_interfaces/de_tahifi_dcpd.xml',
    output: ['@BASENAME@-doc.md', '@BASENAME@-doc.h'],
    command: [
        extract_docs, '-i', '@INPUT@', '-o', '@OUTPUT0@', '-H', '@OUTPUT1@',
        '-c', 'tdbus_dcpd', '-s', 'de.tahifi.Dcpd.', '-n', meson.project_name()
    ])

dbusdl_dbus_src = gnome.gdbus_codegen('de_tahifi_filetransfer',
    sources: '../dbus_interfaces/de_tahifi_filetransfer.xml',
    interface_prefix: 'de.tahifi.',
    namespace: 'tdbus')
dbusdl_dbus_lib = static_library('dbusdl_dbus',
    dbusdl_dbus_src, dependencies: glib_deps, c_args: relaxed_dbus_warnings)
dbusdl_dbus_dep = declare_dependency(link_with: dbusdl_dbus_lib)
dbus_docs += custom_target('de_tahifi_filetransfer_docs',
    input: '../dbus_interfaces/de_tahifi_filetransfer.xml',
    output: ['@BASENAME@-doc.md', '@BASENAME@-doc.h'],
    command: [
        extract_docs, '-i', '@INPUT@', '-o', '@OUTPUT0@', '-H', '@OUTPUT1@',
        '-c', 'tdbus', '-s', 'de.tahifi.', '-n', 'File Download'
    ])

streamplayer_dbus_src = gnome.gdbus_codegen('de_tahifi_streamplayer',
    sources: '../dbus_interfaces/de_tahifi_streamplayer.xml',
    interface_prefix: 'de.tahifi.Streamplayer.',
    namespace: 'tdbus_splay')
streamplayer_dbus_lib = static_library('streamplayer_dbus',
    streamplayer_dbus_src, dependencies: glib_deps, c_args: relaxed_dbus_warnings)
streamplayer_dbus_dep = declare_dependency(link_with: streamplayer_dbus_lib)
dbus_docs += custom_target('de_tahifi_streamplayer_docs',
    input: '../dbus_interfaces/de_tahifi_streamplayer.xml',
    output: ['@BASENAME@-doc.md', '@BASENAME@-doc.h'],
    command: [
        extract_docs, '-i', '@INPUT@', '-o', '@OUTPUT0@', '-H', '@OUTPUT1@',
        '-c', 'tdbus_splay', '-s', 'de.tahifi.Streamplayer.', '-n', 'Stream Player'
    ])

audiopath_dbus_src = gnome.gdbus_codegen('de_tahifi_audiopath',
    sources: '../dbus_interfaces/de_tahifi_audiopath.xml',
    interface_prefix: 'de.tahifi.AudioPath.',
    namespace: 'tdbus_aupath')
audiopath_dbus_lib = static_library('audiopath_dbus',
    audiopath_dbus_src, dependencies: glib_deps, c_args: relaxed_dbus_warnings)
audiopath_dbus_dep = declare_dependency(link_with: audiopath_dbus_lib)
dbus_docs += custom_target('de_tahifi_audiopath_docs',
    input: '../dbus_interfaces/de_tahifi_audiopath.xml',
    output: ['@BASENAME@-doc.md', '@BASENAME@-doc.h'],
    command: [
        extract_docs, '-i', '@INPUT@', '-o', '@OUTPUT0@', '-H', '@OUTPUT1@',
        '-c', 'tdbus_aupath', '-s', 'de.tahifi.AudioPath.', '-n', 'Audio Paths'
    ])

mixer_dbus_src = gnome.gdbus_codegen('de_tahifi_mixer',
    sources: '../dbus_interfaces/de_tahifi_mixer.xml',
    interface_prefix: 'de.tahifi.Mixer.',
    namespace: 'tdbus_mixer')
mixer_dbus_lib = static_library('mixer_dbus',
    mixer_dbus_src, dependencies: glib_deps, c_args: relaxed_dbus_warnings)
mixer_dbus_dep = declare_dependency(link_with: mixer_dbus_lib)
dbus_docs += custom_target('de_tahifi_mixer_docs',
    input: '../dbus_interfaces/de_tahifi_mixer.xml',
    output: ['@BASENAME@-doc.md', '@BASENAME@-doc.h'],
    command: [
        extract_docs, '-i', '@INPUT@', '-o', '@OUTPUT0@', '-H', '@OUTPUT1@',
        '-c', 'tdbus_mixer', '-s', 'de.tahifi.Mixer.', '-n', 'Volume Control'
    ])

artcache_dbus_src = gnome.gdbus_codegen('de_tahifi_artcache',
    sources: '../dbus_interfaces/de_tahifi_artcache.xml',
    interface_prefix: 'de.tahifi.ArtCache.',
    namespace: 'tdbus_artcache')
artcache_dbus_lib = static_library('artcache_dbus',
    artcache_dbus_src, dependencies: glib_deps, c_args: relaxed_dbus_warnings)
artcache_dbus_dep = declare_dependency(link_with: artcache_dbus_lib)
dbus_docs += custom_target('de_tahifi_artcache_docs',
    input: '../dbus_interfaces/de_tahifi_artcache.xml',
    output: ['@BASENAME@-doc.md', '@BASENAME@-doc.h'],
    command: [
        extract_docs, '-i', '@INPUT@', '-o', '@OUTPUT0@', '-H', '@OUTPUT1@',
        '-c', 'tdbus_artcache', '-s', 'de.tahifi.ArtCache.', '-n', 'Cover Art'
    ])

airable_dbus_src = gnome.gdbus_codegen('de_tahifi_airable',
    sources: '../dbus_interfaces/de_tahifi_airable.xml',
    interface_prefix: 'de.tahifi.',
    namespace: 'tdbus')
airable_dbus_lib = static_library('airable_dbus',
    airable_dbus_src, dependencies: glib_deps, c_args: relaxed_dbus_warnings)
airable_dbus_dep = declare_dependency(link_with: airable_dbus_lib)
dbus_docs += custom_target('de_tahifi_airable_docs',
    input: '../dbus_interfaces/de_tahifi_airable.xml',
    output: ['@BASENAME@-doc.md', '@BASENAME@-doc.h'],
    command: [
        extract_docs, '-i', '@INPUT@', '-o', '@OUTPUT0@', '-H', '@OUTPUT1@',
        '-c', 'tdbus', '-s', 'de.tahifi.', '-n', 'Airable'
    ])

credentials_dbus_src = gnome.gdbus_codegen('de_tahifi_credentials',
    sources: '../dbus_interfaces/de_tahifi_credentials.xml',
    interface_prefix: 'de.tahifi.Credentials.',
    namespace: 'tdbus_credentials')
credentials_dbus_lib = static_library('credentials_dbus',
    credentials_dbus_src, dependencies: glib_deps, c_args: relaxed_dbus_warnings)
credentials_dbus_dep = declare_dependency(link_with: credentials_dbus_lib)
dbus_docs += custom_target('de_tahifi_credentials_docs',
    input: '../dbus_interfaces/de_tahifi_credentials.xml',
    output: ['@BASENAME@-doc.md', '@BASENAME@-doc.h'],
    command: [
        extract_docs, '-i', '@INPUT@', '-o', '@OUTPUT0@', '-H', '@OUTPUT1@',
        '-c', 'tdbus_credentials', '-s', 'de.tahifi.Credentials.',
        '-n', 'Passing Credentials Around'
    ])

gerbera_dbus_src = gnome.gdbus_codegen('io_gerbera',
    sources: '../dbus_interfaces/io_gerbera.xml',
    interface_prefix: 'io.',
    namespace: 'tdbus')
gerbera_dbus_lib = static_library('gerbera_dbus',
    gerbera_dbus_src, dependencies: glib_deps, c_args: relaxed_dbus_warnings)
gerbera_dbus_dep = declare_dependency(link_with: gerbera_dbus_lib)
dbus_docs += custom_target('io_gerbera_docs',
    input: '../dbus_interfaces/io_gerbera.xml',
    output: ['@BASENAME@-doc.md', '@BASENAME@-doc.h'],
    command: [
        extract_docs, '-i', '@INPUT@', '-o', '@OUTPUT0@', '-H', '@OUTPUT1@',
        '-c', 'tdbus', '-s', 'io.', '-n', 'Gerbera UPnP Server'
    ])

configuration_dbus_src = gnome.gdbus_codegen('de_tahifi_configuration',
    sources: '../dbus_interfaces/de_tahifi_configuration.xml',
    interface_prefix: 'de.tahifi.',
    namespace: 'tdbus')
configuration_dbus_lib = static_library('configuration_dbus',
    configuration_dbus_src, dependencies: glib_deps, c_args: relaxed_dbus_warnings)
configuration_dbus_dep = declare_dependency(link_with: configuration_dbus_lib)
dbus_docs += custom_target('de_tahifi_configuration_docs',
    input: '../dbus_interfaces/de_tahifi_configuration.xml',
    output: ['@BASENAME@-doc.md', '@BASENAME@-doc.h'],
    command: [
        extract_docs, '-i', '@INPUT@', '-o', '@OUTPUT0@', '-H', '@OUTPUT1@',
        '-c', 'tdbus', '-s', 'de.tahifi.', '-n', 'Configuration Management'
    ])

appliance_dbus_src = gnome.gdbus_codegen('de_tahifi_appliance',
    sources: '../dbus_interfaces/de_tahifi_appliance.xml',
    interface_prefix: 'de.tahifi.Appliance.',
    namespace: 'tdbus_appliance')
appliance_dbus_lib = static_library('appliance_dbus',
    appliance_dbus_src, dependencies: glib_deps, c_args: relaxed_dbus_warnings)
appliance_dbus_dep = declare_dependency(link_with: appliance_dbus_lib)
dbus_docs += custom_target('de_tahifi_appliance_docs',
    input: '../dbus_interfaces/de_tahifi_appliance.xml',
    output: ['@BASENAME@-doc.md', '@BASENAME@-doc.h'],
    command: [
        extract_docs, '-i', '@INPUT@', '-o', '@OUTPUT0@', '-H', '@OUTPUT1@',
        '-c', 'tdbus_appliance', '-s', 'de.tahifi.Appliance.',
        '-n', 'Appliance State and Control'
    ])

jsonio_dbus_src = gnome.gdbus_codegen('de_tahifi_jsonio',
    sources: '../dbus_interfaces/de_tahifi_jsonio.xml',
    interface_prefix: 'de.tahifi.',
    namespace: 'tdbus')
jsonio_dbus_lib = static_library('jsonio_dbus',
    jsonio_dbus_src, dependencies: glib_deps, c_args: relaxed_dbus_warnings)
jsonio_dbus_dep = declare_dependency(link_with: jsonio_dbus_lib)
dbus_docs += custom_target('de_tahifi_jsonio_docs',
    input: '../dbus_interfaces/de_tahifi_jsonio.xml',
    output: ['@BASENAME@-doc.md', '@BASENAME@-doc.h'],
    command: [
        extract_docs, '-i', '@INPUT@', '-o', '@OUTPUT0@', '-H', '@OUTPUT1@',
        '-c', 'tdbus', '-s', 'de.tahifi.', '-n', 'JSON Object Exchange'
    ])

debug_dbus_src = gnome.gdbus_codegen('de_tahifi_debug',
    sources: '../dbus_interfaces/de_tahifi_debug.xml',
    interface_prefix: 'de.tahifi.Debug.',
    namespace: 'tdbus_debug')
debug_dbus_lib = static_library('debug_dbus',
    debug_dbus_src, dependencies: glib_deps, c_args: relaxed_dbus_warnings)
debug_dbus_dep = declare_dependency(link_with: debug_dbus_lib)
dbus_docs += custom_target('de_tahifi_debug_docs',
    input: '../dbus_interfaces/de_tahifi_debug.xml',
    output: ['@BASENAME@-doc.md', '@BASENAME@-doc.h'],
    command: [
        extract_docs, '-i', '@INPUT@', '-o', '@OUTPUT0@', '-H', '@OUTPUT1@',
        '-c', 'tdbus_debug', '-s', 'de.tahifi.Debug.', '-n', 'Debug Levels'
    ])

connman_dbus_src = gnome.gdbus_codegen('net_connman',
    sources: '../dbus_interfaces/net_connman.xml',
    interface_prefix: 'net.connman.',
    namespace: 'tdbus_connman')
connman_dbus_lib = static_library('connman_dbus',
    connman_dbus_src, dependencies: glib_deps, c_args: relaxed_dbus_warnings)
connman_dbus_dep = declare_dependency(link_with: connman_dbus_lib)
dbus_docs += custom_target('net_connman_docs',
    input: '../dbus_interfaces/net_connman.xml',
    output: ['@BASENAME@-doc.md', '@BASENAME@-doc.h'],
    command: [
        extract_docs, '-i', '@INPUT@', '-o', '@OUTPUT0@', '-H', '@OUTPUT1@',
        '-c', 'tdbus_connman', '-s', 'net.connman.', '-n', 'ConnMan Integration'
    ])

logind_dbus_src = gnome.gdbus_codegen('org_freedesktop_login1',
    sources: '../dbus_interfaces/org_freedesktop_login1.xml',
    interface_prefix: 'org.freedesktop.login1.',
    namespace: 'tdbus_logind')
logind_dbus_lib = static_library('logind_dbus',
    logind_dbus_src, dependencies: glib_deps, c_args: relaxed_dbus_warnings)
logind_dbus_dep = declare_dependency(link_with: logind_dbus_lib)
dbus_docs += custom_target('org_freedesktop_login1_docs',
    input: '../dbus_interfaces/org_freedesktop_login1.xml',
    output: ['@BASENAME@-doc.md', '@BASENAME@-doc.h'],
    command: [
        extract_docs, '-i', '@INPUT@', '-o', '@OUTPUT0@', '-H', '@OUTPUT1@',
        '-c', 'tdbus_logind', '-s', 'org.freedesktop.login1.',
        '-n', 'Shutdown via Systemd'
    ])

systemd_dbus_src = gnome.gdbus_codegen('org_freedesktop_systemd1',
    sources: '../dbus_interfaces/org_freedesktop_systemd1.xml',
    interface_prefix: 'org.freedesktop.systemd1.',
    namespace: 'tdbus_systemd')
systemd_dbus_lib = static_library('systemd_dbus',
    systemd_dbus_src, dependencies: glib_deps, c_args: relaxed_dbus_warnings)
systemd_dbus_dep = declare_dependency(link_with: systemd_dbus_lib)
dbus_docs += custom_target('org_freedesktop_systemd1_docs',
    input: '../dbus_interfaces/org_freedesktop_systemd1.xml',
    output: ['@BASENAME@-doc.md', '@BASENAME@-doc.h'],
    command: [
        extract_docs, '-i', '@INPUT@', '-o', '@OUTPUT0@', '-H', '@OUTPUT1@',
        '-c', 'tdbus_systemd', '-s', 'org.freedesktop.systemd1.',
        '-n', 'Systemd Manager'
    ])

dbus_iface_defs_includes = include_directories('../dbus_interfaces')

dcpd_sources = [
    'dcpd.cc', 'os.c', 'named_pipe.c', 'dcp_over_tcp.c',
    'smartphone_app_send.cc', 'messages.c', 'messages_glib.c', 'backtrace.c',
    'connman_iter.c', 'connman_scan.cc', 'connman_common.c',
    'dbus_common.c', 'dbus_iface.cc',
    'configuration.cc', 'configuration_dcpd.cc',
    custom_target('update script',
        input: 'do_update.sh', output: 'do_update_sh.h',
        command: [generate_script_header, '@INPUT@', '@OUTPUT@']),
    custom_target(
        'version information file',
        input: configure_file(input: '../versioninfo.cache.in',
                              output: 'versioninfo.cache', copy: true),
        output: 'versioninfo.h',
        command: [
            autorevision, '-C', meson.current_source_dir(),
            '-t', 'h',
            '-o', 'versioninfo.cache'
        ],
        capture: true
    ),
]

accesspoint_lib = static_library('accesspoint',
    ['accesspoint.cc', 'accesspoint_manager.cc'])

applink_lib = static_library('applink',
    ['applink.cc', 'applink_variables.cc', 'smartphone_app.cc'],
    dependencies: [glib_deps])

audiopath_minidsl_lib = static_library('audiopath_minidsl', 'audiopath_minidsl.cc')

configproxy_lib = static_library('configproxy',
    'configproxy.c', dependencies: [glib_deps])

connman_service_lib = static_library('connman_service', 'connman_service.cc')

connman_technology_registry_lib = static_library('connman_technology_registry',
    'connman_technology_registry.cc', dependencies: [glib_deps])

drcpdcomm_lib = static_library('drcpdcomm', 'drcp.cc')

inifile_lib = static_library('inifile', 'inifile.c')

networkprefs_lib = static_library('networkprefs', 'networkprefs.cc')

network_dispatcher_lib = static_library('network_dispatcher', 'network_dispatcher.cc')

network_lib = static_library('network', 'network.c')

plainplayer_lib = static_library('plainplayer',
    'plainplayer.cc', dependencies: [glib_deps])

registers_lib = static_library('registers', [
    'registers.cc', 'dcpregs_drcp.cc', 'dcpregs_protolevel.cc',
    'dcpregs_appliance.cc', 'dcpregs_internationalization.cc',
    'dcpregs_networkconfig.cc', 'dcpregs_upnpname.cc',
    'dcpregs_upnpserver.cc', 'dcpregs_wlansurvey.cc',
    'dcpregs_accesspoint.cc', 'dcpregs_filetransfer.cc',
    'dcpregs_tcptunnel.cc', 'dcpregs_audiosources.cc',
    'dcpregs_audiopaths.cc', 'dcpregs_playstream.cc',
    'dcpregs_stream_speed.cc', 'dcpregs_mediaservices.cc',
    'dcpregs_searchparameters.cc', 'dcpregs_datetime.cc',
    'volume_control.cc', 'coverart.cc', 'md5.cc', 'gvariantwrapper.cc'],
    dependencies: [glib_deps],
    include_directories: dbus_iface_defs_includes)

servicelist_lib = static_library('servicelist',
    ['connman_service_list.cc', 'network_device_list.cc', 'network_netlink.cc'])

shutdown_guard_lib = static_library('shutdown_guard',
    'shutdown_guard.c', dependencies: [glib_deps])

transactions_lib = static_library('transactions', ['transactions.cc', 'hexdump.c'])

xmodem_lib = static_library('xmodem', 'xmodem.c')

dcpd_libs = [
    static_library('dbus_handlers', [
        'dbus_handlers.cc', 'dbus_handlers_connman_agent.cc',
        'dbus_handlers_connman_manager.cc', 'network_config_to_json.cc'],
        dependencies: [connman_dbus_dep, glib_deps, jsoncpp_deps],
        include_directories: dbus_iface_defs_includes),
    accesspoint_lib, applink_lib, audiopath_minidsl_lib,
    configproxy_lib, connman_service_lib, connman_technology_registry_lib,
    drcpdcomm_lib, inifile_lib, network_dispatcher_lib, network_lib,
    networkprefs_lib, plainplayer_lib, registers_lib, servicelist_lib,
    shutdown_guard_lib, transactions_lib, xmodem_lib
]

executable(
    'dcpd',
    dcpd_sources,
    include_directories: dbus_iface_defs_includes,
    dependencies: [
        airable_dbus_dep, appliance_dbus_dep, artcache_dbus_dep,
        audiopath_dbus_dep, configuration_dbus_dep,
        connman_dbus_dep, credentials_dbus_dep, dbusdl_dbus_dep,
        dcpd_dbus_dep, debug_dbus_dep, gerbera_dbus_dep, glib_deps,
        jsoncpp_deps, jsonio_dbus_dep, logind_dbus_dep, mixer_dbus_dep,
        streamplayer_dbus_dep, systemd_dbus_dep
    ],
    link_with: dcpd_libs,
    install: true
)
