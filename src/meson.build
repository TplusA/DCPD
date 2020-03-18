#
# Copyright (C) 2019, 2020  T+A elektroakustik GmbH & Co. KG
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

config_h = declare_dependency(
    sources: configure_file(input: '../config.h.meson',
                            output: 'config.h',
                            configuration: config_data),
    include_directories: '.')

do_update_sh_h = custom_target('update script',
    input: 'do_update.sh', output: 'do_update_sh.h',
    command: [generate_script_header, '@INPUT@', '@OUTPUT@']
)

gnome = import('gnome')

dbus_iface_dir = '../dbus_interfaces'
dbus_iface_defs_includes = include_directories(dbus_iface_dir)

dbus_iface_data = [
    ['de_tahifi_dcpd',           'de.tahifi.Dcpd.',           'tdbus_dcpd',        meson.project_name()],
    ['de_tahifi_filetransfer',   'de.tahifi.',                'tdbus',             'File Download'],
    ['de_tahifi_streamplayer',   'de.tahifi.Streamplayer.',   'tdbus_splay',       'Stream Player'],
    ['de_tahifi_audiopath',      'de.tahifi.AudioPath.',      'tdbus_aupath',      'Audio Paths'],
    ['de_tahifi_mixer',          'de.tahifi.Mixer.',          'tdbus_mixer',       'Volume Control'],
    ['de_tahifi_artcache',       'de.tahifi.ArtCache.',       'tdbus_artcache',    'Cover Art'],
    ['de_tahifi_airable',        'de.tahifi.',                'tdbus',             'Airable'],
    ['de_tahifi_credentials',    'de.tahifi.Credentials.',    'tdbus_credentials', 'Passing Credentials Around'],
    ['io_gerbera',               'io.',                       'tdbus',             'Gerbera UPnP Server'],
    ['de_tahifi_configuration',  'de.tahifi.',                'tdbus',             'Configuration Management'],
    ['de_tahifi_appliance',      'de.tahifi.Appliance.',      'tdbus_appliance',   'Appliance State and Control'],
    ['de_tahifi_jsonio',         'de.tahifi.',                'tdbus',             'JSON Object Exchange'],
    ['de_tahifi_debug',          'de.tahifi.Debug.',          'tdbus_debug',       'Debug Levels'],
    ['net_connman',              'net.connman.',              'tdbus_connman',     'ConnMan Integration'],
    ['org_freedesktop_login1',   'org.freedesktop.login1.',   'tdbus_logind',      'Shutdown via Systemd'],
    ['org_freedesktop_systemd1', 'org.freedesktop.systemd1.', 'tdbus_systemd',     'Systemd Manager'],
]

dbus_deps = []
dbus_docs = []

foreach d : dbus_iface_data
    dbus_deps += declare_dependency(
        link_with: static_library(
            d[0].split('_')[-1] + '_dbus',
            gnome.gdbus_codegen(d[0],
                                sources: dbus_iface_dir / d[0] + '.xml',
                                interface_prefix: d[1],
                                namespace: d[2]),
            dependencies: [glib_deps, config_h],
            c_args: relaxed_dbus_warnings),
        include_directories: dbus_iface_defs_includes
    )

    dbus_docs += custom_target(d[0] + '_docs',
        input: dbus_iface_dir / d[0] + '.xml',
        output: ['@BASENAME@-doc.md', '@BASENAME@-doc.h'],
        command: [
            extract_docs, '-i', '@INPUT@', '-o', '@OUTPUT0@', '-H', '@OUTPUT1@',
            '-c', d[2], '-s', d[1], '-n', d[3]
        ])
endforeach

accesspoint_lib = static_library('accesspoint',
    ['accesspoint.cc', 'accesspoint_manager.cc'],
    dependencies: config_h
)

applink_lib = static_library('applink',
    ['applink.cc', 'applink_variables.cc', 'smartphone_app.cc'],
    dependencies: [glib_deps, config_h]
)

audiopath_minidsl_lib = static_library('audiopath_minidsl',
    'audiopath_minidsl.cc', dependencies: config_h
)

configproxy_lib = static_library('configproxy',
    'configproxy.c', dependencies: [glib_deps, config_h]
)

connman_service_lib = static_library('connman_service',
    'connman_service.cc', dependencies: config_h
)

connman_technology_registry_lib = static_library('connman_technology_registry',
    'connman_technology_registry.cc', dependencies: [glib_deps, config_h]
)

drcpdcomm_lib = static_library('drcpdcomm', 'drcp.cc', dependencies: config_h)

inifile_lib = static_library('inifile', 'inifile.c', dependencies: config_h)

networkprefs_lib = static_library('networkprefs',
    'networkprefs.cc', dependencies: config_h
)

network_dispatcher_lib = static_library('network_dispatcher',
    'network_dispatcher.cc', dependencies: config_h
)

network_lib = static_library('network', 'network.c', dependencies: config_h)

plainplayer_lib = static_library('plainplayer',
    'plainplayer.cc', dependencies: [glib_deps, config_h]
)

registers_lib = static_library('registers',
    [
        'registers.cc', 'dcpregs_drcp.cc', 'dcpregs_protolevel.cc',
        'dcpregs_appliance.cc', 'dcpregs_internationalization.cc',
        'dcpregs_networkconfig.cc', 'dcpregs_upnpname.cc',
        'dcpregs_upnpserver.cc', 'dcpregs_wlansurvey.cc',
        'dcpregs_accesspoint.cc', 'dcpregs_filetransfer.cc',
        'dcpregs_tcptunnel.cc', 'dcpregs_audiosources.cc',
        'dcpregs_audiopaths.cc', 'dcpregs_playstream.cc',
        'dcpregs_stream_speed.cc', 'dcpregs_mediaservices.cc',
        'dcpregs_searchparameters.cc', 'dcpregs_datetime.cc',
        'volume_control.cc', 'coverart.cc', 'md5.cc', 'gvariantwrapper.cc',
        do_update_sh_h,
    ],
    dependencies: [glib_deps, config_h],
    include_directories: dbus_iface_defs_includes
)

servicelist_lib = static_library('servicelist',
    ['connman_service_list.cc', 'network_device_list.cc', 'network_netlink.cc'],
    dependencies: config_h
)

shutdown_guard_lib = static_library('shutdown_guard',
    'shutdown_guard.c', dependencies: [glib_deps, config_h]
)

transactions_lib = static_library('transactions',
    ['transactions.cc', 'hexdump.c'], dependencies: config_h
)

xmodem_lib = static_library('xmodem', 'xmodem.c', dependencies: config_h)

executable(
    'dcpd',
    [
        'dcpd.cc', 'os.c', 'named_pipe.c', 'dcp_over_tcp.c',
        'smartphone_app_send.cc', 'messages.c', 'messages_glib.c', 'backtrace.c',
        'connman_iter.c', 'connman_scan.cc', 'connman_common.c',
        'dbus_common.c', 'dbus_iface.cc',
        'configuration.cc', 'configuration_dcpd.cc',
        version_info,
    ],
    dependencies: [dbus_deps, glib_deps, jsoncpp_deps, config_h],
    link_with: [
        static_library('dbus_handlers', [
            'dbus_handlers.cc', 'dbus_handlers_connman_agent.cc',
            'dbus_handlers_connman_manager.cc', 'network_config_to_json.cc'],
            dependencies: [dbus_deps, glib_deps, jsoncpp_deps],
        ),
        accesspoint_lib,
        applink_lib,
        audiopath_minidsl_lib,
        configproxy_lib,
        connman_service_lib,
        connman_technology_registry_lib,
        drcpdcomm_lib,
        inifile_lib,
        network_dispatcher_lib,
        network_lib,
        networkprefs_lib,
        plainplayer_lib,
        registers_lib,
        servicelist_lib,
        shutdown_guard_lib,
        transactions_lib,
        xmodem_lib,
    ],
    install: true
)
