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

cutter_dep = dependency('cppcutter', required: false)
compiler = meson.get_compiler('cpp')

if not(compiler.has_header('cutter.h', dependencies: cutter_dep) and \
       compiler.has_header('cppcutter.h', dependencies: cutter_dep))
    subdir_done()
endif

cutter_wrap = find_program('cutter_wrap.sh')

cutter_wrap_args = [
    find_program('cutter').path(), find_program('xsltproc').path(),
    meson.current_build_dir(), meson.current_source_dir()
]

registers_basics_tests = shared_module('test_registers_basics',
    ['test_registers_basics.cc', 'mock_messages.cc'],
    cpp_args: '-Wno-pedantic',
    include_directories: '../src',
    dependencies: [cutter_dep, glib_deps],
    link_with: [
        registers_lib, shutdown_guard_lib, networkprefs_lib,
        servicelist_lib, connman_technology_registry_lib
    ]
)
test('Registers',
    cutter_wrap, args: [cutter_wrap_args, registers_basics_tests.full_path()],
    depends: registers_basics_tests,
    suite: 'old',
)

registers_response_writer_tests = shared_module('test_registers_response_writer',
    'test_registers_response_writer.cc',
    cpp_args: '-Wno-pedantic',
    include_directories: '../src',
    dependencies: cutter_dep,
)
test('Registers Response Writer',
    cutter_wrap, args: [cutter_wrap_args, registers_response_writer_tests.full_path()],
    depends: registers_response_writer_tests,
    suite: 'old',
)

registers_drcp_tests = shared_module('test_registers_drcp',
    ['test_registers_drcp.cc', 'mock_dcpd_dbus.cc', 'mock_dbus_iface.cc',
     'mock_audiopath_dbus.cc', 'mock_logind_manager_dbus.cc', 'mock_os.cc',
     'mock_messages.cc'],
    cpp_args: '-Wno-pedantic',
    include_directories: ['../src', '../dbus_interfaces'],
    dependencies: [cutter_dep, glib_deps],
    link_with: [registers_lib, shutdown_guard_lib, connman_technology_registry_lib]
)
test('Registers DRC',
    cutter_wrap, args: [cutter_wrap_args, registers_drcp_tests.full_path()],
    depends: registers_drcp_tests,
    suite: 'old',
)

registers_networking_tests = shared_module('test_registers_networking',
    ['test_registers_networking.cc', 'mock_connman.cc', 'mock_messages.cc',
     'mock_backtrace.cc', 'mock_os.cc'],
    cpp_args: '-Wno-pedantic',
    include_directories: '../src',
    dependencies: [cutter_dep, glib_deps],
    link_with: [
        registers_lib, shutdown_guard_lib, networkprefs_lib, inifile_lib,
        servicelist_lib, connman_service_lib, connman_technology_registry_lib
    ]
)
test('Registers Networking',
    cutter_wrap, args: [cutter_wrap_args, registers_networking_tests.full_path()],
    depends: registers_networking_tests,
    suite: 'old',
)

registers_upnp_tests = shared_module('test_registers_upnp',
    ['test_registers_upnp.cc', 'mock_messages.cc', 'mock_os.cc'],
    cpp_args: '-Wno-pedantic',
    include_directories: '../src',
    dependencies: [cutter_dep, glib_deps],
    link_with: [
        registers_lib, shutdown_guard_lib, networkprefs_lib,
        servicelist_lib, connman_technology_registry_lib
    ]
)
test('Registers UPnP',
    cutter_wrap, args: [cutter_wrap_args, registers_upnp_tests.full_path()],
    depends: registers_upnp_tests,
    suite: 'old',
)

registers_file_transfer_tests = shared_module('test_registers_file_transfer',
    ['test_registers_file_transfer.cc', 'mock_messages.cc', 'mock_os.cc',
     'mock_file_transfer_dbus.cc', 'mock_logind_manager_dbus.cc',
     'mock_dbus_iface.cc'],
    cpp_args: '-Wno-pedantic',
    include_directories: ['../src', '../dbus_interfaces'],
    dependencies: [cutter_dep, glib_deps],
    link_with: [
        registers_lib, plainplayer_lib, shutdown_guard_lib, networkprefs_lib,
        connman_technology_registry_lib, inifile_lib, xmodem_lib
    ]
)
test('Registers File Transfer',
    cutter_wrap, args: [cutter_wrap_args, registers_file_transfer_tests.full_path()],
    depends: registers_file_transfer_tests,
    suite: 'old',
)

registers_play_app_stream_tests = shared_module('test_registers_play_app_stream',
    ['test_registers_play_app_stream.cc', 'mock_messages.cc',
     'mock_backtrace.cc', 'mock_streamplayer_dbus.cc', 'mock_artcache_dbus.cc',
     'mock_dcpd_dbus.cc', 'mock_audiopath_dbus.cc', 'mock_dbus_iface.cc'],
    cpp_args: '-Wno-pedantic',
    include_directories: ['../src', '../dbus_interfaces'],
    dependencies: [cutter_dep, glib_deps],
    link_with: [
        registers_lib, plainplayer_lib, shutdown_guard_lib, networkprefs_lib,
        connman_technology_registry_lib,
    ]
)
test('Registers Play App Stream',
    cutter_wrap, args: [cutter_wrap_args, registers_play_app_stream_tests.full_path()],
    depends: registers_play_app_stream_tests,
    suite: 'old',
)

registers_media_services_tests = shared_module('test_registers_media_services',
    ['test_registers_media_services.cc', 'mock_messages.cc',
     'mock_credentials_dbus.cc', 'mock_airable_dbus.cc', 'mock_dbus_iface.cc'],
    cpp_args: '-Wno-pedantic',
    include_directories: ['../src', '../dbus_interfaces'],
    dependencies: [cutter_dep, glib_deps],
    link_with: [
        registers_lib, shutdown_guard_lib, networkprefs_lib,
        connman_technology_registry_lib,
    ]
)
test('Registers Media Services',
    cutter_wrap, args: [cutter_wrap_args, registers_media_services_tests.full_path()],
    depends: registers_media_services_tests,
    suite: 'old',
)

registers_audio_sources_tests = shared_module('test_registers_audio_sources',
    ['test_registers_audio_sources.cc', 'mock_messages.cc',
     'mock_backtrace.cc', 'mock_audiopath_dbus.cc', 'mock_dbus_iface.cc'],
    cpp_args: '-Wno-pedantic',
    include_directories: ['../src', '../dbus_interfaces'],
    dependencies: [cutter_dep, glib_deps],
    link_with: [
        registers_lib, plainplayer_lib, shutdown_guard_lib, networkprefs_lib,
        servicelist_lib, connman_technology_registry_lib,
    ]
)
test('Registers Audio Sources',
    cutter_wrap, args: [cutter_wrap_args, registers_audio_sources_tests.full_path()],
    depends: registers_audio_sources_tests,
    suite: 'old',
)

registers_search_tests = shared_module('test_registers_search',
    ['test_registers_search.cc', 'mock_messages.cc', 'mock_dbus_iface.cc',
     'mock_dcpd_dbus.cc'],
    cpp_args: '-Wno-pedantic',
    include_directories: ['../src', '../dbus_interfaces'],
    dependencies: [cutter_dep, glib_deps],
    link_with: [
        registers_lib, shutdown_guard_lib, networkprefs_lib,
        connman_technology_registry_lib,
    ]
)
test('Registers Search',
    cutter_wrap, args: [cutter_wrap_args, registers_search_tests.full_path()],
    depends: registers_search_tests,
    suite: 'old',
)

registers_misc_tests = shared_module('test_registers_misc',
    ['test_registers_misc.cc', 'mock_messages.cc', 'mock_os.cc',
     'mock_dbus_iface.cc', 'mock_dcpd_dbus.cc'],
    cpp_args: '-Wno-pedantic',
    include_directories: ['../src', '../dbus_interfaces'],
    dependencies: [cutter_dep, glib_deps],
    link_with: [
        registers_lib, shutdown_guard_lib, networkprefs_lib,
        connman_technology_registry_lib,
    ]
)
test('Registers Misc',
    cutter_wrap, args: [cutter_wrap_args, registers_misc_tests.full_path()],
    depends: registers_misc_tests,
    suite: 'old',
)

drcpdcomm_tests = shared_module('test_drcpdcomm',
    ['test_drcp_communication.cc', 'mock_os.cc', 'mock_messages.cc'],
    cpp_args: '-Wno-pedantic',
    include_directories: '../src',
    dependencies: cutter_dep,
    link_with: drcpdcomm_lib,
)
test('DRCPD Communication',
    cutter_wrap, args: [cutter_wrap_args, drcpdcomm_tests.full_path()],
    depends: drcpdcomm_tests,
    suite: 'old',
)

transactions_tests = shared_module('test_transactions',
    ['test_transactions.cc', 'mock_dcpd_dbus.cc',
     'mock_logind_manager_dbus.cc', 'mock_os.cc', 'mock_messages.cc',
     'mock_backtrace.cc'],
    cpp_args: '-Wno-pedantic',
    include_directories: '../src',
    dependencies: [cutter_dep, glib_deps],
    link_with: [
        transactions_lib, configproxy_lib, registers_lib, plainplayer_lib,
        servicelist_lib, connman_service_lib, connman_technology_registry_lib,
        networkprefs_lib, shutdown_guard_lib
    ]
)
test('DCP Transactions',
    cutter_wrap, args: [cutter_wrap_args, transactions_tests.full_path()],
    depends: transactions_tests,
    suite: 'old',
)

xmodem_tests = shared_module('test_xmodem',
    'test_xmodem.cc',
    cpp_args: '-Wno-pedantic',
    include_directories: '../src',
    dependencies: cutter_dep,
    link_with: xmodem_lib,
)
test('XMODEM',
    cutter_wrap, args: [cutter_wrap_args, xmodem_tests.full_path()],
    depends: xmodem_tests,
    suite: 'old',
)

networkprefs_tests = shared_module('test_networkprefs',
    ['test_networkprefs.cc','mock_os.cc', 'mock_messages.cc'],
    cpp_args: '-Wno-pedantic',
    include_directories: '../src',
    dependencies: cutter_dep,
    link_with: [
        networkprefs_lib, servicelist_lib, connman_service_lib, inifile_lib
    ]
)
test('Network Preferences',
    cutter_wrap, args: [cutter_wrap_args, networkprefs_tests.full_path()],
    depends: networkprefs_tests,
    suite: 'old',
)

network_dispatcher_tests = shared_module('test_network_dispatcher',
    ['test_network_dispatcher.cc', 'mock_os.cc', 'mock_messages.cc',
     'mock_backtrace.cc'],
    cpp_args: '-Wno-pedantic',
    include_directories: '../src',
    dependencies: cutter_dep,
    link_with: [network_dispatcher_lib, network_lib]
)
test('Network Dispatcher',
    cutter_wrap, args: [cutter_wrap_args, network_dispatcher_tests.full_path()],
    depends: network_dispatcher_tests,
    suite: 'old',
)

applink_tests = shared_module('test_applink',
    ['test_applink.cc', 'mock_os.cc', 'mock_network.cc', 'mock_dbus_iface.cc',
     'mock_airable_dbus.cc', 'mock_credentials_dbus.cc', 'mock_messages.cc',
     'mock_backtrace.cc'],
    cpp_args: '-Wno-pedantic',
    include_directories: '../src',
    dependencies: [cutter_dep, glib_deps],
    link_with: [applink_lib, network_dispatcher_lib]
)
test('App Link Protocol',
    cutter_wrap, args: [cutter_wrap_args, applink_tests.full_path()],
    depends: applink_tests,
    suite: 'old',
)
