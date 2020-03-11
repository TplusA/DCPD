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

registers_tests = shared_module('test_registers',
    ['test_registers.cc', 'mock_dcpd_dbus.cc', 'mock_dbus_iface.cc',
     'mock_file_transfer_dbus.cc', 'mock_streamplayer_dbus.cc',
     'mock_credentials_dbus.cc', 'mock_airable_dbus.cc',
     'mock_artcache_dbus.cc', 'mock_audiopath_dbus.cc',
     'mock_logind_manager_dbus.cc', 'mock_connman.cc', 'mock_os.cc',
     'mock_messages.cc', 'mock_backtrace.cc'],
    include_directories: ['../src', '../dbus_interfaces'],
    dependencies: [cutter_dep, glib_deps],
    link_with: [
        registers_lib, plainplayer_lib, shutdown_guard_lib, networkprefs_lib,
        servicelist_lib, connman_service_lib, connman_technology_registry_lib,
        inifile_lib, xmodem_lib
    ]
)
test('Registers',
    cutter_wrap, args: [cutter_wrap_args, registers_tests.full_path()],
    depends: registers_tests,
    suite: 'old',
)

drcpdcomm_tests = shared_module('test_drcpdcomm',
    ['test_drcp_communication.cc', 'mock_os.cc', 'mock_messages.cc'],
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
    include_directories: '../src',
    dependencies: [cutter_dep, glib_deps],
    link_with: [applink_lib, network_dispatcher_lib]
)
test('App Link Protocol',
    cutter_wrap, args: [cutter_wrap_args, applink_tests.full_path()],
    depends: applink_tests,
    suite: 'old',
)
