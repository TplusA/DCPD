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

compiler = meson.get_compiler('cpp')

if not compiler.has_header('doctest.h')
    subdir_done()
endif

testrunner_lib = static_library('testrunner', 'testrunner.cc',
    cpp_args: '-DDOCTEST_CONFIG_TREAT_CHAR_STAR_AS_STRING',
    include_directories: '../src'
)

test('ConnMan Service',
    executable('test_connman_service',
        ['test_connman_service.cc', 'mock_os.cc', 'mock_messages.cc'],
        include_directories: '../src',
        link_with: [testrunner_lib, connman_service_lib],
        cpp_args: '-DDOCTEST_CONFIG_TREAT_CHAR_STAR_AS_STRING',
        build_by_default: false),
    workdir: meson.current_build_dir(),
    args: ['--reporters=strboxml', '--out=test_connman_service.junit.xml'],
    suite: 'new',
)

test('ConnMan Property Cache',
    executable('test_connman_property_cache',
        'test_connman_property_cache.cc',
        include_directories: '../src',
        link_with: testrunner_lib,
        cpp_args: '-DDOCTEST_CONFIG_TREAT_CHAR_STAR_AS_STRING',
        build_by_default: false),
    workdir: meson.current_build_dir(),
    args: ['--reporters=strboxml', '--out=test_connman_property_cache.junit.xml'],
    suite: 'new',
)

test('Access Point',
    executable('test_access_point',
        ['test_access_point.cc', 'mock_connman_technology_registry.cc',
         'mock_backtrace.cc',
         'mock_os.cc', 'mock_messages.cc'],
        include_directories: '../src',
        link_with: [testrunner_lib, accesspoint_lib, servicelist_lib,
                    connman_service_lib],
        cpp_args: '-DDOCTEST_CONFIG_TREAT_CHAR_STAR_AS_STRING',
        build_by_default: false),
    workdir: meson.current_build_dir(),
    args: ['--reporters=strboxml', '--out=test_access_point.junit.xml'],
    suite: 'new',
)

test('Plain Stream Player',
    executable('test_plainplayer',
        ['test_plainplayer.cc', 'mock_os.cc', 'mock_messages.cc',
         'mock_backtrace.cc'],
        include_directories: '../src',
        link_with: [testrunner_lib, plainplayer_lib],
        cpp_args: '-DDOCTEST_CONFIG_TREAT_CHAR_STAR_AS_STRING',
        build_by_default: false),
    workdir: meson.current_build_dir(),
    args: ['--reporters=strboxml', '--out=test_plainplayer.junit.xml'],
    suite: 'new',
)

test('AuPaL Parser',
    executable('aupal_parser',
        'test_aupal_parser.cc',
        include_directories: '../src',
        link_with: [testrunner_lib, audiopath_minidsl_lib],
        cpp_args: '-DDOCTEST_CONFIG_TREAT_CHAR_STAR_AS_STRING',
        build_by_default: false),
    workdir: meson.current_build_dir(),
    args: ['--reporters=strboxml', '--out=test_aupal_parser.junit.xml'],
    suite: 'new',
)
