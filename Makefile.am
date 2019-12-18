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

SUBDIRS = . src dist tests_new tests

ACLOCAL_AMFLAGS = -I m4

if WITH_MARKDOWN
html_DATA = README.html
endif

EXTRA_DIST = COPYING COPYING.GPLv3 README.md cppcheck_suppressed.txt

EXTRA_DIST += \
    scripts/Back.sh \
    scripts/configure_volume_control.sh \
    scripts/Down.sh \
    scripts/JumpToPos.sh \
    scripts/login_logout.sh \
    scripts/mediaservices_fast.sh \
    scripts/mediaservices_slow.sh \
    scripts/OK.sh \
    scripts/play_app_stream.sh \
    scripts/Play.sh \
    scripts/query.sh \
    scripts/send_dcp_command_from_files.sh \
    scripts/send_dcp_command.sh \
    scripts/send_drcp_command.sh \
    scripts/send_read_register.sh \
    scripts/SkipBackward.sh \
    scripts/SkipForward.sh \
    scripts/start_access_point.sh \
    scripts/Stop.sh \
    scripts/switch_to_language.sh \
    scripts/switch_to_source.sh \
    scripts/Up.sh

CLEANFILES = README.html

EXTRA_DIST += \
    dbus_interfaces/extract_documentation.py \
    dbus_interfaces/de_tahifi_dcpd.xml \
    dbus_interfaces/de_tahifi_configuration.xml \
    dbus_interfaces/de_tahifi_jsonio.xml \
    dbus_interfaces/de_tahifi_debug.xml \
    dbus_interfaces/de_tahifi_filetransfer.xml \
    dbus_interfaces/de_tahifi_streamplayer.xml \
    dbus_interfaces/de_tahifi_airable.xml \
    dbus_interfaces/de_tahifi_artcache.xml \
    dbus_interfaces/de_tahifi_artcache_errors.hh \
    dbus_interfaces/de_tahifi_artcache_monitor_errors.h \
    dbus_interfaces/de_tahifi_artcache_read_errors.h \
    dbus_interfaces/de_tahifi_audiopath.xml \
    dbus_interfaces/de_tahifi_mixer.xml \
    dbus_interfaces/de_tahifi_credentials.xml \
    dbus_interfaces/de_tahifi_appliance.xml \
    dbus_interfaces/io_gerbera.xml \
    dbus_interfaces/net_connman.xml \
    dbus_interfaces/org_freedesktop_login1.xml \
    dbus_interfaces/org_freedesktop_systemd1.xml

BUILT_SOURCES = versioninfo.h

CLEANFILES += $(BUILT_SOURCES)

versioninfo.h: versioninfo.cache
	(cd $(top_srcdir) && $(AUTOREVISION) -t h -o $(abs_top_builddir)/versioninfo.cache >$(abs_top_builddir)/$@)

.md.html:
	$(MARKDOWN) $< >$@

if WITH_DOCTEST
doctest:
	$(MAKE) $(AM_MAKEFLAGS) -C tests_new $@

doctest-valgrind:
	$(MAKE) $(AM_MAKEFLAGS) -C tests_new $@
endif
