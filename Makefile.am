SUBDIRS = . tests

ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = dcpd

html_DATA = README.html

EXTRA_DIST = README.md cppcheck_suppressed.txt
EXTRA_DIST += send_drcp_command.sh

dbusservicedir = $(datadir)/dbus-1/services
dbusservice_DATA = dist/de.tahifi.Dcpd.service

CLEANFILES = README.html

dcpd_SOURCES = \
    dcpd.c os.c os.h registers.h named_pipe.c named_pipe.h \
    network.c network.h \
    transactions.h dcpdefs.h messages.c messages.h \
    dynamic_buffer.h drcp.h drcp_command_codes.h dcpregs_drcp.h \
    dbus_iface.c dbus_iface.h dbus_iface_deep.h

AM_CFLAGS = $(CWARNINGS)

AM_CPPFLAGS = $(DCPD_DEPENDENCIES_CFLAGS)

noinst_LTLIBRARIES = libtransactions.la libdynamic_buffer.la libregisters.la libdcpd_dbus.la libdrcpdcomm.la

dcpd_LDADD = $(noinst_LTLIBRARIES) $(DCPD_DEPENDENCIES_LIBS)

dcpd_LDFLAGS = $(LTLIBINTL)

libdynamic_buffer_la_SOURCES = dynamic_buffer.c dynamic_buffer.h
libdynamic_buffer_la_CFLAGS = $(AM_CFLAGS)

libregisters_la_SOURCES = \
    registers.c registers.h \
    dcpregs_drcp.c dcpregs_drcp.h drcp_command_codes.h messages.h
libregisters_la_CFLAGS = $(AM_CFLAGS)

nodist_libdcpd_dbus_la_SOURCES = dcpd_dbus.c dcpd_dbus.h
libdcpd_dbus_la_CFLAGS = $(CRELAXEDWARNINGS)

libdrcpdcomm_la_SOURCES = drcp.c drcp.h named_pipe.h dynamic_buffer.h messages.h
libdrcpdcomm_la_CFLAGS = $(AM_CFLAGS)

libtransactions_la_SOURCES = \
    transactions.c transactions.h os.h \
    dynamic_buffer.h registers.h named_pipe.h dcpdefs.h messages.h
libtransactions_la_CFLAGS = $(AM_CFLAGS)

EXTRA_DIST += dbus_interfaces/extract_documentation.py dbus_interfaces/de_tahifi_dcpd.xml

BUILT_SOURCES = $(nodist_libdcpd_dbus_la_SOURCES) de_tahifi_dcpd.h de_tahifi_dcpd.md dcpd_dbus.stamp

CLEANFILES += $(BUILT_SOURCES)


de_tahifi_dcpd.h: dcpd_dbus.stamp
de_tahifi_dcpd.md: dcpd_dbus.stamp
dcpd_dbus.c: dcpd_dbus.stamp
dcpd_dbus.h: dcpd_dbus.stamp
dcpd_dbus.stamp: dbus_interfaces/de_tahifi_dcpd.xml
	$(GDBUS_CODEGEN) --generate-c-code=dcpd_dbus --c-namespace tdbus_dcpd --interface-prefix de.tahifi.Dcpd. $<
	$(abs_srcdir)/dbus_interfaces/extract_documentation.py -i $< -o de_tahifi_dcpd.md -H de_tahifi_dcpd.h -c tdbus_dcpd -s de.tahifi.Dcpd. -n "$(PACKAGE_NAME)"
	touch $@

.md.html:
	$(MARKDOWN) $< >$@

if CAN_BUILD_DEBIAN_PACKAGE
DEBIAN_PACKAGE_FILES = debian/changelog debian/compat debian/control debian/rules

EXTRA_DIST += $(DEBIAN_PACKAGE_FILES)

deb: dist
	rm -rf "$(distdir)"
	GZIP=$(GZIP_ENV) gzip -dc "$(distdir).tar.gz" | $(am__untar)
	$(am__cd) "$(distdir)" && DH_SHLIBDEPS_ARGS="$(DH_SHLIBDEPS_ARGS)" $(DPKG_BUILDPACKAGE) -rfakeroot -D -b -t$(host_alias)
	rm -rf "$(distdir)"
else
deb:
	@echo "Cannot build Debian package, requirements not met."
	exit 1
endif
