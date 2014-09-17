bin_PROGRAMS = dcpd

html_DATA = README.html

EXTRA_DIST = README.md

CLEANFILES = README.html

dcpd_SOURCES = \
    dcpd.c registers.c registers.h named_pipe.c named_pipe.h \
    transactions.c transactions.h dcpdefs.h messages.c messages.h \
    dynamic_buffer.c dynamic_buffer.h drcp.c drcp.h drcp_command_codes.h \
    dcpregs_drcp.c dcpregs_drcp.h \
    dbus_iface.c dbus_iface.h dbus_iface_deep.h

AM_CFLAGS = $(CWARNINGS)

AM_CPPFLAGS = $(DCPD_DEPENDENCIES_CFLAGS)

dcpd_LDADD = $(DCPD_DEPENDENCIES_LIBS) libdcpd_dbus.a

noinst_LIBRARIES = libdcpd_dbus.a

nodist_libdcpd_dbus_a_SOURCES = dcpd_dbus.c dcpd_dbus.h

libdcpd_dbus_a_CFLAGS = $(CRELAXEDWARNINGS)

EXTRA_DIST += de_tahifi_dcpd.xml

CLEANFILES += $(nodist_libdcpd_dbus_a_SOURCES) dcpd_dbus.stamp

dcpd_dbus.c: dcpd_dbus.stamp
dcpd_dbus.h: dcpd_dbus.stamp
dcpd_dbus.stamp: de_tahifi_dcpd.xml
	$(GDBUS_CODEGEN) --generate-c-code=dcpd_dbus --c-namespace tdbus_dcpd --interface-prefix de.tahifi.dcpd. $<
	touch $@

.md.html:
	$(MARKDOWN) $< >$@
