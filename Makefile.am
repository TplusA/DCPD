bin_PROGRAMS = dcpd

html_DATA = README.html

EXTRA_DIST = README.md

CLEANFILES = README.html

dcpd_SOURCES = \
    dcpd.c registers.c registers.h named_pipe.c named_pipe.h \
    transactions.c transactions.h dcpdefs.h messages.c messages.h \
    dynamic_buffer.c dynamic_buffer.h drcp.c drcp.h drcp_command_codes.h \
    dcpregs_drcp.c dcpregs_drcp.h

.md.html:
	$(MARKDOWN) $< >$@
