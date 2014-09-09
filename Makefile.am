bin_PROGRAMS = dcpd

html_DATA = README.html

dcpd_SOURCES = \
    dcpd.c registers.c registers.h named_pipe.c named_pipe.h \
    transactions.c transactions.h dcpdefs.h messages.c messages.h

.md.html:
	$(MARKDOWN) $< >$@
