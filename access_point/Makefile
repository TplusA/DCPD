.PHONY: all clean

.SUFFIXES: .pdf .sdiag

all: user_configures_network_settings_over_app.pdf user_starts_access_point_mode.pdf

clean:
	rm -f *.pdf

.sdiag.pdf:
	seqdiag -T pdf $<
