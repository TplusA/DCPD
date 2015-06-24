#! /bin/sh
#
# Send a DRCP command to DCPD over TCP/IP.
#
# In addition to the SPI connection, DCPD also serves incoming TCP/IP
# connections on port 8465. The protocol is the same DCP as over SPI. This
# script specializes in sending DRCP commands (by default to localhost).
#

set -eu

usage()
{
    echo "Usage: $0 [host [port]] -- (r|w) drcp_code [drcp data]"
    exit 1
}

if test $# -lt 3
then
    usage
fi

# patch in the DRCP register
ARGS="$(echo $@ | sed 's/\(-- [rw]\) \+/\1 72 /')"

exec "$(dirname $0)"/send_dcp_command.sh $ARGS
