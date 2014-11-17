#! /bin/sh
#
# Send a DRCP command to DCPD over TCP/IP.
#
# In addition to the SPI connection, DCPD also serves incoming TCP/IP
# connections on port 8465. The protocol is the same DCP as over SPI. This
# script specializes in sending DRCP commands (by default to localhost).
#

set -eu

if test $# -lt 1 || test $# -gt 3
then
    echo "Usage: $0 [host [port]] drcp_code"
    exit 1
fi

HOST='localhost'
PORT='8465'

if test $# -gt 1
then
    HOST="$1"
    shift
fi

if test $# -gt 1
then
    PORT="$1"
    shift
fi

CODE="$1"

HEXCODE="$(printf %02x $CODE)"
HEXCOMMAND="00 48 $HEXCODE 00"

echo "Sending '$HEXCOMMAND' to $HOST:$PORT"
echo "0 $HEXCOMMAND" | xxd -r | nc "$HOST" "$PORT" | hexdump -C
