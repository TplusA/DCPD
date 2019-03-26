#! /bin/sh
#
# Send a read request for DCP registers over TCP/IP.
#

set -eu

if test $# -lt 1 || test $# -gt 3
then
    echo "Usage: $0 [host [port]] dcp_register"
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

REG="$1"

HEXREG="$(printf %02x $REG)"
HEXCOMMAND="01 $HEXREG 00 00"

echo "Sending '$HEXCOMMAND' to $HOST:$PORT"
echo "0 $HEXCOMMAND" | xxd -r | nc -N "$HOST" "$PORT" | hexdump -C
