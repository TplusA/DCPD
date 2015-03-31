#! /bin/sh
#
# Send any DCP command to DCPD over TCP/IP.
#
# In addition to the SPI connection, DCPD also listens to incoming TCP/IP
# connections on port 8465. The protocol is the same DCP as over SPI.
#

set -eu

usage()
{
    echo "Usage: $0 [host [port]] -- (r|w) dcp_code [dcp data]"
    exit 1
}

if test $# -lt 2
then
    usage
fi

HOST='localhost'
PORT='8465'

READING_DCP_COMMAND='no'

if test $# -gt 1
then
    if test "$1" != "--"
    then
        HOST="$1"
    else
        READING_DCP_COMMAND='yes'
    fi

    shift
fi

if test $# -gt 1 && test "$READING_DCP_COMMAND" != 'yes'
then
    if test "$1" != "--"
    then
        PORT="$1"
    else
        READING_DCP_COMMAND='yes'
    fi

    shift
fi

if test $# -gt 1 && test "$READING_DCP_COMMAND" != 'yes'
then
    if test "$1" != "--"
    then
        usage
    else
        READING_DCP_COMMAND='yes'
    fi

    shift
fi

test "$READING_DCP_COMMAND" = yes || usage


case $1
in
    r)
        HEXDCPCOMMAND='01'
        ;;
    w)
        HEXDCPCOMMAND='02'
        ;;
    *)
        usage
        ;;
esac
shift


CODE="$1"
shift
HEXCODE="$(printf %02x $CODE)"


HEXARGUMENTS=
for C in "$@"
do
    HEXARGUMENTS="$HEXARGUMENTS$(printf %02x $C) "
done
HEXARGUMENTS=$(echo $HEXARGUMENTS)


LEN=$(echo $HEXARGUMENTS | wc -w)
echo $LEN
HEXLEN=$(printf %04x $LEN)
HEXLENHI=$(echo $HEXLEN | cut -b 1-2)
HEXLENLO=$(echo $HEXLEN | cut -b 3-4)


HEXCOMMAND="$HEXDCPCOMMAND $HEXCODE $HEXLENLO $HEXLENHI $HEXARGUMENTS"

echo "Sending '$HEXCOMMAND' to $HOST:$PORT"
echo "0 $HEXCOMMAND" | xxd -r | nc "$HOST" "$PORT" | hexdump -C
