#! /bin/sh
#
# Send any DCP command to DCPD over TCP/IP, payload is read from files.
#
# In addition to the SPI connection, DCPD also listens to incoming TCP/IP
# connections on port 8465. The protocol is the same DCP as over SPI.
#

set -eu

usage()
{
    echo "Usage: $0 [host [port]] -- (r|w) dcp_code payload_file [more payload files]"
    exit 1
}

if test $# -lt 3
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

if test $# -eq 0
then
    usage
fi

TEMPFILE="send_dcp_command_from_files.temp"
rm -f "$TEMPFILE"
touch "$TEMPFILE"

while test $# -ne 0
do
    PAYLOAD_FILE="$1"
    shift

    echo "$PAYLOAD_FILE"

    LEN=$(if test -f "$PAYLOAD_FILE"; then stat -c %s "$PAYLOAD_FILE"; else echo 0; fi)
    HEXLEN=$(printf %04x $LEN)
    HEXLENHI=$(echo $HEXLEN | cut -b 1-2)
    HEXLENLO=$(echo $HEXLEN | cut -b 3-4)

    HEXCOMMAND="$HEXDCPCOMMAND $HEXCODE $HEXLENLO $HEXLENHI"

    echo -n "0 $HEXCOMMAND" | xxd -r | cat /dev/stdin "$PAYLOAD_FILE" >>"$TEMPFILE"
done

echo 'Sending command with total size of '$(stat -c %s "$TEMPFILE")" to $HOST:$PORT"
nc -N "$HOST" "$PORT" <"$TEMPFILE" | hexdump -C

rm -f "$TEMPFILE"
