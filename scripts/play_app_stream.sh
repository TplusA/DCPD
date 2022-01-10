#! /bin/sh

ADDR='r1000e'

string_to_hex()
{
    HEXSTRING=
    for C in $(echo -n "$1" | xxd -c 1 -i | sed 's/.*\(0x..\).*/\1/')
    do
        HEXSTRING="${HEXSTRING}${C} "
    done
}

if test $# -ge 1 && test "x$1" = "x-n"
then
    REGISTER_METADATA=238
    REGISTER_URL=239
    shift
else
    REGISTER_METADATA=78
    REGISTER_URL=79
fi

if test $# -ne 1 && test $# -ne 4
then
    cat <<EOF
Usage: $0 [-n] <url> [<artist> <album> <title>]

-n      Push as next stream, not first stream.
url     The URL to play.
artist  Artist name.
album   Album name.
title   Title of the stream.
EOF
    exit 1
fi

string_to_hex "$1"
URL="${HEXSTRING}"

if test $# -eq 4
then
    ARTIST="$2"
    ALBUM="$3"
    TITLE="$4"
else
    ARTIST=
    ALBUM=
    TITLE=
fi

string_to_hex "${ARTIST}"
METADATA="${HEXSTRING}"
string_to_hex "${ALBUM}"
METADATA="${METADATA}0x1d ${HEXSTRING}"
string_to_hex "${TITLE}"
METADATA="${METADATA}0x1d ${HEXSTRING}"

$(dirname $0)/send_dcp_command.sh ${ADDR} -- w ${REGISTER_METADATA} ${METADATA}
exec $(dirname $0)/send_dcp_command.sh ${ADDR} -- w ${REGISTER_URL} ${URL}
