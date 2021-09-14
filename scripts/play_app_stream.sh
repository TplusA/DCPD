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

if test $# -ne 1 && test $# -ne 4
then
    echo "Usage: $0 <url> [<artist> <album> <title>]"
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

$(dirname $0)/send_dcp_command.sh ${ADDR} -- w 78 ${METADATA}
exec $(dirname $0)/send_dcp_command.sh ${ADDR} -- w 79 ${URL}
