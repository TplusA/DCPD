#! /bin/sh

set -eu

DEFAULT_HOST='r1000e'

if test $# -eq 0
then
    MS=0
    HOST="${DEFAULT_HOST}"
elif test $# -eq 1
then
    MS="$1"
    HOST="${DEFAULT_HOST}"
else
    MS="$2"
    HOST="$1"
fi

MS_HEX="$(printf "%08x" $((MS * 1000)) | sed 's/\(..\)\(..\)\(..\)\(..\)/0x\4 0x\3 0x\2 0x\1/g')"

exec $(dirname $0)/send_dcp_command.sh ${HOST} -- w 73 0xc4 ${MS_HEX}
