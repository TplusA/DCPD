#! /bin/sh

set -eu

if test $# -eq 0
then
    MS=0
else
    MS="$1"
fi

MS_HEX="$(printf "%08x" $((MS * 1000)) | sed 's/\(..\)\(..\)\(..\)\(..\)/0x\4 0x\3 0x\2 0x\1/g')"

exec $(dirname $0)/send_dcp_command.sh -- w 73 0xc4 ${MS_HEX}
