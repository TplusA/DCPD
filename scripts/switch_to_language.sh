#! /bin/sh

if test $# -ge 2
then
    DEST="$1"
    shift
else
    DEST='r1000e'
fi

case $1
in
    english)
        BYTES='47 0x65 0x6e 0 0x55 0x53 0 0 0x44 0x45 0'
        ;;
    german)
        BYTES='47 0x64 0x65 0 0x44 0x45 0 0 0x44 0x45 0'
        ;;
    *)
        echo 'Invalid audio source ID'
        echo 'Valid ID are:'
        grep '^ \+[^ *].*)$' <"$0" | sed 's/)//'
        exit 1
        ;;
esac

exec $(dirname $0)/send_dcp_command.sh "$DEST" -- w $BYTES
