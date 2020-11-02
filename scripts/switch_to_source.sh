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
    inactive)
        BYTES='81 0'
        ;;
    standby)
        BYTES='81 0x3a 0x73 0x74 0x61 0x6e 0x64 0x62 0x79 0'
        ;;
    airable)
        BYTES='81 0x61 0x69 0x72 0x61 0x62 0x6c 0x65 0'
        ;;
    tidal)
        BYTES='81 0x61 0x69 0x72 0x61 0x62 0x6c 0x65 0x2e 0x74 0x69 0x64 0x61 0x6c 0'
        ;;
    qobuz)
        BYTES='81 0x61 0x69 0x72 0x61 0x62 0x6c 0x65 0x2e 0x71 0x6f 0x62 0x75 0x7a 0'
        ;;
    deezer)
        BYTES='81 0x61 0x69 0x72 0x61 0x62 0x6c 0x65 0x2e 0x64 0x65 0x65 0x7a 0x65 0x72 0'
        ;;
    highres)
        BYTES='81 0x61 0x69 0x72 0x61 0x62 0x6c 0x65 0x2e 0x68 0x69 0x67 0x68 0x72 0x65 0x73 0x61 0x75 0x64 0x69 0x6f 0'
        ;;
    radio)
        BYTES='81 0x61 0x69 0x72 0x61 0x62 0x6c 0x65 0x2e 0x72 0x61 0x64 0x69 0x6f 0x73 0'
        ;;
    feeds)
        BYTES='81 0x61 0x69 0x72 0x61 0x62 0x6c 0x65 0x2e 0x66 0x65 0x65 0x64 0x73 0'
        ;;
    usb)
        BYTES='81 0x73 0x74 0x72 0x62 0x6f 0x2e 0x75 0x73 0x62 0'
        ;;
    upnp)
        BYTES='81 0x73 0x74 0x72 0x62 0x6f 0x2e 0x75 0x70 0x6e 0x70 0x63 0x6d 0'
        ;;
    app)
        BYTES='81 0x73 0x74 0x72 0x62 0x6f 0x2e 0x70 0x6c 0x61 0x69 0x6e 0x75 0x72 0x6c 0'
        ;;
    roon)
        BYTES='81 0x72 0x6f 0x6f 0x6e 0'
        ;;
    roon_on)
        BYTES='81 0x72 0x6f 0x6f 0x6e 0 0x01'
        ;;
    roon_off)
        BYTES='81 0x72 0x6f 0x6f 0x6e 0 0x00'
        ;;
    *)
        echo 'Invalid audio source ID'
        echo 'Valid ID are:'
        grep '^ \+[^ *].*)$' <"$0" | sed 's/)//'
        exit 1
        ;;
esac

exec $(dirname $0)/send_dcp_command.sh "$DEST" -- w $BYTES
