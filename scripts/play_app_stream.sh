#! /bin/sh

# http://streams.radiobob.de/bob-live/mp3-192/airable/
URL='0x68 0x74 0x74 0x70 0x3a 0x2f 0x2f 0x73 0x74 0x72 0x65 0x61 0x6d 0x73 0x2e 0x72 0x61 0x64 0x69 0x6f 0x62 0x6f 0x62 0x2e 0x64 0x65 0x2f 0x62 0x6f 0x62 0x2d 0x6c 0x69 0x76 0x65 0x2f 0x6d 0x70 0x33 0x2d 0x31 0x39 0x32 0x2f 0x61 0x69 0x72 0x61 0x62 0x6c 0x65 0x2f'

./send_dcp_command.sh r1000e -- w 78 '0x61 0x62 0x63'
exec ./send_dcp_command.sh r1000e -- w 79 $URL
