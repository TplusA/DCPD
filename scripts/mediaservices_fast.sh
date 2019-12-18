#! /bin/sh
echo 0 01 6a 00 00 01 6a 00 00 01 6a 00 00 01 6a 00 00 | xxd -r | nc -N r1000e 8465 | hexdump -C
