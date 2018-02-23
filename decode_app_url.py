#! /usr/bin/env python3
#
# Script for decoding URLs passed from App to ARM through tunnel:
# - Find hexdump in log file or stdin (start line and maximum number of lines
#   can be specified).
# - Take fraction of hexdump the URL is expected to be found (byte offset can
#   be specified).
# - Decode it by XOR'ing each input byte with a number generated by a
#   linear-feedback shift register PRNG.
#

import sys
import getopt
import re

class LFSR:
    def __init__(self, seed, mask):
        self.mask = mask
        self.default_seed = seed
        self.reset()

    def reset(self):
        self.state = self.default_seed

    def get_byte(self):
        lsb = self.state & 1
        self.state >>= 1

        if lsb:
            self.state ^= self.mask

        return self.state & 0xff

class Hexdump:
    def __init__(self, offset = 0):
        self.offset = offset
        self.data = []

    def add_chunk(self, offset, data):
        if offset != self.offset + len(self.data):
            raise IndexError("Hexdump offset does not match; expected {}, got {}".format(self.offset + len(self.data), offset))

        self.data += data

def extract_hexdump(input, start_line, max_lines):
    while start_line > 1:
        input.readline()
        start_line = start_line - 1

    if not max_lines:
        lines = input.readlines()
    else:
        lines = []

        while max_lines > 0:
            lines.append(input.readline())
            max_lines = max_lines - 1

    hexdump = None

    for l in lines:
        m = re.search(r'([\da-f]{4})  ([\da-f]{2} ( *[\da-f]{2})*) *  \|', l)

        if not m:
            continue

        offset = int(m.group(1).strip(), 16)

        if hexdump == None:
            hexdump = Hexdump(offset)

        try:
            hexdump.add_chunk(offset, list(map(lambda x: int(x, 16), re.split(r' +', m.group(2).strip()))))
        except:
            print("Failed processing the following line:")
            print(l.strip())
            raise

    return hexdump

def escaped_hexdump(hexdump):
    escaped = Hexdump(hexdump.offset)

    r = iter(range(0, len(hexdump.data)))

    for i in r:
        b = hexdump.data[i]

        if b == 0x27:
            next(r)

            b = hexdump.data[i + 1]

            if b == 0x01:
                b = 0xff

        escaped.data.append(b)

    return escaped

def error_exit(error_message, exit_code = 1):
    print("ERROR: " + error_message, file = sys.stderr)
    sys.exit(exit_code)

def usage(exit_code = 1):
    print("""Usage:
{0} [-h] [-l start line] [-b start byte] [-u] [input file]

Options:
-h       This help screen.
-l line  Which line to begin in searching for a hexdump (default: 1)
-n num   How many lines to read at most (default: all)
-b byte  At which byte in the hexdump decoding should start (default: 16)
-u       Unescape SPI escape sequences (0x27 handling)""".format(sys.argv[0]))
    sys.exit(exit_code)

def main():
    input = sys.stdin
    start_byte = 16
    start_line = 1
    max_lines = None
    unescape = False

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hb:l:n:u")
    except getopt.GetoptError as err:
        error_exit(str(err))

    for o, a in opts:
        if o == "-h":   usage(0)
        elif o == "-b": start_byte = int(a)
        elif o == "-l": start_line = int(a)
        elif o == "-n": max_lines = int(a)
        elif o == "-u": unescape = True

    if args:
        input = open(args[0], "r")

    try:
        hexdump = extract_hexdump(input, start_line, max_lines)

        if unescape:
            hexdump = escaped_hexdump(hexdump)

        prng = LFSR(44257, 46080)
        decoded = ''.join(list(map(lambda x: chr(x ^ prng.get_byte()), hexdump.data[start_byte:])))

        print(decoded)
    except IndexError as err:
        print("Failed processing input: " + str(err))

if __name__ == '__main__':
    main();
