#! /bin/sh

test $# -eq 2 || exit 1

echo 'static const uint8_t shell_script_content[] =' >"$2"
echo '{' >>"$2"
od -An -tx1 -v <"$1" | sed 's/ / 0x/g;s/^ //;s/ /, /g;s/$/,/' >>"$2"
echo '};' >>"$2"
