#! /bin/sh
LOG='/usr/bin/systemd-cat'
$LOG /usr/bin/sudo /usr/bin/opkg update && $LOG /usr/bin/sudo /usr/bin/opkg upgrade && $LOG /usr/bin/dbus-send --system --print-reply --dest=org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager.Reboot boolean:false
test $? -eq 0 || $LOG /bin/rm $0
