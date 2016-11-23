#! /bin/sh

test "x$FORCE_SYSTEM_UPGRADE" = x && FORCE_SYSTEM_UPGRADE=

LOG='/usr/bin/systemd-cat'

request_reboot_and_exit()
{
    $LOG echo "Exiting with code $1, rebooting"
    $LOG /usr/bin/dbus-send --system --print-reply --dest=org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager.Reboot boolean:false
    exit $1
}

$LOG /usr/bin/sudo /usr/bin/opkg clean
$LOG /usr/bin/sudo /usr/bin/opkg update

INSTALLED_VERSION=$(/usr/bin/sudo /usr/bin/opkg list-installed os-release | sed -n '/^[^ ]/{s/^[^ ]\+ - \([^ ]\+\).*/\1/p}')

if test "x$FORCE_SYSTEM_UPGRADE" = 'xforce' || test -f '/tmp/force_system_upgrade.stamp'
then
    $LOG echo "UPDATE: Forced upgrade"
elif test $(echo "$INSTALLED_VERSION" | wc -w) -eq 1
then
    BOTH_VERSIONS=$(/usr/bin/sudo /usr/bin/opkg list os-release | sed -n '/^[^ ]/{s/^[^ ]\+ - \([^ ]\+\).*/\1/p}')
    VERSIONS_COUNT=$(echo "$BOTH_VERSIONS" | wc -w)

    if test $VERSIONS_COUNT -eq 1
    then
        if test -n "$(/usr/bin/sudo /usr/bin/opkg list-upgradable)"
        then
            $LOG echo "UPDATE: Continue incomplete upgrade"
        else
            $LOG echo "UPDATE: Not upgrading to same version"
            request_reboot_and_exit 0
        fi
    fi

    INSTALLED_VERSION=$(echo $INSTALLED_VERSION | cut -d '-' -f 2)
    $LOG echo "UPDATE: Replace version $INSTALLED_VERSION by remote version"
else
    $LOG echo "UPDATE: Replace installed UNKNOWN version by remote version"
fi

TEMPDIR='/tmp'
INSTALLED_LIST='update_installed.manifest'
REMOTE_ROOTFS_LIST_FULL="update_rootfs.manifest"
REMOTE_ROOTFS_LIST="${REMOTE_ROOTFS_LIST_FULL}.simple"
COMBINED_FILE='update_combined.txt'

# List of all installed packages, transformed into simplified form
/usr/bin/sudo /usr/bin/opkg list-installed | sed 's/ - / /' | sort >"${TEMPDIR}/${INSTALLED_LIST}"

# Root and boot partition image manifests as generated by Yocto Project
BASE_URL=$(grep '^[^# ]' /etc/opkg/all-feed.conf | head -1 | cut -d ' ' -f 3 | sed 's|/all$||')
$LOG wget -q -O "${TEMPDIR}/${REMOTE_ROOTFS_LIST_FULL}" "${BASE_URL}/rootfs.manifest" || request_reboot_and_exit 10

# Little sanity check to filter out error HTML pages
grep -q '^os-release ' "${TEMPDIR}/${REMOTE_ROOTFS_LIST_FULL}" || request_reboot_and_exit 11

# Simplify manifest of distribution our BASE_URL points to
cut -d ' ' -f 1,3 <"${TEMPDIR}/${REMOTE_ROOTFS_LIST_FULL}" | sort >"${TEMPDIR}/${REMOTE_ROOTFS_LIST}"

join -a 1 -a 2 -e ':' -o '0 1.2 2.2' "${TEMPDIR}/${INSTALLED_LIST}" "${TEMPDIR}/${REMOTE_ROOTFS_LIST}" >"${TEMPDIR}/${COMBINED_FILE}"

INSTALL=
REMOVE=
REINSTALL=

while read PKG INSTVERSION REPOVERSION
do
    if test "x$INSTVERSION" != "x$REPOVERSION"
    then
        if test "x$INSTVERSION" = 'x:'
        then
            INSTALL="$INSTALL $PKG"
        elif test  "x$REPOVERSION" = 'x:'
        then
            REMOVE="$REMOVE $PKG"
        else
            REINSTALL="$REINSTALL $PKG"
        fi
    fi
done <"${TEMPDIR}/${COMBINED_FILE}"

if test "x${INSTALL}${REMOVE}${REINSTALL}" = 'x'
then
    $LOG echo "UPDATE: Nothing changed. Funny..."
    request_reboot_and_exit 0
fi

$LOG echo "UPDATE: New    :$INSTALL"
$LOG echo "UPDATE: Removed:$REMOVE"
$LOG echo "UPDATE: Changed:$REINSTALL"

set -x

# Patch the friggin status file to trick opkg into installing what we want
REINSTALL_STATUS_FILTER="$(echo $REINSTALL | sed 's/ /\\|/g')"
sed '/^Package: \('"$REINSTALL_STATUS_FILTER"'\)$/,/^\s*$/{d}' </var/lib/opkg/status >"${TEMPDIR}/update_patched_status.txt"
$LOG /usr/bin/sudo /bin/mv "${TEMPDIR}/update_patched_status.txt" /var/lib/opkg/status

FAILED='no'

# Remove first, then install (files could have been moved between packages,
# removal after install may brick the system)
if test "x${REMOVE}" != 'x'
then
    $LOG /usr/bin/sudo /usr/bin/opkg remove --force-remove --force-depends $REMOVE || FAILED='yes'
fi
if test "x${REINSTALL}${INSTALL}" != 'x'
then
    $LOG /usr/bin/sudo /usr/bin/opkg install --force-downgrade --force-reinstall --force-overwrite --combine $REINSTALL $INSTALL || FAILED='yes'
fi

$LOG /usr/bin/dbus-send --system --print-reply --dest=org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager.Reboot boolean:false || FAILED='yes'

if test $FAILED != 'yes'
then
    $LOG /bin/rm $0
else
    request_reboot_and_exit 12
fi
