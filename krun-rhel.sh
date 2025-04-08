#!/bin/bash

set -euo pipefail

SCRIPT=${0##*/}

function usage
{
	echo "usage: $SCRIPT initramfs.gz RHELVER command" 1>&2
	exit 1
}

if [ $# -lt 3 ]; then
	usage
fi

INITRAMFS="$1"
RHELVER="$2"
shift 2

case $RHELVER in
8|9)		URL="https://ftp.fau.de/rockylinux/$RHELVER/BaseOS/x86_64/os/Packages/k";;
8.[34])		URL="https://dl.rockylinux.org/vault/rocky/$RHELVER/BaseOS/x86_64/os/Packages";;
8.?|9.?)	URL="https://dl.rockylinux.org/vault/rocky/$RHELVER/BaseOS/x86_64/os/Packages/k";;
*)		echo bad version "$RHELVER" 1>&2;;
esac

TMPDIR=$(mktemp -d "/tmp/$SCRIPT.XXXXXXXXXX")
trap 'rm -rf "$TMPDIR"' EXIT

RPMURL=$(lynx -dump -listonly "$URL"|grep kernel-core)
RPMURL=${RPMURL##* }
RPM=$(basename "$RPMURL")
VMLINUZ=${RPM##kernel-core-}
VMLINUZ=${VMLINUZ%%.rpm}
VMLINUZ=$TMPDIR/lib/modules/$VMLINUZ/vmlinuz

# echo URL $URL
# echo RPMURL $RPMURL
# echo RPM $RPM
# echo VMLINUZ $VMLINUZ

cd "$TMPDIR"
curl -s "$RPMURL" | rpm2cpio - | cpio -idm
cd -

./krun.sh "$INITRAMFS" "$VMLINUZ" "$@"
