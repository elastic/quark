#!/bin/bash

set -euo pipefail

SCRIPT=${0##*/}

function usage
{
	echo "usage: $SCRIPT initramfs.gz FEDORAVERSION command" 1>&2
	exit 1
}

if [ $# -lt 3 ]; then
	usage
fi

INITRAMFS="$1"
FEDORAVER="$2"
shift 2

case $FEDORAVER in
2?|3?)		URL="https://archives.fedoraproject.org/pub/archive/fedora/linux/updates/$FEDORAVER/Everything/x86_64/Packages/k";;
43|rawhide)	URL="https://ftp.fau.de/fedora/linux/development/$FEDORAVER/Everything/x86_64/os/Packages/k";;
4?)		URL="https://ftp.fau.de/fedora/linux/updates/$FEDORAVER/Everything/x86_64/Packages/k";;
*)		echo bad version "$FEDORAVER" 1>&2;;
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
