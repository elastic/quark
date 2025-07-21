#!/bin/bash

set -euo pipefail

SCRIPT=${0##*/}
VERBOSE=0

log() { (( VERBOSE )) && printf '%s\n' "INFO: $*" >&2 || true; }
log_error() { printf '%s\n' "ERROR: $*" >&2; }
die() { log_error "$*"; exit 1; }

function usage
{
	echo "usage: $SCRIPT [-v] initramfs.gz FEDORAVERSION command..." 1>&2
	echo
	echo "  -v              Verbose output"
	echo "  initramfs.gz    Path to initramfs image"
	echo "  FEDORAVERSION   Fedora version (e.g. 39, 40, rawhide)"
	echo "  command...      Command to run in guest"
	echo
	echo "Examples:"
	echo "  $SCRIPT -v initramfs.gz rawhide quark-test -vvv"
	exit 1
}

while getopts "vh" opt; do
	case $opt in
		v) VERBOSE=1 ;;
		h) usage ;;
		*) usage ;;
	esac
done
shift $((OPTIND - 1))

if [ $# -lt 3 ]; then
	usage
fi

INITRAMFS="$1"
FEDORAVER="$2"
shift 2

[[ -f $INITRAMFS ]] || die "Initramfs not found: $INITRAMFS"
[[ -f ./krun.sh ]] || die "Required launcher ./krun.sh is missing"

case $FEDORAVER in
2?|3?|40)	URL="https://archives.fedoraproject.org/pub/archive/fedora/linux/updates/$FEDORAVER/Everything/x86_64/Packages/k";;
43|rawhide)	URL="https://ftp.fau.de/fedora/linux/development/$FEDORAVER/Everything/x86_64/os/Packages/k";;
4?)		URL="https://ftp.fau.de/fedora/linux/updates/$FEDORAVER/Everything/x86_64/Packages/k";;
*)		die "Unsupported Fedora version: $FEDORAVER";;
esac

log "Searching for Fedora $FEDORAVER kernel..."

TMPDIR=$(mktemp -d "/tmp/$SCRIPT.XXXXXXXXXX")
readonly TMPDIR
cleanup()	{ [[ -d "$TMPDIR" ]] && rm -rf "$TMPDIR"; }
trap cleanup EXIT

log "Fetching package list from $URL"
RPMURL=$(lynx -dump -listonly "$URL"|grep kernel-core) || die "Can't fetch package list"
RPMURL=${RPMURL##* }
RPM=$(basename "$RPMURL")
VMLINUZ=${RPM##kernel-core-}
VMLINUZ=${VMLINUZ%%.rpm}
VMLINUZ=$TMPDIR/lib/modules/$VMLINUZ/vmlinuz

log "URL: $URL"
log "RPMURL: $RPMURL"
log "Downloading kernel RPM: $RPM"
log "Target vmlinuz: $VMLINUZ"

cd "$TMPDIR"
curl -s "$RPMURL" | rpm2cpio - | cpio -idm
cd -

[[ -f "$VMLINUZ" ]] || die "vmlinuz not found: $VMLINUZ"

log "Kernel ready: $VMLINUZ"
log "Handing off to ./krun.sh"

./krun.sh "$INITRAMFS" "$VMLINUZ" "$@"
