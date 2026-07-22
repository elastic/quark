#!/bin/bash

set -euo pipefail

SCRIPT=${0##*/}
VERBOSE=0

log() { (( VERBOSE )) && printf '%s\n' "INFO: $*" >&2 || true; }
log_error() { printf '%s\n' "ERROR: $*" >&2; }
die() { log_error "$*"; exit 1; }

function usage
{
	echo "usage: $SCRIPT [-v] initramfs.gz command..." 1>&2
	echo
	echo "  -v              Verbose output"
	echo "  initramfs.gz    Path to initramfs image"
	echo "  command...      Command to run in guest"
	echo
	echo "Examples:"
	echo "  $SCRIPT -v initramfs.gz quark-test -vvv"
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

if [ $# -lt 2 ]; then
	usage
fi

INITRAMFS="$1"
shift

[[ -f $INITRAMFS ]] || die "Initramfs not found: $INITRAMFS"
[[ -f ./krun.sh ]] || die "Required launcher ./krun.sh is missing"

URL="https://mirror.rackspace.com/archlinux/core/os/x86_64"

log "Searching for Arch Linux kernel..."

TMPDIR=$(mktemp -d "/tmp/$SCRIPT.XXXXXXXXXX")
readonly TMPDIR
cleanup()	{ [[ -d "$TMPDIR" ]] && rm -rf "$TMPDIR"; }
trap cleanup EXIT

log "Fetching package list from $URL"
PKGURL=$(lynx -dump -listonly "$URL" | grep "/linux-[0-9].*\.pkg\.tar" | grep -v "\.sig") || die "Can't fetch package list"
PKGURL=${PKGURL##* }
PKG=$(basename "$PKGURL")

log "URL: $URL"
log "PKGURL: $PKGURL"
log "Downloading kernel package: $PKG"

cd "$TMPDIR"
curl -s "$PKGURL" -o "$PKG"
zstd -dc "$PKG" | tar -x
cd -

VMLINUZ=$(find "$TMPDIR" -name "vmlinuz" | head -1)
[[ -f "$VMLINUZ" ]] || die "vmlinuz not found in package"

log "Target vmlinuz: $VMLINUZ"

log "Kernel ready: $VMLINUZ"
log "Handing off to ./krun.sh"

./krun.sh "$INITRAMFS" "$VMLINUZ" "$@"
