#!/usr/bin/env bash
#
# krun-ubuntu.sh
# -----------------------------------------
# Download the newest *generic* Linux kernel for an Ubuntu release
# (amd64 | arm64), unpack vmlinuz, and hand it off to ./krun.sh.
#
# Usage:
#	./krun-ubuntu.sh [-a arch] [-v] <ubuntu_version> <initramfs> [command...]
#
# ---------------------------------------------------------------------

set -Eeuo pipefail

SCRIPT=${0##*/}
VERBOSE=0

# ---------- helpers --------------------------------------------------

log()		{ (( $VERBOSE )) && printf '%s\n' "INFO: $*" >&2 || true; }
log_error()	{ printf '%s\n' "ERROR:	$*" >&2; }
die()		{ log_error "$*"; exit 1; }

usage() {
	echo "usage: $SCRIPT [-v] initramfs.gz UBUNTUVERSION command..." 1>&2
	echo
	echo "  -v              Verbose output"
	echo "  initramfs.gz    Path to initramfs image"
	echo "  UBUNTUVERSION   Ubuntu version (e.g. 18.04, noble)"
	echo "  command...      Command to run in guest"
	echo
	echo "Examples:"
	echo "  $SCRIPT -v initramfs.gz 24.04 quark-test -vvv"
	exit 1
}

need_bins()	{ for b; do command -v "$b" >/dev/null || die "Missing $b"; done; }

# ---------- parse args -----------------------------------------------

ARCH=amd64			# Only amd64 for now
VERBOSE=0

while getopts "vh" opt; do
	case $opt in
		v) VERBOSE=1 ;;
		h) usage ;;
		*) usage ;;
	esac
done
shift $((OPTIND - 1))

[[ $# -lt 3 ]] && usage
[[ $ARCH =~ ^(amd64|arm64)$ ]] || die "Invalid architecture: $ARCH"

INITRAMFS="$1"; shift
UBUNTU_VERSION="$1"; shift

[[ -f $INITRAMFS ]] || die "Initramfs not found: $INITRAMFS"
[[ -f ./krun.sh ]] || die "Required launcher ./krun.sh is missing"

readonly UBUNTU_VERSION ARCH INITRAMFS

# ---------- prerequisites --------------------------------------------

need_bins curl awk ar tar gunzip sha256sum
command -v zstd >/dev/null && HAVE_ZSTD=1 || HAVE_ZSTD=0

CURL_OPTS=(--fail --silent --show-error --location --proto '=https' --tlsv1.2)

# ---------- version → codename ---------------------------------------

case "$UBUNTU_VERSION" in
	18.04) CODENAME=bionic ;;
	20.04) CODENAME=focal ;;
	22.04) CODENAME=jammy ;;
	24.04) CODENAME=noble ;;
	25.04) CODENAME=plucky ;;
	*) die "Unsupported Ubuntu version: $UBUNTU_VERSION" ;;
esac

if [[ $ARCH == amd64 ]]; then
	BASE_URL="https://archive.ubuntu.com/ubuntu"
else
	BASE_URL="https://ports.ubuntu.com/ubuntu-ports"
fi

# ---------- main -----------------------------------------------------

REPOS=("${CODENAME}-updates" "${CODENAME}-security" "${CODENAME}")

TMPDIR=$(mktemp -d "/tmp/$SCRIPT.XXXXXXXXXX")
readonly TMPDIR
cleanup()	{ [[ -d "$TMPDIR" ]] && rm -rf "$TMPDIR"; }
trap cleanup EXIT

log "Searching latest *generic* kernel for Ubuntu $UBUNTU_VERSION ($ARCH)…"

LATEST_PATH=""

for repo in "${REPOS[@]}"; do
	# Full path for the download …
	PKG_PATH="dists/$repo/main/binary-$ARCH/Packages.gz"
	# … and relative path as it appears inside the Release file
	PKG_PATH_REL="main/binary-$ARCH/Packages.gz"
	REL_URL="$BASE_URL/dists/$repo/Release"
	log "Checking $REL_URL"

	EXPECTED_HASH=""
	if curl "${CURL_OPTS[@]}" "$REL_URL" -o "$TMPDIR/Release"; then
		EXPECTED_HASH=$(awk -v pk="$PKG_PATH_REL" '
			$1=="SHA256:" {tbl=1;next}
			tbl && $NF==pk {print $1;exit}' "$TMPDIR/Release") || true
	fi

	curl "${CURL_OPTS[@]}" "$BASE_URL/$PKG_PATH" -o "$TMPDIR/Packages.gz" ||
		{ log "No Packages.gz for $repo (arch not built?)"; continue; }

	if [[ -n $EXPECTED_HASH ]]; then
		[[ $(sha256sum "$TMPDIR/Packages.gz" | awk '{print $1}') == "$EXPECTED_HASH" ]] ||
			die "Checksum mismatch for Packages.gz (possible MITM)"
	else
		log "Release digest unavailable; skipping checksum validation (less secure)"
	fi

	if ! gunzip -c "$TMPDIR/Packages.gz" >"$TMPDIR/Packages" 2>/dev/null; then
		die "gunzip failed – archive not gzip? (unexpected for Ubuntu mirrors)"
	fi

	awk -v RS='' '
	    /(^|\n)Package: linux-image-[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-generic($|\n)/ {
	      ver=""; file=""
	      for (i=1;i<=NF;i++){
		if ($i=="Version:")  ver=$(i+1)
		if ($i=="Filename:") file=$(i+1)
	      }
	      if (ver && file) print ver, file
	    }' "$TMPDIR/Packages" > "$TMPDIR/candidates"

	if [[ -s $TMPDIR/candidates ]]; then
		LATEST_PATH=$(sort -V -k1,1 "$TMPDIR/candidates" | tail -1 | awk '{print $2}')
		log "Found candidate in $repo: ${LATEST_PATH##*/}"
		break
	fi
done

[[ -n $LATEST_PATH ]] || die "No linux-image-generic package found for $UBUNTU_VERSION/$ARCH"

DEB_URL="$BASE_URL/$LATEST_PATH"
DEB_FILE="$TMPDIR/${DEB_URL##*/}"

log "Downloading: $DEB_URL"
curl "${CURL_OPTS[@]}" "$DEB_URL" -o "$DEB_FILE"

log "Extracting .deb"
(
	cd "$TMPDIR"
	ar x "${DEB_FILE##*/}"
	if [[ -f data.tar.xz ]]; then tar -xf data.tar.xz
	elif [[ -f data.tar.zst ]]; then
		[[ $HAVE_ZSTD -eq 1 ]] || die "zstd archive but zstd binary missing"
		tar --use-compress-program=zstd -xf data.tar.zst
	elif [[ -f data.tar.gz ]]; then tar -xf data.tar.gz
	else die "Unknown data archive inside .deb"
	fi
)

KERNEL_VER=$(sed -nE 's/linux-image-([0-9]+\.[0-9]+\.[0-9]+-[0-9]+-generic)_.*/\1/p' \
		<<< "${DEB_FILE##*/}")
VMLINUZ="$TMPDIR/boot/vmlinuz-$KERNEL_VER"
[[ -f $VMLINUZ ]] || die "vmlinuz not found: $VMLINUZ"

if file -b "$VMLINUZ" | grep -qi '^gzip compressed'; then
	log "Kernel is gzip-compressed; decompressing…"
	DECOMPRESSED="$TMPDIR/Image-$KERNEL_VER"
	gunzip -c "$VMLINUZ" > "$DECOMPRESSED" \
		|| die "Failed to gunzip kernel"
	VMLINUZ="$DECOMPRESSED"
fi

log "Kernel ready: $VMLINUZ"
log "Handing off to ./krun.sh"

./krun.sh "$INITRAMFS" "$VMLINUZ" "$@"
