#!/bin/bash

set -euo pipefail

FEDORAVER="$1"

function download {
	buildkite-agent artifact download "$1" "$2"
}

if [ -z "${BUILDKITE}" ]; then
	echo "This script doesn't appear to be running in buildkite" 1>&2
	echo "refusing to continue" 1>&2
	exit 1
fi

download initramfs.gz .

echo updating packages...
sudo apt-get -qq update -y
echo installing packages...
sudo apt-get -qq install -y --no-install-recommends	\
     cpio						\
     cpu-checker					\
     lynx 						\
     qemu-system-x86					\
     qemu-kvm						\
     rpm2cpio						\
     > /dev/null

# Make sure we can run things on KVM
sudo kvm-ok

# Run Forrest Run
sudo ./krun-fedora.sh initramfs.gz $FEDORAVER quark-test

exit $?
