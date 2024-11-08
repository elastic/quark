#!/bin/bash

set -euo pipefail

function download {
	buildkite-agent artifact download "$1" "$2"
}

if [ -z "${BUILDKITE}" ]; then
	echo "This script doesn't appear to be running in buildkite" 1>&2
	echo "refusing to continue" 1>&2
	exit 1
fi

download initramfs.gz .
download quark-test .
chmod +x quark-test

echo updating packages...
sudo apt-get -qq update -y
echo installing packages...
sudo apt-get -qq install -y --no-install-recommends qemu-system-x86 > /dev/null

sudo ./quark-test
./krun.sh initramfs.gz kernel-images/linux-4.18.0-553.el8_10.x86_64 quark-test
exit $?
