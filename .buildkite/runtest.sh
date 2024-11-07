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

sudo ./quark-test
ls /usr/bin
sudo apt-get update -y
sudo apt install -y --no-install-recommends qemu-user-static
ls /usr/bin
./krun.sh initramfs.gz kernel-images/linux-4.18.0-553.el8_10.x86_64 quark-test
exit $?
