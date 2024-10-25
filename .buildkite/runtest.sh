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

download quark-test .
chmod +x quark-test

sudo ./quark-test
exit $?
