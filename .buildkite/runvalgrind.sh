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

sudo apt-get update
sudo apt-get install -y 				\
	clang						\
	cpio						\
	gcc						\
	linux-tools-6.11.0-26-generic			\
	make						\
	m4						\
	valgrind

make BPFTOOL="/usr/lib/linux-tools/6.11.0-26-generic/bpftool"

sudo valgrind				\
     --trace-children=no		\
     --child-silent-after-fork=yes	\
     ./quark-test -1			\
     2>&1 | grep -v "^--.*WARNING: unhandled eBPF command"
exit $?
