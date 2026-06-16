#!/bin/bash

set -euo pipefail

if [ -z "${BUILDKITE}" ]; then
	echo "This script doesn't appear to be running in buildkite" 1>&2
	echo "refusing to continue" 1>&2
	exit 1
fi

sudo apt-get update
sudo apt-get install -y 				\
	bison						\
	clang						\
	cpio						\
	gcc						\
	golang						\
	linux-tools-7.0.0-14-generic			\
	make						\
	m4						\
	valgrind

make test-go BPFTOOL="/usr/lib/linux-tools/7.0.0-14-generic/bpftool"
exit $?
