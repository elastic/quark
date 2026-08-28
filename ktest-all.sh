#!/bin/bash

set -euo pipefail

# RHEL 7.4 (3.10.0-693) is the oldest supported kprobe kernel: it
# backported perf clockid, which the KPROBE backend requires.
# For KPROBE backend, test the floor (693) and the last el7 kernel (1160).
# There's no BTF on el7, build initramfs.gz with WITH_BTFHUB=y.
kprobe_only=(linux-3.10.0-693.el7.x86_64 linux-3.10.0-1160.el7.x86_64)

# Kernels without perf clockid (< 4.1, RHEL < 7.4), where the only
# test expected to pass is t_kprobe_clockid: it checks that the KPROBE
# backend refuses to open and fails with EINVAL.
clockid_negative=(linux-3.10.0-123.el7.x86_64)

result=""
error_run=""
declare -i failures=0
all_kernels="$(find kernel-images/{amd64,arm64} -type f)"

function member
{
	local elt=$1
	shift

	for k in "$@"; do
		if [ "$elt" = "$k" ]; then
			return 0
		fi
	done

	return 1
}

for k in $all_kernels
do
	kname="$(basename "$k")"
	cmdline="./krun.sh initramfs.gz $k quark-test"
	if member "$kname" "${clockid_negative[@]}"; then
		cmdline+=" -k t_kprobe_clockid"
	elif member "$kname" "${kprobe_only[@]}"; then
		cmdline+=" -k"
	fi
	if eval "$cmdline"; then
		r="$(printf "%s: ok" "$kname")"
	else
		r="$(printf "%s: fail" "$kname")"
		error_run+="${cmdline}"$'\n'
		failures=$((failures+1))
	fi
	result+="${r}"$'\n'
done

echo -n "$result"
echo failures $failures
if test -n "$error_run"; then
	echo to reproduce failed cases, run:
	echo -n "$error_run"
fi

exit $failures
