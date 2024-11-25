#!/bin/bash

set -euo pipefail

kprobe_only=(linux-3.10.0-123.el7.x86_64)
result=""
error_run=""
declare -i failures=0
all_kernels="$(find kernel-images/{amd64,arm64} -type f)"

function maybe_kflag
{
	for k in "${kprobe_only[@]}"; do
		if [ "$1" = "$k" ]; then
			return 0
		fi
	done

	return 1
}

for k in $all_kernels
do
	kname="$(basename "$k")"
	cmdline="./krun.sh initramfs.gz $k quark-test"
	if maybe_kflag "$kname"; then
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
