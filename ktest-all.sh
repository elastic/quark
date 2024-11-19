#!/bin/bash

Script=${0##*/}

set -euo pipefail

kprobe_only=(linux-3.10.0-123.el7.x86_64)
result=""
declare -i failures=0

function maybe_kflag
{
	for k in "${kprobe_only[@]}"; do
		if [ "$1" = "$k" ]; then
			echo "-k"
			return 0
		fi
	done

	return 1
}

mkdir -p kernel-images/{amd64,arm64}

while IFS= read -r -d '' k
do
	kname="$(basename "$k")"
	echo testing "$kname"
	if ./krun.sh initramfs.gz "$k" quark-test "$(maybe_kflag "$kname")"; then
		r="$(printf "%s: ok" "$kname")"
	else
		r="$(printf "%s: fail" "$kname")"
		failures=$((failures+1))
	fi
	result="${result}${r}\n"
done < <(find kernel-images/{amd64,arm64} -type f -print0)

echo -ne "$result"
echo failures $failures

exit $failures
