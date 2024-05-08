#!/bin/sh

Script=$(basename $0)

function usage
{
	echo "usage: $Script elastic-ebpf-source-path"
	exit 1
}

if [ $# -ne 1 ]; then
	usage
fi

Src="$1"
Commit=$(cd "$Src" && git rev-parse HEAD)
if [ -z $Commit ]; then
	exit 1
fi

cd $(dirname $0)
for x in $(find . -type f); do
	if [ $x = "./$Script" -o $x = "./commit" ]; then
		continue
	fi
	dst=$(realpath "$x")
	src=$(realpath "$Src/$x")
	# set -x
	if ! cp "$src" "$dst"; then
		exit 1
	fi
done

echo $Commit > commit
