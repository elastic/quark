#!/bin/bash

Script=${0##*/}

function usage
{
	echo "usage: $Script initramfs_path kernel_path cmd_line" 1>&2
	exit 1
}

if [ $# -lt 3 ]; then
   usage
fi

initramfs="$1"
kernel="$2"
shift 2
cmdline="$*"

function qemu {
	case "$(file -b "$kernel" | awk '{print $3}')" in
	x86)
		qemu-system-x86_64						\
			-initrd "$initramfs"					\
			-kernel "$kernel"					\
			-nographic						\
			--append "console=ttyS0 quiet $cmdline"
		;;
	ARM64)
		qemu-system-aarch64						\
			-machine virt						\
			-cpu cortex-a57						\
			-initrd "$initramfs"					\
			-kernel "$kernel"					\
			-nographic						\
			--append "console=ttyAMA0 quiet $cmdline"
		;;
	*)
		echo unknown kernel image arch 1>&2; exit 1;;
	esac
}

exitcode=1
while read -r line
do
	echo "$line"
	if grep -q '^quark-test exited with ' <<< "$line"; then
		line="$(tr -d '\r' <<< "$line")"
		exitcode="$(awk '{print $4}' <<< "$line")"
	fi
done < <(qemu)

echo exited with "$exitcode"

exit $((exitcode))
