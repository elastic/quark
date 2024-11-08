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
bin="$1"
cmdline="$*"

function qemu {
	case "$(file -b "$kernel" | awk '{print $3}')" in
	x86)
		qemu-system-x86_64						\
			-m 256M							\
			-enable-kvm						\
			-initrd "$initramfs"					\
			-kernel "$kernel"					\
			-nographic						\
			--append "console=ttyS0 quiet TERM=dumb $cmdline"
		;;
	ARM64)
		qemu-system-aarch64						\
			-m 256M							\
			-machine virt						\
			-cpu cortex-a57						\
			-initrd "$initramfs"					\
			-kernel "$kernel"					\
			-nographic						\
			--append "console=ttyAMA0 quiet TERM=dumb $cmdline"
		;;
	*)
		echo unknown kernel image arch 1>&2; exit 1;;
	esac
}

exitcode=1
while read -r line
do
	line="$(tr -d '\r' <<< "$line")"
	echo "$line"
	if grep -q "^$bin exited with " <<< "$line"; then
		exitcode="$(awk '{print $4}' <<< "$line")"
	fi
done < <(qemu)

echo exited with "$exitcode"

exit $((exitcode))
