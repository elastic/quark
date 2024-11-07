#!/bin/bash

Script=${0##*/}

function usage
{
	echo "usage: $Script initramfs_path kernel_path" 1>&2
	exit 1
}

if [ $# -ne 2 ]; then
   usage
fi

initramfs="$1"
kernel="$2"

function qemu {
	case "$(file -b "$kernel" | awk '{print $3}')" in
	x86)
		qemu-system-x86_64						\
			-enable-kvm						\
			-initrd "$initramfs"					\
			-kernel "$kernel"					\
			-nographic						\
			--append "console=ttyS0 TERM=dumb quark-test"
		;;
	ARM64)
		qemu-system-aarch64						\
			-machine virt						\
			-cpu cortex-a57						\
			-initrd "$initramfs"					\
			-kernel "$kernel"					\
			-nographic						\
			--append "console=ttyAMA0 quiet TERM=dumb quark-test"
		;;
	*)
		echo unknown kernel image arch 1>&2; exit 1;;
	esac
}

while read -r line
do
	echo "$line"
	if grep -q '^quark-test exited with ' <<< "$line"; then
		line="$(tr -d '\r' <<< "$line")"
		exitcode="$(awk '{print $4}' <<< "$line")"
	fi
done < <(qemu)

#echo -n "$exitcode" | hexyl
echo exited with "$exitcode"

exit $((exitcode))
