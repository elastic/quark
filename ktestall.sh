#!/bin/sh

truncate -s 0 result

for k in /d/e/ebpf/kernel-images/debian/x86_64/* /d/kernel-images/*
do
	kname="$(basename "$k")"
	echo testing "$kname"
	if ./ktest.sh initramfs.gz "$k"; then
		printf "%s: ok\n" "$kname" >> result
	else
		printf "%s: fail\n" "$kname" >> result
	fi
done
