// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024 Elastic NV */

#include <err.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/mount.h>
#include <sys/stat.h>

int
main(int argc, char *argv[])
{
	if (argc < 2)
		err(1, "no binary to execute");

	argc--;
	argv++;

	if (mkdir("/proc", 0666) != 0)
		err(1, "mkdir /proc");
	if (mkdir("/sys", 0666) != 0)
		err(1, "mkdir /sys");

	if (mount("proc", "/proc", "proc", 0, NULL) == -1)
		err(1, "mount /proc");
	if (mount(NULL, "/sys", "sysfs", 0, NULL) == -1)
		err(1, "mount /sys");
	if (mount(NULL, "/sys/kernel/tracing", "tracefs", 0, NULL) == -1)
		err(1, "mount /sys/kernel/tracing");

	return (execv(argv[0], argv));
}
