// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024 Elastic NV */

#include <err.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <linux/reboot.h>

#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>

static void
powerdown(void)
{
	for (;;) {
		/*
		 * Powering off is a very tricky thing, make sure we never
		 * return or busy loop. Mostly out of scare of AWS bills.
		 */
		reboot(RB_POWER_OFF);
		sleep(1);
	}
}

static void
display_banner(char *argv[])
{
	struct utsname	  uts;
	char		**pp;

	if (uname(&uts) == -1)
		warn("uname");
	else {
		putchar('`');
		for (pp = argv; *pp != 0; pp++) {
			if (pp != argv)
				putchar(' ');
			printf("%s", *pp);
		}
		putchar('`');
		printf(" on %s %s\n", uts.release, uts.machine);
	}
}

int
main(int argc, char *argv[])
{
	pid_t	pid;
	int	status;

	/*
	 * Cut the kernel some slack until it is in a good shape, I see TSC
	 * recalibration messages after init is forked.
	 */
	sleep(3);

	if (argc < 2) {
		warnx("no binary to execute");
		powerdown();
	}

	argc--;
	argv++;

	pid = fork();
	if (pid == -1) {
		warn("fork");
		powerdown();
	}

	/* child */
	if (pid == 0) {
		if (mkdir("/proc", 0666) != 0)
			err(1, "mkdir /proc");
		if (mkdir("/sys", 0666) != 0)
			err(1, "mkdir /sys");

		if (mount("proc", "/proc", "proc", 0, NULL) == -1)
			err(1, "mount /proc");
		if (mount(NULL, "/sys", "sysfs", 0, NULL) == -1)
			err(1, "mount /sys");
		if (mount(NULL, "/sys/kernel/tracing", "tracefs",
		    0, NULL) == -1) {
			warn("mount /sys/kernel/tracing");
			warnx("trying debugfs...");
			if (mount(NULL, "/sys/kernel/debug", "debugfs",
			    0, NULL) == -1) {
				warn("mount /sys/kernel/debug");
				errx(1, "couldn't mount tracefs or debugfs");
			}
		}

		display_banner(argv);

		return (execv(argv[0], argv));
	}

	/* parent */
	if (waitpid(pid, &status, 0) == -1) {
		warn("waitpid");
		powerdown();
	}

	if (WIFEXITED(status))
		printf("%s exited with %d\n", argv[0], WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		printf("%s exited with signal %d (%s)\n", argv[0],
		    WTERMSIG(status), strsignal(WTERMSIG(status)));
	else if (WCOREDUMP(status))
		printf("%s core dumped\n", argv[0]);
	else
		printf("%s didn't exit cleanly\n", argv[0]);

	powerdown();

	return (0);		/* NOTREACHED */
}
