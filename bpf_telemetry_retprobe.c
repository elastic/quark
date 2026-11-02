// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2026 Elastic NV */

/*
 * Named kretprobes via tracefs.
 *
 * libbpf attaches return probes through perf_event_open, which gives no
 * control over the kretprobe instance pool. On non-preemptible kernels such
 * as RHEL 8's 4.18 the default is one instance per possible CPU, so on a
 * small guest a single in-flight call of the probed function exhausts the
 * pool and every nested or concurrent return is silently dropped. Writing an
 * "r<maxactive>:" command to kprobe_events is the only interface that sets
 * the pool size.
 *
 * This file only creates and removes the tracefs event; attaching a BPF
 * program to it is the caller's job, and the caller must close its perf fd
 * before detaching here or the kernel refuses the removal with EBUSY.
 * Group and event names carry the pid and a nonce because tracefs is global
 * and pids are not. Probes orphaned by an abnormal exit persist until reboot.
 * kprobe_events is always opened O_APPEND and never O_TRUNC, as truncation
 * removes every kprobe event on the system.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "quark.h"
#include "bpf_telemetry_retprobe.h"

/* Kernel KRETPROBE_MAXACTIVE_MAX; larger values fail with EINVAL. */
#define RETPROBE_MAXACTIVE_MAX 4096U

struct bpf_telemetry_retprobe {
	int tracefs_fd;
	bool created;
	char group[64];
	char event[64];
};

/* A command must be submitted in one write; never truncate kprobe_events. */
static int
tracefs_command(int tracefs_fd, const char *command)
{
	int fd, saved_errno;
	ssize_t n;
	size_t len = strlen(command);

	fd = openat(tracefs_fd, "kprobe_events", O_WRONLY | O_APPEND | O_CLOEXEC);
	if (fd == -1)
		return (-1);
	do {
		n = write(fd, command, len);
	} while (n == -1 && errno == EINTR);
	if (n >= 0 && (size_t)n != len)
		errno = EIO;
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return (n >= 0 && (size_t)n == len ? 0 : -1);
}

static int
tracefs_open(void)
{
	static const char *paths[] = {
		"/sys/kernel/tracing", "/sys/kernel/debug/tracing"
	};
	size_t i;
	int dirfd, fd, saved_errno = ENOENT;

	/*
	 * Unlike O_PATH, this open triggers the debugfs tracing automount and
	 * the held descriptor keeps it mounted.
	 * See https://github.com/elastic/quark/issues/179.
	 * open_tracing() in kprobe_queue.c duplicates this lookup, which keeps
	 * this file self-contained for its unit test; change both together.
	 */
	for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		dirfd = open(paths[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (dirfd == -1) {
			if (errno != ENOENT)
				saved_errno = errno;
			continue;
		}
		fd = openat(dirfd, "kprobe_events", O_WRONLY | O_APPEND | O_CLOEXEC);
		if (fd >= 0) {
			close(fd);
			return (dirfd);
		}
		if (errno != ENOENT)
			saved_errno = errno;
		close(dirfd);
	}
	errno = saved_errno;
	return (-1);
}

void
bpf_telemetry_retprobe_detach(struct bpf_telemetry_retprobe *probe)
{
	char command[160];
	int saved_errno = errno;

	if (probe == NULL)
		return;
	if (probe->created) {
		snprintf(command, sizeof(command), "-:%s/%s\n", probe->group,
		    probe->event);
		if (tracefs_command(probe->tracefs_fd, command) == -1)
			qwarn("remove BPF telemetry return probe %s/%s", probe->group,
			    probe->event);
	}
	if (probe->tracefs_fd != -1)
		close(probe->tracefs_fd);
	free(probe);
	errno = saved_errno;
}

static bool
symbol_char(char c, bool first)
{
	return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
	    (!first && ((c >= '0' && c <= '9') || c == '.')));
}

/*
 * Names need only be unique, and pid alone is not across PID namespaces.
 * getrandom would fail until the CRNG is ready, possibly minutes after boot.
 */
static uint64_t
retprobe_nonce(void)
{
	static uint64_t counter;
	struct timespec ts;
	uint64_t now = 0;

	if (clock_gettime(CLOCK_BOOTTIME, &ts) == 0)
		now = TS_TO_NS(ts);
	return (now + __atomic_add_fetch(&counter, 1, __ATOMIC_RELAXED));
}

int
bpf_telemetry_retprobe_create(struct bpf_telemetry_retprobe **result,
    const char *function, unsigned int maxactive)
{
	struct bpf_telemetry_retprobe *probe;
	char command[512];
	uint64_t nonce;
	const char *p;
	int saved_errno;

	if (result == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*result = NULL;
	if (function == NULL || *function == '\0' ||
	    strlen(function) > 255 || maxactive == 0 ||
	    maxactive > RETPROBE_MAXACTIVE_MAX) {
		errno = EINVAL;
		return (-1);
	}
	/*
	 * Function names enter a tracefs command: accept ASCII symbols with
	 * clone suffixes. The kernel parses a leading digit as an address.
	 */
	for (p = function; *p != '\0'; p++) {
		if (!symbol_char(*p, p == function)) {
			errno = EINVAL;
			return (-1);
		}
	}
	if ((probe = calloc(1, sizeof(*probe))) == NULL)
		return (-1);
	probe->tracefs_fd = -1;
	nonce = retprobe_nonce();
	snprintf(probe->group, sizeof(probe->group), "quark_bpf_%ld_%016llx",
	    (long)getpid(), (unsigned long long)nonce);
	snprintf(probe->event, sizeof(probe->event), "ret_%ld_%016llx",
	    (long)getpid(), (unsigned long long)nonce);
	if ((probe->tracefs_fd = tracefs_open()) == -1)
		goto fail;
	snprintf(command, sizeof(command), "r%u:%s/%s %s\n", maxactive,
	    probe->group, probe->event, function);
	if (tracefs_command(probe->tracefs_fd, command) == -1)
		goto fail;
	probe->created = true;
	*result = probe;
	return (0);

fail:
	saved_errno = errno;
	bpf_telemetry_retprobe_detach(probe);
	errno = saved_errno;
	return (-1);
}
