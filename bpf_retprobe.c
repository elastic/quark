// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2026 Elastic NV */

#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/libbpf_version.h>

#include "quark.h"
#include "bpf_retprobe.h"

/* Stable syscall ABI, also when compiling with older libc headers. */
#ifndef __NR_getrandom
#if defined(__x86_64__)
#define __NR_getrandom 318
#elif defined(__aarch64__)
#define __NR_getrandom 278
#endif
#endif

#define RETPROBE_MAXACTIVE_MAX 4096U

struct bpf_telemetry_retprobe {
	struct bpf_link *link;
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

static int
retprobe_id(const struct bpf_telemetry_retprobe *probe, uint64_t *id)
{
	char path[160], extra;
	unsigned long long value;
	FILE *fp;
	int fd, n, saved_errno, read_error;

	snprintf(path, sizeof(path), "events/%s/%s/id", probe->group, probe->event);
	fd = openat(probe->tracefs_fd, path, O_RDONLY | O_CLOEXEC);
	if (fd == -1)
		return (-1);
	if ((fp = fdopen(fd, "r")) == NULL) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return (-1);
	}
	n = fscanf(fp, "%llu %c", &value, &extra);
	read_error = ferror(fp);
	saved_errno = read_error ? EIO : EINVAL;
	fclose(fp);
	if (read_error || n != 1 || value > UINT_MAX) {
		errno = saved_errno;
		return (-1);
	}
	*id = (uint64_t)value;
	return (0);
}

void
bpf_telemetry_retprobe_detach(struct bpf_telemetry_retprobe *probe)
{
	char command[160];
	int saved_errno = errno;

	if (probe == NULL)
		return;
	if (bpf_link__destroy(probe->link) != 0)
		qwarn("detach BPF telemetry return probe %s/%s", probe->group,
		    probe->event);
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

int
bpf_telemetry_retprobe_create(struct bpf_telemetry_retprobe **result,
    const char *function, unsigned int maxactive)
{
	struct bpf_telemetry_retprobe *probe;
	char command[512];
	uint64_t nonce;
	const unsigned char *p;
	size_t done = 0;
	ssize_t n;
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
	/* Function names enter a tracefs command: reject command syntax. */
	for (p = (const unsigned char *)function; *p != '\0'; p++) {
		if (!isalnum(*p) && *p != '_' && *p != '.') {
			errno = EINVAL;
			return (-1);
		}
	}
	if ((probe = calloc(1, sizeof(*probe))) == NULL)
		return (-1);
	probe->tracefs_fd = -1;
	while (done < sizeof(nonce)) {
		n = syscall(__NR_getrandom, (char *)&nonce + done,
		    sizeof(nonce) - done, 1U /* GRND_NONBLOCK */);
		if (n == -1 && errno == EINTR)
			continue;
		if (n <= 0) {
			if (n == 0)
				errno = EIO;
			goto fail;
		}
		done += (size_t)n;
	}
	/* Randomness also distinguishes consumers in separate PID namespaces. */
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

int
bpf_telemetry_retprobe_missed(const struct bpf_telemetry_retprobe *probe,
    uint64_t *missed)
{
	char name[128], *line = NULL;
	unsigned long long hits, misses;
	size_t capacity = 0;
	FILE *fp;
	int fd, saved_errno = ENOENT, result = -1;

	if (probe == NULL || missed == NULL || !probe->created) {
		errno = EINVAL;
		return (-1);
	}
	fd = openat(probe->tracefs_fd, "kprobe_profile", O_RDONLY | O_CLOEXEC);
	if (fd == -1)
		return (-1);
	if ((fp = fdopen(fd, "r")) == NULL) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return (-1);
	}
	errno = 0;
	while (getline(&line, &capacity, fp) != -1) {
		if (sscanf(line, " %127s %llu %llu", name, &hits, &misses) != 3 ||
		    strcmp(name, probe->event) != 0)
			continue;
		*missed = (uint64_t)misses;
		result = 0;
		break;
	}
	if (ferror(fp))
		saved_errno = EIO;
	else if (result == -1 && errno != 0)
		saved_errno = errno;
	free(line);
	fclose(fp);
	if (result == -1)
		errno = saved_errno;
	return (result);
}

int
bpf_telemetry_retprobe_attach(struct bpf_telemetry_retprobe **result,
    struct bpf_program *program, const char *function, unsigned int maxactive)
{
	struct bpf_telemetry_retprobe *probe;
	struct perf_event_attr attr = {0};
	struct bpf_perf_event_opts opts = {
		.sz = sizeof(opts),
/* Older libbpf selects ioctl automatically when perf BPF links are absent. */
#if LIBBPF_MAJOR_VERSION > 1 || \
    (LIBBPF_MAJOR_VERSION == 1 && LIBBPF_MINOR_VERSION >= 2)
		.force_ioctl_attach = true
#endif
	};
	uint64_t id, missed;
	int pfd = -1, saved_errno;
	long error;

	if (result == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*result = NULL;
	if (program == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (bpf_telemetry_retprobe_create(&probe, function, maxactive) == -1)
		return (-1);
	if (retprobe_id(probe, &id) == -1 ||
	    bpf_telemetry_retprobe_missed(probe, &missed) == -1)
		goto fail;
	attr.size = sizeof(attr);
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.config = id;
	/*
	 * Like libbpf's legacy kprobe attachment, one system-wide perf fd is
	 * sufficient: the trace-kprobe BPF array runs before per-CPU sampling.
	 */
	pfd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
	if (pfd == -1)
		goto fail;
	probe->link = bpf_program__attach_perf_event_opts(program, pfd, &opts);
	error = libbpf_get_error(probe->link);
	if (probe->link == NULL || error != 0) {
		probe->link = NULL;
		if (error != 0)
			errno = (int)-error;
		else if (errno == 0)
			errno = EIO;
		goto fail;
	}
	/* The link now owns pfd. */
	*result = probe;
	return (0);

fail:
	saved_errno = errno;
	if (pfd != -1)
		close(pfd);
	bpf_telemetry_retprobe_detach(probe);
	errno = saved_errno;
	return (-1);
}
