// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2026 Elastic NV */

/* Record tracefs commands; use ordinary fds without touching kernel probes. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "quark.h"
#include "quark-test.h"

static int test_open(const char *, int, ...);
static int test_openat(int, const char *, int, ...);
static ssize_t test_write(int, const void *, size_t);
static long test_syscall(long, ...);
static void test_log(int, int, const char *, int, const char *, ...);
#define open test_open
#define openat test_openat
#define write test_write
#define syscall test_syscall
#define qlog_func test_log
/* Keep this copy and all test calls separate from the real library symbols. */
#define bpf_telemetry_retprobe_create test_bpf_telemetry_retprobe_create
#define bpf_telemetry_retprobe_detach test_bpf_telemetry_retprobe_detach
#include "bpf_retprobe.c"
#undef open
#undef openat
#undef write
#undef syscall
#undef qlog_func

enum failure_mode { OK, RANDOM_FAIL, OPEN_FAIL, CREATE_FAIL, SHORT_WRITE, DELETE_FAIL };
static enum failure_mode failure;
static char commands[32][512];
static unsigned int command_count, warning_count;
static uint64_t nonce;
static int last_directory = -1, last_command = -1;

static int
test_open(const char *path, int flags, ...)
{
	assert(strstr(path, "/sys/kernel/") == path && (flags & O_DIRECTORY));
	if (failure == OPEN_FAIL)
		return (errno = EACCES, -1);
	return (last_directory = open("/dev/null", O_RDONLY | O_CLOEXEC));
}

static int
test_openat(int directory, const char *path, int flags, ...)
{
	assert(directory >= 0 && strcmp(path, "kprobe_events") == 0);
	assert((flags & O_APPEND) && !(flags & O_TRUNC));
	return (last_command = open("/dev/null", O_WRONLY | O_CLOEXEC));
}

static ssize_t
test_write(int fd, const void *buffer, size_t length)
{
	const char *command = buffer;

	assert(fd == last_command && length < sizeof(commands[0]));
	assert(command_count < nitems(commands));
	memcpy(commands[command_count], buffer, length);
	commands[command_count++][length] = '\0';
	if ((failure == CREATE_FAIL && command[0] == 'r') ||
	    (failure == DELETE_FAIL && command[0] == '-'))
		return (errno = EINVAL, -1);
	if (failure == SHORT_WRITE)
		return ((ssize_t)length - 1);
	return ((ssize_t)length);
}

static long
test_syscall(long number, ...)
{
	va_list args;
	void *buffer;

	assert(number == __NR_getrandom);
	va_start(args, number);
	buffer = va_arg(args, void *);
	assert(va_arg(args, size_t) == sizeof(nonce));
	assert(va_arg(args, int) == 1); /* GRND_NONBLOCK */
	va_end(args);
	if (failure == RANDOM_FAIL)
		return (errno = EAGAIN, -1);
	nonce++;
	memcpy(buffer, &nonce, sizeof(nonce));
	return (sizeof(nonce));
}

static void
test_log(int priority, int do_errno, const char *function, int line,
    const char *format, ...)
{
	(void)priority; (void)do_errno; (void)function; (void)line; (void)format;
	warning_count++;
}

int
t_bpf_retprobe(const struct test *t, struct quark_queue_attr *qa)
{
	struct bpf_telemetry_retprobe *first = NULL, *second = NULL;
	char group[64], event[64], expected[160], symbol[256];
	unsigned int maxactive, before;
	int first_fd;
	enum failure_mode mode;
	const char *invalid[] = { "", "__sys_bpf\nr:x/y z", "bad/name", "bad name" };

	/* The runner can call the test again without forking. */
	failure = OK;
	command_count = warning_count = 0;
	nonce = 0;
	last_directory = last_command = -1;

	for (size_t i = 0; i < nitems(invalid); i++)
		assert(bpf_telemetry_retprobe_create(&first, invalid[i], 4096) == -1 &&
		    errno == EINVAL && first == NULL);
	assert(bpf_telemetry_retprobe_create(&first, "__sys_bpf", 0) == -1 && errno == EINVAL);
	assert(bpf_telemetry_retprobe_create(&first, "__sys_bpf", 4097) == -1 && errno == EINVAL);
	assert(command_count == 0);
	assert(bpf_telemetry_retprobe_create(&first, "__sys_bpf", 4096) == 0);
	assert(bpf_telemetry_retprobe_create(&second, "__sys_bpf", 4096) == 0);
	assert(strcmp(commands[0], commands[1]) != 0);
	assert(sscanf(commands[0], "r%u:%63[^/]/%63s %255s", &maxactive, group,
	    event, symbol) == 4 && maxactive == 4096 && !strcmp(symbol, "__sys_bpf"));
	snprintf(expected, sizeof(expected), "-:%s/%s\n", group, event);
	first_fd = first->tracefs_fd;
	errno = EDOM;
	bpf_telemetry_retprobe_detach(first);
	assert(errno == EDOM && !strcmp(commands[2], expected));
	assert(fcntl(first_fd, F_GETFD) == -1 && errno == EBADF);
	assert(fcntl(second->tracefs_fd, F_GETFD) != -1);
	snprintf(expected, sizeof(expected), "-:%s/%s\n", second->group, second->event);
	bpf_telemetry_retprobe_detach(second);
	assert(!strcmp(commands[3], expected) && warning_count == 0);
	for (mode = RANDOM_FAIL; mode <= SHORT_WRITE; mode++) {
		before = command_count;
		failure = mode;
		assert(bpf_telemetry_retprobe_create(&first, "__sys_bpf", 4096) == -1 && first == NULL);
		assert(errno == (mode == RANDOM_FAIL ? EAGAIN : mode == OPEN_FAIL ? EACCES :
		    mode == SHORT_WRITE ? EIO : EINVAL));
		assert(command_count == before + (mode >= CREATE_FAIL ? 1U : 0U));
		assert(fcntl(last_directory, F_GETFD) == -1 && errno == EBADF);
	}
	failure = OK;
	assert(bpf_telemetry_retprobe_create(&first, "__sys_bpf", 4096) == 0);
	failure = DELETE_FAIL;
	errno = EDOM;
	bpf_telemetry_retprobe_detach(first);
	assert(errno == EDOM && warning_count == 1);
	assert(fcntl(last_directory, F_GETFD) == -1 && errno == EBADF);
	assert(fcntl(last_command, F_GETFD) == -1 && errno == EBADF);
	return (0);
}
