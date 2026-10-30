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
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include "quark.h"
#include "quark-test.h"

static int test_open(const char *, int, ...);
static int test_openat(int, const char *, int, ...);
static ssize_t test_write(int, const void *, size_t);
static long test_syscall(long, ...);
static void test_log(int, int, const char *, int, const char *, ...);
static struct bpf_link *test_attach(const struct bpf_program *, int,
    const struct bpf_perf_event_opts *);
static long test_libbpf_error(const void *);
static int test_destroy(struct bpf_link *);
#define open test_open
#define openat test_openat
#define write test_write
#define syscall test_syscall
#define qlog_func test_log
#define bpf_program__attach_perf_event_opts test_attach
#define libbpf_get_error test_libbpf_error
#define bpf_link__destroy test_destroy
/* Keep this copy and all test calls separate from the real library symbols. */
#define bpf_telemetry_retprobe_create test_bpf_telemetry_retprobe_create
#define bpf_telemetry_retprobe_detach test_bpf_telemetry_retprobe_detach
#define bpf_telemetry_retprobe_attach test_bpf_telemetry_retprobe_attach
#define bpf_telemetry_retprobe_missed test_bpf_telemetry_retprobe_missed
#include "bpf_telemetry_retprobe.c"
#undef open
#undef openat
#undef write
#undef syscall
#undef qlog_func
#undef bpf_program__attach_perf_event_opts
#undef libbpf_get_error
#undef bpf_link__destroy

enum failure_mode {
	OK, OPEN_FAIL, CREATE_FAIL, SHORT_WRITE, DELETE_FAIL,
	ID_FAIL, PROFILE_FAIL, PERF_FAIL, ATTACH_FAIL, PROFILE_MISSING,
	SWEEP_CREATE, SWEEP_OPEN, SWEEP_ALL
};
static enum failure_mode failure;
static char commands[64][512];
static unsigned int command_count, warning_count;
static char fake_program;
static int last_directory = -1, last_command = -1;
static int last_perf = -1, last_auxiliary = -1;
static struct test_link { int fd; bool alive; } links[8];
static unsigned int link_count;
static const char *special_event;
/* Another consumer's sweep: removed events, a listing and an event in use. */
static char swept[8][64];
static unsigned int swept_count;
static const char *listing = "";
static const char *busy_event;
static int swept_perf = -1;

static void
sweep_last_create(void)
{
	char group[64];
	unsigned int i = command_count;

	while (i > 0 && commands[i - 1][0] != 'r')
		i--;
	assert(i > 0 && swept_count < nitems(swept));
	assert(sscanf(commands[i - 1], "r%*u:%63[^/]/%63s", group,
	    swept[swept_count]) == 2);
	swept_count++;
}

static bool
was_swept(const char *text)
{
	unsigned int i;

	for (i = 0; i < swept_count; i++)
		if (strstr(text, swept[i]) != NULL)
			return (true);
	return (false);
}

static int
text_fd(const char *value)
{
	FILE *fp = tmpfile();
	int fd;

	assert(fp != NULL && fputs(value, fp) >= 0 && fflush(fp) == 0);
	rewind(fp);
	assert((fd = dup(fileno(fp))) != -1 && fclose(fp) == 0);
	return (last_auxiliary = fd);
}

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
	char profile[8192] = "unrelated 9 999\n", group[64], event[64];
	size_t used = strlen(profile);
	unsigned int i;

	assert(directory >= 0);
	if (strncmp(path, "events/", 7) == 0 && was_swept(path))
		return (errno = ENOENT, -1);
	if (strncmp(path, "events/", 7) == 0)
		return (failure == ID_FAIL ? (errno = EACCES, -1) : text_fd("123\n"));
	if (strcmp(path, "kprobe_profile") == 0) {
		if (failure == PROFILE_FAIL)
			return (errno = EACCES, -1);
		for (i = 0; i < command_count && failure != PROFILE_MISSING; i++) {
			if (sscanf(commands[i], "r%*u:%63[^/]/%63s", group, event) != 2)
				continue;
			used += (size_t)snprintf(profile + used, sizeof(profile) - used,
			    "%s 5 %u\n", event, special_event && !strcmp(event, special_event) ? 11 : 7);
			assert(used < sizeof(profile));
		}
		return (text_fd(profile));
	}
	assert(strcmp(path, "kprobe_events") == 0);
	if ((flags & O_ACCMODE) == O_RDONLY)
		return (text_fd(listing));
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
	if (command[0] == '-' && was_swept(command))
		return (errno = ENOENT, -1);
	if (command[0] == '-' && busy_event != NULL && strstr(command, busy_event))
		return (errno = EBUSY, -1);
	if (command[0] == 'r' && (failure == SWEEP_ALL ||
	    (failure == SWEEP_CREATE && swept_count == 0)))
		sweep_last_create();
	return ((ssize_t)length);
}

static long
test_syscall(long number, ...)
{
	va_list args;
	struct perf_event_attr *attr;

	assert(number == __NR_perf_event_open);
	va_start(args, number);
	attr = va_arg(args, struct perf_event_attr *);
	assert(attr->type == PERF_TYPE_TRACEPOINT && attr->config == 123);
	assert(va_arg(args, int) == -1 && va_arg(args, int) == 0);
	assert(va_arg(args, int) == -1 && va_arg(args, int) == PERF_FLAG_FD_CLOEXEC);
	va_end(args);
	if (failure == PERF_FAIL)
		return (errno = EPERM, -1);
	last_perf = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (failure == SWEEP_OPEN && swept_count == 0) {
		/* The id was reused; a high fd lets the test check closure. */
		assert((swept_perf = fcntl(last_perf, F_DUPFD_CLOEXEC, 512)) != -1);
		close(last_perf);
		last_perf = swept_perf;
		sweep_last_create();
	}
	return (last_perf);
}

static struct bpf_link *
test_attach(const struct bpf_program *program, int fd,
    const struct bpf_perf_event_opts *opts)
{
	assert(program != NULL && fd >= 0 && opts->sz == sizeof(*opts));
#if LIBBPF_MAJOR_VERSION > 1 || \
    (LIBBPF_MAJOR_VERSION == 1 && LIBBPF_MINOR_VERSION >= 2)
	assert(opts->force_ioctl_attach);
#endif
	if (failure == ATTACH_FAIL)
		return (errno = EBUSY, NULL);
	assert(link_count < nitems(links));
	links[link_count] = (struct test_link) { fd, true };
	return ((struct bpf_link *)&links[link_count++]);
}

static long
test_libbpf_error(const void *link)
{
	return (link != NULL ? 0 : -errno);
}

static int
test_destroy(struct bpf_link *link)
{
	struct test_link *owned = (struct test_link *)link;

	if (owned != NULL) {
		assert(owned->alive && close(owned->fd) == 0);
		owned->alive = false;
	}
	return (0);
}

static void
test_log(int priority, int do_errno, const char *function, int line,
    const char *format, ...)
{
	(void)priority; (void)do_errno; (void)function; (void)line; (void)format;
	warning_count++;
}

static void
test_resources(void)
{
	struct bpf_telemetry_retprobe *first = NULL, *second = NULL;
	char group[64], event[64], expected[160], symbol[256];
	unsigned int maxactive, before;
	int first_fd;
	enum failure_mode mode;
	const char *invalid[] = { "", "__sys_bpf\nr:x/y z", "bad/name", "bad name",
	    "123", "0xffffffff81000000", ".isra.0", "caf\xc3\xa9" };

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
	for (mode = OPEN_FAIL; mode <= SHORT_WRITE; mode++) {
		before = command_count;
		failure = mode;
		assert(bpf_telemetry_retprobe_create(&first, "__sys_bpf", 4096) == -1 && first == NULL);
		assert(errno == (mode == OPEN_FAIL ? EACCES :
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
	failure = OK;
}

static void
test_attachments(void)
{
	struct bpf_telemetry_retprobe *first = NULL, *second = NULL;
	struct bpf_program *program = (struct bpf_program *)&fake_program;
	uint64_t missed;
	unsigned int before;
	int first_perf, expected_errors[] = { EACCES, EACCES, EPERM, EBUSY, ENOENT };
	enum failure_mode mode;

	assert(bpf_telemetry_retprobe_attach(&first, NULL, "__sys_bpf", 4096) == -1 &&
	    errno == EINVAL && first == NULL);
	assert(bpf_telemetry_retprobe_attach(&first, program, "__sys_bpf", 4096) == 0);
	first_perf = last_perf;
	assert(bpf_telemetry_retprobe_attach(&second, program, "__sys_bpf", 4096) == 0);
	special_event = second->event;
	assert(bpf_telemetry_retprobe_missed(first, &missed) == 0 && missed == 7);
	assert(bpf_telemetry_retprobe_missed(second, &missed) == 0 && missed == 11);
	assert(fcntl(last_auxiliary, F_GETFD) == -1 && errno == EBADF);
	bpf_telemetry_retprobe_detach(first);
	assert(fcntl(first_perf, F_GETFD) == -1 && errno == EBADF);
	assert(fcntl(last_perf, F_GETFD) != -1);
	assert(bpf_telemetry_retprobe_missed(second, &missed) == 0 && missed == 11);
	bpf_telemetry_retprobe_detach(second);
	assert(fcntl(last_perf, F_GETFD) == -1 && errno == EBADF);
	special_event = NULL;
	for (mode = ID_FAIL; mode <= PROFILE_MISSING; mode++) {
		before = command_count;
		failure = mode;
		assert(bpf_telemetry_retprobe_attach(&first, program, "__sys_bpf", 4096) == -1 &&
		    first == NULL && errno == expected_errors[mode - ID_FAIL]);
		assert(command_count == before + 2 && commands[before][0] == 'r' &&
		    commands[before + 1][0] == '-');
		assert(fcntl(last_directory, F_GETFD) == -1 && errno == EBADF);
		assert(fcntl(last_command, F_GETFD) == -1 && errno == EBADF);
		if (mode == ATTACH_FAIL)
			assert(fcntl(last_perf, F_GETFD) == -1 && errno == EBADF);
	}
	assert(warning_count == 1); /* Only the deliberate resource-removal failure. */
}

static void
test_cleanup(void)
{
	struct bpf_telemetry_retprobe *probe = NULL;
	struct bpf_program *program = (struct bpf_program *)&fake_program;
	unsigned int before, warnings = warning_count;

	listing = "p:kprobes/other do_sys_open\n"
	    "r:quark_bpf_1_00000000000000aa/ret_1_00000000000000aa __sys_bpf\n"
	    "r4096:quark_bpf_2_00000000000000bb/ret_2_00000000000000bb __sys_bpf\n"
	    "r4096:quark_bpf_3_00000000000000cc/ret_3_00000000000000cc __sys_bpf\n"
	    "p:quark_bpf_4_00000000000000dd/entry __sys_bpf\n"
	    "r:other/ret_5 __sys_bpf\n";
	busy_event = "ret_3_00000000000000cc";
	before = command_count;
	assert(bpf_telemetry_retprobe_create(&probe, "__sys_bpf", 4096) == 0);
	assert(command_count == before + 4 && commands[before + 3][0] == 'r');
	assert(!strcmp(commands[before],
	    "-:quark_bpf_1_00000000000000aa/ret_1_00000000000000aa\n"));
	assert(!strcmp(commands[before + 1],
	    "-:quark_bpf_2_00000000000000bb/ret_2_00000000000000bb\n"));
	assert(!strcmp(commands[before + 2],
	    "-:quark_bpf_3_00000000000000cc/ret_3_00000000000000cc\n"));
	bpf_telemetry_retprobe_detach(probe);
	listing = "";
	busy_event = NULL;

	failure = SWEEP_CREATE;
	swept_count = 0;
	before = command_count;
	assert(bpf_telemetry_retprobe_attach(&probe, program, "__sys_bpf", 4096) == 0);
	assert(command_count == before + 3 && commands[before][0] == 'r' &&
	    strstr(commands[before + 1], swept[0]) != NULL &&
	    strstr(commands[before + 2], probe->event) != NULL);
	bpf_telemetry_retprobe_detach(probe);

	failure = SWEEP_OPEN;
	swept_count = 0;
	before = command_count;
	assert(bpf_telemetry_retprobe_attach(&probe, program, "__sys_bpf", 4096) == 0);
	assert(command_count == before + 3 && commands[before][0] == 'r' &&
	    strstr(commands[before + 1], swept[0]) != NULL &&
	    strstr(commands[before + 2], probe->event) != NULL);
	assert(fcntl(swept_perf, F_GETFD) == -1 && errno == EBADF);
	bpf_telemetry_retprobe_detach(probe);

	failure = SWEEP_ALL;
	swept_count = 0;
	before = command_count;
	assert(bpf_telemetry_retprobe_attach(&probe, program, "__sys_bpf", 4096) == -1 &&
	    probe == NULL && errno == ENOENT);
	assert(command_count == before + 2 * RETPROBE_ATTEMPTS &&
	    swept_count == RETPROBE_ATTEMPTS);
	assert(warning_count == warnings);
	failure = OK;
	swept_count = 0;
}

int
t_bpf_telemetry_retprobe(const struct test *t, struct quark_queue_attr *qa)
{
	unsigned int i;

	(void)t;
	(void)qa;
	/* The runner can call the test again without forking. */
	failure = OK;
	command_count = warning_count = link_count = 0;
	last_directory = last_command = last_perf = last_auxiliary = -1;
	memset(links, 0, sizeof(links));
	special_event = NULL;
	swept_count = 0;
	listing = "";
	busy_event = NULL;
	swept_perf = -1;
	test_resources();
	test_attachments();
	test_cleanup();
	for (i = 0; i < link_count; i++)
		assert(!links[i].alive);
	return (0);
}
