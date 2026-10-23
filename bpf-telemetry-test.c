// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2026 Elastic NV */

/* Pure userspace tests: all tracing, perf and attachment operations are mocked. */
#include <sys/syscall.h>

#include <linux/perf_event.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "quark.h"

static FILE *test_fopen(const char *, const char *);
static int test_open(const char *, int, ...);
static int test_openat(int, const char *, int, ...);
static ssize_t test_write(int, const void *, size_t);
static ssize_t test_getrandom(void *, size_t, unsigned int);
static long test_syscall(long, ...);
static struct bpf_link *test_attach(const struct bpf_program *, int,
    const struct bpf_perf_event_opts *);
static long test_libbpf_error(const void *);
static int test_destroy(struct bpf_link *);
static void test_log(int, int, const char *, int, const char *, ...);

/* Include the implementation so both architecture selectors can be tested. */
#define fopen test_fopen
#define open test_open
#define openat test_openat
#define write test_write
#define syscall test_syscall
#define bpf_program__attach_perf_event_opts test_attach
#define libbpf_get_error test_libbpf_error
#define bpf_link__destroy test_destroy
#define qlog_func test_log
#include "bpf_telemetry.c"
#undef fopen
#undef open
#undef openat
#undef write
#undef syscall
#undef bpf_program__attach_perf_event_opts
#undef libbpf_get_error
#undef bpf_link__destroy
#undef qlog_func

#define SYMBOL_SECURITY \
    "0000000000000000 T security_bpf\n" \
    "0000000000000000 T security_bpf_prog\n"
#define SYMBOL_MODERN SYMBOL_SECURITY \
    "0000000000000000 t __sys_bpf\n" \
    "0000000000000000 T bpf_sys_bpf\n"
#define SYMBOL_X86 SYMBOL_SECURITY \
    "0000000000000000 T __x64_sys_bpf\n"
#define SYMBOL_COMPAT "0000000000000000 T __ia32_sys_bpf\n"
#define SYMBOL_ARM64 SYMBOL_SECURITY \
    "0000000000000000 T __arm64_sys_bpf\n"

enum test_failure {
	TEST_NO_FAILURE,
	TEST_RANDOM_FAILURE,
	TEST_CREATE_FAILURE,
	TEST_PROFILE_FAILURE,
	TEST_PERF_FAILURE,
	TEST_ATTACH_FAILURE
};

struct test_event {
	char group[64];
	char event[64];
	bool alive;
	uint64_t missed;
};

struct test_link {
	int fd;
	bool alive;
};

static const char *symbol_fixture;
static enum test_failure failure;
static struct test_event events[32];
static struct test_link links[32];
static unsigned int event_count, deleted_count, link_count, warning_count;
static uint64_t nonce_sequence;
static int command_fd = -1, last_perf_fd = -1;
static unsigned int selector_cases, trampoline_cases, retprobe_cases;

static int
text_fd(const char *text_value)
{
	FILE *fp = tmpfile();
	int fd;

	assert(fp != NULL);
	assert(fputs(text_value, fp) >= 0);
	assert(fflush(fp) == 0);
	rewind(fp);
	assert((fd = dup(fileno(fp))) != -1);
	assert(fclose(fp) == 0);
	return (fd);
}

static FILE *
test_fopen(const char *path, const char *mode)
{
	FILE *fp;

	if (strcmp(path, "/proc/kallsyms") != 0)
		return (fopen(path, mode));
	assert(symbol_fixture != NULL);
	assert((fp = fdopen(text_fd(symbol_fixture), "r")) != NULL);
	return (fp);
}

static int
test_open(const char *path, int flags, ...)
{
	assert(strcmp(path, "/sys/kernel/tracing") == 0);
	assert((flags & O_DIRECTORY) != 0);
	return (open("/dev/null", O_RDONLY | O_CLOEXEC));
}

static int
test_openat(int directory, const char *path, int flags, ...)
{
	char expected[160], text_value[8192];
	size_t offset = 0;
	unsigned int i;
	int n;

	assert(directory >= 0);
	if (strcmp(path, "kprobe_events") == 0) {
		assert((flags & O_APPEND) != 0 && (flags & O_TRUNC) == 0);
		command_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
		return (command_fd);
	}
	if (strcmp(path, "kprobe_profile") == 0) {
		if (failure == TEST_PROFILE_FAILURE) {
			errno = EACCES;
			return (-1);
		}
		/* An unrelated event must never be mistaken for ours. */
		offset = (size_t)snprintf(text_value, sizeof(text_value), "other 9 999\n");
		for (i = 0; i < event_count; i++) {
			if (!events[i].alive)
				continue;
			n = snprintf(text_value + offset, sizeof(text_value) - offset,
			    "%s 5 %llu\n", events[i].event,
			    (unsigned long long)events[i].missed);
			assert(n > 0 && (size_t)n < sizeof(text_value) - offset);
			offset += (size_t)n;
		}
		return (text_fd(text_value));
	}
	for (i = 0; i < event_count; i++) {
		snprintf(expected, sizeof(expected), "events/%.63s/%.63s/id", events[i].group,
		    events[i].event);
		if (events[i].alive && strcmp(path, expected) == 0)
			return (text_fd("123\n"));
	}
	assert(!"unexpected tracefs path");
	errno = ENOENT;
	return (-1);
}

static ssize_t
test_write(int fd, const void *buffer, size_t length)
{
	char command[512], group[64], event[64], function[256];
	unsigned int maxactive, i;

	assert(fd == command_fd && length < sizeof(command));
	memcpy(command, buffer, length);
	command[length] = '\0';
	if (command[0] == 'r') {
		if (failure == TEST_CREATE_FAILURE) {
			errno = EINVAL;
			return (-1);
		}
		assert(sscanf(command, "r%u:%63[^/]/%63s %255s", &maxactive, group,
		    event, function) == 4);
		assert(maxactive == 4096 && strcmp(function, "__sys_bpf") == 0);
		assert(event_count < sizeof(events) / sizeof(events[0]));
		for (i = 0; i < event_count; i++) {
			assert(strcmp(events[i].group, group) != 0);
			assert(strcmp(events[i].event, event) != 0);
		}
		strcpy(events[event_count].group, group);
		strcpy(events[event_count].event, event);
		events[event_count].alive = true;
		events[event_count].missed = 7;
		event_count++;
	} else {
		assert(sscanf(command, "-:%63[^/]/%63s", group, event) == 2);
		for (i = 0; i < event_count; i++) {
			if (events[i].alive && strcmp(events[i].group, group) == 0 &&
			    strcmp(events[i].event, event) == 0)
				break;
		}
		assert(i < event_count); /* Only an owned event can be deleted. */
		events[i].alive = false;
		deleted_count++;
	}
	return ((ssize_t)length);
}

static ssize_t
test_getrandom(void *buffer, size_t length, unsigned int flags)
{
	uint64_t nonce = ++nonce_sequence;

	assert(flags == 1U && length == sizeof(nonce));
	if (failure == TEST_RANDOM_FAILURE) {
		errno = EIO;
		return (-1);
	}
	memcpy(buffer, &nonce, length);
	return ((ssize_t)length);
}

static long
test_syscall(long number, ...)
{
	struct perf_event_attr *attr;
	va_list args;
	void *buffer;
	size_t length;
	unsigned int flags;
	ssize_t result;

	va_start(args, number);
	if (number == __NR_getrandom) {
		buffer = va_arg(args, void *);
		length = va_arg(args, size_t);
		flags = (unsigned int)va_arg(args, int);
		va_end(args);
		result = test_getrandom(buffer, length, flags);
		return ((long)result);
	}
	assert(number == __NR_perf_event_open);
	attr = va_arg(args, struct perf_event_attr *);
	assert(attr->type == PERF_TYPE_TRACEPOINT && attr->config == 123);
	assert(va_arg(args, int) == -1);
	assert(va_arg(args, int) == 0);
	assert(va_arg(args, int) == -1);
	assert(va_arg(args, int) == PERF_FLAG_FD_CLOEXEC);
	va_end(args);
	if (failure == TEST_PERF_FAILURE) {
		errno = EPERM;
		return (-1);
	}
	last_perf_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	return (last_perf_fd);
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
	if (failure == TEST_ATTACH_FAILURE) {
		errno = EBUSY;
		return (NULL);
	}
	assert(link_count < sizeof(links) / sizeof(links[0]));
	links[link_count].fd = fd;
	links[link_count].alive = true;
	return ((struct bpf_link *)&links[link_count++]);
}

static long
test_libbpf_error(const void *pointer)
{
	return (pointer != NULL ? 0 : -errno);
}

static int
test_destroy(struct bpf_link *link)
{
	struct test_link *test_link = (struct test_link *)link;

	if (test_link != NULL) {
		assert(test_link->alive);
		assert(close(test_link->fd) == 0);
		test_link->alive = false;
	}
	return (0);
}

static void
test_log(int priority, int do_errno, const char *function, int line,
    const char *format, ...)
{
	(void)priority;
	(void)do_errno;
	(void)function;
	(void)line;
	(void)format;
	warning_count++;
}

static void
add_function(struct btf *btf, const char *name, int result,
    const int *args, size_t count)
{
	int prototype = btf__add_func_proto(btf, result);
	size_t i;

	assert(prototype > 0);
	for (i = 0; i < count; i++)
		assert(btf__add_func_param(btf, "arg", args[i]) == 0);
	assert(btf__add_func(btf, name, BTF_FUNC_GLOBAL, prototype) > 0);
}

enum fixture_defect {
	FIXTURE_VALID,
	FIXTURE_UNSIGNED_RESULT,
	FIXTURE_UNSIGNED_COMMAND,
	FIXTURE_BAD_SECURITY,
	FIXTURE_BAD_WRAPPER,
	FIXTURE_ENUM_COMMAND
};

/* helper_enum: -1 missing, 0 old enum, 1 enum containing sys_bpf. */
static struct btf *
btf_fixture(bool common, int helper_enum, enum fixture_defect defect)
{
	struct btf *btf = btf__new_empty();
	int int32, unsigned32, long64, regs, pointer, const_regs, regs_pointer, args[3];
	int enum_command;

	assert(btf != NULL);
	assert((int32 = btf__add_int(btf, "int", 4, BTF_INT_SIGNED)) > 0);
	assert((unsigned32 = btf__add_int(btf, "u32", 4, 0)) > 0);
	assert((long64 = btf__add_int(btf, "long int", 8, BTF_INT_SIGNED)) > 0);
	assert((regs = btf__add_struct(btf, "pt_regs", 168)) > 0);
	assert((const_regs = btf__add_const(btf, regs)) > 0);
	assert((regs_pointer = btf__add_ptr(btf, const_regs)) > 0);
	assert((pointer = btf__add_ptr(btf, int32)) > 0);
	if (helper_enum >= 0) {
		assert(btf__add_enum(btf, "bpf_func_id", 4) > 0);
		assert(btf__add_enum_value(btf, "BPF_FUNC_unspec", 0) == 0);
		if (helper_enum != 0)
			assert(btf__add_enum_value(btf, "BPF_FUNC_sys_bpf", 166) == 0);
	}
	args[0] = defect == FIXTURE_BAD_SECURITY ? long64 : int32;
	args[1] = pointer;
	args[2] = unsigned32;
	add_function(btf, "security_bpf", int32, args, 3);
	add_function(btf, "security_bpf_prog", int32, &pointer, 1);
	if (common) {
		args[0] = defect == FIXTURE_UNSIGNED_COMMAND ? unsigned32 : int32;
		if (defect == FIXTURE_ENUM_COMMAND) {
			assert((enum_command = btf__add_enum(btf, "bpf_cmd", 4)) > 0);
			assert(btf__add_enum_value(btf, "BPF_PROG_LOAD", 5) == 0);
			args[0] = enum_command;
		}
		add_function(btf, "__sys_bpf",
		    defect == FIXTURE_UNSIGNED_RESULT ? unsigned32 : int32, args, 3);
	}
	if (defect == FIXTURE_BAD_WRAPPER)
		regs_pointer = pointer;
	add_function(btf, "__x64_sys_bpf", long64, &regs_pointer, 1);
	add_function(btf, "__ia32_sys_bpf", long64, &regs_pointer, 1);
	add_function(btf, "__arm64_sys_bpf", long64, &regs_pointer, 1);
	args[0] = int32;
	args[1] = pointer;
	args[2] = unsigned32;
	add_function(btf, "sys_bpf", long64, args, 3);
	args[0] = args[1] = args[2] = long64;
	add_function(btf, "__se_sys_bpf", long64, args, 3);
	return (btf);
}

static void
check_selector(struct btf *btf, const char *symbols, enum telemetry_arch arch,
    size_t capacity, int error, const char *first, enum bpf_telemetry_abi abi,
    size_t expected_count)
{
	struct bpf_telemetry_boundary result[2] = {
		{ "untouched", BPF_TELEMETRY_ABI_DIRECT },
		{ "untouched", BPF_TELEMETRY_ABI_DIRECT }
	};
	size_t count = 99;

	symbol_fixture = symbols;
	errno = 0;
	if (error != 0) {
		assert(telemetry_select_boundaries_arch(btf, result, capacity, &count,
		    arch) == -1);
		assert(errno == error && count == 0);
		assert(strcmp(result[0].symbol, "untouched") == 0);
	} else {
		assert(telemetry_select_boundaries_arch(btf, result, capacity, &count,
		    arch) == 0);
		assert(count == expected_count && strcmp(result[0].symbol, first) == 0);
		assert(result[0].abi == abi);
		if (count == 2) {
			assert(strcmp(result[1].symbol, "__ia32_sys_bpf") == 0);
			assert(result[1].abi == BPF_TELEMETRY_ABI_X86_COMPAT);
		}
	}
	btf__free(btf);
	selector_cases++;
}

static void
test_selector(void)
{
#define CHECK(btf, symbols, arch, cap, error, first, abi, count) \
	check_selector(btf, symbols, arch, cap, error, first, abi, count)
#define MODERN(defect) btf_fixture(true, 1, defect)
#define OLD(defect) btf_fixture(false, 0, defect)
	CHECK(MODERN(FIXTURE_VALID), SYMBOL_MODERN, TELEMETRY_ARCH_X86, 2, 0,
	    "__sys_bpf", BPF_TELEMETRY_ABI_DIRECT, 1);
	CHECK(MODERN(FIXTURE_ENUM_COMMAND), SYMBOL_MODERN, TELEMETRY_ARCH_ARM64, 2, 0,
	    "__sys_bpf", BPF_TELEMETRY_ABI_DIRECT, 1);
	CHECK(MODERN(FIXTURE_UNSIGNED_RESULT), SYMBOL_MODERN, TELEMETRY_ARCH_X86, 2,
	    EOPNOTSUPP, NULL, 0, 0);
	CHECK(MODERN(FIXTURE_UNSIGNED_COMMAND), SYMBOL_MODERN, TELEMETRY_ARCH_X86, 2,
	    EOPNOTSUPP, NULL, 0, 0);
	CHECK(MODERN(FIXTURE_BAD_SECURITY), SYMBOL_MODERN, TELEMETRY_ARCH_X86, 2,
	    EOPNOTSUPP, NULL, 0, 0);
	CHECK(OLD(FIXTURE_VALID), SYMBOL_X86, TELEMETRY_ARCH_X86, 2, 0,
	    "__x64_sys_bpf", BPF_TELEMETRY_ABI_X86_NATIVE, 1);
	CHECK(OLD(FIXTURE_VALID), SYMBOL_X86 SYMBOL_COMPAT, TELEMETRY_ARCH_X86, 2, 0,
	    "__x64_sys_bpf", BPF_TELEMETRY_ABI_X86_NATIVE, 2);
	CHECK(OLD(FIXTURE_VALID), SYMBOL_X86 SYMBOL_COMPAT, TELEMETRY_ARCH_X86, 1,
	    ENOSPC, NULL, 0, 0);
	CHECK(OLD(FIXTURE_BAD_WRAPPER), SYMBOL_X86, TELEMETRY_ARCH_X86, 2,
	    EOPNOTSUPP, NULL, 0, 0);
	CHECK(btf_fixture(false, 1, FIXTURE_VALID), SYMBOL_X86, TELEMETRY_ARCH_X86, 2,
	    EOPNOTSUPP, NULL, 0, 0);
	CHECK(btf_fixture(false, -1, FIXTURE_VALID), SYMBOL_X86, TELEMETRY_ARCH_X86, 2,
	    EOPNOTSUPP, NULL, 0, 0);
	CHECK(OLD(FIXTURE_VALID), SYMBOL_X86 "0000000000000000 T bpf_sys_bpf\n",
	    TELEMETRY_ARCH_X86, 2, EOPNOTSUPP, NULL, 0, 0);
	CHECK(OLD(FIXTURE_VALID), SYMBOL_X86 "0000000000000000 T kern_sys_bpf\n",
	    TELEMETRY_ARCH_X86, 2, EOPNOTSUPP, NULL, 0, 0);
	CHECK(MODERN(FIXTURE_VALID), SYMBOL_MODERN "0000000000000000 t __sys_bpf\n",
	    TELEMETRY_ARCH_X86, 2, EOPNOTSUPP, NULL, 0, 0);
	CHECK(btf_fixture(false, 1, FIXTURE_VALID),
	    SYMBOL_X86 "0000000000000000 t __sys_bpf.isra.0\n",
	    TELEMETRY_ARCH_X86, 2, EOPNOTSUPP, NULL, 0, 0);
	CHECK(OLD(FIXTURE_VALID),
	    SYMBOL_X86 "0000000000000000 t __sys_bpf [module]\n",
	    TELEMETRY_ARCH_X86, 2, 0, "__x64_sys_bpf", BPF_TELEMETRY_ABI_X86_NATIVE, 1);
	CHECK(MODERN(FIXTURE_VALID),
	    "0000000000000000 T security_bpf\n0000000000000000 t __sys_bpf\n",
	    TELEMETRY_ARCH_X86, 2, EOPNOTSUPP, NULL, 0, 0);
	CHECK(OLD(FIXTURE_VALID), SYMBOL_ARM64, TELEMETRY_ARCH_ARM64, 2, 0,
	    "__arm64_sys_bpf", BPF_TELEMETRY_ABI_ARM64_WRAPPER, 1);
	CHECK(OLD(FIXTURE_BAD_WRAPPER), SYMBOL_ARM64, TELEMETRY_ARCH_ARM64, 2,
	    EOPNOTSUPP, NULL, 0, 0);
	CHECK(OLD(FIXTURE_VALID), SYMBOL_SECURITY "0000000000000000 T sys_bpf\n",
	    TELEMETRY_ARCH_ARM64, 2, 0, "sys_bpf", BPF_TELEMETRY_ABI_DIRECT, 1);
	CHECK(OLD(FIXTURE_VALID), SYMBOL_SECURITY "0000000000000000 t __se_sys_bpf\n",
	    TELEMETRY_ARCH_ARM64, 2, 0, "__se_sys_bpf", BPF_TELEMETRY_ABI_DIRECT, 1);
	CHECK(OLD(FIXTURE_VALID), SYMBOL_SECURITY, TELEMETRY_ARCH_ARM64, 2,
	    EOPNOTSUPP, NULL, 0, 0);
#undef OLD
#undef MODERN
#undef CHECK
}

static void
test_trampoline_wrappers(void)
{
	static const struct bpf_telemetry_boundary boundaries[] = {
		{ "__x64_sys_bpf", BPF_TELEMETRY_ABI_X86_NATIVE },
		{ "__ia32_sys_bpf", BPF_TELEMETRY_ABI_X86_COMPAT },
		{ "__arm64_sys_bpf", BPF_TELEMETRY_ABI_ARM64_WRAPPER },
		{ "sys_bpf", BPF_TELEMETRY_ABI_DIRECT },
		{ "__se_sys_bpf", BPF_TELEMETRY_ABI_DIRECT }
	};
	struct bpf_telemetry_trampoline_layout layout;
	struct bpf_telemetry_boundary wrong = boundaries[0];
	struct btf *btf;
	size_t i;

	btf = btf_fixture(false, 0, FIXTURE_VALID);
	for (i = 0; i < sizeof(boundaries) / sizeof(boundaries[0]); i++) {
		assert(bpf_telemetry_trampoline_layout(btf, &boundaries[i], &layout) == 0);
		assert(layout.kind == (i < 3 ? BPF_TELEMETRY_TRAMPOLINE_WRAPPER :
		    BPF_TELEMETRY_TRAMPOLINE_DIRECT3));
		assert(layout.result_slot == (i < 3 ? 1 : 3));
		trampoline_cases++;
	}
	wrong.abi = BPF_TELEMETRY_ABI_X86_COMPAT;
	assert(bpf_telemetry_trampoline_layout(btf, &wrong, &layout) == -1 &&
	    errno == EOPNOTSUPP && layout.kind == BPF_TELEMETRY_TRAMPOLINE_NONE);
	wrong = boundaries[3];
	wrong.symbol = "__sys_bpf.isra.0";
	assert(bpf_telemetry_trampoline_layout(btf, &wrong, &layout) == -1 &&
	    errno == EOPNOTSUPP);
	assert(bpf_telemetry_trampoline_layout(NULL, &wrong, &layout) == -1 &&
	    errno == EINVAL);
	assert(bpf_telemetry_trampoline_layout(btf, NULL, &layout) == -1 &&
	    errno == EINVAL);
	assert(bpf_telemetry_trampoline_layout(btf, &wrong, NULL) == -1 &&
	    errno == EINVAL);
	btf__free(btf);
	btf = btf_fixture(false, 0, FIXTURE_BAD_WRAPPER);
	assert(bpf_telemetry_trampoline_layout(btf, &boundaries[0], &layout) == -1 &&
	    errno == EOPNOTSUPP && layout.kind == BPF_TELEMETRY_TRAMPOLINE_NONE);
	btf__free(btf);
	trampoline_cases++;
}

enum trampoline_defect {
	TRAMPOLINE_VALID,
	TRAMPOLINE_POINTER32,
	TRAMPOLINE_UNSIGNED_RESULT,
	TRAMPOLINE_LONG_RESULT,
	TRAMPOLINE_UNSIGNED_COMMAND,
	TRAMPOLINE_ENUM_COMMAND,
	TRAMPOLINE_LONG_SIZE,
	TRAMPOLINE_SIGNED_SIZE,
	TRAMPOLINE_SMALL_BPF_PTR,
	TRAMPOLINE_UNION_OFFSET,
	TRAMPOLINE_UNION_SIZE,
	TRAMPOLINE_UNION_SCALAR,
	TRAMPOLINE_FLAG_OFFSET,
	TRAMPOLINE_FLAG_SCALAR,
	TRAMPOLINE_FLAG_NOT_BITFIELD,
	TRAMPOLINE_COMMON_POINTER,
	TRAMPOLINE_COMMON_SIZE
};

static struct btf *
trampoline_fixture(unsigned int count, bool byvalue, enum trampoline_defect defect)
{
	struct btf *btf = btf__new_empty();
	int int32, uint32, long64, boolean, pointer, pointer_union, bpfptr, args[5];

	assert(btf != NULL);
	assert(btf__set_pointer_size(btf, defect == TRAMPOLINE_POINTER32 ? 4 : 8) == 0);
	assert((int32 = btf__add_int(btf, "int", 4, BTF_INT_SIGNED)) > 0);
	assert((uint32 = btf__add_int(btf, "unsigned int", 4, 0)) > 0);
	assert((long64 = btf__add_int(btf, "long int", 8, BTF_INT_SIGNED)) > 0);
	assert((boolean = btf__add_int(btf, "_Bool", 1, BTF_INT_BOOL)) > 0);
	assert((pointer = btf__add_ptr(btf, 0)) > 0);
	assert((pointer_union = btf__add_union(btf, "", defect ==
	    TRAMPOLINE_UNION_SIZE ? 16 : 8)) > 0);
	assert(btf__add_field(btf, "kernel", pointer, 0, 0) == 0);
	assert(btf__add_field(btf, "user", defect == TRAMPOLINE_UNION_SCALAR ?
	    long64 : pointer, 0, 0) == 0);
	assert((bpfptr = btf__add_struct(btf, "", defect ==
	    TRAMPOLINE_SMALL_BPF_PTR ? 8 : 16)) > 0);
	assert(btf__add_field(btf, "", pointer_union,
	    defect == TRAMPOLINE_UNION_OFFSET ? 8 : 0, 0) == 0);
	assert(btf__add_field(btf, "is_kernel", defect == TRAMPOLINE_FLAG_SCALAR ?
	    uint32 : boolean, defect == TRAMPOLINE_FLAG_OFFSET ? 65 : 64,
	    defect == TRAMPOLINE_FLAG_NOT_BITFIELD ? 0 : 1) == 0);
	assert((bpfptr = btf__add_typedef(btf, "sockptr_t", bpfptr)) > 0);
	assert((bpfptr = btf__add_typedef(btf, "bpfptr_t", bpfptr)) > 0);
	args[0] = defect == TRAMPOLINE_UNSIGNED_COMMAND ? uint32 : int32;
	if (defect == TRAMPOLINE_ENUM_COMMAND) {
		assert((args[0] = btf__add_enum(btf, "bpf_cmd", 4)) > 0);
		assert(btf__add_enum_value(btf, "BPF_PROG_LOAD", 5) == 0);
	}
	args[1] = byvalue ? bpfptr : pointer;
	args[2] = defect == TRAMPOLINE_LONG_SIZE ? long64 :
	    defect == TRAMPOLINE_SIGNED_SIZE ? int32 : uint32;
	args[3] = defect == TRAMPOLINE_COMMON_POINTER ? pointer : bpfptr;
	args[4] = defect == TRAMPOLINE_COMMON_SIZE ? int32 : uint32;
	add_function(btf, "__sys_bpf", defect == TRAMPOLINE_UNSIGNED_RESULT ? uint32 :
	    defect == TRAMPOLINE_LONG_RESULT ? long64 : int32, args, count);
	/* The ordinary selector intentionally permits unknown argument layouts. */
	args[0] = int32;
	args[1] = pointer;
	args[2] = uint32;
	add_function(btf, "security_bpf", int32, args, 3);
	add_function(btf, "security_bpf_prog", int32, &pointer, 1);
	return (btf);
}

static void
test_trampoline_direct(void)
{
	const struct bpf_telemetry_boundary boundary = {
		"__sys_bpf", BPF_TELEMETRY_ABI_DIRECT
	};
	struct bpf_telemetry_trampoline_layout layout;
	struct bpf_telemetry_boundary selected[2];
	enum trampoline_defect defect;
	struct btf *btf;
	size_t count;
	unsigned int argc;

	btf = trampoline_fixture(3, false, TRAMPOLINE_VALID);
	assert(bpf_telemetry_trampoline_layout(btf, &boundary, &layout) == 0 &&
	    layout.kind == BPF_TELEMETRY_TRAMPOLINE_DIRECT3 && layout.result_slot == 3);
	btf__free(btf);
	trampoline_cases++;
	for (argc = 3; argc <= 5; argc += 2) {
		for (defect = TRAMPOLINE_VALID; defect <= TRAMPOLINE_COMMON_SIZE; defect++) {
			btf = trampoline_fixture(argc, true, defect);
			if (defect == TRAMPOLINE_VALID || defect == TRAMPOLINE_ENUM_COMMAND ||
			    (argc == 3 && defect >= TRAMPOLINE_COMMON_POINTER)) {
				assert(bpf_telemetry_trampoline_layout(btf, &boundary, &layout) == 0);
				assert(layout.kind == (argc == 3 ?
				    BPF_TELEMETRY_TRAMPOLINE_DIRECT_BPF_PTR3 :
				    BPF_TELEMETRY_TRAMPOLINE_DIRECT_BPF_PTR5));
				assert(layout.result_slot == (argc == 3 ? 4 : 7));
			} else {
				assert(bpf_telemetry_trampoline_layout(btf, &boundary, &layout) == -1 &&
				    errno == EOPNOTSUPP && layout.kind == BPF_TELEMETRY_TRAMPOLINE_NONE);
				if (defect == TRAMPOLINE_SMALL_BPF_PTR) {
					symbol_fixture = SYMBOL_MODERN;
					assert(telemetry_select_boundaries_arch(btf, selected, 2, &count,
					    TELEMETRY_ARCH_X86) == 0 && count == 1);
				}
			}
			btf__free(btf);
			trampoline_cases++;
		}
	}
	btf = trampoline_fixture(4, true, TRAMPOLINE_VALID);
	assert(bpf_telemetry_trampoline_layout(btf, &boundary, &layout) == -1 &&
	    errno == EOPNOTSUPP && layout.kind == BPF_TELEMETRY_TRAMPOLINE_NONE);
	btf__free(btf);
	trampoline_cases++;
}

static void
test_retprobes(void)
{
	struct bpf_telemetry_retprobe *first = NULL, *second = NULL;
	struct bpf_program *program = (struct bpf_program *)&nonce_sequence;
	uint64_t missed;
	unsigned int created_before, deleted_before;
	int expected_errors[] = { 0, EIO, EINVAL, EACCES, EPERM, EBUSY };
	enum test_failure mode;

	assert(bpf_telemetry_retprobe_attach(&first, program, "__sys_bpf\nr:x/y z",
	    4096) == -1 && errno == EINVAL && first == NULL);
	assert(bpf_telemetry_retprobe_attach(&first, program, "__sys_bpf", 0) == -1 &&
	    errno == EINVAL);
	assert(bpf_telemetry_retprobe_attach(&first, program, "__sys_bpf", 4097) == -1 &&
	    errno == EINVAL);
	assert(event_count == 0);
	retprobe_cases++;

	assert(bpf_telemetry_retprobe_attach(&first, program, "__sys_bpf", 4096) == 0);
	assert(bpf_telemetry_retprobe_attach(&second, program, "__sys_bpf", 4096) == 0);
	assert(event_count == 2 && deleted_count == 0);
	assert(bpf_telemetry_retprobe_missed(first, &missed) == 0 && missed == 7);
	events[1].missed = 11;
	assert(bpf_telemetry_retprobe_missed(second, &missed) == 0 && missed == 11);
	errno = EDOM;
	bpf_telemetry_retprobe_detach(first);
	assert(errno == EDOM && deleted_count == 1);
	assert(bpf_telemetry_retprobe_missed(second, &missed) == 0 && missed == 11);
	bpf_telemetry_retprobe_detach(second);
	assert(deleted_count == 2);
	assert(fcntl(last_perf_fd, F_GETFD) == -1 && errno == EBADF);
	retprobe_cases++;

	for (mode = TEST_RANDOM_FAILURE; mode <= TEST_ATTACH_FAILURE; mode++) {
		created_before = event_count;
		deleted_before = deleted_count;
		failure = mode;
		assert(bpf_telemetry_retprobe_attach(&first, program, "__sys_bpf", 4096) == -1);
		assert(first == NULL && errno == expected_errors[mode]);
		assert(event_count - created_before == deleted_count - deleted_before);
		if (mode == TEST_ATTACH_FAILURE)
			assert(fcntl(last_perf_fd, F_GETFD) == -1 && errno == EBADF);
		retprobe_cases++;
	}
	failure = TEST_NO_FAILURE;
	assert(warning_count == 0 && event_count == deleted_count);
}

int
main(void)
{
	test_selector();
	test_trampoline_wrappers();
	test_trampoline_direct();
	test_retprobes();
	printf("bpf telemetry: %u selector, %u trampoline and %u return-probe tests passed\n",
	    selector_cases, trampoline_cases, retprobe_cases);
	return (0);
}
