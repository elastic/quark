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

#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_version.h>

#include "quark.h"
#include "bpf_telemetry.h"

/* Stable syscall ABI, also when compiling with older libc headers. */
#ifndef __NR_getrandom
#if defined(__x86_64__)
#define __NR_getrandom 318
#elif defined(__aarch64__)
#define __NR_getrandom 278
#endif
#endif

#define RETPROBE_MAXACTIVE_MAX 4096U

enum telemetry_symbol {
	TELEMETRY_SYS_BPF,
	TELEMETRY_X64_BPF,
	TELEMETRY_IA32_BPF,
	TELEMETRY_ARM64_BPF,
	TELEMETRY_LEGACY_BPF,
	TELEMETRY_LEGACY_SE_BPF,
	TELEMETRY_HELPER_BPF,
	TELEMETRY_KERN_BPF,
	TELEMETRY_SECURITY_BPF,
	TELEMETRY_SECURITY_PROG,
	TELEMETRY_SYMBOL_COUNT
};

enum telemetry_arch {
	TELEMETRY_ARCH_X86,
	TELEMETRY_ARCH_ARM64
};

static const char *const telemetry_symbols[TELEMETRY_SYMBOL_COUNT] = {
	[TELEMETRY_SYS_BPF] = "__sys_bpf",
	[TELEMETRY_X64_BPF] = "__x64_sys_bpf",
	[TELEMETRY_IA32_BPF] = "__ia32_sys_bpf",
	[TELEMETRY_ARM64_BPF] = "__arm64_sys_bpf",
	[TELEMETRY_LEGACY_BPF] = "sys_bpf",
	[TELEMETRY_LEGACY_SE_BPF] = "__se_sys_bpf",
	[TELEMETRY_HELPER_BPF] = "bpf_sys_bpf",
	[TELEMETRY_KERN_BPF] = "kern_sys_bpf",
	[TELEMETRY_SECURITY_BPF] = "security_bpf",
	[TELEMETRY_SECURITY_PROG] = "security_bpf_prog"
};

/* Addresses may be hidden; only exact, non-module text symbols are needed. */
static int
telemetry_read_symbols(unsigned int found[TELEMETRY_SYMBOL_COUNT])
{
	char address[32], type, name[512], module[2], *line = NULL;
	size_t capacity = 0, i;
	FILE *fp;
	int saved_errno = 0;

	if ((fp = fopen("/proc/kallsyms", "re")) == NULL)
		return (-1);
	errno = 0;
	while (getline(&line, &capacity, fp) != -1) {
		if (sscanf(line, "%31s %c %511s %1s", address, &type, name,
		    module) != 3 || strchr("tTwW", type) == NULL)
			continue;
		for (i = 0; i < TELEMETRY_SYMBOL_COUNT; i++) {
			if (strcmp(name, telemetry_symbols[i]) == 0 && found[i] < 2)
				found[i]++;
		}
	}
	if (ferror(fp))
		saved_errno = errno != 0 ? errno : EIO;
	else if (errno != 0)
		saved_errno = errno;
	free(line);
	fclose(fp);
	if (saved_errno != 0) {
		errno = saved_errno;
		return (-1);
	}
	return (0);
}

static const struct btf_type *
telemetry_type(const struct btf *btf, unsigned int id)
{
	int resolved = btf__resolve_type(btf, id);

	return (resolved > 0 ? btf__type_by_id(btf, (unsigned int)resolved) : NULL);
}

static const struct btf_type *
telemetry_prototype(const struct btf *btf, const char *name)
{
	const struct btf_type *type;
	int id;

	id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);
	if (id < 0 || (type = btf__type_by_id(btf, (unsigned int)id)) == NULL)
		return (NULL);
	type = btf__type_by_id(btf, type->type);
	return (type != NULL && btf_is_func_proto(type) ? type : NULL);
}

static bool
telemetry_integer(const struct btf_type *type, unsigned int bytes, bool sign)
{
	return (type != NULL && btf_is_int(type) && type->size == bytes &&
	    btf_int_bits(type) == bytes * 8 && btf_int_offset(type) == 0 &&
	    (btf_int_encoding(type) & BTF_INT_BOOL) == 0 &&
	    (!sign || (btf_int_encoding(type) & BTF_INT_SIGNED) != 0));
}

static bool
telemetry_command_type(const struct btf_type *type, bool sign)
{
	return (telemetry_integer(type, 4, sign) ||
	    (type != NULL && btf_is_enum(type) && type->size == 4));
}

static bool
telemetry_pointer(const struct btf_type *type)
{
	return (type != NULL && btf_is_ptr(type));
}

static bool
telemetry_security_prototypes(const struct btf *btf)
{
	const struct btf_type *prototype;
	const struct btf_param *params;

	prototype = telemetry_prototype(btf, "security_bpf");
	if (prototype == NULL || btf_vlen(prototype) < 3)
		return (false);
	params = btf_params(prototype);
	if (!telemetry_command_type(telemetry_type(btf, params[0].type), false) ||
	    !telemetry_pointer(telemetry_type(btf, params[1].type)) ||
	    !telemetry_integer(telemetry_type(btf, params[2].type), 4, false))
		return (false);
	prototype = telemetry_prototype(btf, "security_bpf_prog");
	return (prototype != NULL && btf_vlen(prototype) >= 1 &&
	    telemetry_pointer(telemetry_type(btf, btf_params(prototype)[0].type)));
}

static bool
telemetry_common_prototype(const struct btf *btf)
{
	const struct btf_type *prototype = telemetry_prototype(btf, "__sys_bpf");

	return (prototype != NULL && btf_vlen(prototype) >= 3 &&
	    telemetry_integer(telemetry_type(btf, prototype->type), 4, true) &&
	    telemetry_command_type(telemetry_type(btf,
	    btf_params(prototype)[0].type), true));
}

/* Absence of the enum itself cannot establish absence of the helper. */
static bool
telemetry_legacy_helpers_absent(const struct btf *btf)
{
	const struct btf_type *type;
	const char *name;
	unsigned int i;
	int id;

	id = btf__find_by_name_kind(btf, "bpf_func_id", BTF_KIND_ENUM);
	if (id < 0 || (type = btf__type_by_id(btf, (unsigned int)id)) == NULL ||
	    btf_vlen(type) == 0)
		return (false);
	for (i = 0; i < btf_vlen(type); i++) {
		name = btf__name_by_offset(btf, btf_enum(type)[i].name_off);
		if (name == NULL || strcmp(name, "BPF_FUNC_sys_bpf") == 0)
			return (false);
	}
	return (true);
}

static bool
telemetry_wrapper_prototype(const struct btf *btf, const char *name)
{
	const struct btf_type *prototype, *pointer, *regs;
	const char *type_name;

	prototype = telemetry_prototype(btf, name);
	if (prototype == NULL || btf_vlen(prototype) != 1 ||
	    !telemetry_integer(telemetry_type(btf, prototype->type), 8, true))
		return (false);
	pointer = telemetry_type(btf, btf_params(prototype)[0].type);
	if (!telemetry_pointer(pointer))
		return (false);
	regs = telemetry_type(btf, pointer->type);
	if (regs == NULL || !btf_is_struct(regs))
		return (false);
	type_name = btf__name_by_offset(btf, regs->name_off);
	return (type_name != NULL && strcmp(type_name, "pt_regs") == 0);
}

static bool
telemetry_legacy_direct_prototype(const struct btf *btf, const char *name)
{
	const struct btf_type *prototype, *command, *attr, *size;
	const struct btf_param *params;

	prototype = telemetry_prototype(btf, name);
	if (prototype == NULL || btf_vlen(prototype) != 3 ||
	    !telemetry_integer(telemetry_type(btf, prototype->type), 8, true))
		return (false);
	params = btf_params(prototype);
	command = telemetry_type(btf, params[0].type);
	attr = telemetry_type(btf, params[1].type);
	size = telemetry_type(btf, params[2].type);
	/* sys_bpf's declared signature, or the generic __se_sys_bpf longs. */
	return ((telemetry_command_type(command, true) && telemetry_pointer(attr) &&
	    telemetry_integer(size, 4, false)) ||
	    (telemetry_integer(command, 8, true) && telemetry_integer(attr, 8, true) &&
	    telemetry_integer(size, 8, true)));
}

static int
telemetry_select_boundaries_arch(struct btf *btf,
    struct bpf_telemetry_boundary *boundaries, size_t capacity, size_t *count,
    enum telemetry_arch arch)
{
	struct bpf_telemetry_boundary selected[2];
	unsigned int found[TELEMETRY_SYMBOL_COUNT] = { 0 };
	size_t selected_count = 0;

	if (count == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*count = 0;
	if (btf == NULL || boundaries == NULL || capacity == 0) {
		errno = EINVAL;
		return (-1);
	}
	if (telemetry_read_symbols(found) == -1)
		return (-1);
	if (found[TELEMETRY_SECURITY_BPF] != 1 ||
	    found[TELEMETRY_SECURITY_PROG] != 1 ||
	    !telemetry_security_prototypes(btf))
		goto unsupported;
	if (found[TELEMETRY_SYS_BPF] != 0) {
		if (found[TELEMETRY_SYS_BPF] != 1 || !telemetry_common_prototype(btf))
			goto unsupported;
		selected[selected_count++] = (struct bpf_telemetry_boundary) {
			"__sys_bpf", BPF_TELEMETRY_ABI_DIRECT
		};
	} else {
		/* Never silently fall back to syscall-only coverage on a new kernel. */
		if (found[TELEMETRY_HELPER_BPF] != 0 || found[TELEMETRY_KERN_BPF] != 0 ||
		    !telemetry_legacy_helpers_absent(btf))
			goto unsupported;
		if (arch == TELEMETRY_ARCH_X86) {
			if (found[TELEMETRY_X64_BPF] != 1 ||
			    !telemetry_wrapper_prototype(btf, "__x64_sys_bpf"))
				goto unsupported;
			selected[selected_count++] = (struct bpf_telemetry_boundary) {
				"__x64_sys_bpf", BPF_TELEMETRY_ABI_X86_NATIVE
			};
			if (found[TELEMETRY_IA32_BPF] != 0) {
				if (found[TELEMETRY_IA32_BPF] != 1 ||
				    !telemetry_wrapper_prototype(btf, "__ia32_sys_bpf"))
					goto unsupported;
				selected[selected_count++] = (struct bpf_telemetry_boundary) {
					"__ia32_sys_bpf", BPF_TELEMETRY_ABI_X86_COMPAT
				};
			}
		} else if (arch == TELEMETRY_ARCH_ARM64 &&
		    found[TELEMETRY_ARM64_BPF] != 0) {
			if (found[TELEMETRY_ARM64_BPF] != 1 ||
			    !telemetry_wrapper_prototype(btf, "__arm64_sys_bpf"))
				goto unsupported;
			selected[selected_count++] = (struct bpf_telemetry_boundary) {
				"__arm64_sys_bpf", BPF_TELEMETRY_ABI_ARM64_WRAPPER
			};
		} else if (arch == TELEMETRY_ARCH_ARM64 &&
		    found[TELEMETRY_LEGACY_BPF] == 1 &&
		    telemetry_legacy_direct_prototype(btf, "sys_bpf")) {
			selected[selected_count++] = (struct bpf_telemetry_boundary) {
				"sys_bpf", BPF_TELEMETRY_ABI_DIRECT
			};
		} else if (arch == TELEMETRY_ARCH_ARM64 &&
		    found[TELEMETRY_LEGACY_BPF] == 0 &&
		    found[TELEMETRY_LEGACY_SE_BPF] == 1 &&
		    telemetry_legacy_direct_prototype(btf, "__se_sys_bpf")) {
			selected[selected_count++] = (struct bpf_telemetry_boundary) {
				"__se_sys_bpf", BPF_TELEMETRY_ABI_DIRECT
			};
		} else
			goto unsupported;
	}
	if (selected_count > capacity) {
		errno = ENOSPC;
		return (-1);
	}
	memcpy(boundaries, selected, selected_count * sizeof(*selected));
	*count = selected_count;
	return (0);

unsupported:
	errno = EOPNOTSUPP;
	return (-1);
}

int
bpf_telemetry_select_boundaries(struct btf *btf,
    struct bpf_telemetry_boundary *boundaries, size_t capacity, size_t *count)
{
#if defined(__x86_64__)
	return (telemetry_select_boundaries_arch(btf, boundaries, capacity, count,
	    TELEMETRY_ARCH_X86));
#elif defined(__aarch64__)
	return (telemetry_select_boundaries_arch(btf, boundaries, capacity, count,
	    TELEMETRY_ARCH_ARM64));
#else
	if (count != NULL)
		*count = 0;
	errno = EOPNOTSUPP;
	return (-1);
#endif
}

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
	struct perf_event_attr attr = {};
	struct bpf_perf_event_opts opts = {
		.sz = sizeof(opts),
/* Older libbpf selects ioctl automatically when perf BPF links are absent. */
#if LIBBPF_MAJOR_VERSION > 1 || \
    (LIBBPF_MAJOR_VERSION == 1 && LIBBPF_MINOR_VERSION >= 2)
		.force_ioctl_attach = true
#endif
	};
	char command[512];
	uint64_t nonce, id, missed;
	const unsigned char *p;
	size_t done = 0;
	ssize_t n;
	int pfd = -1, saved_errno;
	long error;

	if (result == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*result = NULL;
	if (program == NULL || function == NULL || *function == '\0' ||
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
