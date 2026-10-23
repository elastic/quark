// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2026 Elastic NV */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/btf.h>

#include "bpf_telemetry.h"

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

static int
telemetry_select_boundaries_arch(struct btf *btf,
    struct bpf_telemetry_boundary *boundaries, size_t capacity, size_t *count,
    enum telemetry_arch arch)
{
	unsigned int found[TELEMETRY_SYMBOL_COUNT] = { 0 };

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
	/* Legacy boundaries remain unsupported until their full ABI validates. */
	if (found[TELEMETRY_SECURITY_BPF] != 1 ||
	    found[TELEMETRY_SECURITY_PROG] != 1 ||
	    found[TELEMETRY_SYS_BPF] != 1 ||
	    !telemetry_security_prototypes(btf) || !telemetry_common_prototype(btf)) {
		errno = EOPNOTSUPP;
		return (-1);
	}
	boundaries[0] = (struct bpf_telemetry_boundary) {
		"__sys_bpf", BPF_TELEMETRY_ABI_DIRECT
	};
	*count = 1;
	return (0);
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
