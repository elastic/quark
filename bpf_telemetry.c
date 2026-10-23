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
	for (;;) {
		errno = 0;
		if (getline(&line, &capacity, fp) == -1)
			break;
		if (sscanf(line, "%31s %c %511s %1s", address, &type, name,
		    module) != 3 || strchr("tTwW", type) == NULL)
			continue;
		for (i = 0; i < TELEMETRY_SYMBOL_COUNT; i++) {
			if (strcmp(name, telemetry_symbols[i]) == 0 && found[i] < 2)
				found[i]++;
		}
	}
	/* Some libc versions do not set ferror on allocation failure. */
	if (ferror(fp) || !feof(fp))
		saved_errno = errno != 0 ? errno : EIO;
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
	int depth;

	prototype = telemetry_prototype(btf, name);
	if (prototype == NULL || btf_vlen(prototype) != 1 ||
	    !telemetry_integer(telemetry_type(btf, prototype->type), 8, true))
		return (false);
	pointer = telemetry_type(btf, btf_params(prototype)[0].type);
	if (!telemetry_pointer(pointer))
		return (false);
	/*
	 * Older BTF deduplication can leave pt_regs a forward declaration,
	 * which btf__resolve_type() treats as void, so skip modifiers here.
	 */
	regs = btf__type_by_id(btf, pointer->type);
	for (depth = 0; regs != NULL && btf_is_mod(regs) && depth < 32; depth++)
		regs = btf__type_by_id(btf, regs->type);
	if (regs == NULL || !(btf_is_struct(regs) ||
	    (btf_is_fwd(regs) && !btf_kflag(regs))))
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

static bool
telemetry_unsigned_integer(const struct btf_type *type, unsigned int bytes)
{
	return (telemetry_integer(type, bytes, false) &&
	    (btf_int_encoding(type) & BTF_INT_SIGNED) == 0);
}

/* bpfptr_t is sockptr_t: a pointer union followed by a one-bit bool. */
static bool
telemetry_bpfptr(const struct btf *btf, unsigned int id)
{
	const struct btf_type *type = telemetry_type(btf, id), *pointer_union, *flag;
	const struct btf_member *members;
	const char *name;
	unsigned int i;

	if (type == NULL || !btf_is_struct(type) || type->size != 16 ||
	    btf_vlen(type) != 2 || btf_member_bit_offset(type, 0) != 0 ||
	    btf_member_bitfield_size(type, 0) != 0 ||
	    btf_member_bit_offset(type, 1) != 64 ||
	    btf_member_bitfield_size(type, 1) != 1)
		return (false);
	members = btf_members(type);
	name = btf__name_by_offset(btf, members[1].name_off);
	flag = telemetry_type(btf, members[1].type);
	if (name == NULL || strcmp(name, "is_kernel") != 0 || flag == NULL ||
	    !btf_is_int(flag) || flag->size != 1 || btf_int_bits(flag) != 8 ||
	    btf_int_offset(flag) != 0 || btf_int_encoding(flag) != BTF_INT_BOOL)
		return (false);
	pointer_union = telemetry_type(btf, members[0].type);
	if (pointer_union == NULL || !btf_is_union(pointer_union) ||
	    pointer_union->size != 8 || btf_vlen(pointer_union) != 2)
		return (false);
	members = btf_members(pointer_union);
	for (i = 0; i < 2; i++) {
		name = btf__name_by_offset(btf, members[i].name_off);
		if (name == NULL || strcmp(name, i == 0 ? "kernel" : "user") != 0 ||
		    btf_member_bit_offset(pointer_union, i) != 0 ||
		    btf_member_bitfield_size(pointer_union, i) != 0 ||
		    !telemetry_pointer(telemetry_type(btf, members[i].type)))
			return (false);
	}
	return (true);
}

int
bpf_telemetry_trampoline_layout(struct btf *btf,
    const struct bpf_telemetry_boundary *boundary,
    struct bpf_telemetry_trampoline_layout *layout)
{
	const struct btf_type *prototype;
	const struct btf_param *params;
	unsigned int count;
	bool direct;

	if (layout != NULL)
		memset(layout, 0, sizeof(*layout));
	if (btf == NULL || boundary == NULL || boundary->symbol == NULL ||
	    layout == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (btf__pointer_size(btf) != 8)
		goto unsupported;
	direct = boundary->abi == BPF_TELEMETRY_ABI_DIRECT;
	if (!direct) {
		if (!((boundary->abi == BPF_TELEMETRY_ABI_X86_NATIVE &&
		    strcmp(boundary->symbol, "__x64_sys_bpf") == 0) ||
		    (boundary->abi == BPF_TELEMETRY_ABI_X86_COMPAT &&
		    strcmp(boundary->symbol, "__ia32_sys_bpf") == 0) ||
		    (boundary->abi == BPF_TELEMETRY_ABI_ARM64_WRAPPER &&
		    strcmp(boundary->symbol, "__arm64_sys_bpf") == 0)) ||
		    !telemetry_wrapper_prototype(btf, boundary->symbol))
			goto unsupported;
		layout->kind = BPF_TELEMETRY_TRAMPOLINE_WRAPPER;
		layout->result_slot = 1;
		return (0);
	}
	if (strcmp(boundary->symbol, "sys_bpf") == 0 ||
	    strcmp(boundary->symbol, "__se_sys_bpf") == 0) {
		if (!telemetry_legacy_direct_prototype(btf, boundary->symbol))
			goto unsupported;
		layout->kind = BPF_TELEMETRY_TRAMPOLINE_DIRECT3;
		layout->result_slot = 3;
		return (0);
	}
	if (strcmp(boundary->symbol, "__sys_bpf") != 0 ||
	    (prototype = telemetry_prototype(btf, boundary->symbol)) == NULL ||
	    !telemetry_integer(telemetry_type(btf, prototype->type), 4, true))
		goto unsupported;
	count = btf_vlen(prototype);
	params = btf_params(prototype);
	if ((count != 3 && count != 5) ||
	    !telemetry_command_type(telemetry_type(btf, params[0].type), true) ||
	    !telemetry_unsigned_integer(telemetry_type(btf, params[2].type), 4))
		goto unsupported;
	if (count == 3 && telemetry_pointer(telemetry_type(btf, params[1].type))) {
		layout->kind = BPF_TELEMETRY_TRAMPOLINE_DIRECT3;
		layout->result_slot = 3;
		return (0);
	}
	if (!telemetry_bpfptr(btf, params[1].type) || (count == 5 &&
	    (!telemetry_bpfptr(btf, params[3].type) ||
	    !telemetry_unsigned_integer(telemetry_type(btf, params[4].type), 4))))
		goto unsupported;
	layout->kind = count == 3 ? BPF_TELEMETRY_TRAMPOLINE_DIRECT_BPF_PTR3 :
	    BPF_TELEMETRY_TRAMPOLINE_DIRECT_BPF_PTR5;
	layout->result_slot = count == 3 ? 4 : 7;
	return (0);

unsupported:
	errno = EOPNOTSUPP;
	return (-1);
}
