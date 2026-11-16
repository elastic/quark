// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2026 Elastic NV */

/* Pure userspace tests: the symbol inventory is simulated. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <bpf/btf.h>

#include "quark.h"
#include "quark-test.h"

static const char *symbol_fixture;
static unsigned int selector_cases, trampoline_cases;
static unsigned int getline_calls;
static int getline_error = -1;
static bool stale_errno;
static FILE *test_fopen(const char *, const char *);
static ssize_t test_getline(char **, size_t *, FILE *);

/* Include the implementation to test both architecture selectors. */
#define bpf_telemetry_select_boundaries test_bpf_telemetry_select_boundaries
/* The function-like macro leaves the structure tag unchanged. */
#define bpf_telemetry_trampoline_layout(...) \
	test_bpf_telemetry_trampoline_layout(__VA_ARGS__)
#define fopen test_fopen
#define getline test_getline
#include "bpf_telemetry.c"
#undef getline
#undef fopen

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

static FILE *
test_fopen(const char *path, const char *mode)
{
	FILE *fp;

	assert(strcmp(path, "/proc/kallsyms") == 0 && strcmp(mode, "re") == 0);
	assert((fp = tmpfile()) != NULL);
	assert(fputs(symbol_fixture, fp) >= 0 && fflush(fp) == 0);
	rewind(fp);
	getline_calls = 0;
	return (fp);
}

static ssize_t
test_getline(char **line, size_t *capacity, FILE *fp)
{
	ssize_t length;

	/* Fail after all three required symbols, without setting stream flags. */
	if (getline_calls++ == 3 && getline_error >= 0) {
		assert(!ferror(fp) && !feof(fp));
		errno = getline_error;
		return (-1);
	}
	length = getline(line, capacity, fp);
	/* Model unrelated errno surviving clean EOF, regardless of libc changes. */
	if (stale_errno)
		errno = ERANGE;
	return (length);
}

static void
test_read_symbols(void)
{
	static const struct {
		int read_error, expected_error;
	} cases[] = { { -1, 0 }, { ENOMEM, ENOMEM }, { 0, EIO } };

	symbol_fixture = SYMBOL_MODERN;
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		unsigned int found[TELEMETRY_SYMBOL_COUNT] = { 0 };
		int result;

		getline_error = cases[i].read_error;
		stale_errno = getline_error < 0;
		result = telemetry_read_symbols(found);
		assert(result == (cases[i].expected_error == 0 ? 0 : -1));
		if (result == -1)
			assert(errno == cases[i].expected_error);
		assert(found[TELEMETRY_SYS_BPF] == 1 &&
		    found[TELEMETRY_SECURITY_BPF] == 1 &&
		    found[TELEMETRY_SECURITY_PROG] == 1);
	}
	getline_error = -1;
	stale_errno = false;
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
	FIXTURE_ENUM_COMMAND,
	FIXTURE_FWD_STRUCT,
	FIXTURE_FWD_UNION,
	FIXTURE_FWD_ONLY
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
	/* Fedora 32's 5.11 BTF points the wrappers at a declaration. */
	if (defect == FIXTURE_FWD_STRUCT || defect == FIXTURE_FWD_UNION)
		assert(btf__add_struct(btf, "pt_regs", 168) > 0);
	if (defect == FIXTURE_FWD_STRUCT || defect == FIXTURE_FWD_ONLY)
		regs = btf__add_fwd(btf, "pt_regs", BTF_FWD_STRUCT);
	else if (defect == FIXTURE_FWD_UNION)
		regs = btf__add_fwd(btf, "pt_regs", BTF_FWD_UNION);
	else
		regs = btf__add_struct(btf, "pt_regs", 168);
	assert(regs > 0);
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
	CHECK(OLD(FIXTURE_FWD_STRUCT), SYMBOL_X86 SYMBOL_COMPAT,
	    TELEMETRY_ARCH_X86, 2, 0, "__x64_sys_bpf",
	    BPF_TELEMETRY_ABI_X86_NATIVE, 2);
	CHECK(OLD(FIXTURE_FWD_UNION), SYMBOL_X86, TELEMETRY_ARCH_X86, 2,
	    EOPNOTSUPP, NULL, 0, 0);
	CHECK(OLD(FIXTURE_FWD_ONLY), SYMBOL_X86, TELEMETRY_ARCH_X86, 2,
	    EOPNOTSUPP, NULL, 0, 0);
	CHECK(OLD(FIXTURE_FWD_STRUCT), SYMBOL_ARM64, TELEMETRY_ARCH_ARM64, 2, 0,
	    "__arm64_sys_bpf", BPF_TELEMETRY_ABI_ARM64_WRAPPER, 1);
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
	CHECK(MODERN(FIXTURE_VALID),
	    SYMBOL_SECURITY "0000000000000000 t __sys_bpf.isra.0\n",
	    TELEMETRY_ARCH_X86, 2, EOPNOTSUPP, NULL, 0, 0);
	CHECK(MODERN(FIXTURE_VALID),
	    SYMBOL_SECURITY "0000000000000000 t __sys_bpf [module]\n",
	    TELEMETRY_ARCH_X86, 2, EOPNOTSUPP, NULL, 0, 0);
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

int
t_bpf_telemetry(const struct test *t, struct quark_queue_attr *qa)
{
	test_read_symbols();
	selector_cases = trampoline_cases = 0;
	test_selector();
	test_trampoline_wrappers();
	test_trampoline_direct();
	qdebugx("bpf telemetry: %u selector and %u trampoline tests passed",
	    selector_cases, trampoline_cases);
	return (0);
}

#undef bpf_telemetry_trampoline_layout
#undef bpf_telemetry_select_boundaries
