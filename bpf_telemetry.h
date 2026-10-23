/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Elastic NV */

#ifndef _BPF_TELEMETRY_H_
#define _BPF_TELEMETRY_H_

#include <stddef.h>
#include <stdint.h>

struct btf;

enum bpf_telemetry_abi {
	BPF_TELEMETRY_ABI_DIRECT = 0,
	BPF_TELEMETRY_ABI_X86_NATIVE = 1,
	BPF_TELEMETRY_ABI_X86_COMPAT = 2,
	BPF_TELEMETRY_ABI_ARM64_WRAPPER = 3
};

struct bpf_telemetry_boundary {
	const char *symbol;
	enum bpf_telemetry_abi abi;
};

/* Exact symbol/prototype selection, with no version or clone-name guesses. */
int bpf_telemetry_select_boundaries(struct btf *,
    struct bpf_telemetry_boundary *, size_t, size_t *);

enum bpf_telemetry_trampoline_kind {
	BPF_TELEMETRY_TRAMPOLINE_NONE,
	BPF_TELEMETRY_TRAMPOLINE_DIRECT3,
	BPF_TELEMETRY_TRAMPOLINE_DIRECT_BPF_PTR3,
	BPF_TELEMETRY_TRAMPOLINE_DIRECT_BPF_PTR5,
	BPF_TELEMETRY_TRAMPOLINE_WRAPPER
};

struct bpf_telemetry_trampoline_layout {
	enum bpf_telemetry_trampoline_kind kind;
	uint32_t result_slot;
};

/*
 * Describe 64-bit trampoline context slots for an already selected boundary.
 * This validates BTF layout, not trampoline availability; attachment must still
 * be attempted. EOPNOTSUPP leaves kind NONE and permits kprobe fallback.
 */
int bpf_telemetry_trampoline_layout(struct btf *,
    const struct bpf_telemetry_boundary *,
    struct bpf_telemetry_trampoline_layout *);

#endif
