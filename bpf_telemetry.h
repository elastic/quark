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

#endif
