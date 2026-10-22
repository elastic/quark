/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Elastic NV */

#ifndef _BPF_TELEMETRY_H_
#define _BPF_TELEMETRY_H_

#include <stddef.h>
#include <stdint.h>

struct btf;
struct bpf_program;
struct bpf_telemetry_retprobe;

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

/*
 * Named tracefs return probes allow an explicit instance limit and expose
 * tracefs miss counts. Older kernels omit exhausted return-instance pools
 * from these counts; invocation correlation must detect missing returns too.
 * Ordinary libbpf perf-PMU kretprobes provide neither facility.
 * Functions return -1 with errno set, except detach, which preserves errno.
 */
int bpf_telemetry_retprobe_attach(struct bpf_telemetry_retprobe **,
    struct bpf_program *, const char *, unsigned int);
void bpf_telemetry_retprobe_detach(struct bpf_telemetry_retprobe *);
int bpf_telemetry_retprobe_missed(const struct bpf_telemetry_retprobe *,
    uint64_t *);

#endif
