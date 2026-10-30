/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Elastic NV */

#ifndef _BPF_TELEMETRY_RETPROBE_H_
#define _BPF_TELEMETRY_RETPROBE_H_

#include <stdint.h>

struct bpf_program;
struct bpf_telemetry_retprobe;

/*
 * Internal resource constructor: creates a named tracefs return probe without
 * attaching a BPF program; it requires a mounted, writable tracefs. The caller
 * owns the resource until detach. Creation first removes all consumers' probes
 * that are not in use, which reclaims those left by a consumer that exited
 * without detach.
 * Creation returns -1 with errno set; detach preserves errno.
 */
int bpf_telemetry_retprobe_create(struct bpf_telemetry_retprobe **,
    const char *, unsigned int);
void bpf_telemetry_retprobe_detach(struct bpf_telemetry_retprobe *);

/*
 * Attach with an explicit instance limit and readable tracefs miss counters.
 * Old kernels omit return-pool exhaustion, so these counts can underreport
 * loss. Attachment failures remove the resource; a probe that another
 * consumer's creation removes before attachment is recreated. Functions return
 * -1 with errno set; successful attachment transfers the resource to the caller.
 */
int bpf_telemetry_retprobe_attach(struct bpf_telemetry_retprobe **,
    struct bpf_program *, const char *, unsigned int);
int bpf_telemetry_retprobe_missed(const struct bpf_telemetry_retprobe *,
    uint64_t *);

#endif
