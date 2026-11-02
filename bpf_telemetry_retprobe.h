/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Elastic NV */

#ifndef _BPF_TELEMETRY_RETPROBE_H_
#define _BPF_TELEMETRY_RETPROBE_H_

struct bpf_telemetry_retprobe;

/*
 * Internal resource constructor: creates a named tracefs return probe without
 * attaching a BPF program; it requires a mounted, writable tracefs. The caller
 * owns the resource until detach.
 * Creation returns -1 with errno set; detach preserves errno.
 */
int bpf_telemetry_retprobe_create(struct bpf_telemetry_retprobe **,
    const char *, unsigned int);
void bpf_telemetry_retprobe_detach(struct bpf_telemetry_retprobe *);

#endif
