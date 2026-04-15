// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* Copyright (c) 2026 Elastic NV */

#include "vmlinux.h"		/* XXX still getting the old one XXX */

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <linux/limits.h>

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, __u64 clone_flags)
{
	return (0);
}

char _license[] SEC("license") = "Dual BSD/GPL";
