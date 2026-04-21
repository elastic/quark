// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* Copyright (c) 2026 Elastic NV */

#include "vmlinux.h"		/* XXX still getting the old one XXX */

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "nova.h"

/* XXX check if there isn't something like this on the headers XXX */
#define LOOP_CONTINUE	0
#define LOOP_STOP	1

#define E2BIG		7

extern void bpf_preempt_disable(void) __ksym __weak;
extern void bpf_preempt_enable(void) __ksym __weak;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct nova_rule);
} scratch_rule SEC(".maps");

#define my_rule_eval_ctx()	bpf_map_lookup_elem(&scratch_rule, &(int){0})

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct nova_rule);
	__uint(max_entries, NOVA_MAX_RULES);
} ruleset SEC(".maps");

struct rule_eval_loop_ctx {
	struct nova_rule	*rctx;
	struct nova_rule	*match;
};

static void
preempt_disable(void)
{
	if (bpf_ksym_exists(bpf_preempt_disable))
		bpf_preempt_disable();
}

static void
preempt_enable(void)
{
	if (bpf_ksym_exists(bpf_preempt_enable))
		bpf_preempt_enable();
}

static int
rule_eval_loop(__u32 i, struct rule_eval_loop_ctx *lctx)
{
	struct nova_rule	*cand;
	struct nova_rule	*rctx;

	rctx = lctx->rctx;
	if (rctx == NULL ||
	    ((cand = bpf_map_lookup_elem(&ruleset, &i)) == NULL))
		return (LOOP_CONTINUE); /* XXX signal something is really wrong XXX */
	rctx->fields = 0;
	rctx->fields |= (__u64)(rctx->pid == cand->pid) * QUARK_RF_PROCESS_PID;
	rctx->fields |= (__u64)(rctx->ppid == cand->ppid) * QUARK_RF_PROCESS_PPID;
	rctx->fields |= (__u64)(rctx->uid == cand->uid) * QUARK_RF_PROCESS_UID;
	rctx->fields |= (__u64)(rctx->gid == cand->gid) * QUARK_RF_PROCESS_GID;
	rctx->fields |= (__u64)(rctx->sid == cand->sid) * QUARK_RF_PROCESS_SID;
	rctx->fields |= (__u64)(rctx->poison_tag == cand->poison_tag) * QUARK_RF_POISON;

	if ((rctx->fields & cand->fields) == cand->fields) {
		lctx->match = cand;

		return (LOOP_STOP);
	}

	return (LOOP_CONTINUE);
}

static int
rule_eval(struct nova_rule *rctx)
{
	struct rule_eval_loop_ctx	lctx;
	int				r;

	lctx.rctx = rctx;
	lctx.match = NULL;

	r = bpf_loop(NOVA_MAX_RULES, rule_eval_loop, &lctx, 0);
	if (r < 0) {
		bpf_printk("bad bpf_loop %d", r);
		return (0);
	}
	if (lctx.match == NULL)
		return (0);

	return (0);
}

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, __u64 clone_flags)
{
	struct nova_rule	*rctx;
	int			 r;

	bpf_preempt_disable();

	rctx = my_rule_eval_ctx();
	r = rule_eval(rctx);
	/* XXX r ignored for now */

	bpf_preempt_enable();

	return (0);
}

char _license[] SEC("license") = "Dual BSD/GPL";
