// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* Copyright (c) 2026 Elastic NV */

#include "vmlinux.h"		/* XXX still getting the old one XXX */

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "nova.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wpadded"

/* XXX check if there isn't something like this on the headers XXX */
#define LOOP_CONTINUE	0
#define LOOP_STOP	1

#define E2BIG		7

extern void bpf_preempt_disable(void) __ksym __weak;
extern void bpf_preempt_enable(void) __ksym __weak;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct path_lpm_key);
} scratch_path SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct path_lpm_key);
	__type(value, u64);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, NOVA_MAX_PATHS);
} lpm_path SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct nova_rule);
	__uint(max_entries, NOVA_MAX_RULES);
} ruleset SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, NOVA_MAX_RULES);
	__type(key, __u32);
	__type(value, struct nova_rule_pcpu);
} ruleset_pcpu SEC(".maps");

const volatile u_int	rules_active;

/*
 * Consider moving most of these to a map, currently we need them on the stack
 * which is limited to 512 bytes.
 */
struct eval {
	/* fields is the bitmask of things that have been filled */
	__u64			 fields;		/* QUARK_RF_* bitmask */
	__u64			 poison_tag;		/* QUARK_RF_POISON */
	__u32			 pid;			/* QUARK_RF_PROCESS_PID */
	__u32			 ppid;			/* QUARK_RF_PROCESS_PPID */
	__u32			 uid;			/* QUARK_RF_PROCESS_UID */
	__u32			 gid;			/* QUARK_RF_PROCESS_GID */
	__u32			 sid;			/* QUARK_RF_PROCESS_SID */
	__u32			 pad0;
	struct path_lpm_key	*process_filename;	/* QUARK_RF_PROCESS_FILENAME */
	struct path_lpm_key	*file_path;		/* QUARK_RF_PROCESS_FILE_PATH */
	struct nova_rule	*match;			/* result of eval_run */
	char			 comm[16];		/* QUARK_RF_PROCESS_COMM */
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
eval_loop(__u32 i, struct eval *eval)
{
	struct nova_rule	*rule;
	struct nova_rule_pcpu	*rule_pcpu;
	__u64			*v, matched;

	if ((rule = bpf_map_lookup_elem(&ruleset, &i)) == NULL) {
		bpf_printk("rule not found, this is a bug");
		return (LOOP_CONTINUE);
	}
	if ((rule_pcpu = bpf_map_lookup_elem(&ruleset_pcpu, &i)) == NULL) {
		bpf_printk("rule_pcpu not found, this is a bug");
		return (LOOP_CONTINUE);
	}
	rule_pcpu->evals++;

	/*
	 * matched is a bitmask of fields that match (are equal).
	 * eval->fields are the valid fields for evaluation
	 * rule->fields are the fields that must match for this rule to be
	 * considered a match. We over compare things as can be seen below, this
	 * is to avoid having to do multiple jumps like: if (eval->fields &
	 * FOO), we curb it later with matched &= eval->fields.
	 */
	matched = 0;
	matched |= (__u64)(eval->pid == rule->pid) * QUARK_RF_PROCESS_PID;
	matched |= (__u64)(eval->ppid == rule->ppid) * QUARK_RF_PROCESS_PPID;
	matched |= (__u64)(eval->uid == rule->uid) * QUARK_RF_PROCESS_UID;
	matched |= (__u64)(eval->gid == rule->gid) * QUARK_RF_PROCESS_GID;
	matched |= (__u64)(eval->sid == rule->sid) * QUARK_RF_PROCESS_SID;
	matched |= (__u64)(eval->poison_tag == rule->poison_tag) * QUARK_RF_POISON;

	if (rule->fields & QUARK_RF_PROCESS_FILENAME &&
	    eval->fields & QUARK_RF_PROCESS_FILENAME &&
	    eval->process_filename != NULL) {
		eval->process_filename->meta = META_MAKE(i, META_RF_PROCESS_FILENAME);
		eval->process_filename->prefixlen = PATH_LPM_KEYLEN * 8;
		v = bpf_map_lookup_elem(&lpm_path, eval->process_filename);
		matched |= (v != NULL) * QUARK_RF_PROCESS_FILENAME;
	}

	if (rule->fields & QUARK_RF_FILE_PATH &&
	    eval->fields & QUARK_RF_FILE_PATH &&
	    eval->file_path != NULL) {
		eval->file_path->meta = META_MAKE(i, META_RF_FILE_PATH);
		eval->file_path->prefixlen = PATH_LPM_KEYLEN * 8;
		v = bpf_map_lookup_elem(&lpm_path, eval->file_path);
		matched |= (v != NULL) * QUARK_RF_FILE_PATH;
	}

	matched &= eval->fields;
	if ((matched & rule->fields) == rule->fields) {
		rule_pcpu->hits++;
		eval->match = rule;
		return (LOOP_STOP);
	}

	return (LOOP_CONTINUE);
}

static int
eval_run(struct eval *eval)
{
	if (bpf_loop(rules_active, eval_loop, eval, 0) < 0) {
		bpf_printk("bad bpf_loop");
		return (0);
	}

	if (eval->match == NULL)
		return (0);

	bpf_printk("rule %d matched! (0x%x)",
	    eval->match->number, eval->match->fields);

	return (0);
}

static void
eval_init(struct eval *eval)
{
	eval->fields = 0;
	eval->process_filename = bpf_map_lookup_elem(&scratch_path, &(int){0});
	eval->file_path = bpf_map_lookup_elem(&scratch_path, &(int){1});
	eval->match = NULL;
}

static void
eval_init_task(struct eval *eval, struct task_struct *task)
{
	eval->pid = BPF_CORE_READ(task, tgid);
	eval->fields |= QUARK_RF_PROCESS_PID;
	eval->ppid = BPF_CORE_READ(task, group_leader, real_parent, tgid);
	eval->fields |= QUARK_RF_PROCESS_PPID;
	eval->uid = BPF_CORE_READ(task, cred, uid.val);
	eval->fields |= QUARK_RF_PROCESS_UID;
	eval->gid = BPF_CORE_READ(task, cred, gid.val);
	eval->fields |= QUARK_RF_PROCESS_GID;
#if 0
	eval->sid = 		/* XXX TODO XXX */
	eval->fields |= QUARK_RF_PROCESS_SID;
#endif
	if (BPF_CORE_READ_STR_INTO(eval->comm, task, comm) > 0)
		eval->fields |= QUARK_RF_PROCESS_COMM;
	/* TODO MORE TODO */
}

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, __u64 clone_flags)
{
	struct eval		 eval;
	int			 r;

	preempt_disable();

	eval_init(&eval);
	eval_init_task(&eval, task);

	if (BPF_CORE_READ(task, mm, exe_file) != NULL &&
	    eval.process_filename != NULL) {
		if (bpf_d_path(&task->mm->exe_file->f_path,
		    eval.process_filename->path,
		    sizeof(eval.process_filename->path)) <= 0)
			bpf_printk("can't make filename");
		else
			eval.fields |= QUARK_RF_PROCESS_FILENAME;
	}

	r = eval_run(&eval);
	r = 0; /* XXX r ignored for now */

	preempt_enable();

	return (r);
}

#pragma GCC diagnostic pop

char _license[] SEC("license") = "Dual BSD/GPL";
