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
#define PATH_MAX	4096

#define MAX(_a, _b)	((_a) > (_b) ? (_a) : (_b))
#define MIN(_a, _b)	((_a) < (_b) ? (_a) : (_b))

#define PATH_LPM_KEY_BITLEN	((sizeof(struct path_lpm_key) - 4) * 8)

extern void bpf_preempt_disable(void) __ksym __weak;
extern void bpf_preempt_enable(void) __ksym __weak;

struct eval_path {
	char			 full[PATH_MAX];
	__u32			 full_len;
	__u32			 pad0;
	struct path_lpm_key	 pre;		/* QUARK_RF_* prefix */
	struct path_lpm_key	 post;		/* QUARK_RF_* postfix */
};

/*
 * Our rule evaluation context, we have a single instance of this throughout the
 * evaluation phase.
 * Don't forget to bump NOVA_PATH_FIELDS if you add another eval_path.
 */
struct eval {
	/* fields is the bitmask of things that have been filled */
	__u64			 fields;		/* QUARK_RF_* bitmask */
	__u64			 poison_tag;		/* QUARK_RF_POISON */
	__u32			 pid;			/* QUARK_RF_PID */
	__u32			 ppid;			/* QUARK_RF_PPID */
	__u32			 uid;			/* QUARK_RF_UID */
	__u32			 gid;			/* QUARK_RF_GID */
	__u32			 sid;			/* QUARK_RF_SID */
	__u32			 pad0;
	struct eval_path	 exe;			/* QUARK_RF_EXE */
	struct eval_path	 filepath;		/* QUARK_RF_FILEPATH */
	char			 comm[16];		/* QUARK_RF_COMM */
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct eval);
} scratch_eval SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct path_lpm_key);
	__type(value, __u32);
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

static __always_inline struct eval *
eval_ctx(void)
{
	return (bpf_map_lookup_elem(&scratch_eval, &(int){0}));
}

/*
 * 0 for no match
 * 1 for match
 */
static int
eval_path_match(struct eval_path *ep, struct nova_rule *rule, __u16 mcode)
{
	__u32	*v, post_len, start;

	/*
	 * Lookup prefix
	 */
	ep->pre.meta = META_MAKE(rule->number, mcode);
	v = bpf_map_lookup_elem(&lpm_path, &ep->pre);
	if (v == NULL)
		return (0);
	post_len = *v;
	/*
	 * No suffix, so it's a match
	 */
	if (post_len == 0)
		return (1);
	if (post_len > NOVA_PATHLEN)
		post_len = NOVA_PATHLEN;
	/*
	 * Find the suffix start
	 */
	if (ep->full_len > post_len)
		start = ep->full_len - post_len;
	else
		start = 0;
	/*
	 * Copy suffix so we can do a lookup
	 */
	if (bpf_probe_read_kernel_str(ep->post.path, post_len,
	    &ep->full[start]) < 0) {
		bpf_printk("can't make post rule %d", rule->number);
		return (0);
	}
	/*
	 * Build the key that would match this suffix in this rule, and do a
	 * lookup.
	 */
	ep->post.meta = META_MAKE(rule->number, mcode | META_RF_POSTFIX);
	v = bpf_map_lookup_elem(&lpm_path, &ep->post);
	if (v == NULL)
		return (0);

	return (1);
}

static int
eval_loop(__u32 i, struct nova_rule **match)
{
	struct eval		*eval;
	struct nova_rule	*rule;
	struct nova_rule_pcpu	*rule_pcpu;

	if ((eval = eval_ctx()) == NULL) {
		bpf_printk("no eval");
		return (LOOP_CONTINUE);
	}
	if ((rule = bpf_map_lookup_elem(&ruleset, &i)) == NULL) {
		bpf_printk("rule not found, this is a bug");
		return (LOOP_CONTINUE);
	}
	if ((rule_pcpu = bpf_map_lookup_elem(&ruleset_pcpu, &i)) == NULL) {
		bpf_printk("rule_pcpu not found, this is a bug");
		return (LOOP_CONTINUE);
	}
	rule_pcpu->evals++;

	if ((eval->fields & rule->fields) != rule->fields)
		return (LOOP_CONTINUE);

	if (rule->fields & QUARK_RF_PID && eval->pid != rule->pid)
		return (LOOP_CONTINUE);
	if (rule->fields & QUARK_RF_PPID && eval->ppid != rule->ppid)
		return (LOOP_CONTINUE);
	if (rule->fields & QUARK_RF_UID && eval->uid != rule->uid)
		return (LOOP_CONTINUE);
	if (rule->fields & QUARK_RF_GID && eval->gid != rule->gid)
		return (LOOP_CONTINUE);
	if (rule->fields & QUARK_RF_SID && eval->sid != rule->sid)
		return (LOOP_CONTINUE);
	if (rule->fields & QUARK_RF_POISON &&
	    eval->poison_tag != rule->poison_tag)
		return (LOOP_CONTINUE);

	if ((rule->fields & QUARK_RF_EXE) &&
	    !eval_path_match(&eval->exe, rule, META_RF_EXE))
		return (LOOP_CONTINUE);
	if ((rule->fields & QUARK_RF_FILEPATH) &&
	    !eval_path_match(&eval->filepath, rule, META_RF_FILEPATH))
		return (LOOP_CONTINUE);

	*match = rule;
	rule_pcpu->hits++;

	return (LOOP_STOP);
}

static int
eval_run(struct eval *eval)
{
	struct nova_rule	*match = NULL;

	if (bpf_loop(rules_active, eval_loop, &match, 0) < 0) {
		bpf_printk("bad bpf_loop");
		return (0);
	}

	if (match == NULL)
		return (0);

	bpf_printk("rule %d matched! (0x%x)", match->number, match->fields);

	return (0);
}

static void
eval_path_init(struct eval_path *ep)
{
	ep->full_len = 0;
	ep->full[0] = 0;
	ep->pre.prefixlen = PATH_LPM_KEY_BITLEN;
	ep->post.prefixlen = PATH_LPM_KEY_BITLEN;
}

static struct eval *
eval_init(void)
{
	struct eval	*eval;

	if ((eval = eval_ctx()) == NULL)
		return (NULL);

	eval->fields = 0;
	eval_path_init(&eval->exe);
	eval_path_init(&eval->filepath);

	return (eval);
}

static void
eval_init_task(struct eval *eval, struct task_struct *task)
{
	eval->pid = BPF_CORE_READ(task, tgid);
	eval->fields |= QUARK_RF_PID;
	eval->ppid = BPF_CORE_READ(task, group_leader, real_parent, tgid);
	eval->fields |= QUARK_RF_PPID;
	eval->uid = BPF_CORE_READ(task, cred, uid.val);
	eval->fields |= QUARK_RF_UID;
	eval->gid = BPF_CORE_READ(task, cred, gid.val);
	eval->fields |= QUARK_RF_GID;
#if 0
	eval->sid = 		/* XXX TODO XXX */
	eval->fields |= QUARK_RF_SID;
#endif
	/* XXX NOT WORTH THE BRANCH? XXX */
	if (BPF_CORE_READ_STR_INTO(eval->comm, task, comm) > 0)
		eval->fields |= QUARK_RF_COMM;
	/* TODO MORE TODO */
}

static int
bprm_check1(struct linux_binprm *bprm, int ret)
{
	struct task_struct	*task = bpf_get_current_task_btf();
	struct eval		*eval;
	int			 r;
	long			 len;

	if ((eval = eval_init()) == NULL)
		return (0);
	eval_init_task(eval, task);

	if (bprm->file == NULL)
		goto noexe;

	len = bpf_d_path(&bprm->file->f_path, eval->exe.full, PATH_MAX);
	if (len < 0) {
		bpf_printk("can't make executable 1");
		goto noexe;
	}
	eval->exe.full_len = len;
	len = bpf_probe_read_kernel_str(eval->exe.pre.path,
	    sizeof(eval->exe.pre.path), eval->exe.full);
	if (len < 0) {
		bpf_printk("can't make executable 2");
		goto noexe;
	}

	eval->fields |= QUARK_RF_EXE;
noexe:
	r = eval_run(eval);
	r = 0; /* XXX r ignored for now */

	return (r);
}

SEC("lsm/bprm_check_security")
int
BPF_PROG(bprm_check, struct linux_binprm *bprm, int ret)
{
	int	r;

	preempt_disable();
	r = bprm_check1(bprm, ret);
	preempt_enable();

	return (r);
}

#pragma GCC diagnostic pop

char _license[] SEC("license") = "Dual BSD/GPL";
