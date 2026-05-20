// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* Copyright (c) 2026 Elastic NV */

#include "vmlinux.h"		/* XXX still getting the old one XXX */

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* XXX Remove me once we update our ancient vmlinux.h XXX */
struct bpf_dynptr {
	__u64 __opaque[2];
} __attribute__((aligned(8)));

#include "nova.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wpadded"

#define LOOP_CONTINUE	0
#define LOOP_STOP	1

#define E2BIG		7
#define ENOBUFS		105
#define PATH_MAX	4096

#define MAX(_a, _b)	((_a) > (_b) ? (_a) : (_b))
#define MIN(_a, _b)	((_a) < (_b) ? (_a) : (_b))

#define PATH_LPM_KEY_BITLEN	((sizeof(struct path_lpm_key) - 4) * 8)

extern void bpf_preempt_disable(void) __ksym __weak;
extern void bpf_preempt_enable(void) __ksym __weak;

struct output {
	__u32			head_len;
	__u32			total_len;
	__u32			var_off;
	__u32			pad;
	struct bpf_dynptr	dptr;
};

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
	__u64			fields;		/* QUARK_RF_* bitmask */
	__u64			poison_tag;	/* QUARK_RF_POISON */
	struct nova_task	nt;
	struct eval_path	exe;		/* QUARK_RF_EXE */
	struct eval_path	filepath;	/* QUARK_RF_FILEPATH */
	struct eval_path	cwd;
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

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 * 1024 * 1024);
} output_ring SEC(".maps");

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

static __u64
ktime_get_boot_ns(void)
{
	if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_ktime_get_boot_ns))
		return (bpf_ktime_get_boot_ns());
	else
		return (0);
}

static void
task_to_nova(struct task_struct *task, struct nova_task *nt)
{
	const struct cred	*cred;
	struct task_struct	*gl;
	struct signal_struct	*sig;
	struct pid		*pgid_pid, *sid_pid;
	int			 e_pgid, e_sid;
	struct tty_struct	*tty;
	const struct tty_driver *tty_driver;
	const struct nsproxy	*ns;
	struct pid		*pid;
	int			 pid_level;

	__builtin_memset(nt, 0, sizeof(*nt));

	if (bpf_core_enum_value_exists(enum pid_type, PIDTYPE_PGID))
		e_pgid = bpf_core_enum_value(enum pid_type, PIDTYPE_PGID);
	else
		e_pgid = PIDTYPE_PGID;
	if (bpf_core_enum_value_exists(enum pid_type, PIDTYPE_SID))
		e_sid = bpf_core_enum_value(enum pid_type, PIDTYPE_SID);
	else
		e_sid = PIDTYPE_SID;

	cred = BPF_CORE_READ(task, cred);
	gl = BPF_CORE_READ(task, group_leader);
	sig = BPF_CORE_READ(gl, signal);
	pgid_pid = BPF_CORE_READ(sig, pids[e_pgid]);
	sid_pid  = BPF_CORE_READ(sig, pids[e_sid]);
	tty = BPF_CORE_READ(sig, tty);
	tty_driver = BPF_CORE_READ(tty, driver);
	ns = BPF_CORE_READ(task, nsproxy);
	pid = BPF_CORE_READ(task, thread_pid);

	bpf_core_read(&nt->cap_eff, sizeof(nt->cap_eff), &cred->cap_effective);
	bpf_core_read(&nt->cap_perm, sizeof(nt->cap_perm), &cred->cap_permitted);

	nt->start_time_ns = BPF_CORE_READ(gl, start_time);
	nt->tid = BPF_CORE_READ(task, pid);
	nt->pid = BPF_CORE_READ(task, tgid);
	nt->ppid = BPF_CORE_READ(gl, real_parent, tgid);
	nt->uid = BPF_CORE_READ(cred, uid.val);
	nt->gid = BPF_CORE_READ(cred, gid.val);
	nt->suid = BPF_CORE_READ(cred, suid.val);
	nt->sgid = BPF_CORE_READ(cred, sgid.val);
	nt->euid = BPF_CORE_READ(cred, euid.val);
	nt->egid = BPF_CORE_READ(cred, egid.val);
	nt->pgid = BPF_CORE_READ(pgid_pid, numbers[0].nr);
	nt->sid = BPF_CORE_READ(sid_pid, numbers[0].nr);
	nt->tty_major = BPF_CORE_READ(tty_driver, major);
	nt->tty_minor = BPF_CORE_READ(tty_driver, minor_start);
	nt->tty_minor += BPF_CORE_READ(tty, index);
	nt->uts_inonum = BPF_CORE_READ(ns, uts_ns, ns.inum);
	nt->ipc_inonum = BPF_CORE_READ(ns, ipc_ns, ns.inum);
	nt->mnt_inonum = BPF_CORE_READ(ns, mnt_ns, ns.inum);
	nt->net_inonum = BPF_CORE_READ(ns, net_ns, ns.inum);
	nt->cgroup_inonum = BPF_CORE_READ(ns, cgroup_ns, ns.inum);
	nt->time_inonum = BPF_CORE_READ(ns, time_ns, ns.inum);
	if (pid != NULL) {
		pid_level = BPF_CORE_READ(pid, level);
		nt->pid_inonum = BPF_CORE_READ(pid,
		    numbers[pid_level].ns, ns.inum);
	} else
		nt->pid_inonum = 0;
	BPF_CORE_READ_STR_INTO(&nt->comm, task, comm);
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

	if (rule->fields & QUARK_RF_PID && eval->nt.pid != rule->pid)
		return (LOOP_CONTINUE);
	if (rule->fields & QUARK_RF_PPID && eval->nt.ppid != rule->ppid)
		return (LOOP_CONTINUE);
	if (rule->fields & QUARK_RF_UID && eval->nt.uid != rule->uid)
		return (LOOP_CONTINUE);
	if (rule->fields & QUARK_RF_GID && eval->nt.gid != rule->gid)
		return (LOOP_CONTINUE);
	if (rule->fields & QUARK_RF_SID && eval->nt.sid != rule->sid)
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
		return (QUARK_RA_PASS);

	bpf_printk("rule %d matched! (0x%x)", match->number, match->fields);

	return (match->action);
}

static void
eval_path_init(struct eval_path *ep)
{
	ep->full_len = 0;
	ep->full[0] = 0;
	ep->pre.prefixlen = PATH_LPM_KEY_BITLEN;
	ep->post.prefixlen = PATH_LPM_KEY_BITLEN;
}

#define EP_BASIC	0
#define EP_ALL		1
static int
eval_path_prepare(struct eval_path *dst, struct path *src, int mode)
{
	long	len, full_len;

	full_len = bpf_d_path(src, dst->full, PATH_MAX);
	if (full_len < 0) {
		bpf_printk("can't make path 1");
		return (-1);
	}
	if (mode == EP_BASIC)
		goto done;
	len = bpf_probe_read_kernel_str(dst->pre.path,
	    sizeof(dst->pre.path), dst->full);
	if (len < 0) {
		bpf_printk("can't make path 2");
		return (-1);
	}

done:
	dst->full_len = full_len;

	return (0);
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
	task_to_nova(task, &eval->nt);
	eval->fields |= QUARK_RF_PID | QUARK_RF_PPID | QUARK_RF_UID | QUARK_RF_GID;
}

static __always_inline void *
output_reserve(struct output *o, __u32 head_len, __u32 total_len)
{
	struct nova_event	*ev;

	o->head_len = head_len;
	o->total_len = total_len;
	o->var_off = o->head_len;

	if (bpf_ringbuf_reserve_dynptr(&output_ring,
	    o->total_len, 0, &o->dptr) != 0)
		return (NULL);

	if ((ev = bpf_dynptr_data(&o->dptr, 0, head_len)) == NULL)
		return (NULL);

	__builtin_memset(ev, 0, head_len);

	ev->ts = bpf_ktime_get_ns();
	ev->ts_boot = ktime_get_boot_ns();

	return (ev);
}

static __always_inline void
output_discard(struct output *o)
{
	bpf_ringbuf_discard_dynptr(&o->dptr, 0);
}

/*
 * Writes src into output, fills in nv with offsets so userland can fetch it,
 * src_len_max is max storage len of src_len.
 */
static __always_inline long
output_vl_write(struct output *o, struct nova_vl *nv,
    void *src, __u32 src_len, const __u32 src_len_max)
{
	long err;

	nv->len = 0;
	nv->off = 0;

	if (src_len == 0)
		return (0);
	if (src_len > src_len_max)
		return (-E2BIG);

	err = bpf_dynptr_write(&o->dptr, o->var_off, src, src_len, 0);
	if (err != 0)
		return (err);

	nv->len = src_len;
	nv->off = o->var_off;
	o->var_off += src_len;

	return (0);
}

/*
 * Writes path into output, fills in nv.
 */
static __always_inline long
output_vl_path(struct output *o, struct nova_vl *nv, struct eval_path *src)
{
	return (output_vl_write(o, nv, src->full, src->full_len, PATH_MAX));
}

static __always_inline void
output_submit(struct output *o)
{
	bpf_ringbuf_submit_dynptr(&o->dptr, 0);
}

static int
output_task_event(__u16 kind, struct eval *eval)
{
	struct output		 o;
	struct nova_task_event	*nte;

	nte = output_reserve(&o, sizeof(*nte),
	    sizeof(*nte) + eval->exe.full_len + eval->cwd.full_len);
	if (nte == NULL)
		goto discard;
	/*
	 * Borrow nova_task from eval
	 */
	nte->nt = eval->nt;
	if (output_vl_path(&o, &nte->nt.vl_exe, &eval->exe) != 0)
		goto discard;
	if (output_vl_path(&o, &nte->nt.vl_cwd, &eval->cwd) != 0)
		goto discard;

	nte->ev.kind = kind;

	output_submit(&o);

	return (0);

discard:
	output_discard(&o);

	return (-1);
}

static int
bprm_check1(struct linux_binprm *bprm, int ret)
{
	struct task_struct	*task = bpf_get_current_task_btf();
	struct eval		*eval;
	int			 r;

	if ((eval = eval_init()) == NULL)
		return (0);
	eval_init_task(eval, task);

	if (bprm->file == NULL)
		goto noexe;

	if (eval_path_prepare(&eval->exe, &bprm->file->f_path, EP_ALL) != 0) {
		bpf_printk("can't make executable 1");
		goto noexe;
	}

	eval->fields |= QUARK_RF_EXE;
noexe:
	if (eval_path_prepare(&eval->cwd, &task->fs->pwd, EP_BASIC) != 0)
		bpf_printk("can't cwd");

	r = eval_run(eval);

	if (r != QUARK_RA_PASS)
		goto done;

	if (output_task_event(NOVA_EXEC, eval) == -1)
		bpf_printk("can't output NOVA_EXEC");

done:
	return (ret);	/* Always pass for now */
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

/*
 * TODO this is wrong, task_alloc() happens before pid allocation, so we have to
 * emit the event _after_ in another probe, but we have to block and collect
 * executable here.
 */
static int
task_alloc1(struct task_struct *task, int ret)
{
	struct eval		*eval;
	int			 r;

	if ((eval = eval_init()) == NULL)
		return (0);
	eval_init_task(eval, task);

	if (eval_path_prepare(&eval->exe, &task->mm->exe_file->f_path,
	    EP_ALL) != 0) {
		bpf_printk("can't make executable 1");
		goto noexe;
	}
	eval->fields |= QUARK_RF_EXE;
noexe:
	if (eval_path_prepare(&eval->cwd, &task->fs->pwd, EP_BASIC) != 0)
		bpf_printk("can't cwd");

	r = eval_run(eval);

	if (r != QUARK_RA_PASS)
		goto done;

	if (output_task_event(NOVA_FORK, eval) == -1)
		bpf_printk("can't output NOVA_FORK");

done:
	return (ret);	/* Always pass for now */
}

SEC("lsm/task_alloc")
int
BPF_PROG(task_alloc, struct task_struct *child, unsigned long clone_flags,
    int ret)
{
	int	r;

	preempt_disable();
	r = task_alloc1(child, ret);
	preempt_enable();

	return (r);
}

static int
task_exit1(struct task_struct *task)
{
	struct eval *eval;
	int          r;

	if ((eval = eval_init()) == NULL)
		return (0);
	eval_init_task(eval, task);

	eval->nt.exit_code = BPF_CORE_READ(task, exit_code);

	r = eval_run(eval);
	if (r != QUARK_RA_PASS)
		return (0);

	if (output_task_event(NOVA_EXIT, eval) == -1)
		bpf_printk("can't output NOVA_EXIT");

	return (0);
}

SEC("tp_btf/sched_process_exit")
int
BPF_PROG(sched_exit, struct task_struct *task)
{
	int r;

	preempt_disable();
	r = task_exit1(task);
	preempt_enable();

	return (r);
}


#pragma GCC diagnostic pop

char _license[] SEC("license") = "Dual BSD/GPL";
