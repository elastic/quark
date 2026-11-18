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

static void
probe_prologue(void)
{
	preempt_disable();
}

static void
probe_epilogue(void)
{
	preempt_enable();
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
	/* The lines of a block are not rules of this loop, see blk_decide() */
	if (rule->action == QUARK_RA_BLOCK_ON ||
	    rule->action == QUARK_RA_BLOCK_EXCEPT)
		return (LOOP_CONTINUE);
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

	ev->ts = bpf_ktime_get_boot_ns();

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

	probe_prologue();
	r = bprm_check1(bprm, ret);
	probe_epilogue();

	return (r);
}

/*
 * TODO stop evaluating things twice, store the result from the lsm probe
 * somewhere and retrieve here.
 */
static int
sched_process_fork1(struct task_struct *parent, struct task_struct *child)
{
	struct eval		*eval;
	int			 r;

	if ((eval = eval_init()) == NULL)
		return (0);
	eval_init_task(eval, child);

	r = eval_run(eval);

	if (r != QUARK_RA_PASS)
		goto done;

	/*
	 * TODO: missing cwd
	 */

	if (output_task_event(NOVA_FORK, eval) == -1)
		bpf_printk("can't output NOVA_FORK");

done:
	return (0);
}

SEC("tp_btf/sched_process_fork")
int
BPF_PROG(sched_process_fork, struct task_struct *parent,
    struct task_struct *child)
{
	int	r;

	probe_prologue();
	r = sched_process_fork1(parent, child);
	probe_epilogue();

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

	/* output emited from sched_proc_fork */

done:
	return (ret);	/* Always pass for now */
}

SEC("lsm/task_alloc")
int
BPF_PROG(task_alloc, struct task_struct *child, unsigned long clone_flags,
    int ret)
{
	int	r;

	probe_prologue();
	r = task_alloc1(child, ret);
	probe_epilogue();

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

	probe_prologue();
	r = task_exit1(task);
	probe_epilogue();

	return (r);
}

/*
 * Blocks: deny an operation of a process in a container when a block of
 * the ruleset matches it. The blocks are compiled in userspace, see
 * block.c: every line of every block is one bit, and each field gives the
 * set of lines that accept its value. A hook ANDs these sets into M, the
 * lines that match, and a block denies when (on & M) != 0 and
 * (except & M) == 0.
 *
 * The programs below are separate from the ones above, which they don't
 * need: a block works with them not loaded. They use nothing newer than
 * bpf_loop(), Linux 5.17.
 */

#define EPERM			1
#define BLK_CLONE_THREAD	0x00010000
#define BLK_PF_KTHREAD		0x00200000

/* Set before load, 0 blocks makes the hooks return at once */
const volatile __u32	blk_n_blocks;
const volatile __u64	blk_dc_exe;		/* lines without process.exe */
const volatile __u64	blk_dc_file;		/* lines without file.path */
const volatile __u64	blk_dc_container;	/* lines without a container field */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct nova_block);
	__uint(max_entries, NOVA_MAX_BLOCKS);
} blk_blocks SEC(".maps");

/* Lines whose container fields match, by container id */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct nova_block_cid);
	__type(value, __u64);
	__uint(max_entries, NOVA_BLOCK_MAX_CONTAINERS);
} blk_container SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct nova_block_path_key);
	__type(value, __u64);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, NOVA_BLOCK_MAX_PATHS);
} blk_path_exe SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct nova_block_path_key);
	__type(value, __u64);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, NOVA_BLOCK_MAX_PATHS);
} blk_path_file SEC(".maps");

/* Denied operations, struct nova_deny_event */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} blk_ring SEC(".maps");

/* Denials of each block */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, NOVA_MAX_BLOCKS);
} blk_denied SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct nova_block_stats);
	__uint(max_entries, 1);
} blk_stats SEC(".maps");

static __always_inline int
blk_prefix(const char *s, const char *prefix, int len)
{
	int	i;

	for (i = 0; i < len; i++) {
		if (s[i] != prefix[i])
			return (0);
	}

	return (1);
}

/*
 * The container id in the name of a cgroup, <prefix><id>.scope with a
 * lowercase hex id, the rule of container_scope_lookup() in quark.c. n is
 * what the read of name returned, the length with the NUL. Returns 0 and
 * fills cid for a container, -1 otherwise.
 */
static __always_inline int
blk_parse_cgroup(const char *name, long n, struct nova_block_cid *cid)
{
	__u32	len, plen, id_len, i;
	char	c;

	/* A full buffer may be a cut name */
	if (n < 8 || n >= NOVA_CGROUP_NAMELEN)
		return (-1);
	len = n - 1;

	i = (len - 6) & (NOVA_CGROUP_NAMELEN - 1);
	if (i > NOVA_CGROUP_NAMELEN - 7)
		return (-1);
	if (name[i] != '.' || name[i + 1] != 's' || name[i + 2] != 'c' ||
	    name[i + 3] != 'o' || name[i + 4] != 'p' || name[i + 5] != 'e')
		return (-1);

	if (blk_prefix(name, "cri-containerd-", 15))
		plen = 15;
	else if (blk_prefix(name, "containerd-", 11))
		plen = 11;
	else if (blk_prefix(name, "docker-", 7))
		plen = 7;
	else if (blk_prefix(name, "libpod-", 7))
		plen = 7;
	else if (blk_prefix(name, "crio-", 5))
		plen = 5;
	else
		return (-1);

	if (len <= plen + 6)
		return (-1);
	id_len = len - plen - 6;
	if (id_len > NOVA_CONTAINER_IDLEN)
		return (-1);
	__builtin_memset(cid, 0, sizeof(*cid));
	for (i = 0; i < NOVA_CONTAINER_IDLEN; i++) {
		if (i >= id_len)
			break;
		c = name[(plen + i) & (NOVA_CGROUP_NAMELEN - 1)];
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
			return (-1);
		cid->id[i] = c;
	}

	return (0);
}

/*
 * The lines that the container fields allow. A container without an entry
 * has no metadata yet, or is not known to kubernetes: only the lines
 * without container fields.
 */
static __always_inline __u64
blk_container_lines(struct nova_block_cid *cid)
{
	__u64	*v;

	v = bpf_map_lookup_elem(&blk_container, cid);

	return (v != NULL ? *v : blk_dc_container);
}

/*
 * The container lines of the current task, from the name of its pids
 * cgroup, the cgroup that the EBPF backend reports. -1 if the task is not
 * in a container, then no block applies. The buffers are on the stack of
 * this function, so it must not be inlined.
 */
static __noinline int
blk_cbits_task(__u64 *bits)
{
	char			 name[NOVA_CGROUP_NAMELEN];
	struct nova_block_cid	 cid;
	struct task_struct	*task;
	const char		*kname;
	long			 n;
	int			 cgrp_id;

	if (!bpf_core_enum_value_exists(enum cgroup_subsys_id, pids_cgrp_id))
		return (-1);
	cgrp_id = bpf_core_enum_value(enum cgroup_subsys_id, pids_cgrp_id);
	task = (struct task_struct *)bpf_get_current_task();
	kname = BPF_CORE_READ(task, cgroups, subsys[cgrp_id], cgroup, kn, name);
	n = bpf_probe_read_kernel_str(name, sizeof(name), kname);
	if (blk_parse_cgroup(name, n, &cid) != 0)
		return (-1);
	*bits = blk_container_lines(&cid);

	return (0);
}

/*
 * The lines that accept the executable. -1 if the path can't be had, also
 * when it does not fit in the key. The key is on the stack of this
 * function, so it must not be inlined.
 */
static __noinline int
blk_exe_bits(struct path *path, __u64 *bits)
{
	struct nova_block_path_key	 key;
	__u64				*v;

	__builtin_memset(&key, 0, sizeof(key));
	key.prefixlen = NOVA_PATHLEN * 8;
	if (bpf_d_path(path, key.path, NOVA_PATHLEN) < 0)
		return (-1);
	v = bpf_map_lookup_elem(&blk_path_exe, &key);
	*bits = v != NULL ? *v : 0;

	return (0);
}

/*
 * The lines that match an operation: m are the lines of the container,
 * bits the lines that accept the path. A line with a path field does not
 * match without a path, and a line about files never matches a process
 * operation, or the other way around.
 */
static __always_inline __u64
blk_match(__u64 m, int file, int has_path, __u64 bits)
{
	if (!has_path)
		bits = 0;
	if (file) {
		m &= bits | blk_dc_file;
		m &= blk_dc_exe;
	} else {
		m &= bits | blk_dc_exe;
		m &= blk_dc_file;
	}

	return (m);
}

struct blk_decide {
	__u64	m;
	__s32	block;
	__u32	pad0;
};

static long
blk_decide_cb(__u32 i, struct blk_decide *d)
{
	struct nova_block	*blk;

	if ((blk = bpf_map_lookup_elem(&blk_blocks, &i)) == NULL)
		return (LOOP_STOP);
	if ((blk->on & d->m) != 0 && (blk->except & d->m) == 0) {
		d->block = i;
		return (LOOP_STOP);
	}

	return (LOOP_CONTINUE);
}

/* The first block that denies with these lines, or -1 */
static __always_inline int
blk_decide(__u64 m)
{
	struct blk_decide	d;

	d.m = m;
	d.block = -1;
	d.pad0 = 0;
	if (m != 0)
		bpf_loop(blk_n_blocks, blk_decide_cb, &d, 0);

	return (d.block);
}

static __always_inline void
blk_count_denied(__u32 block)
{
	__u64	*v;

	if ((v = bpf_map_lookup_elem(&blk_denied, &block)) != NULL)
		(*v)++;
}

static __always_inline void
blk_count_no_path(void)
{
	struct nova_block_stats	*st;

	if ((st = bpf_map_lookup_elem(&blk_stats, &(__u32){0})) != NULL)
		st->no_path++;
}

/*
 * Tell userspace about a denied operation: a record in the ring, for the
 * caller to add the paths and submit. The operation is denied whatever
 * happens here: a full ring buffer must not switch a block off, the report
 * is counted as lost and this returns NULL.
 */
static __always_inline struct nova_deny_event *
blk_report(__u32 op, __u32 block)
{
	struct nova_deny_event	*ev;
	struct nova_block_stats	*st;
	__u64			 id;

	if ((ev = bpf_ringbuf_reserve(&blk_ring, sizeof(*ev), 0)) == NULL) {
		if ((st = bpf_map_lookup_elem(&blk_stats, &(__u32){0})) != NULL)
			st->lost++;
		return (NULL);
	}
	__builtin_memset(ev, 0, sizeof(*ev));
	ev->ev.kind = NOVA_DENY;
	ev->ev.ts = bpf_ktime_get_boot_ns();
	ev->op = op;
	ev->block = block;
	id = bpf_get_current_pid_tgid();
	ev->pid = id >> 32;
	ev->tid = (__u32)id;
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));

	return (ev);
}

/* A fork or an exec with this executable, NULL if there is none */
static __always_inline int
blk_process(__u32 op, struct path *exe, int has_exe)
{
	struct nova_deny_event	*ev;
	__u64			 m, bits = 0;
	int			 block;

	if (blk_cbits_task(&m) != 0)
		return (0);
	if (has_exe && blk_exe_bits(exe, &bits) != 0)
		has_exe = 0;
	if (!has_exe)
		blk_count_no_path();
	m = blk_match(m, 0, has_exe, bits);
	if ((block = blk_decide(m)) < 0)
		return (0);
	blk_count_denied(block);
	if ((ev = blk_report(op, block)) != NULL) {
		/* It fits and resolves, it did a moment ago for the lookup */
		if (has_exe)
			bpf_d_path(exe, ev->path, sizeof(ev->path));
		bpf_ringbuf_submit(ev, 0);
	}

	return (-EPERM);
}

/* An exec, the executable is the new program */
SEC("lsm/bprm_check_security")
int
BPF_PROG(blk_bprm_check, struct linux_binprm *bprm, int ret)
{
	struct task_struct	*task = bpf_get_current_task_btf();
	struct file		*file = bprm->file;

	if (ret != 0)
		return (ret);
	if (blk_n_blocks == 0 || (task->flags & BLK_PF_KTHREAD))
		return (0);
	if (file == NULL)
		return (blk_process(NOVA_OP_EXEC, NULL, 0));

	return (blk_process(NOVA_OP_EXEC, &file->f_path, 1));
}

/*
 * A fork, the executable is the one of the parent. The child has no pid
 * yet. A new thread is not a fork.
 */
SEC("lsm/task_alloc")
int
BPF_PROG(blk_task_alloc, struct task_struct *child, unsigned long clone_flags,
    int ret)
{
	struct task_struct	*task = bpf_get_current_task_btf();
	struct mm_struct	*mm = child->mm;
	struct file		*file;

	if (ret != 0)
		return (ret);
	if (blk_n_blocks == 0 || (clone_flags & BLK_CLONE_THREAD) ||
	    (task->flags & BLK_PF_KTHREAD))
		return (0);
	if (mm == NULL || (file = mm->exe_file) == NULL)
		return (blk_process(NOVA_OP_FORK, NULL, 0));

	return (blk_process(NOVA_OP_FORK, &file->f_path, 1));
}

/*
 * File blocks. A file hook can't use bpf_d_path(): up to Linux 6.6 only
 * file_open may call it, and path_mknod never. So the path is built here
 * from the dentries, as ebpf_resolve_path_to_string() of the EBPF backend
 * does, and both backends give the same path for a file.
 *
 * The path is built in scratch memory of the CPU. A hook can be preempted
 * by a task that runs a hook on the same CPU, so there are a few scratch
 * slots and a hook takes a free one with an atomic exchange. With no slot
 * free the operation is allowed, and counted: nova_block_stats.no_slot is
 * not zero when BLK_NSLOTS is too small.
 */

#define BLK_S_IFMT	00170000
#define BLK_S_IFREG	0100000
#define BLK_FMODE_WRITE	0x2

#define BLK_NSLOTS	4
/*
 * The verifier takes the worst case of every offset and length on its
 * own, so the buffer is twice what a path can use.
 */
#define BLK_WORKLEN	512
#define BLK_WORKMASK	255
/* Components and mount points of a path, more than fit in NOVA_PATHLEN */
#define BLK_WALK_MAX	256

struct blk_scratch {
	__u64				busy;
	struct nova_block_path_key	key[2];	/* the paths of the operation */
	/*
	 * A path is built from its end, which is at NOVA_PATHLEN - 1.
	 * Nothing is written from there on, so that part is always zero.
	 */
	char				work[BLK_WORKLEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct blk_scratch);
	__uint(max_entries, BLK_NSLOTS);
} blk_scratch SEC(".maps");

static __always_inline struct blk_scratch *
blk_scratch_try(__u32 slot)
{
	struct blk_scratch	*s;

	if ((s = bpf_map_lookup_elem(&blk_scratch, &slot)) == NULL)
		return (NULL);

	return (__sync_lock_test_and_set(&s->busy, 1) == 0 ? s : NULL);
}

/*
 * Take a free slot. Not a loop: the slot number must be in the stack for
 * the lookup, and the verifier of Linux before 6.x then loses its bounds
 * and sees a loop without an end.
 */
static __always_inline struct blk_scratch *
blk_scratch_get(__u32 *slot)
{
	struct blk_scratch	*s;

	_Static_assert(BLK_NSLOTS == 4, "one line for each slot");
	if ((s = blk_scratch_try(0)) != NULL)
		*slot = 0;
	else if ((s = blk_scratch_try(1)) != NULL)
		*slot = 1;
	else if ((s = blk_scratch_try(2)) != NULL)
		*slot = 2;
	else if ((s = blk_scratch_try(3)) != NULL)
		*slot = 3;

	return (s);
}

static __always_inline void
blk_scratch_put(struct blk_scratch *s)
{
	s->busy = 0;
}

struct blk_walk {
	struct dentry	*dentry;	/* where we are */
	struct vfsmount	*vfsmnt;
	struct mount	*mnt;
	struct dentry	*root_dentry;	/* the root of the task */
	struct vfsmount	*root_mnt;
	__u32		 slot;
	__u32		 pos;		/* start of the path in work */
	__u32		 done;
	__u32		 pad0;
};

/* One step up: put the name of a dentry in front of the path */
static long
blk_walk_cb(__u32 i, struct blk_walk *w)
{
	struct blk_scratch	*s;
	struct dentry		*dentry = w->dentry, *parent;
	struct vfsmount		*vfsmnt = w->vfsmnt;
	struct mount		*mnt = w->mnt, *parent_mnt;
	struct qstr		 name;
	__u32			 len, pos, slot = w->slot;

	if (dentry == w->root_dentry && vfsmnt == w->root_mnt) {
		w->done = 1;
		return (LOOP_STOP);
	}
	parent = BPF_CORE_READ(dentry, d_parent);
	if (dentry == parent || dentry == BPF_CORE_READ(vfsmnt, mnt_root)) {
		parent_mnt = BPF_CORE_READ(mnt, mnt_parent);
		/*
		 * The root of a mount without a parent: the file is not
		 * below the root of the task. As d_path(), stop with the
		 * path in that mount.
		 */
		if (parent_mnt == mnt) {
			w->done = 1;
			return (LOOP_STOP);
		}
		/* The root of a mount, go on from where it is mounted */
		w->dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
		w->mnt = parent_mnt;
		w->vfsmnt = &parent_mnt->mnt;
		return (LOOP_CONTINUE);
	}

	name = BPF_CORE_READ(dentry, d_name);
	len = name.len;
	pos = w->pos;
	/* Too long for a line to match */
	if (len == 0 || len > BLK_WORKMASK || len + 1 > pos)
		return (LOOP_STOP);
	pos = (pos - len - 1) & BLK_WORKMASK;
	if ((s = bpf_map_lookup_elem(&blk_scratch, &slot)) == NULL)
		return (LOOP_STOP);
	s->work[pos] = '/';
	if (bpf_probe_read_kernel(&s->work[pos + 1], len & BLK_WORKMASK,
	    name.name) != 0)
		return (LOOP_STOP);
	w->pos = pos;
	w->dentry = parent;

	return (LOOP_CONTINUE);
}

/*
 * The path of a file as the task sees it, from its root, in key i of the
 * scratch slot, ready for a lookup. -1 if the path can't be had, also when
 * it does not fit in the key.
 */
static __noinline int
blk_file_path(__u32 slot, __u32 i, struct vfsmount *vfsmnt,
    struct dentry *dentry)
{
	struct blk_scratch		*s;
	struct nova_block_path_key	*key;
	struct task_struct		*task;
	const struct dentry_operations	*d_op;
	struct blk_walk			 w;
	struct path			 root;
	struct qstr			 name;
	__u32				 pos;
	long				 n;

	if (vfsmnt == NULL || dentry == NULL)
		return (-1);
	if ((s = bpf_map_lookup_elem(&blk_scratch, &slot)) == NULL)
		return (-1);
	key = &s->key[i & 1];
	__builtin_memset(key, 0, sizeof(*key));
	key->prefixlen = NOVA_PATHLEN * 8;

	/*
	 * A file that is in no directory, a memfd: its name alone, as
	 * d_path() gives it through d_dname().
	 */
	d_op = BPF_CORE_READ(dentry, d_op);
	if (dentry == BPF_CORE_READ(dentry, d_parent) && d_op != NULL &&
	    BPF_CORE_READ(d_op, d_dname) != NULL) {
		name = BPF_CORE_READ(dentry, d_name);
		n = bpf_probe_read_kernel_str(key->path, NOVA_PATHLEN,
		    name.name);
		/* A full buffer may be a cut name */
		return (n > 0 && n < NOVA_PATHLEN ? 0 : -1);
	}

	task = (struct task_struct *)bpf_get_current_task();
	root = BPF_CORE_READ(task, fs, root);
	w.dentry = dentry;
	w.vfsmnt = vfsmnt;
	/* container_of(), which the warnings of this file don't take */
	w.mnt = (struct mount *)((char *)vfsmnt - offsetof(struct mount, mnt));
	w.root_dentry = root.dentry;
	w.root_mnt = root.mnt;
	w.slot = slot;
	w.pos = NOVA_PATHLEN - 1;
	w.done = 0;
	w.pad0 = 0;
	bpf_loop(BLK_WALK_MAX, blk_walk_cb, &w, 0);
	if (!w.done)
		return (-1);
	pos = w.pos;
	/* The root itself has no name */
	if (pos >= NOVA_PATHLEN - 1) {
		pos = NOVA_PATHLEN - 2;
		s->work[NOVA_PATHLEN - 2] = '/';
	}
	pos &= BLK_WORKMASK;
	/* The path and the zeroes after it */
	if (bpf_probe_read_kernel(key->path, NOVA_PATHLEN, &s->work[pos]) != 0)
		return (-1);

	return (0);
}

/* The lines that accept the path in key i */
static __always_inline __u64
blk_file_bits(struct blk_scratch *s, __u32 i)
{
	__u64	*v;

	v = bpf_map_lookup_elem(&blk_path_file, &s->key[i & 1]);

	return (v != NULL ? *v : 0);
}

/*
 * An operation on a file, or on two for a rename and a link: one denial
 * is enough. Both paths are resolved first, the report has both.
 */
static __always_inline int
blk_file(__u32 op, struct vfsmount *mnt, struct dentry *dentry,
    struct vfsmount *mnt2, struct dentry *dentry2, int two)
{
	struct nova_deny_event	*ev;
	struct nova_block_stats	*st;
	struct blk_scratch	*s;
	__u64			 cm, bits = 0, bits2 = 0;
	__u32			 slot = 0;
	int			 has = 0, has2 = 0, block, ret = 0;

	if (blk_cbits_task(&cm) != 0)
		return (0);
	if ((s = blk_scratch_get(&slot)) == NULL) {
		if ((st = bpf_map_lookup_elem(&blk_stats, &(__u32){0})) != NULL)
			st->no_slot++;
		return (0);
	}
	if (blk_file_path(slot, 0, mnt, dentry) == 0) {
		has = 1;
		bits = blk_file_bits(s, 0);
	}
	if (two && blk_file_path(slot, 1, mnt2, dentry2) == 0) {
		has2 = 1;
		bits2 = blk_file_bits(s, 1);
	}
	if (!has || (two && !has2))
		blk_count_no_path();

	block = blk_decide(blk_match(cm, 1, has, bits));
	if (block < 0 && two)
		block = blk_decide(blk_match(cm, 1, has2, bits2));
	if (block >= 0) {
		blk_count_denied(block);
		if ((ev = blk_report(op, block)) != NULL) {
			if (has)
				bpf_probe_read_kernel(ev->path,
				    sizeof(ev->path), s->key[0].path);
			if (has2)
				bpf_probe_read_kernel(ev->path2,
				    sizeof(ev->path2), s->key[1].path);
			bpf_ringbuf_submit(ev, 0);
		}
		ret = -EPERM;
	}
	blk_scratch_put(s);

	return (ret);
}

static __always_inline int
blk_is_reg(umode_t mode)
{
	return ((mode & BLK_S_IFMT) == BLK_S_IFREG);
}

/*
 * The hooks below are the ones of cloud-defend, with its filters, and
 * file_truncate. They are loaded only for a ruleset with a block on
 * file.path.
 */

/*
 * A new file, also from an open. mknod(2) without a file type makes a
 * regular file.
 */
SEC("lsm/path_mknod")
int
BPF_PROG(blk_path_mknod, const struct path *dir, struct dentry *dentry,
    umode_t mode, unsigned int dev, int ret)
{
	if (ret != 0)
		return (ret);
	if (!blk_is_reg(mode) && (mode & BLK_S_IFMT) != 0)
		return (0);

	return (blk_file(NOVA_OP_CREATE, BPF_CORE_READ(dir, mnt), dentry,
	    NULL, NULL, 0));
}

SEC("lsm/path_chmod")
int
BPF_PROG(blk_path_chmod, const struct path *path, umode_t mode, int ret)
{
	if (ret != 0)
		return (ret);
	if (!blk_is_reg(BPF_CORE_READ(path, dentry, d_inode, i_mode)))
		return (0);

	return (blk_file(NOVA_OP_CHMOD, BPF_CORE_READ(path, mnt),
	    BPF_CORE_READ(path, dentry), NULL, NULL, 0));
}

/* An open for writing, a read is not denied */
SEC("lsm/file_open")
int
BPF_PROG(blk_file_open, struct file *file, int ret)
{
	if (ret != 0)
		return (ret);
	if (!(BPF_CORE_READ(file, f_mode) & BLK_FMODE_WRITE) ||
	    !blk_is_reg(BPF_CORE_READ(file, f_inode, i_mode)))
		return (0);

	return (blk_file(NOVA_OP_OPEN, BPF_CORE_READ(file, f_path.mnt),
	    BPF_CORE_READ(file, f_path.dentry), NULL, NULL, 0));
}

SEC("lsm/path_truncate")
int
BPF_PROG(blk_path_truncate, const struct path *path, int ret)
{
	if (ret != 0)
		return (ret);
	if (!blk_is_reg(BPF_CORE_READ(path, dentry, d_inode, i_mode)))
		return (0);

	return (blk_file(NOVA_OP_TRUNCATE, BPF_CORE_READ(path, mnt),
	    BPF_CORE_READ(path, dentry), NULL, NULL, 0));
}

/*
 * Since Linux 6.2 a truncate through an open file is this hook and not
 * path_truncate: ftruncate(2), and open(2) with O_TRUNC, which also
 * truncates a file that is opened for reading. Cloud-defend does not have
 * it. It is loaded where the kernel has the hook.
 */
SEC("lsm/file_truncate")
int
BPF_PROG(blk_file_truncate, struct file *file, int ret)
{
	if (ret != 0)
		return (ret);
	if (!blk_is_reg(BPF_CORE_READ(file, f_inode, i_mode)))
		return (0);

	return (blk_file(NOVA_OP_TRUNCATE, BPF_CORE_READ(file, f_path.mnt),
	    BPF_CORE_READ(file, f_path.dentry), NULL, NULL, 0));
}

/*
 * A rename takes a file away from the old path and makes one at the new
 * path, so both are tested. The hook got a fifth argument in Linux 5.19,
 * which moves the result of the hooks before us: there is one program for
 * each form, and block_programs() in nova_queue.c loads the one of the
 * running kernel.
 */
SEC("lsm/path_rename")
int
BPF_PROG(blk_path_rename, const struct path *old_dir,
    struct dentry *old_dentry, const struct path *new_dir,
    struct dentry *new_dentry, unsigned int flags, int ret)
{
	if (ret != 0)
		return (ret);

	return (blk_file(NOVA_OP_RENAME, BPF_CORE_READ(old_dir, mnt),
	    old_dentry, BPF_CORE_READ(new_dir, mnt), new_dentry, 1));
}

SEC("lsm/path_rename")
int
BPF_PROG(blk_path_rename4, const struct path *old_dir,
    struct dentry *old_dentry, const struct path *new_dir,
    struct dentry *new_dentry, int ret)
{
	if (ret != 0)
		return (ret);

	return (blk_file(NOVA_OP_RENAME, BPF_CORE_READ(old_dir, mnt),
	    old_dentry, BPF_CORE_READ(new_dir, mnt), new_dentry, 1));
}

/*
 * A hard link is a new name for the file, and a way to change it under
 * that name: the file and the new path are tested. Both are in the mount
 * of the new directory.
 */
SEC("lsm/path_link")
int
BPF_PROG(blk_path_link, struct dentry *old_dentry, const struct path *new_dir,
    struct dentry *new_dentry, int ret)
{
	struct vfsmount	*mnt;

	if (ret != 0)
		return (ret);
	mnt = BPF_CORE_READ(new_dir, mnt);

	return (blk_file(NOVA_OP_LINK, mnt, old_dentry, mnt, new_dentry, 1));
}

SEC("lsm/path_unlink")
int
BPF_PROG(blk_path_unlink, const struct path *dir, struct dentry *dentry,
    int ret)
{
	if (ret != 0)
		return (ret);

	return (blk_file(NOVA_OP_UNLINK, BPF_CORE_READ(dir, mnt), dentry,
	    NULL, NULL, 0));
}

/*
 * The test program, run with BPF_PROG_TEST_RUN: evaluate the blocks for
 * the operation in the struct nova_block_test that the first argument
 * points to, in user memory, with the code of the hooks. A raw tracepoint
 * program, as a syscall program can't use the tries.
 */
static __noinline int
blk_test_cbits(const char *ucgroup, __u64 *bits)
{
	char			name[NOVA_CGROUP_NAMELEN];
	struct nova_block_cid	cid;
	long			n;

	n = bpf_probe_read_user_str(name, sizeof(name), ucgroup);
	if (blk_parse_cgroup(name, n, &cid) != 0)
		return (-1);
	*bits = blk_container_lines(&cid);

	return (0);
}

static __noinline int
blk_test_path_bits(const char *upath, int file, __u64 *bits)
{
	struct nova_block_path_key	 key;
	__u64				*v;

	__builtin_memset(&key, 0, sizeof(key));
	key.prefixlen = NOVA_PATHLEN * 8;
	if (bpf_probe_read_user_str(key.path, NOVA_PATHLEN, upath) < 0)
		return (-1);
	if (file)
		v = bpf_map_lookup_elem(&blk_path_file, &key);
	else
		v = bpf_map_lookup_elem(&blk_path_exe, &key);
	*bits = v != NULL ? *v : 0;

	return (0);
}

SEC("raw_tp")
int
BPF_PROG(blk_test, const char *in)
{
	struct {
		__u32	kind;
		__u32	flags;
		__u64	cbits;
	} hdr;
	__u64		 m, bits = 0;
	int		 file, has_path, block;

	if (bpf_probe_read_user(&hdr, sizeof(hdr), in) != 0)
		return (NOVA_BT_FAULT);
	file = hdr.kind == NOVA_BT_FILE;
	has_path = (hdr.flags & NOVA_BT_HAS_PATH) != 0;

	if (hdr.flags & NOVA_BT_HAS_CBITS)
		m = hdr.cbits;
	else if (blk_test_cbits(in +
	    __builtin_offsetof(struct nova_block_test, cgroup), &m) != 0)
		return (NOVA_BT_NOT_CONTAINER);
	if (has_path && blk_test_path_bits(in +
	    __builtin_offsetof(struct nova_block_test, path), file, &bits) != 0)
		return (NOVA_BT_FAULT);
	m = blk_match(m, file, has_path, bits);
	block = blk_decide(m);

	return (block < 0 ? NOVA_BT_ALLOW : 1 + block);
}

#pragma GCC diagnostic pop

char _license[] SEC("license") = "Dual BSD/GPL";
