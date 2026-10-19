// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2021 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "Dedup.h"
#include "File.h"
#include "Helpers.h"
#include "PathResolver.h"
#include "State.h"
#include "Varlen.h"

// Set from userspace when QQ_FILE is enabled. The do_filp_open() return is
// shared with file_access, which loads it on its own; the file event side of
// that hook (create, memfd and shmem opens) is behind this flag so that
// file_access alone does not emit file events.
const volatile bool file_events_enabled = false;

/* vfs_unlink */
DECL_FUNC_ARG(vfs_unlink, dentry);
DECL_FUNC_RET(vfs_unlink);
/* vfs_rename */
DECL_FUNC_ARG(vfs_rename, old_dentry);
DECL_FUNC_ARG(vfs_rename, new_dentry);
DECL_FUNC_RET(vfs_rename);
DECL_FUNC_ARG_EXISTS(vfs_rename, rd);
/* do_truncate */
DECL_FUNC_ARG(do_truncate, filp);
DECL_FUNC_RET(do_truncate);

static int do_unlinkat__enter()
{
    struct ebpf_events_state state = {};
    state.unlink.step              = UNLINK_STATE_INIT;
    if (ebpf_events_is_trusted_pid()) {
        return 0;
    }
    ebpf_events_state__set(EBPF_EVENTS_STATE_UNLINK, &state);
    return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(fentry__do_unlinkat)
{
    int r;

    preempt_disable();
    r = do_unlinkat__enter();
    preempt_enable();

    return r;
}

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(kprobe__do_unlinkat)
{
    int r;

    preempt_disable();
    r = do_unlinkat__enter();
    preempt_enable();

    return r;
}

SEC("fentry/filename_unlinkat")
int BPF_PROG(fentry__filename_unlinkat)
{
    int r;

    preempt_disable();
    r = do_unlinkat__enter();
    preempt_enable();

    return r;
}

SEC("kprobe/filename_unlinkat")
int BPF_KPROBE(kprobe__filename_unlinkat)
{
    int r;

    preempt_disable();
    r = do_unlinkat__enter();
    preempt_enable();

    return r;
}

/*
 * The unlink state is normally deleted by vfs_unlink__exit() once the event
 * is emitted, but that never runs when the unlink fails, be it in path lookup
 * or in vfs_unlink() itself. A stale entry would then shadow the rename state
 * in mnt_want_write__enter() and every later rename on this thread would be
 * lost, so always reap it when the syscall returns.
 */
static int do_unlinkat__exit()
{
    ebpf_events_state__del(EBPF_EVENTS_STATE_UNLINK);
    return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(fexit__do_unlinkat)
{
    int r;

    preempt_disable();
    r = do_unlinkat__exit();
    preempt_enable();

    return r;
}

SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(kretprobe__do_unlinkat)
{
    int r;

    preempt_disable();
    r = do_unlinkat__exit();
    preempt_enable();

    return r;
}

SEC("fexit/filename_unlinkat")
int BPF_PROG(fexit__filename_unlinkat)
{
    int r;

    preempt_disable();
    r = do_unlinkat__exit();
    preempt_enable();

    return r;
}

SEC("kretprobe/filename_unlinkat")
int BPF_KRETPROBE(kretprobe__filename_unlinkat)
{
    int r;

    preempt_disable();
    r = do_unlinkat__exit();
    preempt_enable();

    return r;
}

static int mnt_want_write__enter(struct vfsmount *mnt)
{
    struct ebpf_events_state *state = NULL;

    state = ebpf_events_state__get(EBPF_EVENTS_STATE_UNLINK);
    if (state) {
        // Certain filesystems (eg. overlayfs) call mnt_want_write
        // multiple times during the same execution context.
        // Only take into account the first invocation.
        if (state->unlink.step != UNLINK_STATE_INIT)
            goto out;
        state->unlink.mnt  = mnt;
        state->unlink.step = UNLINK_STATE_MOUNT_SET;
        goto out;
    }

    state = ebpf_events_state__get(EBPF_EVENTS_STATE_RENAME);
    if (state) {
        // Certain filesystems (eg. overlayfs) call mnt_want_write
        // multiple times during the same execution context.
        // Only take into account the first invocation.
        if (state->rename.step != RENAME_STATE_INIT)
            goto out;
        state->rename.mnt  = mnt;
        state->rename.step = RENAME_STATE_MOUNT_SET;
        goto out;
    }

out:
    return 0;
}

SEC("fentry/mnt_want_write")
int BPF_PROG(fentry__mnt_want_write, struct vfsmount *mnt)
{
    int r;

    preempt_disable();
    r = mnt_want_write__enter(mnt);
    preempt_enable();

    return r;
}

SEC("kprobe/mnt_want_write")
int BPF_KPROBE(kprobe__mnt_want_write, struct vfsmount *mnt)
{
    int r;

    preempt_disable();
    r = mnt_want_write__enter(mnt);
    preempt_enable();

    return r;
}

static int vfs_unlink__exit(int ret)
{
    if (ret != 0)
        goto out;

    struct ebpf_events_state *state = ebpf_events_state__get(EBPF_EVENTS_STATE_UNLINK);
    if (!state || state->unlink.step != UNLINK_STATE_DENTRY_SET) {
        // Omit logging as this happens in the happy path.
        goto out;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct ebpf_file_delete_event *event = get_event_buffer();
    if (!event) {
        bpf_printk("vfs_unlink__exit: failed to reserve event\n");
        goto out;
    }

    event->hdr.type    = EBPF_EVENT_FILE_DELETE;
    event->hdr.ts      = bpf_ktime_get_boot_ns();
    ebpf_pid_info__fill(&event->pids, task);
    ebpf_cred_info__fill(&event->creds, task);

    struct path p;
    p.dentry = &state->unlink.de;
    p.mnt    = state->unlink.mnt;
    struct ebpf_namespace_info ns;
    ebpf_ns__fill(&ns, task);
    event->mntns = ns.mnt_inonum;
    bpf_get_current_comm(event->comm, TASK_COMM_LEN);
    ebpf_file_info__fill(&event->finfo, p.dentry);

    // Variable length fields
    ebpf_vl_fields__init(&event->vl_fields);
    struct ebpf_varlen_field *field;
    long size;

    // path
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_PATH);
    size  = ebpf_resolve_path_to_string(field->data, &p, task);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    // symlink_target_path
    field      = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_SYMLINK_TARGET_PATH);
    char *link = BPF_CORE_READ(p.dentry, d_inode, i_link);
    size       = read_kernel_str_or_empty_str(field->data, PATH_MAX, link);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    // pids ss cgroup path
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_PIDS_SS_CGROUP_PATH);
    size  = ebpf_resolve_pids_ss_cgroup_path_to_string(field->data, task);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    ebpf_ringbuf_write(&ringbuf, event, EVENT_SIZE(event), 0);

    // Certain filesystems (eg. overlayfs) call vfs_unlink twice during the same
    // execution context.
    // In order to not emit a second event, delete the state explicitly.
    ebpf_events_state__del(EBPF_EVENTS_STATE_UNLINK);

out:
    return 0;
}

SEC("fexit/vfs_unlink")
int BPF_PROG(fexit__vfs_unlink)
{
    int ret, r;

    preempt_disable();
    ret = FUNC_RET_READ(___type(ret), vfs_unlink);
    r = vfs_unlink__exit(ret);
    preempt_enable();

    return r;
}

SEC("kretprobe/vfs_unlink")
int BPF_KRETPROBE(kretprobe__vfs_unlink, int ret)
{
    int r;

    preempt_disable();
    r = vfs_unlink__exit(ret);
    preempt_enable();

    return r;
}

static int vfs_unlink__enter(struct dentry *de)
{
    struct ebpf_events_state *state = ebpf_events_state__get(EBPF_EVENTS_STATE_UNLINK);
    if (!state || state->unlink.step != UNLINK_STATE_MOUNT_SET) {
        // Omit logging as this happens in the happy path.
        goto out;
    }

    if (bpf_core_read(&state->unlink.de, sizeof(struct dentry), de)) {
        bpf_printk("vfs_unlink__enter: failed to read dentry\n");
        goto out;
    }
    state->unlink.step = UNLINK_STATE_DENTRY_SET;

out:
    return 0;
}

SEC("fentry/vfs_unlink")
int BPF_PROG(fentry__vfs_unlink)
{
    struct dentry *de;
    int r;

    preempt_disable();
    de = FUNC_ARG_READ(___type(de), vfs_unlink, dentry);
    r = vfs_unlink__enter(de);
    preempt_enable();

    return r;
}

SEC("kprobe/vfs_unlink")
int BPF_KPROBE(kprobe__vfs_unlink)
{
    struct dentry *de;
    int r;

    preempt_disable();
    r = 0;
    if (FUNC_ARG_READ_PTREGS(de, vfs_unlink, dentry)) {
        bpf_printk("kprobe__vfs_unlink: error reading dentry\n");
        goto out;
    }

    r = vfs_unlink__enter(de);
out:
    preempt_enable();
    return r;
}

// prepare a file event and send it to ringbuf.
// if devshm_only the event is only sent if the file path starts with /dev/shm
//
// Global function, see ebpf_ptr_to_scalar(): do_filp_open__exit() reaches
// this from three places (create, memfd, shmem) and the verifier would walk
// the path resolvers once per place otherwise. `file` is the struct file *
// as a scalar: 4.18's verifier only accepts scalar arguments for a global
// function and rejects a struct file * or void * taken from the probe context
// ("Caller passes invalid args"). Disables preemption itself for the per-cpu
// event buffer and resolver scratch: the caller must not, as a global function
// may not be called with preemption disabled on 6.10-6.14 verifiers.
__noinline int prepare_and_send_file_event(u64 file, enum ebpf_event_type type, bool devshm_only)
{
    struct file *f = (struct file *)file;
    struct ebpf_file_create_event *event;

    preempt_disable();
    event = get_event_buffer();
    if (!event)
        goto out;

    event->hdr.type    = type;
    event->hdr.ts      = bpf_ktime_get_boot_ns();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct path p            = BPF_CORE_READ(f, f_path);
    ebpf_pid_info__fill(&event->pids, task);
    ebpf_cred_info__fill(&event->creds, task);
    struct ebpf_namespace_info ns;
    ebpf_ns__fill(&ns, task);
    event->mntns = ns.mnt_inonum;
    bpf_get_current_comm(event->comm, TASK_COMM_LEN);
    ebpf_file_info__fill(&event->finfo, p.dentry);

    // Variable length fields
    ebpf_vl_fields__init(&event->vl_fields);
    struct ebpf_varlen_field *field;
    long size;

    // symlink_target_path
    field      = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_SYMLINK_TARGET_PATH);
    char *link = BPF_CORE_READ(p.dentry, d_inode, i_link);
    size       = read_kernel_str_or_empty_str(field->data, PATH_MAX, link);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    // pids ss cgroup path
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_PIDS_SS_CGROUP_PATH);
    size  = ebpf_resolve_pids_ss_cgroup_path_to_string(field->data, task);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    // path
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_PATH);
    size  = ebpf_resolve_path_to_string(field->data, &p, task);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    // skip event if only /dev/shm files are wanted and the path does not start with it
    if (!devshm_only || (size >= (long)sizeof(DEVSHM_STRING) - 1 &&
                         is_equal_prefix(field->data, DEVSHM_STRING, sizeof(DEVSHM_STRING) - 1)))
        ebpf_ringbuf_write(&ringbuf, event, EVENT_SIZE(event), 0);

out:
    preempt_enable();
    return 0;
}

/*
 * File access: report opens of files whose leaf or parent name is in the
 * anchor map, and failed opens of such names, from the same do_filp_open()
 * return the create event is taken from. Userspace applies the real path
 * patterns; the probe only has to be cheap on the miss path, which is every
 * other open on the host. Off by default: userspace sets the flag when it
 * wants the event, so with it off the verifier prunes the whole branch and
 * the maps below are never created.
 */
const volatile bool file_access_enabled = false;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ebpf_file_access_name);
    __type(value, u32);
    __uint(max_entries, 0); // sized by userspace, see bpf_queue_open1()
} elastic_ebpf_file_access_anchors SEC(".maps");

/*
 * The generation of the anchor set, bumped by userspace each time the names
 * are reset (quark_queue_file_access_name_reset(3)). Part of the dedup key
 * below, so a class claimed under the old names is reported again under the
 * new ones without touching the seen map, which is frozen. One entry, read
 * only on the hit path; not frozen itself.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
} elastic_ebpf_file_access_generation SEC(".maps");

// (process life, file) the dedup entries are kept by, and the generation of
// the anchor set the entry was claimed under.
struct file_access_seen_key {
    struct ebpf_dedup_file_key file;
    u64 generation;
};

/*
 * Access classes already reported for a (process life, file), one entry per
 * (tgid, device, inode, i_generation, anchor generation) so a second watched
 * file is reported again, including one that took over a freed inode number.
 * A class is claimed only once its event is in the ring buffer. Stale entries
 * never suppress, see Dedup.h; LRU eviction, procfs inode churn and a full
 * ring buffer cost a duplicate, never a lost event.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct file_access_seen_key);
    __type(value, struct ebpf_dedup_seen);
    __uint(max_entries, 0); // sized by userspace, see bpf_queue_open1()
} elastic_ebpf_file_access_file_seen SEC(".maps");

/*
 * Failed opens have no inode; they are deduplicated per (process life, base
 * directory, requested string, errno) instead, the string as a 32 bit FNV-1a
 * hash. The base directory is the inode a relative name was resolved
 * against, not the dirfd number: AT_FDCWD names a different directory after
 * every chdir() and a closed descriptor is reused, so the number would fold
 * the same relative name in different directories into one attempt. It is
 * zero for an absolute name, and carries the directory's i_generation for
 * the same reason the file key does, see Dedup.h. Same value, same per
 * class bits, same generation and same contract as the file map; a hash
 * collision costs a duplicate suppression of a different name and nothing
 * else.
 */
struct file_access_fail_key {
    u32 tgid;
    s32 error;
    u32 base_dev;
    u32 name_hash;
    u64 base_inode;
    u32 base_i_generation;
    u32 pad; // the map compares every byte of the key, keep it zero
    u64 generation;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct file_access_fail_key);
    __type(value, struct ebpf_dedup_seen);
    __uint(max_entries, 0); // sized by userspace, see bpf_queue_open1()
} elastic_ebpf_file_access_fail_seen SEC(".maps");

// Bits of ebpf_dedup_seen.bits, one per access class of open_flags.
#define FILE_ACCESS_CLASS_READ (1ULL << 0)
#define FILE_ACCESS_CLASS_WRITE (1ULL << 1)
#define FILE_ACCESS_CLASS_EXEC (1ULL << 2)
#define FILE_ACCESS_CLASS_PATH (1ULL << 3)

// include/uapi/asm-generic/fcntl.h, include/linux/fs.h (__FMODE_EXEC)
#define FILE_ACCESS_O_ACCMODE 00000003
#define FILE_ACCESS_O_WRONLY 00000001
#define FILE_ACCESS_O_RDWR 00000002
#define FILE_ACCESS_O_CREAT 00000100
#define FILE_ACCESS_O_TRUNC 00001000
#define FILE_ACCESS_O_APPEND 00002000
#define FILE_ACCESS_O_PATH 010000000
#define FILE_ACCESS___FMODE_EXEC 0x20

// How many directories are tested for a parent anchor, counting the leaf's
// own directory as the first: with 3, a/b/c/leaf is reported for an anchor on
// a, a/b/c/d/leaf is not. Bounded: every open on the system pays for the
// misses.
#define FILE_ACCESS_ANCESTORS 3

// Per-cpu scratch, only used between the preempt_disable() and
// preempt_enable() of file_access__open() and file_access__open_failed().
// The requested pathname of a failed open is read here, and the keys and
// paths live here rather than on the stack: do_filp_open__exit() sits close
// to the 512 byte combined stack limit already.
#define FILE_ACCESS_FILENAME_MAX 256

struct file_access_scratch {
    char filename[FILE_ACCESS_FILENAME_MAX];
    struct ebpf_file_access_name key;
    u32 leaf;
    int len;
    s32 slash[FILE_ACCESS_ANCESTORS + 1]; // last separators of filename, most recent first, -1 if none
    struct file_access_seen_key file_key;
    struct file_access_fail_key fail_key;
    struct ebpf_dedup_seen fresh;
    struct path path;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct file_access_scratch);
    __uint(max_entries, 1);
} elastic_ebpf_file_access_scratch SEC(".maps");

// The generation of the anchor set in force, for the dedup keys.
static __always_inline u64 file_access_generation(void)
{
    u64 *generation;
    u32  zero = 0;

    generation = bpf_map_lookup_elem(&elastic_ebpf_file_access_generation, &zero);

    return generation != NULL ? *generation : 0;
}

static u64 file_access_class(u32 open_flags)
{
    if (open_flags & FILE_ACCESS_O_PATH)
        return FILE_ACCESS_CLASS_PATH;
    if (open_flags & FILE_ACCESS___FMODE_EXEC)
        return FILE_ACCESS_CLASS_EXEC;
    if ((open_flags & FILE_ACCESS_O_ACCMODE) != 0 ||
        (open_flags & (FILE_ACCESS_O_CREAT | FILE_ACCESS_O_TRUNC | FILE_ACCESS_O_APPEND)))
        return FILE_ACCESS_CLASS_WRITE;
    return FILE_ACCESS_CLASS_READ;
}

// Anchor roles of a dentry name, 0 when the name is not an anchor.
static __always_inline u32 file_access_anchor(struct ebpf_file_access_name *key, const unsigned char *name)
{
    u32 *roles;

    __builtin_memset(key, 0, sizeof(*key));
    if (bpf_probe_read_kernel_str(key->name, sizeof(key->name), name) <= 0)
        return 0;
    roles = bpf_map_lookup_elem(&elastic_ebpf_file_access_anchors, key);

    return roles != NULL ? *roles : 0;
}

// True if the leaf is a leaf anchor or one of its FILE_ACCESS_ANCESTORS
// nearest ancestors is a parent anchor. The walk follows d_parent, so it
// stops at the root of the filesystem the file is on, which is its own
// parent, not at the mount point: a file reached through a bind mount is
// still matched against its directories on the underlying filesystem.
static __always_inline bool file_access_anchored(struct ebpf_file_access_name *key, struct dentry *de)
{
    struct dentry *parent;
    int            i;

    if (file_access_anchor(key, BPF_CORE_READ(de, d_name.name)) & EBPF_FILE_ACCESS_ANCHOR_LEAF)
        return true;
    for (i = 0; i < FILE_ACCESS_ANCESTORS; i++) {
        parent = BPF_CORE_READ(de, d_parent);
        if (parent == NULL || parent == de)
            return false;
        if (file_access_anchor(key, BPF_CORE_READ(parent, d_name.name)) &
            EBPF_FILE_ACCESS_ANCHOR_PARENT)
            return true;
        de = parent;
    }

    return false;
}

// Out of line so that its namespace struct is not in the emitter's frame, see
// file_access__match().
static __attribute__((noinline)) void file_access_event__fill_task(struct ebpf_file_access_event *event,
                                                                   struct task_struct *task)
{
    struct ebpf_namespace_info ns;

    event->hdr.type    = EBPF_EVENT_FILE_ACCESS;
    event->hdr.ts      = bpf_ktime_get_boot_ns();
    ebpf_pid_info__fill(&event->pids, task);
    ebpf_cred_info__fill(&event->creds, task);
    ebpf_ns__fill(&ns, task);
    event->mntns = ns.mnt_inonum;
    bpf_get_current_comm(event->comm, TASK_COMM_LEN);
}

// The match half of a completed open: the anchor walk, then the dedup test,
// with the keys in the per-cpu scratch. True if the open is to be reported;
// scratch->path is then the file's path for the emitter.
//
// A subprogram of its own, not the top of file_access__open(): the verifier
// charges a program the deepest chain of frames it can reach, and with the
// file events on the same hook that chain runs do_filp_open__exit() through
// the emitter into the path resolver, a few bytes under the 512 limit.
// Here, the walk's locals are off the stack before the emitter calls the
// resolvers, and the emitter itself keeps little live across its calls.
static __attribute__((noinline)) bool file_access__match(struct file_access_scratch *scratch,
                                                         struct file *f, u32 open_flags)
{
    struct task_struct *task;
    struct dentry      *de;

    scratch->path = BPF_CORE_READ(f, f_path);
    de            = scratch->path.dentry;
    if (!file_access_anchored(&scratch->key, de))
        return false;

    task                                = (struct task_struct *)bpf_get_current_task();
    scratch->file_key.file.tgid         = BPF_CORE_READ(task, tgid);
    scratch->file_key.file.dev          = BPF_CORE_READ(de, d_inode, i_sb, s_dev);
    scratch->file_key.file.inode        = BPF_CORE_READ(de, d_inode, i_ino);
    scratch->file_key.file.i_generation = BPF_CORE_READ(de, d_inode, i_generation);
    scratch->file_key.file.pad          = 0;
    scratch->file_key.generation        = file_access_generation();

    return !ebpf_dedup__test(&elastic_ebpf_file_access_file_seen, &scratch->file_key,
                             &scratch->fresh, task, file_access_class(open_flags));
}

// A completed open: match, resolve, emit. Kept out of line so its locals are
// not added to the do_filp_open__exit() frame that every open pays for.
// Disables preemption itself for the per-cpu scratch, event buffer and
// resolver state, like prepare_and_send_file_event(): the caller runs with
// preemption enabled.
static __attribute__((noinline)) void file_access__open(struct file *f, u32 open_flags)
{
    struct ebpf_file_access_event *event;
    struct file_access_scratch    *scratch;
    struct task_struct            *task;
    struct dentry                 *de;
    u32                            zero = 0;

    preempt_disable();
    scratch = bpf_map_lookup_elem(&elastic_ebpf_file_access_scratch, &zero);
    if (scratch == NULL)
        goto out;
    if (!file_access__match(scratch, f, open_flags))
        goto out;

    event = get_event_buffer();
    if (!event)
        goto out;

    event->open_flags = open_flags;
    event->fmode      = BPF_CORE_READ(f, f_mode);
    event->error      = 0;
    event->flags      = 0;
    event->dfd        = 0;
    task              = (struct task_struct *)bpf_get_current_task();
    file_access_event__fill_task(event, task);
    de = scratch->path.dentry; // a plain load: scratch is not a kernel type
    ebpf_file_info__fill(&event->finfo, de);

    // Variable length fields
    ebpf_vl_fields__init(&event->vl_fields);
    struct ebpf_varlen_field *field;
    long size;

    // path
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_PATH);
    size  = ebpf_resolve_path_to_string(field->data, &scratch->path, task);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    // symlink_target_path, the inode's inline target when the opened file is
    // the symlink itself (O_PATH|O_NOFOLLOW). i_link shares a union with
    // i_pipe, i_cdev and i_dir_seq, so on anything but a symlink it is not a
    // string. A symlink whose filesystem does not keep the target inline
    // (xfs, btrfs, long targets on ext4) has no i_link and comes back empty.
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_SYMLINK_TARGET_PATH);
    if (S_ISLNK(event->finfo.mode)) {
        de   = scratch->path.dentry;
        size = read_kernel_str_or_empty_str(field->data, PATH_MAX,
                                            BPF_CORE_READ(de, d_inode, i_link));
    } else {
        field->data[0] = '\0';
        size           = 1;
    }
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    // No cgroup path: the consumer takes it from the process the event is
    // linked to, and resolving it here was the deepest frame on this chain.

    // The class is claimed only once the event is out, see ebpf_dedup__set().
    if (ebpf_ringbuf_write(&ringbuf, event, EVENT_SIZE(event), 0) == 0)
        ebpf_dedup__set(&elastic_ebpf_file_access_file_seen, &scratch->file_key,
                        &scratch->fresh);

out:
    preempt_enable();
}

// The string counterpart of the ancestor walk in file_access_anchored(): true
// if one of the FILE_ACCESS_ANCESTORS directory components before the leaf of
// scratch->filename is a parent anchor. Component i lies between slash[i + 1]
// and slash[i]; a relative name's first component starts at 0, which is what
// the -1 sentinel yields. The indices come from map memory for the same
// reason as leaf and len in the caller.
static __always_inline bool file_access_string_anchored(struct file_access_scratch *scratch)
{
    u32 *roles;
    int  i, start, end, clen;

    for (i = 0; i < FILE_ACCESS_ANCESTORS; i++) {
        end   = *(volatile s32 *)&scratch->slash[i];
        start = *(volatile s32 *)&scratch->slash[i + 1] + 1;
        if (end < 0)
            return false;
        clen = end - start;
        if (clen <= 0 || clen >= EBPF_FILE_ACCESS_NAME_MAX)
            continue;
        start &= FILE_ACCESS_FILENAME_MAX - 1;
        clen &= EBPF_FILE_ACCESS_NAME_MAX - 1;
        __builtin_memset(&scratch->key, 0, sizeof(scratch->key));
        if (bpf_probe_read_kernel(scratch->key.name, clen, &scratch->filename[start]) != 0)
            return false;
        roles = bpf_map_lookup_elem(&elastic_ebpf_file_access_anchors, &scratch->key);
        if (roles != NULL && (*roles & EBPF_FILE_ACCESS_ANCHOR_PARENT))
            return true;
    }

    return false;
}

// The match half of a failed open, the string counterpart of
// file_access__match(): the requested name is read into the scratch, its leaf
// and directory components are matched against the anchors, the base
// directory of a relative name is resolved into scratch->path and the dedup
// key is tested. True if the open is to be reported.
static __attribute__((noinline)) bool file_access__match_failed(struct file_access_scratch *scratch,
                                                                int dfd, struct filename *pathname,
                                                                u32 open_flags, long error)
{
    struct task_struct *task;
    struct dentry      *base;
    const char         *name;
    u32                 hash;
    int                 len, leaf, i, j;

    name = BPF_CORE_READ(pathname, name);
    len  = bpf_probe_read_kernel_str(scratch->filename, sizeof(scratch->filename), name);
    if (len <= 1 || len >= (int)sizeof(scratch->filename)) // empty, or truncated: leaf unknown
        return false;

    // FNV-1a over the whole string for the dedup key, the leaf start, which
    // is the byte after the last '/', and the positions of the last few '/'
    // for the ancestor components. The length and indices live in the
    // scratch map across the loop on purpose: a register the verifier
    // tracks as a distinct range on every iteration turns each loop exit
    // into a separate verification of everything after it, map memory is
    // opaque to it. The volatile reloads keep clang from forwarding the
    // stored values.
    scratch->leaf = 0;
    scratch->len  = len;
    for (i = 0; i < FILE_ACCESS_ANCESTORS + 1; i++)
        scratch->slash[i] = -1;
    hash = 2166136261u;
    for (i = 0; i < FILE_ACCESS_FILENAME_MAX; i++) {
        if (i >= len - 1) // len includes the NUL
            break;
        hash = (hash ^ (u8)scratch->filename[i]) * 16777619u;
        if (scratch->filename[i] == '/') {
            scratch->leaf = i + 1;
            for (j = FILE_ACCESS_ANCESTORS; j > 0; j--)
                scratch->slash[j] = scratch->slash[j - 1];
            scratch->slash[0] = i;
        }
    }
    len  = *(volatile int *)&scratch->len;
    leaf = *(volatile u32 *)&scratch->leaf & (FILE_ACCESS_FILENAME_MAX - 1);
    // A leaf too long to be an anchor can still sit under a parent anchor,
    // as on the success path.
    u32 *roles = NULL;
    if (len - 1 - leaf < EBPF_FILE_ACCESS_NAME_MAX) {
        __builtin_memset(&scratch->key, 0, sizeof(scratch->key));
        if (bpf_probe_read_kernel_str(scratch->key.name, sizeof(scratch->key.name),
                                      &scratch->filename[leaf]) <= 0)
            return false;
        roles = bpf_map_lookup_elem(&elastic_ebpf_file_access_anchors, &scratch->key);
    }
    if ((roles == NULL || !(*roles & EBPF_FILE_ACCESS_ANCHOR_LEAF)) &&
        !file_access_string_anchored(scratch))
        return false;

    task = (struct task_struct *)bpf_get_current_task();

    // The base directory of a relative name, part of the dedup key and the
    // emitter's cwd field. Left empty for an absolute name or a dirfd that
    // is not a valid descriptor.
    scratch->path.dentry = NULL;
    scratch->path.mnt    = NULL;
    if (scratch->filename[0] != '/') {
        if (dfd == AT_FDCWD) {
            scratch->path = BPF_CORE_READ(task, fs, pwd);
        } else {
            struct file **fdt = BPF_CORE_READ(task, files, fdt, fd);
            struct file  *df  = NULL;
            u32           max = BPF_CORE_READ(task, files, fdt, max_fds);

            if (dfd >= 0 && (u32)dfd < max)
                bpf_core_read(&df, sizeof(df), &fdt[dfd]);
            if (df != NULL)
                scratch->path = BPF_CORE_READ(df, f_path);
        }
    }

    scratch->fail_key.tgid              = BPF_CORE_READ(task, tgid);
    scratch->fail_key.error             = error;
    scratch->fail_key.base_dev          = 0;
    scratch->fail_key.name_hash         = hash;
    scratch->fail_key.base_inode        = 0;
    scratch->fail_key.base_i_generation = 0;
    scratch->fail_key.pad               = 0;
    scratch->fail_key.generation        = file_access_generation();
    base = scratch->path.dentry; // a plain load: scratch is not a kernel type
    if (base != NULL) {
        scratch->fail_key.base_dev          = BPF_CORE_READ(base, d_inode, i_sb, s_dev);
        scratch->fail_key.base_inode        = BPF_CORE_READ(base, d_inode, i_ino);
        scratch->fail_key.base_i_generation = BPF_CORE_READ(base, d_inode, i_generation);
    }

    return !ebpf_dedup__test(&elastic_ebpf_file_access_fail_seen, &scratch->fail_key,
                             &scratch->fresh, task, file_access_class(open_flags));
}

// A failed open: only EACCES, EPERM and ENOENT are of interest, and only when
// the leaf of the requested string is a leaf anchor or one of the directory
// components before it is a parent anchor. There is no dentry, so the names
// are matched on the string and the base directory of a relative name is
// resolved so userspace can rebuild the path. Disables preemption itself for
// the per-cpu scratch, like file_access__open().
static __attribute__((noinline)) void file_access__open_failed(int dfd, struct filename *pathname,
                                                               u32 open_flags, long error)
{
    struct ebpf_file_access_event *event;
    struct file_access_scratch    *scratch;
    struct task_struct            *task;
    u32                            zero = 0;

    if (error != EACCES && error != EPERM && error != ENOENT)
        return;
    if (pathname == NULL)
        return;
    if (ebpf_events_is_trusted_pid())
        return;

    preempt_disable();
    scratch = bpf_map_lookup_elem(&elastic_ebpf_file_access_scratch, &zero);
    if (scratch == NULL)
        goto out;
    if (!file_access__match_failed(scratch, dfd, pathname, open_flags, error))
        goto out;

    event = get_event_buffer();
    if (!event)
        goto out;

    event->open_flags = open_flags;
    event->fmode      = 0;
    event->error      = error;
    event->flags      = EBPF_FILE_ACCESS_F_FAILED;
    event->dfd        = dfd;
    task              = (struct task_struct *)bpf_get_current_task();
    file_access_event__fill_task(event, task);
    __builtin_memset(&event->finfo, 0, sizeof(event->finfo));

    // Variable length fields
    ebpf_vl_fields__init(&event->vl_fields);
    struct ebpf_varlen_field *field;
    long size;

    // filename: the requested string
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_FILENAME);
    size  = bpf_probe_read_kernel_str(field->data, FILE_ACCESS_FILENAME_MAX, scratch->filename);
    if (size <= 0) {
        field->data[0] = '\0';
        size = 1;
    }
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    // cwd: the directory a relative name was resolved against
    if (scratch->filename[0] != '/') {
        event->flags |= EBPF_FILE_ACCESS_F_RELATIVE;
        field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_CWD);
        if (scratch->path.dentry != NULL)
            size = ebpf_resolve_path_to_string(field->data, &scratch->path, task);
        else {
            field->data[0] = '\0';
            size = 1;
        }
        ebpf_vl_field__set_size(&event->vl_fields, field, size);
    }

    // The class is claimed only once the event is out, see ebpf_dedup__set().
    if (ebpf_ringbuf_write(&ringbuf, event, EVENT_SIZE(event), 0) == 0)
        ebpf_dedup__set(&elastic_ebpf_file_access_fail_seen, &scratch->fail_key,
                        &scratch->fresh);

out:
    preempt_enable();
}

// Runs with preemption enabled, see prepare_and_send_file_event(); nothing
// here but that call and the two file_access__open*() touches per-cpu state.
static int do_filp_open__exit(int dfd, struct filename *pathname, const struct open_flags *op,
                              struct file *f)
{
    /*
    'ret' fields such f_mode and f_path should be obtained via BPF_CORE_READ
    because there's a kernel bug that causes a panic.
    Read more: github.com/torvalds/linux/commit/588a25e92458c6efeb7a261d5ca5726f5de89184
    */

    if (IS_ERR_OR_NULL(f)) {
        if (file_access_enabled && f != NULL)
            file_access__open_failed(dfd, pathname,
                                     op != NULL ? (u32)BPF_CORE_READ(op, open_flag) : 0,
                                     -(long)f);
        goto out;
    }

    if (ebpf_events_is_trusted_pid())
        goto out;

    // op is NULL on a kretprobe kernel when the entry state was missed; f_flags
    // is then the fallback, and do_dentry_open() has already stripped
    // O_CREAT|O_EXCL|O_NOCTTY|O_TRUNC from it, so such an open is classified
    // and reported without them.
    if (file_access_enabled)
        file_access__open(f, op != NULL ? (u32)BPF_CORE_READ(op, open_flag)
                                        : (u32)BPF_CORE_READ(f, f_flags));

    // The rest is the file event side of this hook, which file_access alone
    // must not turn on.
    if (!file_events_enabled)
        goto out;

    fmode_t fmode = BPF_CORE_READ(f, f_mode);
    if ((fmode & (fmode_t)0x100000) ||                                 // FMODE_CREATED
        (ebpf_events_state__get(EBPF_EVENTS_STATE_FS_CREATE) != NULL)) { // 4.18.x
        // generate a file creation event
        prepare_and_send_file_event(ebpf_ptr_to_scalar(f), EBPF_EVENT_FILE_CREATE, false);
    } else {
        // check if memfd file is being opened
        struct path p              = BPF_CORE_READ(f, f_path);
        struct dentry *curr_dentry = BPF_CORE_READ(&p, dentry);
        struct qstr component      = BPF_CORE_READ(curr_dentry, d_name);
        char buf_filename[8]       = {0};
        int ret =
            bpf_probe_read_kernel_str(buf_filename, sizeof(MEMFD_STRING), (void *)component.name);
        if (ret <= 0) {
            bpf_printk("could not read d_name at %p\n", component.name);
            goto out;
        }
        // check if file name starts with "memfd:"
        int is_memfd = is_equal_prefix(MEMFD_STRING, buf_filename, sizeof(MEMFD_STRING) - 1);
        if (is_memfd) {
            // generate a memfd file open event
            prepare_and_send_file_event(ebpf_ptr_to_scalar(f), EBPF_EVENT_FILE_MEMFD_OPEN, false);
            goto out;
        }

        struct vfsmount *curr_vfsmount = BPF_CORE_READ(&p, mnt);
        const char *fs_type_name       = BPF_CORE_READ(curr_vfsmount, mnt_sb, s_type, name);

        // check if /dev/shm shared memory file is being opened
        // first check if fs is tmpfs
        char buf_fsname[8] = {0};
        ret = bpf_probe_read_kernel_str(buf_fsname, sizeof(TMPFS_STRING), (void *)fs_type_name);
        if (ret <= 0) {
            bpf_printk("could not read fsname at %p\n", fs_type_name);
            goto out;
        }

        int is_tmpfs = is_equal_prefix(buf_fsname, TMPFS_STRING, sizeof(TMPFS_STRING) - 1);
        if (is_tmpfs) {
            // now filter for /dev/shm prefix, if there is match - send an SHMEM file open event
            prepare_and_send_file_event(ebpf_ptr_to_scalar(f), EBPF_EVENT_FILE_SHMEM_OPEN, true);
        }
    }

out:
    // Only the fsnotify probe, loaded with the file events, sets this state;
    // without them the delete would lock a bucket on every open for nothing.
    if (file_events_enabled)
        ebpf_events_state__del(EBPF_EVENTS_STATE_FS_CREATE);

    return 0;
}

static int fsnotify__enter(u32 mask)
{
    if (mask & 0x100) { // FS_CREATE
        struct ebpf_events_state state = {};
        ebpf_events_state__set(EBPF_EVENTS_STATE_FS_CREATE, &state);
    }

    return 0;
}

SEC("kprobe/fsnotify")
int BPF_KPROBE(kprobe__fsnotify,
               struct inode *to_tell,
               u32 mask,
               const void *data,
               int data_is,
               const unsigned char *file_name,
               u32 cookie)
{
    int r;

    preempt_disable();
    r = fsnotify__enter(mask);
    preempt_enable();

    return r;
}

SEC("fentry/fsnotify")
int BPF_PROG(fentry__fsnotify,
             struct inode *to_tell,
             u32 mask,
             const void *data,
             int data_is,
             const unsigned char *file_name,
             u32 cookie)
{
    int r;

    preempt_disable();
    r = fsnotify__enter(mask);
    preempt_enable();

    return r;
}

SEC("fexit/do_filp_open")
int BPF_PROG(fexit__do_filp_open,
             int dfd,
             struct filename *pathname,
             const struct open_flags *op,
             struct file *ret)
{
    return do_filp_open__exit(dfd, pathname, op, ret);
}

// Without fexit the arguments are gone by the time we see the return; the
// entry kprobe below keeps them, and is only loaded when file access events
// are wanted since the create event does not need them.
static int do_filp_open__enter(int dfd, struct filename *pathname, const struct open_flags *op)
{
    struct ebpf_events_state state = {};

    if (ebpf_events_is_trusted_pid())
        return 0;
    state.filp_open.dfd      = dfd;
    state.filp_open.pathname = pathname;
    state.filp_open.op       = op;
    ebpf_events_state__set(EBPF_EVENTS_STATE_FILP_OPEN, &state);

    return 0;
}

SEC("kprobe/do_filp_open")
int BPF_KPROBE(kprobe__do_filp_open, int dfd, struct filename *pathname, const struct open_flags *op)
{
    int r;

    preempt_disable();
    r = do_filp_open__enter(dfd, pathname, op);
    preempt_enable();

    return r;
}

static int do_filp_open__kretprobe(struct file *ret)
{
    struct ebpf_events_state *state    = NULL;
    int                       dfd      = 0;
    struct filename          *pathname = NULL;
    const struct open_flags  *op       = NULL;
    int                       r;

    // The entry kprobe that keeps the arguments is loaded only with the file
    // access events; the file events alone would pay a lookup per open for a
    // state nothing sets.
    if (file_access_enabled)
        state = ebpf_events_state__get(EBPF_EVENTS_STATE_FILP_OPEN);
    if (state != NULL) {
        dfd      = state->filp_open.dfd;
        pathname = state->filp_open.pathname;
        op       = state->filp_open.op;
    }
    r = do_filp_open__exit(dfd, pathname, op, ret);
    if (state != NULL)
        ebpf_events_state__del(EBPF_EVENTS_STATE_FILP_OPEN);

    return r;
}

SEC("kretprobe/do_filp_open")
int BPF_KRETPROBE(kretprobe__do_filp_open, struct file *ret)
{
    return do_filp_open__kretprobe(ret);
}

SEC("fexit/do_file_open")
int BPF_PROG(fexit__do_file_open,
             int dfd,
             struct filename *pathname,
             const struct open_flags *op,
             struct file *ret)
{
    return do_filp_open__exit(dfd, pathname, op, ret);
}

SEC("kprobe/do_file_open")
int BPF_KPROBE(kprobe__do_file_open, int dfd, struct filename *pathname, const struct open_flags *op)
{
    int r;

    preempt_disable();
    r = do_filp_open__enter(dfd, pathname, op);
    preempt_enable();

    return r;
}

SEC("kretprobe/do_file_open")
int BPF_KRETPROBE(kretprobe__do_file_open, struct file *ret)
{
    return do_filp_open__kretprobe(ret);
}

static int do_renameat2__enter()
{
    struct ebpf_events_state state = {};
    state.rename.step              = RENAME_STATE_INIT;

    if (ebpf_events_is_trusted_pid())
        goto out;
    ebpf_events_state__set(EBPF_EVENTS_STATE_RENAME, &state);

    u32 zero = 0;
    struct ebpf_events_scratch_space *ss =
        bpf_map_lookup_elem(&elastic_ebpf_events_init_buffer, &zero);
    if (!ss)
        goto out;
    ebpf_events_scratch_space__set(EBPF_EVENTS_STATE_RENAME, ss);

out:
    return 0;
}

SEC("fentry/do_renameat2")
int BPF_PROG(fentry__do_renameat2)
{
    int r;

    preempt_disable();
    r = do_renameat2__enter();
    preempt_enable();

    return r;
}

SEC("kprobe/do_renameat2")
int BPF_KPROBE(kprobe__do_renameat2)
{
    int r;

    preempt_disable();
    r = do_renameat2__enter();
    preempt_enable();

    return r;
}

SEC("fentry/filename_renameat2")
int BPF_PROG(fentry__filename_renameat2)
{
    int r;

    preempt_disable();
    r = do_renameat2__enter();
    preempt_enable();

    return r;
}

SEC("kprobe/filename_renameat2")
int BPF_KPROBE(kprobe__filename_renameat2)
{
    int r;

    preempt_disable();
    r = do_renameat2__enter();
    preempt_enable();

    return r;
}

/* Same as do_unlinkat__exit(), see comment there. */
static int do_renameat2__exit()
{
    ebpf_events_state__del(EBPF_EVENTS_STATE_RENAME);
    return 0;
}

SEC("fexit/do_renameat2")
int BPF_PROG(fexit__do_renameat2)
{
    int r;

    preempt_disable();
    r = do_renameat2__exit();
    preempt_enable();

    return r;
}

SEC("kretprobe/do_renameat2")
int BPF_KRETPROBE(kretprobe__do_renameat2)
{
    int r;

    preempt_disable();
    r = do_renameat2__exit();
    preempt_enable();

    return r;
}

SEC("fexit/filename_renameat2")
int BPF_PROG(fexit__filename_renameat2)
{
    int r;

    preempt_disable();
    r = do_renameat2__exit();
    preempt_enable();

    return r;
}

SEC("kretprobe/filename_renameat2")
int BPF_KRETPROBE(kretprobe__filename_renameat2)
{
    int r;

    preempt_disable();
    r = do_renameat2__exit();
    preempt_enable();

    return r;
}

// Resolve (mnt, dentry) into the rename scratch space's new_path.
//
// Global function, see ebpf_ptr_to_scalar(): vfs_rename__enter() resolves two
// paths and the verifier would walk the resolver once per call otherwise. It
// always writes new_path, a buffer picked by argument would be two verifier
// states again; the caller moves the first result to old_path.
__noinline int vfs_rename__resolve_path(u64 mnt, u64 dentry)
{
    struct ebpf_events_scratch_space *ss;
    struct task_struct *task;
    struct path p;
    int r = -1;

    // For the resolver's per-cpu scratch, see prepare_and_send_file_event().
    preempt_disable();
    ss = ebpf_events_scratch_space__get(EBPF_EVENTS_STATE_RENAME);
    if (!ss)
        goto out;

    task     = (struct task_struct *)bpf_get_current_task();
    p.mnt    = (struct vfsmount *)mnt;
    p.dentry = (struct dentry *)dentry;
    ebpf_resolve_path_to_string(ss->rename.new_path, &p, task);
    r = 0;

out:
    preempt_enable();
    return r;
}

// Runs with preemption enabled, see vfs_rename__resolve_path(); the state and
// scratch maps are keyed by task, only the resolver's scratch is per-cpu.
static int vfs_rename__enter(struct dentry *old_dentry, struct dentry *new_dentry)
{
    struct ebpf_events_scratch_space *ss;
    struct ebpf_events_state *state;

    state = ebpf_events_state__get(EBPF_EVENTS_STATE_RENAME);
    if (!state || state->rename.step != RENAME_STATE_MOUNT_SET) {
        // Omit logging as this happens in the happy path.
        goto out;
    }

    // mnt was read back from the state map, so the verifier already sees a
    // scalar; the dentries come from the probe context and need the detour.
    u64 mnt = (u64)state->rename.mnt;
    if (vfs_rename__resolve_path(mnt, ebpf_ptr_to_scalar(old_dentry)))
        goto out;

    // The resolver runs with preemption enabled, so this task may have been
    // scheduled out and the LRU maps may have recycled its entries for
    // another task, which the verifier can't see: a map value pointer taken
    // before the call would then write into that task's entry. Look the
    // entries up again after each call and write through them with
    // preemption disabled, the window the code had before the resolver
    // became a global function. A missing entry means the state is gone and
    // the exit hook will find nothing either.
    preempt_disable();
    ss = ebpf_events_scratch_space__get(EBPF_EVENTS_STATE_RENAME);
    if (ss)
        bpf_probe_read_kernel(ss->rename.old_path, PATH_MAX, ss->rename.new_path);
    preempt_enable();
    if (!ss)
        goto out;

    if (vfs_rename__resolve_path(mnt, ebpf_ptr_to_scalar(new_dentry)))
        goto out;

    preempt_disable();
    state = ebpf_events_state__get(EBPF_EVENTS_STATE_RENAME);
    if (state) {
        state->rename.step = RENAME_STATE_PATHS_SET;
        state->rename.de   = old_dentry;
    }
    preempt_enable();

out:
    return 0;
}

SEC("fentry/vfs_rename")
int BPF_PROG(fentry__vfs_rename)
{
    struct dentry *old_dentry, *new_dentry;

    if (FUNC_ARG_EXISTS(vfs_rename, rd)) {
        /* Function arguments have been refactored into struct renamedata */
        struct renamedata *rd = (struct renamedata *)ctx[0];
        old_dentry            = rd->old_dentry;
        new_dentry            = rd->new_dentry;
    } else {
        /* Dentries are accessible from ctx */
        old_dentry = FUNC_ARG_READ(___type(old_dentry), vfs_rename, old_dentry);
        new_dentry = FUNC_ARG_READ(___type(new_dentry), vfs_rename, new_dentry);
    }

    return vfs_rename__enter(old_dentry, new_dentry);
}

SEC("kprobe/vfs_rename")
int BPF_KPROBE(kprobe__vfs_rename)
{
    struct dentry *old_dentry, *new_dentry;
    int r = 0;

    if (FUNC_ARG_EXISTS(vfs_rename, rd)) {
        /* Function arguments have been refactored into struct renamedata */
        struct renamedata rd;
        bpf_core_read(&rd, sizeof(rd), (void *)PT_REGS_PARM1(ctx));
        old_dentry = rd.old_dentry;
        new_dentry = rd.new_dentry;
    } else {
        /* Dentries are accessible from ctx */
        if (FUNC_ARG_READ_PTREGS(old_dentry, vfs_rename, old_dentry)) {
            bpf_printk("kprobe__vfs_rename: error reading old_dentry\n");
            goto out;
        }
        if (FUNC_ARG_READ_PTREGS(new_dentry, vfs_rename, new_dentry)) {
            bpf_printk("kprobe__vfs_rename: error reading new_dentry\n");
            goto out;
        }
    }

    r = vfs_rename__enter(old_dentry, new_dentry);
out:
    return r;
}

static int vfs_rename__exit(int ret)
{
    if (ret)
        goto out;

    struct ebpf_events_state *state = ebpf_events_state__get(EBPF_EVENTS_STATE_RENAME);
    if (!state || state->rename.step != RENAME_STATE_PATHS_SET) {
        // Omit logging as this happens in the happy path.
        goto out;
    }

    struct ebpf_events_scratch_space *ss = ebpf_events_scratch_space__get(EBPF_EVENTS_STATE_RENAME);
    if (!ss) {
        bpf_printk("vfs_rename__exit: scratch space missing\n");
        goto out;
    }

    struct ebpf_file_rename_event *event = get_event_buffer();
    if (!event)
        goto out;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    // NOTE: this temp variable is necessary to keep the verifier happy
    struct dentry *de = (struct dentry *)state->rename.de;

    event->hdr.type    = EBPF_EVENT_FILE_RENAME;
    event->hdr.ts      = bpf_ktime_get_boot_ns();
    ebpf_pid_info__fill(&event->pids, task);
    ebpf_cred_info__fill(&event->creds, task);
    struct ebpf_namespace_info ns;
    ebpf_ns__fill(&ns, task);
    event->mntns = ns.mnt_inonum;
    bpf_get_current_comm(event->comm, TASK_COMM_LEN);
    ebpf_file_info__fill(&event->finfo, de);

    // Variable length fields
    ebpf_vl_fields__init(&event->vl_fields);
    struct ebpf_varlen_field *field;
    long size;

    // old path
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_OLD_PATH);
    size  = read_kernel_str_or_empty_str(field->data, PATH_MAX, ss->rename.old_path);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    // new path
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_NEW_PATH);
    size  = read_kernel_str_or_empty_str(field->data, PATH_MAX, ss->rename.new_path);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    // symlink_target_path
    field      = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_SYMLINK_TARGET_PATH);
    char *link = BPF_CORE_READ(de, d_inode, i_link);
    size       = read_kernel_str_or_empty_str(field->data, PATH_MAX, link);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    // pids ss cgroup path
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_PIDS_SS_CGROUP_PATH);
    size  = ebpf_resolve_pids_ss_cgroup_path_to_string(field->data, task);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    ebpf_ringbuf_write(&ringbuf, event, EVENT_SIZE(event), 0);

    // Certain filesystems (eg. overlayfs) call vfs_rename twice during the same
    // execution context.
    // In order to not emit a second event, delete the state explicitly.
    ebpf_events_state__del(EBPF_EVENTS_STATE_RENAME);

out:
    return 0;
}

SEC("fexit/vfs_rename")
int BPF_PROG(fexit__vfs_rename)
{
    int ret, r;

    preempt_disable();
    ret = FUNC_RET_READ(___type(ret), vfs_rename);
    r = vfs_rename__exit(ret);
    preempt_enable();

    return r;
}

SEC("kretprobe/vfs_rename")
int BPF_KRETPROBE(kretprobe__vfs_rename, int ret)
{
    int r;

    preempt_disable();
    r = vfs_rename__exit(ret);
    preempt_enable();

    return r;
}

static void file_modify_event__emit(enum ebpf_file_change_type typ, struct path *path)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct ebpf_file_modify_event *event = get_event_buffer();
    if (!event) {
        bpf_printk("file_modify_event__emit: failed to reserve event\n");
        goto out;
    }

    event->hdr.type    = EBPF_EVENT_FILE_MODIFY;
    event->hdr.ts      = bpf_ktime_get_boot_ns();
    event->change_type = typ;
    ebpf_pid_info__fill(&event->pids, task);
    ebpf_cred_info__fill(&event->creds, task);
    struct ebpf_namespace_info ns;
    ebpf_ns__fill(&ns, task);
    event->mntns = ns.mnt_inonum;
    bpf_get_current_comm(event->comm, TASK_COMM_LEN);
    struct dentry *d = BPF_CORE_READ(path, dentry);
    ebpf_file_info__fill(&event->finfo, d);

    switch (event->finfo.type) {
    case EBPF_FILE_TYPE_FILE:
        break;
    default:
        goto out;
    }

    // Variable length fields
    ebpf_vl_fields__init(&event->vl_fields);
    struct ebpf_varlen_field *field;
    long size;

    // path
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_PATH);
    size  = ebpf_resolve_path_to_string(field->data, path, task);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    // symlink_target_path
    field      = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_SYMLINK_TARGET_PATH);
    char *link = BPF_CORE_READ(path, dentry, d_inode, i_link);
    size       = read_kernel_str_or_empty_str(field->data, PATH_MAX, link);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    // pids ss cgroup path
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_PIDS_SS_CGROUP_PATH);
    size  = ebpf_resolve_pids_ss_cgroup_path_to_string(field->data, task);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    ebpf_ringbuf_write(&ringbuf, event, EVENT_SIZE(event), 0);

out:
    return;
}

SEC("kprobe/chmod_common")
int BPF_KPROBE(kprobe__chmod_common, const struct path *path, umode_t mode)
{
    struct ebpf_events_state state = {};
    state.chmod.path               = (struct path *)path;
    state.chmod.mode               = mode;

    preempt_disable();
    if (ebpf_events_is_trusted_pid())
        goto out;

    ebpf_events_state__set(EBPF_EVENTS_STATE_CHMOD, &state);

out:
    preempt_enable();
    return 0;
}

static void chmod_common__exit(struct path *path, int ret)
{
    if (ret)
        goto out;

    if (ebpf_events_is_trusted_pid())
        goto out;

    file_modify_event__emit(EBPF_FILE_CHANGE_TYPE_PERMISSIONS, path);

out:
    return;
}

SEC("fexit/chmod_common")
int BPF_PROG(fexit__chmod_common, const struct path *path, umode_t mode, int ret)
{
    preempt_disable();
    chmod_common__exit((struct path *)path, ret);
    preempt_enable();
    return 0;
}

SEC("kretprobe/chmod_common")
int BPF_KRETPROBE(kretprobe__chmod_common, int ret)
{
    struct ebpf_events_state *state;

    preempt_disable();
    state = ebpf_events_state__get(EBPF_EVENTS_STATE_CHMOD);
    if (!state)
        goto out;

    chmod_common__exit(state->chmod.path, ret);

out:
    preempt_enable();
    return 0;
}

SEC("kprobe/do_truncate")
int BPF_KPROBE(kprobe__do_truncate)
{
    struct ebpf_events_state state = {};

    preempt_disable();

    if (ebpf_events_is_trusted_pid())
        goto out;

    struct file *filp;
    if (FUNC_ARG_READ_PTREGS(filp, do_truncate, filp)) {
        bpf_printk("kprobe__do_truncate: error reading filp\n");
        goto out;
    }

    state.truncate.path = path_from_file(filp);
    ebpf_events_state__set(EBPF_EVENTS_STATE_TRUNCATE, &state);

out:
    preempt_enable();
    return 0;
}

static void do_truncate__exit(struct path *path, int ret)
{
    if (ret)
        goto out;

    if (ebpf_events_is_trusted_pid())
        goto out;

    file_modify_event__emit(EBPF_FILE_CHANGE_TYPE_CONTENT, path);

out:
    return;
}

SEC("fexit/do_truncate")
int BPF_PROG(fexit__do_truncate)
{
    struct file *filp;
    int ret;

    preempt_disable();
    filp = FUNC_ARG_READ(___type(filp), do_truncate, filp);
    ret = FUNC_RET_READ(___type(ret), do_truncate);
    do_truncate__exit(path_from_file(filp), ret);
    preempt_enable();

    return 0;
}

SEC("kretprobe/do_truncate")
int BPF_KRETPROBE(kretprobe__do_truncate, int ret)
{
    struct ebpf_events_state *state;

    preempt_disable();
    state = ebpf_events_state__get(EBPF_EVENTS_STATE_TRUNCATE);
    if (!state)
        goto out;

    do_truncate__exit(state->truncate.path, ret);

out:
    preempt_enable();
    return 0;
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(kprobe__vfs_write, struct file *file)
{
    struct ebpf_events_state state = {};

    preempt_disable();
    if (ebpf_events_is_trusted_pid())
        goto out;

    state.write.path = path_from_file(file);
    ebpf_events_state__set(EBPF_EVENTS_STATE_WRITE, &state);
out:
    preempt_enable();
    return 0;
}

SEC("kprobe/vfs_writev")
int BPF_KPROBE(kprobe__vfs_writev, struct file *file)
{
    struct ebpf_events_state state = {};

    preempt_disable();
    if (ebpf_events_is_trusted_pid())
        goto out;

    state.writev.path = path_from_file(file);
    ebpf_events_state__set(EBPF_EVENTS_STATE_WRITEV, &state);

out:
    preempt_enable();
    return 0;
}

static void vfs_write__exit(struct path *path, ssize_t ret)
{
    if (ret <= 0)
        goto out;

    if (ebpf_events_is_trusted_pid())
        goto out;

    file_modify_event__emit(EBPF_FILE_CHANGE_TYPE_CONTENT, path);

out:
    return;
}

SEC("fexit/vfs_write")
int BPF_PROG(
    fexit__vfs_write, struct file *file, const char *buf, size_t count, loff_t *pos, ssize_t ret)
{
    preempt_disable();
    vfs_write__exit(path_from_file(file), ret);
    preempt_enable();
    return 0;
}

SEC("fexit/vfs_writev")
int BPF_PROG(fexit__vfs_writev,
             struct file *file,
             const struct iovec *vec,
             unsigned long vlen,
             loff_t *pos,
             rwf_t flags,
             ssize_t ret)
{
    preempt_disable();
    vfs_write__exit(path_from_file(file), ret);
    preempt_enable();
    return 0;
}

SEC("kretprobe/vfs_write")
int BPF_KRETPROBE(kretprobe__vfs_write, ssize_t ret)
{
    struct ebpf_events_state *state;

    preempt_disable();
    state = ebpf_events_state__get(EBPF_EVENTS_STATE_WRITE);
    if (!state)
        goto out;

    vfs_write__exit(state->write.path, ret);

out:
    preempt_enable();
    return 0;
}

SEC("kretprobe/vfs_writev")
int BPF_KRETPROBE(kretprobe__vfs_writev, ssize_t ret)
{
    struct ebpf_events_state *state;

    preempt_disable();
    state = ebpf_events_state__get(EBPF_EVENTS_STATE_WRITEV);
    if (!state)
        goto out;

    vfs_write__exit(state->writev.path, ret);

out:
    preempt_enable();
    return 0;
}

SEC("kprobe/chown_common")
int BPF_KPROBE(kprobe__chown_common, struct path *path, uid_t user, gid_t group)
{
    struct ebpf_events_state state = {};

    preempt_disable();
    if (ebpf_events_is_trusted_pid())
        goto out;
    state.chown.path               = path;
    ebpf_events_state__set(EBPF_EVENTS_STATE_CHOWN, &state);
out:
    preempt_enable();
    return 0;
}

static void chown_common__exit(struct path *path, int ret)
{
    if (ret)
        goto out;

    if (ebpf_events_is_trusted_pid())
        goto out;

    file_modify_event__emit(EBPF_FILE_CHANGE_TYPE_OWNER, path);

out:
    return;
}

SEC("fexit/chown_common")
int BPF_PROG(fexit__chown_common, struct path *path, uid_t user, gid_t group, int ret)
{
    preempt_disable();
    chown_common__exit(path, ret);
    preempt_enable();
    return 0;
}

SEC("kretprobe/chown_common")
int BPF_KRETPROBE(kretprobe__chown_common, int ret)
{
    struct ebpf_events_state *state;

    preempt_disable();
    state = ebpf_events_state__get(EBPF_EVENTS_STATE_CHOWN);
    if (!state)
        goto out;

    chown_common__exit(state->chown.path, ret);

out:
    preempt_enable();
    return 0;
}
