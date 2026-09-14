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

#include "File.h"
#include "Helpers.h"
#include "PathResolver.h"
#include "State.h"
#include "Varlen.h"

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
// if path_prefix is non-NULL then event will only be sent to ringbuf if file path has that prefix
static void prepare_and_send_file_event(struct file *f,
                                        enum ebpf_event_type type,
                                        const char *path_prefix,
                                        int path_prefix_len)
{
    struct ebpf_file_create_event *event = get_event_buffer();
    if (!event)
        return;

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

    // skip event if prefix is specified and file path does not start with it
    if (path_prefix) {
        if ((path_prefix_len > 0) && (size >= path_prefix_len)) {
            if (is_equal_prefix(field->data, path_prefix, path_prefix_len))
                ebpf_ringbuf_write(&ringbuf, event, EVENT_SIZE(event), 0);
        }
    } else {
        ebpf_ringbuf_write(&ringbuf, event, EVENT_SIZE(event), 0);
    }
}

/*
 * File access: report opens of files whose leaf or parent name is in the
 * anchor map, from the same do_filp_open() return the create event is taken
 * from. Userspace applies the real path patterns; the probe only has to be
 * cheap on the miss path, which is every other open on the host. Off by
 * default: userspace sets the flag when it wants the event, so with it off
 * the verifier prunes the whole branch and the maps below are never created.
 */
const volatile bool file_access_enabled = false;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ebpf_file_access_name);
    __type(value, u32);
    __uint(max_entries, 0); // sized by userspace, see bpf_queue_open1()
} elastic_ebpf_file_access_anchors SEC(".maps");

/*
 * Access classes already reported for a (process life, file), one entry per
 * (tgid, device, inode) so a second watched file is reported again. The value
 * carries the process start time and self_exec_id, which the kernel bumps on
 * every exec and never reuses within a process life; a stale entry (recycled
 * tgid or previous program image) no longer matches and is claimed anew, so
 * it never suppresses and the map needs no exec or exit clearing. LRU
 * eviction and procfs inode churn cost a duplicate, never a lost event.
 */
struct file_access_file_key {
    u32 tgid;
    u32 dev;
    u64 inode;
};

struct file_access_seen {
    u64 start_time_ns;
    u64 exec_id;
    u64 bits;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct file_access_file_key);
    __type(value, struct file_access_seen);
    __uint(max_entries, 0); // sized by userspace, see bpf_queue_open1()
} elastic_ebpf_file_access_file_seen SEC(".maps");

// Bits of file_access_seen.bits, one per access class of open_flags.
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

// How many directories above the leaf a parent anchor is looked for, so that
// a directory of interest also covers files a few levels below it. Bounded:
// every open on the system pays for the misses.
#define FILE_ACCESS_ANCESTORS 3

// Per-cpu scratch, safe since the callers run with preemption disabled. The
// keys and paths live here rather than on the stack: do_filp_open__exit()
// sits close to the 512 byte combined stack limit already.
struct file_access_scratch {
    struct ebpf_file_access_name key;
    struct file_access_file_key file_key;
    struct file_access_seen fresh;
    struct path path;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct file_access_scratch);
    __uint(max_entries, 1);
} elastic_ebpf_file_access_scratch SEC(".maps");

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

// The exec generation of the process. self_exec_id is u64 since Linux 5.7 and
// u32 before, so read it by its relocated size; the targets are little endian
// so a narrower field lands in the low bytes. RHEL 8 (4.18) backported the
// widening under kABI and the live field only exists in the task_struct_rh
// extension there, see vmlinux_extra.h; a kernel with neither yields zero and
// falls back to start_time alone.
static u64 file_access_exec_id(const struct task_struct *task)
{
    const struct task_struct *leader  = BPF_CORE_READ(task, group_leader);
    u64                       exec_id = 0;

    if (bpf_core_field_exists(leader->self_exec_id)) {
        bpf_core_read(&exec_id, bpf_core_field_size(leader->self_exec_id),
                      &leader->self_exec_id);
    } else if (bpf_core_field_exists(struct task_struct___el8, task_struct_rh)) {
        exec_id = BPF_CORE_READ((const struct task_struct___el8 *)leader, task_struct_rh,
                                self_exec_id);
    }

    return exec_id;
}

// Returns true if the class was already reported for this process life and
// key. Best effort with a plain read-test-write (an atomic or needs 5.12 and
// -mcpu=v3); a lost race on a fresh or stale entry overwrites it, so the
// failure mode is a duplicate event, never a lost one.
static __always_inline bool file_access_seen__test_and_set(void *map, const void *key,
                                                           struct file_access_scratch *scratch,
                                                           const struct task_struct  *task,
                                                           u64                        bit)
{
    u64 start_time_ns = BPF_CORE_READ(task, group_leader, start_time);
    u64 exec_id       = file_access_exec_id(task);

    struct file_access_seen *seen = bpf_map_lookup_elem(map, key);
    if (seen == NULL || seen->start_time_ns != start_time_ns || seen->exec_id != exec_id) {
        scratch->fresh.start_time_ns = start_time_ns;
        scratch->fresh.exec_id       = exec_id;
        scratch->fresh.bits          = bit;
        bpf_map_update_elem(map, key, &scratch->fresh, BPF_ANY);
        return false;
    }
    if (seen->bits & bit)
        return true;
    seen->bits |= bit;

    return false;
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
// nearest ancestors is a parent anchor. The walk stops at the root of the
// dentry tree, which is its own parent, so it does not cross mounts.
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

static void file_access_event__fill_task(struct ebpf_file_access_event *event,
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

// A completed open: leaf or ancestor anchor hit, dedup, resolve, emit. Kept
// out of line, like prepare_and_send_file_event(), so its locals are not
// added to the do_filp_open__exit() frame that every open pays for.
static __attribute__((noinline)) void file_access__open(struct file *f, u32 open_flags)
{
    struct ebpf_file_access_event *event;
    struct file_access_scratch    *scratch;
    struct task_struct            *task;
    struct dentry                 *de;
    u32                            zero = 0;
    u64                            class;

    scratch = bpf_map_lookup_elem(&elastic_ebpf_file_access_scratch, &zero);
    if (scratch == NULL)
        return;

    de = BPF_CORE_READ(f, f_path.dentry);
    if (!file_access_anchored(&scratch->key, de))
        return;

    task                    = (struct task_struct *)bpf_get_current_task();
    class                   = file_access_class(open_flags);
    scratch->file_key.tgid  = BPF_CORE_READ(task, tgid);
    scratch->file_key.dev   = BPF_CORE_READ(de, d_inode, i_sb, s_dev);
    scratch->file_key.inode = BPF_CORE_READ(de, d_inode, i_ino);
    if (file_access_seen__test_and_set(&elastic_ebpf_file_access_file_seen, &scratch->file_key,
                                       scratch, task, class))
        return;

    event = get_event_buffer();
    if (!event)
        return;

    file_access_event__fill_task(event, task);
    ebpf_file_info__fill(&event->finfo, de);
    event->open_flags = open_flags;
    event->fmode      = BPF_CORE_READ(f, f_mode);

    // Variable length fields
    ebpf_vl_fields__init(&event->vl_fields);
    struct ebpf_varlen_field *field;
    long size;

    // path
    field         = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_PATH);
    scratch->path = BPF_CORE_READ(f, f_path);
    size          = ebpf_resolve_path_to_string(field->data, &scratch->path, task);
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
}

static int do_filp_open__exit(int dfd, struct filename *pathname, const struct open_flags *op,
                              struct file *f)
{
    /*
    'ret' fields such f_mode and f_path should be obtained via BPF_CORE_READ
    because there's a kernel bug that causes a panic.
    Read more: github.com/torvalds/linux/commit/588a25e92458c6efeb7a261d5ca5726f5de89184
    */

    if (IS_ERR_OR_NULL(f))
        goto out;

    if (ebpf_events_is_trusted_pid())
        goto out;

    if (file_access_enabled)
        file_access__open(f, op != NULL ? (u32)BPF_CORE_READ(op, open_flag)
                                        : (u32)BPF_CORE_READ(f, f_flags));

    fmode_t fmode = BPF_CORE_READ(f, f_mode);
    if ((fmode & (fmode_t)0x100000) ||                                 // FMODE_CREATED
        (ebpf_events_state__get(EBPF_EVENTS_STATE_FS_CREATE) != NULL)) { // 4.18.x
        // generate a file creation event
        prepare_and_send_file_event(f, EBPF_EVENT_FILE_CREATE, NULL, 0);
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
            prepare_and_send_file_event(f, EBPF_EVENT_FILE_MEMFD_OPEN, NULL, 0);
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
            prepare_and_send_file_event(f, EBPF_EVENT_FILE_SHMEM_OPEN, DEVSHM_STRING,
                                        sizeof(DEVSHM_STRING) - 1);
        }
    }

out:
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
    int r;

    preempt_disable();
    r = do_filp_open__exit(dfd, pathname, op, ret);
    preempt_enable();

    return r;
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
    struct ebpf_events_state *state;
    int                       dfd      = 0;
    struct filename          *pathname = NULL;
    const struct open_flags  *op       = NULL;
    int                       r;

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
    int r;

    preempt_disable();
    r = do_filp_open__kretprobe(ret);
    preempt_enable();

    return r;
}

SEC("fexit/do_file_open")
int BPF_PROG(fexit__do_file_open,
             int dfd,
             struct filename *pathname,
             const struct open_flags *op,
             struct file *ret)
{
    int r;

    preempt_disable();
    r = do_filp_open__exit(dfd, pathname, op, ret);
    preempt_enable();

    return r;
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
    int r;

    preempt_disable();
    r = do_filp_open__kretprobe(ret);
    preempt_enable();

    return r;
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

static int vfs_rename__enter(struct dentry *old_dentry, struct dentry *new_dentry)
{
    struct ebpf_events_state *state;

    state = ebpf_events_state__get(EBPF_EVENTS_STATE_RENAME);
    if (!state || state->rename.step != RENAME_STATE_MOUNT_SET) {
        // Omit logging as this happens in the happy path.
        goto out;
    }

    struct ebpf_events_scratch_space *ss = ebpf_events_scratch_space__get(EBPF_EVENTS_STATE_RENAME);
    if (!ss) {
        bpf_printk("vfs_rename__enter: scratch space missing\n");
        goto out;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct path p;
    p.mnt    = state->rename.mnt;
    p.dentry = old_dentry;
    ebpf_resolve_path_to_string(ss->rename.old_path, &p, task);
    p.dentry = new_dentry;
    ebpf_resolve_path_to_string(ss->rename.new_path, &p, task);

    state->rename.step = RENAME_STATE_PATHS_SET;
    state->rename.de   = old_dentry;

out:
    return 0;
}

SEC("fentry/vfs_rename")
int BPF_PROG(fentry__vfs_rename)
{
    struct dentry *old_dentry, *new_dentry;
    int r;

    preempt_disable();

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

    r = vfs_rename__enter(old_dentry, new_dentry);
    preempt_enable();
    return r;
}

SEC("kprobe/vfs_rename")
int BPF_KPROBE(kprobe__vfs_rename)
{
    struct dentry *old_dentry, *new_dentry;
    int r;

    preempt_disable();
    r = 0;
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
    preempt_enable();
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
