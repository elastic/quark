// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2026 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

#ifndef EBPF_EVENTPROBE_EVENTS_DEDUP_H
#define EBPF_EVENTPROBE_EVENTS_DEDUP_H

#include "vmlinux.h"
#include "vmlinux_extra.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

/*
 * Once per process life deduplication shared by the probes that report a
 * transition rather than every call (mprotect, file_access). A map keyed by
 * the caller's choice, usually (tgid, device, inode), holds the bits already
 * reported for that key together with the process start time and
 * self_exec_id, which the kernel bumps on every exec and never reuses within
 * a process life; an entry left behind by a dead process (recycled tgid) or
 * by a previous program image no longer matches and is simply claimed anew,
 * so a stale entry never suppresses and the map needs no exec or exit
 * clearing. (The mm pointer would not do: it is freed at exec and can come
 * straight back from the slab two images later.) LRU eviction takes care of
 * the leftovers and at worst costs a duplicate.
 */
struct ebpf_dedup_file_key {
    u32 tgid;
    u32 dev;
    u64 inode;
};

struct ebpf_dedup_seen {
    u64 start_time_ns;
    u64 exec_id;
    u64 bits;
};

// The exec generation of the process. self_exec_id is u64 since Linux 5.7 and
// u32 before, so read it by its relocated size; the targets are little endian
// so a narrower field lands in the low bytes. RHEL 8 (4.18) backported the
// widening under kABI and the live field only exists in the task_struct_rh
// extension there, see vmlinux_extra.h; a kernel with neither yields zero and
// falls back to start_time alone.
static u64 ebpf_dedup_exec_id(const struct task_struct *task)
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

// Returns true if bit was already reported for this process life and key.
// fresh is caller provided storage for the replacement value (stack, or map
// memory when the caller is short on stack). Best effort with a plain
// read-test-write (an atomic or needs 5.12 and -mcpu=v3); a lost race on a
// fresh or stale entry overwrites it, so the failure mode is a duplicate
// event, never a lost one.
static __always_inline bool ebpf_dedup__test_and_set(void *map, const void *key,
                                                     struct ebpf_dedup_seen *fresh,
                                                     const struct task_struct *task, u64 bit)
{
    u64 start_time_ns = BPF_CORE_READ(task, group_leader, start_time);
    u64 exec_id       = ebpf_dedup_exec_id(task);

    struct ebpf_dedup_seen *seen = bpf_map_lookup_elem(map, key);
    if (seen == NULL || seen->start_time_ns != start_time_ns || seen->exec_id != exec_id) {
        fresh->start_time_ns = start_time_ns;
        fresh->exec_id       = exec_id;
        fresh->bits          = bit;
        bpf_map_update_elem(map, key, fresh, BPF_ANY);
        return false;
    }
    if (seen->bits & bit)
        return true;
    seen->bits |= bit;

    return false;
}

#endif // EBPF_EVENTPROBE_EVENTS_DEDUP_H
