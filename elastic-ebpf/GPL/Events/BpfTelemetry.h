// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* Copyright (c) 2026 Elastic NV */

#ifndef EBPF_BPF_TELEMETRY_H
#define EBPF_BPF_TELEMETRY_H

#include "BpfCallStack.h"

#define EBPF_BPF_COMMON_ATTRS (1U << 16)

struct ebpf_bpf_load_attr {
    u32 prog_type;
    u32 insn_cnt;
    u64 insns;
    u64 license;
    u32 log_level;
    u32 log_size;
    u64 log_buf;
    u32 kern_version;
    u32 prog_flags;
    char prog_name[EBPF_BPF_NAME_LEN];
    u32 prog_ifindex;
    u32 expected_attach_type;
};

struct ebpf_bpf_call {
    u32 cmd;
    u32 collect;
    u32 valid;
    u32 security_seen;
    u32 id; // provisional until fd installation succeeds
    u32 object_type;
    u32 type;
    u32 insn_cnt;
    u32 flags;
    u32 attach_type;
    char name[EBPF_BPF_NAME_LEN];
};

struct ebpf_bpf_calls {
    struct ebpf_bpf_call_stack stack;
    // An untracked overflow invocation must not overwrite a tracked parent.
    u64 blocked_sp;
    u64 task_start_time;
    struct ebpf_bpf_call call[EBPF_BPF_CALL_DEPTH];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct ebpf_bpf_calls);
    __uint(max_entries, 4096);
} bpf_calls SEC(".maps");

static const struct ebpf_bpf_calls empty_bpf_calls;

static void bpf_capture_lost(u32 frames, bool metadata)
{
    u32 zero = 0;
    struct ebpf_event_stats *stats;

    if (!frames)
        return;
    stats = bpf_map_lookup_elem(&ringbuf_stats, &zero);
    if (!stats)
        return;
    if (metadata)
        stats->bpf_metadata_lost += frames;
    else
        stats->bpf_state_lost += frames;
}

static int bpf_call__enter(u64 sp, u32 cmd)
{
    u64 task = bpf_get_current_pid_tgid();
    u64 start_time;
    struct ebpf_bpf_calls *calls;
    struct ebpf_bpf_call *call;
    u32 dropped;
    int slot;

    if (is_consumer())
        return 0;
    start_time = BPF_CORE_READ((const struct task_struct *)bpf_get_current_task(), start_time);
    calls = bpf_map_lookup_elem(&bpf_calls, &task);
    if (!calls) {
        if (bpf_map_update_elem(&bpf_calls, &task, &empty_bpf_calls, BPF_NOEXIST)) {
            bpf_capture_lost(1, false);
            return 0;
        }
        calls = bpf_map_lookup_elem(&bpf_calls, &task);
        if (!calls)
            return 0;
    }
    // Task-exit cleanup is the normal path; also defend against a missed
    // cleanup followed by pid reuse with a different kernel stack address.
    if (calls->task_start_time != start_time) {
        bpf_capture_lost(calls->stack.depth, false);
        calls->stack.depth = 0;
        calls->blocked_sp = 0;
        calls->task_start_time = start_time;
    }
    if (sp >= calls->blocked_sp)
        calls->blocked_sp = 0;
    slot = bpf_call_push(&calls->stack, sp, &dropped);
    bpf_capture_lost(dropped, false);
    if (slot < 0 || slot >= EBPF_BPF_CALL_DEPTH) {
        if (!calls->blocked_sp)
            calls->blocked_sp = sp;
        bpf_capture_lost(1, false);
        return 0;
    }
    call = &calls->call[slot];
    __builtin_memset(call, 0, sizeof(*call));
    call->cmd = cmd & ~EBPF_BPF_COMMON_ATTRS;
    // Snapshot trust per invocation; a self-insert cannot hide its result.
    call->collect = call->cmd == BPF_PROG_LOAD && !ebpf_events_is_trusted_pid();
    return 0;
}

static struct ebpf_bpf_call *bpf_call__current(void)
{
    u64 task = bpf_get_current_pid_tgid();
    struct ebpf_bpf_calls *calls = bpf_map_lookup_elem(&bpf_calls, &task);
    u32 depth;

    if (!calls || calls->blocked_sp)
        return NULL;
    // Check the index after subtraction, including wraparound from depth 0.
    depth = calls->stack.depth - 1;
    if (depth >= EBPF_BPF_CALL_DEPTH)
        return NULL;
    return &calls->call[depth];
}

SEC("kprobe/security_bpf")
int BPF_KPROBE(bpf_load__security, u32 cmd, const void *attr)
{
    struct ebpf_bpf_call *call;
    struct ebpf_bpf_load_attr a = {};

    preempt_disable();
    call = bpf_call__current();
    if (!call || !call->collect)
        goto out;
    if ((cmd & ~EBPF_BPF_COMMON_ATTRS) != call->cmd || call->security_seen) {
        // A missed boundary must not turn a child's metadata into a parent.
        call->collect = 0;
        bpf_capture_lost(1, false);
        goto out;
    }
    // security_bpf receives the kernel's normalized, zero-filled attr copy.
    call->security_seen = 1;
    if (!bpf_probe_read_kernel(&a, sizeof(a), attr)) {
        call->type = a.prog_type;
        call->insn_cnt = a.insn_cnt;
        call->flags = a.prog_flags;
        call->attach_type = a.expected_attach_type;
        __builtin_memcpy(call->name, a.prog_name, sizeof(call->name));
        call->valid |= EBPF_BPF_VALID_ATTR;
    }
out:
    preempt_enable();
    return 0;
}

SEC("kprobe/security_bpf_prog")
int BPF_KPROBE(bpf_load__prog, const struct bpf_prog *prog)
{
    struct ebpf_bpf_call *call;

    preempt_disable();
    call = bpf_call__current();
    if (call && call->collect && (call->valid & EBPF_BPF_VALID_ATTR)) {
        // The object is referenced here, after ID allocation and before fd
        // installation. Never resolve the returned fd through a racing table.
        if (call->id) {
            call->collect = 0;
            bpf_capture_lost(1, false);
        } else {
            call->id = BPF_CORE_READ(prog, aux, id);
            call->object_type = BPF_CORE_READ(prog, type);
        }
    }
    preempt_enable();
    return 0;
}

static int bpf_call__exit(u64 sp, s32 ret)
{
    u64 task = bpf_get_current_pid_tgid();
    struct ebpf_bpf_calls *calls = bpf_map_lookup_elem(&bpf_calls, &task);
    struct ebpf_bpf_call *call;
    struct ebpf_process_bpf_event *event;
    u32 dropped, enclosing;
    int slot;

    if (!calls)
        return 0;
    if (sp >= calls->blocked_sp)
        calls->blocked_sp = 0;
    slot = bpf_call_find_return(&calls->stack, sp, &dropped);
    bpf_capture_lost(dropped, false);
    if (slot < 0 || slot >= EBPF_BPF_CALL_DEPTH) {
        // If an entry was missed, its typed hooks may have seen a tracked
        // parent. Discard that parent's event rather than publish ambiguity.
        enclosing = bpf_call_unmatched_return(&calls->stack, sp);
#pragma unroll
        for (int i = 0; i < EBPF_BPF_CALL_DEPTH; i++) {
            if ((enclosing & (1U << i)) && calls->call[i].collect) {
                calls->call[i].collect = 0;
                bpf_capture_lost(1, false);
            }
        }
        return 0; // never consume an unrelated invocation
    }
    call = &calls->call[slot];
    if (!call->collect)
        goto out;
    event = get_zeroed_event_buffer(sizeof(*event));
    if (!event) {
        bpf_capture_lost(1, false);
        goto out;
    }
    event->hdr.type = EBPF_EVENT_PROCESS_BPF;
    event->hdr.ts = bpf_ktime_get_boot_ns();
    ebpf_pid_info__fill(&event->pids, (const struct task_struct *)bpf_get_current_task());
    event->ret = ret;
    event->cmd = call->cmd;
    event->valid = call->valid;
    if (call->valid & EBPF_BPF_VALID_ATTR) {
        event->type = call->type;
        event->attach_type = call->attach_type;
        event->flags = call->flags;
        event->insn_cnt = call->insn_cnt;
        __builtin_memcpy(event->name, call->name, sizeof(event->name));
    }
    if (ret >= 0) {
        if (call->id && call->object_type) {
            event->valid |= EBPF_BPF_VALID_OBJECT;
            event->kind = EBPF_BPF_KIND_PROG;
            event->id = call->id;
            event->type = call->object_type;
        }
    }
    if ((call->security_seen && !(call->valid & EBPF_BPF_VALID_ATTR)) ||
        (ret >= 0 && (!call->id || !call->object_type)))
        bpf_capture_lost(1, true);
    ebpf_ringbuf_write(&ringbuf, event, sizeof(*event), 0);
out:
    if (!calls->stack.depth)
        bpf_map_delete_elem(&bpf_calls, &task);
    return 0;
}

// These boundary probes are attached manually to one selected dispatcher, or
// to the legacy native/compat wrappers. Never attach both strategies.
SEC("kprobe")
int bpf_call_enter_direct(struct pt_regs *ctx)
{
    preempt_disable();
    bpf_call__enter(PT_REGS_SP(ctx), PT_REGS_PARM1(ctx));
    preempt_enable();
    return 0;
}

SEC("kprobe")
int bpf_call_enter_native(struct pt_regs *ctx)
{
    const struct pt_regs *regs = (const void *)PT_REGS_PARM1(ctx);
    u32 cmd;

#if defined(__TARGET_ARCH_x86)
    cmd = BPF_CORE_READ(regs, di);
#elif defined(__TARGET_ARCH_arm64)
    cmd = BPF_CORE_READ(regs, regs[0]);
#else
#error unsupported BPF operation boundary architecture
#endif
    preempt_disable();
    bpf_call__enter(PT_REGS_SP(ctx), cmd);
    preempt_enable();
    return 0;
}

#if defined(__TARGET_ARCH_x86)
SEC("kprobe")
int bpf_call_enter_compat(struct pt_regs *ctx)
{
    const struct pt_regs *regs = (const void *)PT_REGS_PARM1(ctx);
    u32 cmd = BPF_CORE_READ(regs, bx);

    preempt_disable();
    bpf_call__enter(PT_REGS_SP(ctx), cmd);
    preempt_enable();
    return 0;
}
#endif

SEC("kretprobe")
int bpf_call_exit(struct pt_regs *ctx)
{
    u64 sp = PT_REGS_SP(ctx);

#if defined(__TARGET_ARCH_x86)
    sp -= sizeof(u64); // RET has popped the return address on x86.
#endif
    preempt_disable();
    bpf_call__exit(sp, (s32)PT_REGS_RC(ctx));
    preempt_enable();
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int bpf_call_task_exit(void *ctx)
{
    u64 task = bpf_get_current_pid_tgid();
    struct ebpf_bpf_calls *calls;

    preempt_disable();
    calls = bpf_map_lookup_elem(&bpf_calls, &task);
    if (calls) {
        bpf_capture_lost(calls->stack.depth, false);
        bpf_map_delete_elem(&bpf_calls, &task);
    }
    preempt_enable();
    return 0;
}

#endif
