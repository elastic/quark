// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* Copyright (c) 2026 Elastic NV */

#ifndef EBPF_EVENTPROBE_EVENTS_BPFCALLSTACK_H
#define EBPF_EVENTPROBE_EVENTS_BPFCALLSTACK_H

/* vmlinux.h supplies these types to BPF programs. */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

/*
 * The syscall/SYSCALL-program loader path has two live dispatcher levels.
 * Extra slots provide headroom for saved frames left by missed returns.
 * This storage bound is not a guarantee about kernel nesting depth.
 */
#define EBPF_BPF_CALL_DEPTH 8

struct ebpf_bpf_call_stack {
    __u64 sp[EBPF_BPF_CALL_DEPTH];
    __u32 depth;
};

/*
 * sp is an opaque position on one task's kernel stack. Each invocation's
 * entry and return must supply the same nonzero value; nested calls must
 * have smaller values. An entry at the same or a higher position supersedes
 * stale frames whose returns were missed.
 * Return the new frame's index, or -1 for invalid position/state or a full stack.
 * The caller must clear its parallel frame data after a successful push.
 * After a rejected push, the caller must prevent the untracked invocation's
 * metadata from enriching a saved parent until that invocation has unwound.
 * dropped counts existing frames discarded here, not the rejected new entry.
 */
static __inline__ __attribute__((always_inline)) int
bpf_call_push(struct ebpf_bpf_call_stack *stack, __u64 sp, __u32 *dropped)
{
    __u32 depth = stack->depth;

    *dropped = 0;
    if (sp == 0 || depth > EBPF_BPF_CALL_DEPTH)
        return -1;

#ifdef __clang__
#pragma unroll
#endif
    // Constant indices after unrolling keep each map read verifier-bounded.
    for (int i = EBPF_BPF_CALL_DEPTH - 1; i >= 0; i--) {
        if ((__u32)i >= depth)
            continue;
        if (stack->sp[i] > sp)
            break;
        depth = (__u32)i;
        (*dropped)++;
    }

    stack->depth = depth;
    if (depth >= EBPF_BPF_CALL_DEPTH)
        return -1;
    stack->sp[depth] = sp;
    stack->depth = depth + 1;
    return (int)depth;
}

/*
 * Drop and count saved positions below this return: those calls have finished
 * even if no entry matches. Pop an exact match without counting it as dropped.
 * An unmatched return preserves enclosing frames, including returns from calls
 * whose entry overflowed the bounded stack. The caller must then invalidate
 * their metadata using bpf_call_unmatched_return(). Inactive position slots
 * need not be cleared; only indices below depth are live.
 */
static __inline__ __attribute__((always_inline)) int
bpf_call_find_return(struct ebpf_bpf_call_stack *stack, __u64 sp, __u32 *dropped)
{
    __u32 depth = stack->depth;
    int found = -1;

    *dropped = 0;
    if (sp == 0 || depth > EBPF_BPF_CALL_DEPTH)
        return -1;

#ifdef __clang__
#pragma unroll
#endif
    for (int i = EBPF_BPF_CALL_DEPTH - 1; i >= 0; i--) {
        if ((__u32)i >= depth)
            continue;
        if (stack->sp[i] > sp)
            break;
        depth = (__u32)i;
        if (stack->sp[i] == sp) {
            found = i;
            break;
        }
        (*dropped)++;
    }
    stack->depth = depth;
    return found;
}

/*
 * An unmatched child return proves its entry was not tracked. Its metadata
 * hooks may have enriched an enclosing frame, so the caller must invalidate
 * collection for these slots without consuming their eventual returns.
 */
static __inline__ __attribute__((always_inline)) __u32
bpf_call_unmatched_return(const struct ebpf_bpf_call_stack *stack, __u64 sp)
{
    __u32 depth = stack->depth;
    __u32 mask = 0;

    if (sp == 0 || depth > EBPF_BPF_CALL_DEPTH)
        return 0;

#ifdef __clang__
#pragma unroll
#endif
    for (int i = 0; i < EBPF_BPF_CALL_DEPTH; i++) {
        if ((__u32)i < depth && stack->sp[i] > sp)
            mask |= 1U << i;
    }
    return mask;
}

#endif
