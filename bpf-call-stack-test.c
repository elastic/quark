// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2026 Elastic NV */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "elastic-ebpf/GPL/Events/BpfCallStack.h"
#include "quark-test.h"

static void
expect_same(const struct ebpf_bpf_call_stack *stack,
    const struct ebpf_bpf_call_stack *saved)
{
    assert(stack->depth == saved->depth);
    assert(memcmp(stack->sp, saved->sp, sizeof(stack->sp)) == 0);
}

static void
expect_push(struct ebpf_bpf_call_stack *stack, __u64 sp, int index,
    __u32 discarded)
{
    __u32 dropped = ~0U;

    assert(bpf_call_push(stack, sp, &dropped) == index);
    assert(dropped == discarded);
    if (index >= 0) {
        assert(stack->depth == (__u32)index + 1);
        assert(stack->sp[index] == sp);
    }
}

static void
expect_return(struct ebpf_bpf_call_stack *stack, __u64 sp, int index,
    __u32 discarded)
{
    __u32 dropped = ~0U;

    assert(bpf_call_find_return(stack, sp, &dropped) == index);
    assert(dropped == discarded);
    if (index >= 0)
        assert(stack->depth == (__u32)index);
}

static void
test_normal_and_nested(void)
{
    struct ebpf_bpf_call_stack stack = {.sp = {0}, .depth = 0};
    int report[EBPF_BPF_CALL_DEPTH] = {0};
    __u32 dropped;
    int slot;

    expect_push(&stack, 1000, 0, 0);
    expect_return(&stack, 1000, 0, 0);
    expect_return(&stack, 1000, -1, 0);

    /* Ignored commands occupy frames too; only the caller selects events. */
    slot = bpf_call_push(&stack, 1000, &dropped);
    assert(slot == 0 && dropped == 0);
    report[slot] = 0; /* excluded outer PROG_TEST_RUN */
    slot = bpf_call_push(&stack, 900, &dropped);
    assert(slot == 1 && dropped == 0);
    report[slot] = 1; /* reportable inner load */
    slot = bpf_call_push(&stack, 800, &dropped);
    assert(slot == 2 && dropped == 0);
    report[slot] = 0; /* ignored inner command */

    slot = bpf_call_find_return(&stack, 800, &dropped);
    assert(slot == 2 && dropped == 0 && report[slot] == 0);
    slot = bpf_call_find_return(&stack, 900, &dropped);
    assert(slot == 1 && dropped == 0 && report[slot] == 1);
    slot = bpf_call_find_return(&stack, 1000, &dropped);
    assert(slot == 0 && dropped == 0 && report[slot] == 0);
    assert(stack.depth == 0);
}

static void
test_missed_returns(void)
{
    struct ebpf_bpf_call_stack stack = {.sp = {0}, .depth = 0};

    expect_push(&stack, 1000, 0, 0);
    expect_push(&stack, 900, 1, 0);
    expect_push(&stack, 800, 2, 0);
    /* Both inner returns were missed; a sibling entry discards both. */
    expect_push(&stack, 900, 1, 2);
    expect_return(&stack, 900, 1, 0);
    expect_return(&stack, 1000, 0, 0);

    expect_push(&stack, 1000, 0, 0);
    expect_push(&stack, 900, 1, 0);
    expect_push(&stack, 800, 2, 0);
    /* A parent return recovers even without another intervening entry. */
    expect_return(&stack, 1000, 0, 2);
    expect_return(&stack, 800, -1, 0);

    expect_push(&stack, 1000, 0, 0);
    expect_push(&stack, 900, 1, 0);
    /* Same-depth reuse of the entire call boundary discards stale state. */
    expect_push(&stack, 1000, 0, 2);
    expect_return(&stack, 1000, 0, 0);
}

static void
test_missing_entries(void)
{
    struct ebpf_bpf_call_stack stack = {.sp = {0}, .depth = 0}, saved;

    expect_return(&stack, 1000, -1, 0);
    expect_push(&stack, 1000, 0, 0);
    expect_push(&stack, 800, 1, 0);
    saved = stack;
    /* A missing entry at any depth cannot consume either recorded frame. */
    expect_return(&stack, 700, -1, 0);
    expect_same(&stack, &saved);
    expect_return(&stack, 900, -1, 0);
    expect_same(&stack, &saved);
    expect_return(&stack, 1100, -1, 0);
    expect_same(&stack, &saved);
    expect_return(&stack, 800, 1, 0);
    expect_return(&stack, 1000, 0, 0);
}

static void
test_overflow(void)
{
    struct ebpf_bpf_call_stack stack = {.sp = {0}, .depth = 0}, saved;

    for (int i = 0; i < EBPF_BPF_CALL_DEPTH; i++)
        expect_push(&stack, 1000 - (__u64)i * 10, i, 0);
    saved = stack;
    expect_push(&stack, 900, -1, 0);
    expect_push(&stack, 890, -1, 0);
    expect_same(&stack, &saved);
    expect_return(&stack, 890, -1, 0);
    expect_return(&stack, 900, -1, 0);
    expect_same(&stack, &saved);
    for (int i = EBPF_BPF_CALL_DEPTH - 1; i >= 0; i--)
        expect_return(&stack, 1000 - (__u64)i * 10, i, 0);

    /* A missed overflow return cannot block recovery at a parent entry. */
    for (int i = 0; i < EBPF_BPF_CALL_DEPTH; i++)
        expect_push(&stack, 1000 - (__u64)i * 10, i, 0);
    expect_push(&stack, 900, -1, 0);
    expect_push(&stack, 980, 2, 6);
    expect_return(&stack, 980, 2, 0);
    expect_return(&stack, 990, 1, 0);
    expect_return(&stack, 1000, 0, 0);

    for (int i = 0; i < EBPF_BPF_CALL_DEPTH; i++)
        expect_push(&stack, 1000 - (__u64)i * 10, i, 0);
    expect_return(&stack, 1000, 0, EBPF_BPF_CALL_DEPTH - 1);
}

static void
test_invalid_sp(void)
{
    struct ebpf_bpf_call_stack stack = {.sp = {0}, .depth = 0}, saved;

    expect_push(&stack, 0, -1, 0);
    expect_return(&stack, 0, -1, 0);
    expect_push(&stack, 1000, 0, 0);
    saved = stack;
    expect_push(&stack, 0, -1, 0);
    expect_return(&stack, 0, -1, 0);
    expect_same(&stack, &saved);
    expect_return(&stack, 1000, 0, 0);

    /* Corrupt depth must not result in out-of-bounds SP reads or writes. */
    stack.depth = EBPF_BPF_CALL_DEPTH + 1;
    saved = stack;
    expect_push(&stack, 900, -1, 0);
    expect_return(&stack, 1000, -1, 0);
    expect_same(&stack, &saved);
}

static void
test_task_reuse(void)
{
    struct ebpf_bpf_call_stack stack = {.sp = {0}, .depth = 0};

    expect_push(&stack, 1000, 0, 0);
    expect_push(&stack, 900, 1, 0);
    /* An equal or higher reused SP recovers stale frames at the next entry. */
    expect_push(&stack, 1100, 0, 2);
    expect_return(&stack, 1100, 0, 0);

    expect_push(&stack, 1000, 0, 0);
    expect_push(&stack, 900, 1, 0);
    /* Actual task-lifetime reuse requires caller cleanup, not SP guessing. */
    memset(&stack, 0, sizeof(stack));
    expect_return(&stack, 1000, -1, 0);
    expect_push(&stack, 800, 0, 0);
    expect_return(&stack, 800, 0, 0);
}

static void
test_unmatched_return_metadata(void)
{
    struct ebpf_bpf_call_stack stack = {.sp = {0}, .depth = 0}, saved;
    struct {
        int collect;
        __u32 requested_type;
        __u32 candidate_id;
    } frame[EBPF_BPF_CALL_DEPTH] = {{0, 0, 0}};
    __u32 mask, dropped;
    int slot, emitted = 0;

    assert(bpf_call_unmatched_return(&stack, 900) == 0);
    expect_push(&stack, 1000, 0, 0);
    frame[0].collect = 1;
    /*
     * The parent's security observation and the child's entry are missed.
     * Observed child metadata is therefore wrongly staged in the parent.
     */
    frame[0].requested_type = 7;
    frame[0].candidate_id = 123;
    expect_return(&stack, 900, -1, 0);
    saved = stack;
    mask = bpf_call_unmatched_return(&stack, 900);
    assert(mask == 1U);
    expect_same(&stack, &saved);
    for (int i = 0; i < EBPF_BPF_CALL_DEPTH; i++) {
        if (mask & (1U << i))
            frame[i].collect = 0;
    }
    slot = bpf_call_find_return(&stack, 1000, &dropped);
    assert(slot == 0 && dropped == 0);
    if (frame[slot].collect)
        emitted++;
    assert(emitted == 0); /* never pair child's metadata with parent's fd */

    expect_push(&stack, 1000, 0, 0);
    expect_push(&stack, 800, 1, 0);
    saved = stack;
    assert(bpf_call_unmatched_return(&stack, 700) == 3U);
    assert(bpf_call_unmatched_return(&stack, 900) == 1U);
    assert(bpf_call_unmatched_return(&stack, 1100) == 0);
    assert(bpf_call_unmatched_return(&stack, 0) == 0);
    expect_same(&stack, &saved);

    /* Next observed entry at the same SP replaces the missed-return frame. */
    frame[1].collect = 1;
    frame[1].candidate_id = 456;
    expect_push(&stack, 800, 1, 1);
    memset(&frame[1], 0, sizeof(frame[1])); /* caller's push contract */
    frame[1].collect = 1;
    frame[1].requested_type = 1;
    frame[1].candidate_id = 789;
    slot = bpf_call_find_return(&stack, 800, &dropped);
    assert(slot == 1 && dropped == 0);
    assert(frame[slot].collect && frame[slot].requested_type == 1);
    assert(frame[slot].candidate_id == 789);
    expect_return(&stack, 1000, 0, 0);
}

int
t_bpf_call_stack(const struct test *t, struct quark_queue_attr *qa)
{
    test_normal_and_nested();
    test_missed_returns();
    test_missing_entries();
    test_overflow();
    test_invalid_sp();
    test_task_reuse();
    test_unmatched_return_metadata();
    return 0;
}
