// SPDX-License-Identifier: Apache-2.0
/*
 * Decisive test for the premise of PR #406 / #404:
 *
 *   "before Linux 5.9 (bdb7b79b4ce8) helpers were declared to return int,
 *    and the JIT zero-extends the 32-bit result, so a 64-bit compare
 *    against a negative errno never matches on older kernels"
 *
 * We force bpf_probe_read_kernel_str() (and, as a fallback for kernels
 * that lack it, bpf_probe_read_str()) to fail with -EFAULT, and record:
 *
 *   - the raw 64-bit value of R0 as returned by the helper
 *   - whether the 64-bit signed compare `ret < 0` takes the error branch
 *     (the exact pre-#406 code shape, e.g. read_kernel_str_or_empty_str)
 *   - whether the 32-bit compare `(int)ret < 0` takes it (the #406 fix)
 *
 * and the same for a duplicate BPF_NOEXIST bpf_map_update_elem(),
 * compared against -EEXIST in 64 bits (the exact #404 code shape).
 *
 * If the premise is right, on a pre-5.9 kernel raw R0 is 0x00000000fffffff2
 * and the 64-bit branches are NOT taken. If the kernel sign-extends (as
 * bdb7b79b4ce8's own commit message states all in-kernel helpers do), raw
 * R0 is 0xfffffffffffffff2 and the 64-bit branches ARE taken.
 *
 * barrier_var() between every use prevents clang from folding the three
 * observations into one compare.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define TEST_EFAULT_ADDR ((const void *)16) /* unmapped, faults everywhere */
#define TEST_EEXIST	 17

#define BRANCH_TAKEN	 1
#define BRANCH_NOT_TAKEN 2

struct results {
	__u64	ran;
	__u64	str_raw;	/* raw R0 from the failed string read */
	__u64	str_lt0_64;	/* ret < 0        -> 1 taken, 2 not */
	__u64	str_lt0_32;	/* (int)ret < 0   -> 1 taken, 2 not */
	__u64	upd_raw;	/* raw R0 from duplicate BPF_NOEXIST update */
	__u64	upd_eq_eexist_64; /* ret == -EEXIST (64-bit) -> 1/2 */
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2); /* [0] = kernel_str prog, [1] = str prog */
	__type(key, __u32);
	__type(value, struct results);
} results_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u32);
} dedup_map SEC(".maps");

static __always_inline void
record(struct results *res, long ret)
{
	__u32	k = 1, v = 1;
	long	ret2;

	barrier_var(ret);
	res->str_raw = (__u64)ret;
	barrier_var(ret);
	res->str_lt0_64 = ret < 0 ? BRANCH_TAKEN : BRANCH_NOT_TAKEN;
	barrier_var(ret);
	res->str_lt0_32 = (int)ret < 0 ? BRANCH_TAKEN : BRANCH_NOT_TAKEN;

	/* #404 shape: duplicate BPF_NOEXIST insert, compared in 64 bits */
	bpf_map_update_elem(&dedup_map, &k, &v, BPF_ANY);
	ret2 = bpf_map_update_elem(&dedup_map, &k, &v, BPF_NOEXIST);
	barrier_var(ret2);
	res->upd_raw = (__u64)ret2;
	barrier_var(ret2);
	res->upd_eq_eexist_64 =
	    ret2 == -TEST_EEXIST ? BRANCH_TAKEN : BRANCH_NOT_TAKEN;

	res->ran++;
}

SEC("tracepoint/syscalls/sys_enter_getpid")
int test_kernel_str(void *ctx)
{
	__u32		 key = 0;
	char		 buf[16];
	struct results	*res;
	long		 ret;

	res = bpf_map_lookup_elem(&results_map, &key);
	if (res == NULL)
		return 0;
	ret = bpf_probe_read_kernel_str(buf, sizeof(buf), TEST_EFAULT_ADDR);
	record(res, ret);

	return 0;
}

/* Fallback for kernels without bpf_probe_read_kernel_str (< 5.5, old RHEL8):
 * bpf_probe_read_str (4.11+) was equally declared int before bdb7b79b4ce8. */
SEC("tracepoint/syscalls/sys_enter_getppid")
int test_str(void *ctx)
{
	__u32		 key = 1;
	char		 buf[16];
	struct results	*res;
	long		 ret;

	res = bpf_map_lookup_elem(&results_map, &key);
	if (res == NULL)
		return 0;
	ret = bpf_probe_read_str(buf, sizeof(buf), TEST_EFAULT_ADDR);
	record(res, ret);

	return 0;
}
