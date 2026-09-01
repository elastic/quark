// SPDX-License-Identifier: Apache-2.0
/*
 * Userspace driver for t_helper_ret.bpf.c, see the comment there.
 *
 * Loads the object (preferring the bpf_probe_read_kernel_str program,
 * falling back to bpf_probe_read_str on kernels that lack it), triggers
 * the tracepoint, and prints the recorded raw helper return plus the
 * outcome of the 64-bit and 32-bit compares.
 *
 * Exit codes (propagated by init/krun.sh out of the VM):
 *   0  helper return was SIGN-extended: 64-bit `< 0` compares work,
 *      the PR #406/#404 premise is DISPROVEN on this kernel
 *   1  helper return was ZERO-extended: the premise is CONFIRMED
 *   2  error / inconclusive
 */
#include <sys/syscall.h>
#include <sys/utsname.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define BRANCH_TAKEN	 1
#define BRANCH_NOT_TAKEN 2

struct results {
	__u64	ran;
	__u64	str_raw;
	__u64	str_lt0_64;
	__u64	str_lt0_32;
	__u64	upd_raw;
	__u64	upd_eq_eexist_64;
};

static int
libbpf_print(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	if (level == LIBBPF_DEBUG)
		return (0);
	return (vfprintf(stderr, fmt, ap));
}

static struct bpf_object *
open_and_load(const char *path, const char *enable, const char *disable,
    struct bpf_program **progp)
{
	struct bpf_object	*obj;
	struct bpf_program	*prog;

	obj = bpf_object__open_file(path, NULL);
	if (obj == NULL)
		err(2, "bpf_object__open_file %s", path);
	prog = bpf_object__find_program_by_name(obj, disable);
	if (prog == NULL)
		errx(2, "program %s not found", disable);
	bpf_program__set_autoload(prog, false);

	if (bpf_object__load(obj) != 0) {
		bpf_object__close(obj);
		return (NULL);
	}
	*progp = bpf_object__find_program_by_name(obj, enable);
	if (*progp == NULL)
		errx(2, "program %s not found", enable);

	return (obj);
}

static const char *
branch(__u64 v)
{
	switch (v) {
	case BRANCH_TAKEN:	return "TAKEN";
	case BRANCH_NOT_TAKEN:	return "NOT taken";
	default:		return "??";
	}
}

int
main(int argc, char *argv[])
{
	const char		*path = argc > 1 ? argv[1] : "./t_helper_ret.bpf.o";
	const char		*helper;
	struct bpf_object	*obj;
	struct bpf_program	*prog = NULL;
	struct bpf_link		*link;
	struct results		 res;
	struct utsname		 uts;
	__u32			 key;
	int			 i, map_fd, hi32, lo32;

	libbpf_set_print(libbpf_print);

	if (uname(&uts) == 0)
		printf("kernel: %s %s\n", uts.release, uts.machine);

	obj = open_and_load(path, "test_kernel_str", "test_str", &prog);
	if (obj != NULL) {
		helper = "bpf_probe_read_kernel_str";
		key = 0;
	} else {
		fprintf(stderr,
		    "load with bpf_probe_read_kernel_str failed, "
		    "falling back to bpf_probe_read_str\n");
		obj = open_and_load(path, "test_str", "test_kernel_str", &prog);
		helper = "bpf_probe_read_str";
		key = 1;
	}
	if (obj == NULL)
		errx(2, "could not load bpf object with either helper");

	link = bpf_program__attach(prog);
	if (link == NULL)
		err(2, "bpf_program__attach");

	/* trigger both tracepoints, only the loaded one records */
	for (i = 0; i < 3; i++) {
		syscall(SYS_getpid);
		syscall(SYS_getppid);
	}

	map_fd = bpf_object__find_map_fd_by_name(obj, "results_map");
	if (map_fd < 0)
		errx(2, "results_map not found");
	if (bpf_map_lookup_elem(map_fd, &key, &res) != 0)
		err(2, "bpf_map_lookup_elem");
	if (res.ran == 0)
		errx(2, "probe attached but never fired");

	hi32 = (int)(res.str_raw >> 32);
	lo32 = (int)(res.str_raw & 0xffffffffu);

	printf("helper:                        %s (forced fault at addr 16)\n",
	    helper);
	printf("fired:                         %llu time(s)\n",
	    (unsigned long long)res.ran);
	printf("raw 64-bit helper return (R0): 0x%016llx (%lld)\n",
	    (unsigned long long)res.str_raw, (long long)res.str_raw);
	printf("  low 32 bits as errno:        %d (%s)\n",
	    lo32, lo32 < 0 ? strerror(-lo32) : "not an errno");
	printf("64-bit compare `ret < 0`:      %s\n", branch(res.str_lt0_64));
	printf("32-bit compare `(int)ret < 0`: %s\n", branch(res.str_lt0_32));
	printf("dup BPF_NOEXIST update (R0):   0x%016llx (%lld)\n",
	    (unsigned long long)res.upd_raw, (long long)res.upd_raw);
	printf("64-bit `ret == -EEXIST`:       %s\n",
	    branch(res.upd_eq_eexist_64));

	bpf_link__destroy(link);
	bpf_object__close(obj);

	if (lo32 >= 0) {
		printf("VERDICT: inconclusive, helper did not fail (%d)\n",
		    lo32);
		return (2);
	}
	if (hi32 == -1 && res.str_lt0_64 == BRANCH_TAKEN) {
		printf("VERDICT: SIGN-extended, 64-bit compares work: "
		    "PR premise DISPROVEN on this kernel\n");
		return (0);
	}
	if (hi32 == 0 && res.str_lt0_64 == BRANCH_NOT_TAKEN) {
		printf("VERDICT: ZERO-extended, 64-bit compares broken: "
		    "PR premise CONFIRMED on this kernel\n");
		return (1);
	}
	printf("VERDICT: inconclusive (hi32=0x%08x lt0_64=%llu)\n",
	    (unsigned int)hi32, (unsigned long long)res.str_lt0_64);
	return (2);
}
