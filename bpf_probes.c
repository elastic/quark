#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	/* The size is set in userspace derived from ncpu. */
	__uint(max_entries, 0);
} ringbuf SEC(".maps");

#include "Process/Probe.bpf.c"
#include "Network/Probe.bpf.c"
#include "File/Probe.bpf.c"
