#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	/* 4 MiB compile-time default; userspace resizes at load from ncpu. */
	__uint(max_entries, 1 << 22);
} ringbuf SEC(".maps");

#include "Process/Probe.bpf.c"
#include "Network/Probe.bpf.c"
#include "File/Probe.bpf.c"
