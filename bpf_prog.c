#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22); // 4 MiB
} ringbuf SEC(".maps");

#include "Process/Probe.bpf.c"
#include "Network/Probe.bpf.c"
