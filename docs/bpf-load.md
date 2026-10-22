# BPF telemetry stack: LOAD foundation draft

This local branch, `nberlin/bpf-stack-load`, starts from #435's parent
`2a0d7eeaa45bc5ac3ac7677274f5c00b7b84da59` through the standalone support
branch `nberlin/bpf-stack-hooks` (`51df19f`). That first commit adds tested
selection/attachment/correlation utilities without enabling telemetry; this
branch adds the LOAD event slice on top. It replaces the LOAD portion
rather than stacking a second implementation onto the original syscall
tracepoints. No remote PR has been created or modified.

The full delivery remains lifecycle telemetry, load-time
`bpf_probe_write_user` information, and strangers' access/tampering with
quark-owned maps, programs and links. This first slice reports only LOAD.
Owned-map mutation is next, so the trusted-pid-map bypass gets direct
telemetry before completing every lifecycle command. Helpers and attachment
slices follow; LOAD alone does not detect that map-write bypass.

## What the draft implements

* Operation entry snapshots consumer/trust selection and normalized command.
  `security_bpf` supplies the kernel's copied, zero-filled attributes.
  `security_bpf_prog` snapshots a referenced program after ID assignment,
  before fd installation. Only a successful operation publishes object ID
  and observed type; fd zero is success, and late fd-allocation failure does
  not publish a provisional object as a successful load.
* Exact `__sys_bpf` entry/return is selected when its symbol and common ABI
  validate. Older kernels without in-kernel syscall helpers use native and
  compat wrapper pairs. The selector rejects ambiguous/missing symbols,
  incompatible prototypes and a modern syscall-only fallback. It reads only
  the command argument at the boundary, avoiding aggregate argument/return
  slot assumptions in newer `__sys_bpf` prototypes.
* The first implementation uses kprobes/return probes. Trampoline optimization
  is deferred; counting BTF parameters is not a valid fexit result offset
  when parameters include by-value aggregates.
* Per-task state holds eight nested frames, including excluded commands.
  Kernel stack positions match returns (x86 return SP minus eight, arm64
  unchanged). Overflow blocks inner metadata collectors; stale frames are
  discarded, unmatched nested returns invalidate ambiguous parent capture,
  and repeated security observations invalidate a frame even if its first
  attr read failed. Task exit deletes state, and task start time defends
  against PID reuse after missed cleanup. These are conservative loss
  defenses, not proof that arbitrary combinations of missed probes are
  observable or recoverable.
* Public validity bits distinguish copied attrs and successful object
  identity. Instruction count and bounded name describe the copied request;
  type comes from the referenced program when object validity is set.
  Actor tgid/tid/start time survive a missing process-cache entry.
* Missing essential hooks fail initialization. Capture-state, metadata and
  tracefs miss counters are separate from ring-buffer loss; tracefs misses
  can overlap state losses and old kernels omit pool exhaustion from them.
  Statistics mark an unavailable/stale tracefs refresh explicitly.
* `QQ_BPF_DETAILS` remains the accepted direction for a separate required
  extra-collection capability set. No flag is shipped in this slice: cheap
  LOAD names come with copied attrs, and there is no actual optional
  collector to enable yet. Write-user remains a detection capability.

## Return attachment decision still needed

The pinned libbpf kretprobe API cannot request `maxactive`, and ordinary PMU
return probes do not expose a named miss counter. The draft creates unique
tracefs `r4096` events, attaches through perf, and deletes only its own events
on close or initialization failure. It requires already mounted, writable
tracefs and readable kprobe profiles; it never mounts tracefs. Nonblocking
randomness prevents startup hanging in an early guest; missing entropy can
fail initialization for an explicit retry.

A crash/SIGKILL closes the perf attachment but can leave disabled named
tracefs events and their pools behind. The user has been asked whether this
new dependency/lifetime behavior is acceptable before further slices are
built on it. Options:

| Option | Coverage and cost |
| --- | --- |
| Retain named return probes for the first slice | Explicit 4096-instance limit and readable profiles back to the older tracefs ABI; adds tracefs permission/mount requirements and crash cleanup debt. Normal and partial-failure cleanup are tested with mocks. |
| Use trampolines first, retain named probes for old kernels | Reduces probe traps and avoids named events on supported newer kernels; needs correct aggregate ABI result-slot handling, separate nesting/correlation validation, and still needs an old-kernel strategy. |
| Use only anonymous PMU return probes | Simpler lifecycle but loses explicit pool sizing and named miss visibility with this libbpf API. This would weaken the selected overload policy and is not the draft's default. |

There is no automatic silent fallback to incomplete core coverage.

## Bounds, cost and validation

The call-state map has 4096 entries of 536 bytes (about 2.1 MiB of values,
plus hash overhead) per queue. Each selected boundary also has a 4096-instance
kernel return-probe pool. Ignored commands still incur entry/security/return
callbacks and nesting work. Top-level calls currently insert/delete map state;
polling overhead must be measured before merge. No probe or workload cost has
been inferred from the earlier low-volume host sample.

Non-root validation includes full dynamic/static builds, native and arm64
BPF compilation, existing C tests, pure adversarial correlation tests,
synthetic BTF selection and mocked return-probe lifecycle tests, plus Go
unit tests. Mock tests never attach probes or write tracefs. Source checks
support SP normalization; early RHEL 8 BTFHub samples have the required
legacy wrapper/security prototypes and no syscall helper enum. These are
source/BTF checks, not kernel runtime validation.

The compiled root integration test checks copied/truncated attrs, early
faults, verifier rejection, successful fd zero and independently queried IDs,
late EMFILE, consumer/trusted suppression, common-bit commands, x86 compat,
and multiple inner helper LOAD results under an excluded PROG_TEST_RUN.
It has not run. The raw nested program still needs verifier validation.
No sudo has been used. Native/compat/helper execution, concurrency/loss,
user-attr races and RHEL 8.5/8.8-to-current kernel runs remain merge gates.
Exact symbol/prototype presence cannot prove that compiler optimization did
not inline another caller; runtime path tests remain necessary.
