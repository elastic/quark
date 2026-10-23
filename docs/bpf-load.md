# BPF telemetry stack: LOAD foundation

This stack starts from #435's parent
`2a0d7eeaa45bc5ac3ac7677274f5c00b7b84da59` through the standalone support
branch `nberlin/bpf-stack-hooks` (`51df19f`). That first commit adds tested
selection/attachment/correlation utilities without enabling telemetry.
The LOAD PR adds the event slice on top. These are new PRs associated with
the review of [PR #435](https://github.com/elastic/quark/pull/435).
They preserve that PR's review history. A separate adapter PR adds fentry/fexit
selection and retains the named-return-probe implementation as its fallback.

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
* This LOAD PR uses kprobes/return probes. A separate PR adds trampolines with
  validated layouts; counting BTF parameters is not a valid fexit result
  offset when parameters include by-value aggregates.
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

Compat calls on supported 64-bit kernels remain in scope. The x86 test uses
`int $0x80` with low-address attrs from a 64-bit binary. A 32-bit quark build
is not required.

## Return attachment policy

The pinned libbpf PMU kretprobe API cannot request `maxactive`.
This adapter creates unique
tracefs `r4096` events, attaches through perf, and deletes only its own events
on close or initialization failure. It requires already mounted, writable
tracefs and readable kprobe profiles; it never mounts tracefs. Nonblocking
randomness prevents startup hanging in an early guest; missing entropy can
fail initialization for an explicit retry.

A crash/SIGKILL closes the perf attachment but can leave disabled named
tracefs events and their pools behind. The accepted stack policy prefers
fentry/fexit and retains this adapter for compatibility. The separate adapter
PR implements that preference; this LOAD PR supplies its tested prerequisite.

Anonymous PMU probes can expose misses through perf BPF links on upstream
6.7+ but still lack explicit pool sizing. Older named profiles omit return-pool
exhaustion. Neither interface establishes complete loss accounting on all
supported kernels. Changing the compatibility adapter is separate work.

There is no automatic silent fallback to incomplete core coverage.

## Bounds, cost and validation

The call-state map has 4096 entries of 536 bytes (about 2.1 MiB of values,
plus hash overhead) per queue. Each selected boundary also has a 4096-instance
kernel return-probe pool. Ignored commands still incur entry/security/return
callbacks and nesting work. Top-level calls currently insert/delete map state;
polling overhead must be measured before merge. No probe or workload cost has
been inferred from the earlier low-volume host sample.

At `58d89d1`, the standalone static binaries and test initramfs built.
The call-state tests, 22 BTF selector tests and seven return-probe lifecycle
tests passed. Mock tests never attach probes or write tracefs. Source checks
support SP normalization; early RHEL 8 BTFHub samples have the required
legacy wrapper/security prototypes and no syscall helper enum. These are
source/BTF checks, not kernel runtime validation.

The `t_bpf_load` integration test passed on Ubuntu `7.0.0-38-generic` x86-64
at `58d89d1`, independently of the trampoline adapter. It checks copied/truncated attrs, early
faults, verifier rejection, successful fd zero and independently queried IDs,
late EMFILE, consumer/trusted suppression, common-bit commands, x86 compat,
and repeated inner helper LOAD results under an excluded PROG_TEST_RUN.
It requires exact event counts and zero reported state, metadata or
return-probe losses. The test ran as guest root in disposable QEMU software
emulation. The host process used no sudo, guest disk or filesystem share.

The tested kernel uses the shared dispatcher. Legacy native/compat wrappers,
the five-argument dispatcher, arm64, concurrency/loss stress, user-attr races
and the RHEL 8-to-current matrix remain merge gates. Software emulation is
not a performance benchmark. The adapter PR records its separate guest tests.
Exact symbol/prototype presence cannot prove that compiler optimization did
not inline another caller; runtime path tests remain necessary.
