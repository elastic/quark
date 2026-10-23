# BPF telemetry stack: LOAD foundation and adapters

This stack starts from #435's parent
`2a0d7eeaa45bc5ac3ac7677274f5c00b7b84da59` through the standalone support
branch `nberlin/bpf-stack-hooks` (`51df19f`). That first commit adds tested
selection/attachment/correlation utilities without enabling telemetry.
The LOAD PR adds the event slice on top. These are new PRs associated with
the review of [PR #435](https://github.com/elastic/quark/pull/435).
They preserve that PR's review history. This adapter PR adds fentry/fexit
selection and retains the named-return-probe implementation as its fallback.
It adds no event families or ownership/helper API.

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
* Prefer fentry/fexit after validating the actual BTF signature. The return
  slot accounts for each 16-byte `bpfptr_t` taking two slots: the three-arg
  dispatcher returns at slot 4 and the five-arg dispatcher at slot 7.
  Fixed-offset exit programs keep these accesses verifier-checkable.
  Scalar/pointer legacy boundaries use their corresponding layouts. Kernel
  load/attachment, not version guessing, decides trampoline availability.
* Per-task state holds eight nested frames, including excluded commands.
  Kernel stack positions match returns (x86 return SP minus eight, arm64
  unchanged). With trampolines, use the saved-argument context address as
  the stack position: audited x86/arm64 trampoline implementations pass the
  same address to both callbacks for an invocation. Keep it opaque and never
  export or dereference it after the callback. Overflow blocks inner metadata
  collectors; stale frames are
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

## Adapter selection

The accepted policy prefers trampolines and retains kprobes as the compatibility
fallback, preserving the same command, result and identity contract. Both
adapters attach the return before the entry and clean up partial initialization.
Unrelated events retain their own fentry-first preference on retry.

Trampolines need no named tracefs events or kretprobe pool. Recursion protection
can skip callbacks, and trampoline rebuilding can bypass fexit for a call
already in progress. Retain the existing conservative state recovery; neither
adapter guarantees complete observation under arbitrary missed callbacks.
Trampoline recursion-miss counters are not yet collected. The named-return
statistics validity flag is false in trampoline mode.
The context-address invariant is visible in the shared fentry/fexit invocation
sites in the [x86 trampoline generator](https://github.com/torvalds/linux/blob/v6.1/arch/x86/net/bpf_jit_comp.c)
and [arm64 generator](https://github.com/torvalds/linux/blob/v6.1/arch/arm64/net/bpf_jit_comp.c).
Runtime pairing tests remain necessary for each supported kernel family.

The kprobe fallback creates unique tracefs `r4096` events. It requires mounted,
writable tracefs and readable profiles, never mounts tracefs itself, and removes
only its own events on close or initialization failure. A crash can leave
disabled events/pools. Old profiles omit return-pool exhaustion. Anonymous PMU
probes can expose misses through perf BPF links on upstream 6.7+ but still lack
explicit pool sizing; changing that fallback remains separate work.

For testing, `QUARK_BPF_ADAPTER=trampoline` or `kprobe` forces that adapter and
fails if it cannot initialize; `auto` is the default. This is independent of
adapter selection for other event classes. The matrix must exercise forced
modes so an unnoticed fallback cannot masquerade as trampoline validation.

## Bounds, cost and validation

The call-state map has 4096 entries of 536 bytes (about 2.1 MiB of values,
plus hash overhead) per queue. Each boundary using the kprobe fallback also has
a 4096-instance kernel return-probe pool. Ignored commands still incur entry/security/return
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

The integration test checks copied/truncated attrs, early
faults, verifier rejection, successful fd zero and independently queried IDs,
late EMFILE, consumer/trusted suppression, common-bit commands, x86 compat,
and repeated inner helper LOAD results under an excluded PROG_TEST_RUN, with
zero reported state, metadata or return-probe loss in this fixture.

| QEMU guest kernel | Adapter | Result |
| --- | --- | --- |
| Ubuntu `7.0.0-38-generic` (`7.0.0-38.38`) | Forced trampoline | Pass |
| Same Ubuntu kernel | Forced kprobe | Pass |
| Rocky `4.18.0-477.27.1.el8_8.x86_64` | Automatic selection, kprobe fallback after aggregate trampoline rejection | Pass |

These are disposable software-emulated guests using the static test initramfs,
512 MiB RAM, QEMU's `max` CPU and `random.trust_cpu=on` for guest entropy.
The host process ran without sudo. No guest disk or host share was needed.
Both kernels were extracted from official HTTPS packages and their package
checksums verified against repository metadata. Rocky results are not exact
Red Hat build validation. Both tested kernels have a shared `__sys_bpf`;
legacy wrapper selection, the five-argument dispatcher and arm64 currently
have source/BTF/unit/compile checks, not runtime proof from this run.

The standalone LOAD prerequisite at `58d89d1` also passed `t_bpf_load` on the
Ubuntu kernel with its kprobe adapter. That run did not include trampolines.
Compat calls on supported 64-bit kernels remain in scope; a 32-bit quark
build is not required.

Kernel execution exposed two verifier bounds issues in the earlier LOAD slice
and fixture mistakes in `qwrite` success checks and read-only attrs on modern
LOAD writeback. The LOAD prerequisite includes those fixes. Concurrency/loss stress,
shared-user-attr races, arm64 and the remaining RHEL 8-to-current matrix are
still merge gates. Software emulation is not a performance benchmark.
Exact symbol/prototype presence cannot prove that compiler optimization did
not inline another caller; runtime path tests remain necessary.
