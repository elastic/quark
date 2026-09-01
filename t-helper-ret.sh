#!/bin/bash
#
# Build and run t_helper_ret across kernels to decide the PR #406/#404
# premise: "pre-5.9 kernels zero-extend BPF helper returns, so 64-bit
# compares against negative errnos never match".
#
# Usage:
#   ./t-helper-ret.sh                      # default matrix (see below)
#   ./t-helper-ret.sh fedora:31 rhel:8.3   # explicit targets
#
# Default targets:
#   fedora:31  -> 5.8.18, the last vanilla-ish kernel before bdb7b79b4ce8
#                 (v5.9), has bpf_probe_read_kernel_str and ringbuf.
#                 If the PR premise is real, it MUST reproduce here.
#   fedora:30  -> 5.6.13, second pre-5.9 data point.
#   rhel:8.3   -> 4.18.0-240 backport kernel, quark's real-world floor
#                 for the ebpf probes.
#   fedora:41  -> modern control, expected sign-extended.
#
# Kernels are fetched with curl (no lynx needed) and cached in
# kernel-images/helper-ret/. The guest verdict is parsed from the
# explicit "t_helper_ret exited with N" marker printed by init, never
# from harness exit codes:
#   0 = sign-extended, 64-bit compares work   -> premise DISPROVEN
#   1 = zero-extended, 64-bit compares broken -> premise CONFIRMED
#   2 = error/inconclusive in the guest

set -euo pipefail

CLANG=${CLANG:-clang}
CC=${CC:-cc}
CACHE=kernel-images/helper-ret
LOGDIR=helper-ret-logs

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
	targets=(fedora:31 fedora:30 rhel:8.3 fedora:41)
fi

# Fetch a kernel-core rpm for flavor:ver, extract vmlinuz, cache it.
# Prints the cached vmlinuz path on stdout; everything else goes to stderr.
fetch_kernel()
{
	local flavor=$1 ver=$2 url pkg="kernel-core" rpm tmp vmlinuz cached

	case "$flavor:$ver" in
	fedora:2?|fedora:3?|fedora:40|fedora:41|fedora:42)
		url="https://archives.fedoraproject.org/pub/archive/fedora/linux/updates/$ver/Everything/x86_64/Packages/k/";;
	fedora:*)
		url="https://ftp.fau.de/fedora/linux/updates/$ver/Everything/x86_64/Packages/k/";;
	rhel:8|rhel:9|rhel:10)
		url="https://ftp.fau.de/rockylinux/$ver/BaseOS/x86_64/os/Packages/k/";;
	rhel:8.[34])
		url="https://dl.rockylinux.org/vault/rocky/$ver/BaseOS/x86_64/os/Packages/";;
	rhel:8.?|rhel:9.?|rhel:10.?)
		url="https://dl.rockylinux.org/vault/rocky/$ver/BaseOS/x86_64/os/Packages/k/";;
	*)
		echo "unsupported target $flavor:$ver" >&2; return 1;;
	esac

	rpm=$(curl -fsSL "$url" |
		grep -oE "$pkg-[0-9][^\"'<>]*\.x86_64\.rpm" | sort -uV | tail -1)
	[ -n "$rpm" ] || { echo "no $pkg rpm found at $url" >&2; return 1; }

	cached="$CACHE/vmlinuz-${rpm%.rpm}"
	if [ -f "$cached" ]; then
		echo "using cached $cached" >&2
		echo "$cached"
		return 0
	fi

	echo "downloading $url$rpm" >&2
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' RETURN
	curl -fsSL "$url$rpm" -o "$tmp/$rpm"
	(cd "$tmp" && rpm2cpio "$rpm" | cpio -idm --quiet "*vmlinuz*")
	vmlinuz=$(find "$tmp/lib/modules" -name vmlinuz | head -1)
	[ -n "$vmlinuz" ] || { echo "no vmlinuz in $rpm" >&2; return 1; }
	mkdir -p "$CACHE"
	cp "$vmlinuz" "$cached"
	echo "$cached"
}

echo "== building deps (libquark_big.a, include/, init) =="
make -j"$(nproc)" include libquark_big.a init >/dev/null

echo "== compiling t_helper_ret.bpf.o =="
$CLANG -g -O2 -target bpf -D__TARGET_ARCH_x86 -Iinclude \
	-c t_helper_ret.bpf.c -o t_helper_ret.bpf.o

echo "== emitted bytecode for the compares (corroboration) =="
# The 64-bit signed compare on the full register (`if r0 s< 0`) and the
# 32-bit one on the subregister (`if w0 ...`) must both be present, or
# the test isn't testing the claimed code shape.
if command -v llvm-objdump >/dev/null; then
	llvm-objdump -d --no-show-raw-insn t_helper_ret.bpf.o |
		grep -E "<test_|if [rw]0 s|if r0 ==" || true
else
	echo "llvm-objdump not found, skipping disassembly"
fi

echo "== compiling t_helper_ret (static) =="
$CC -g -O2 -Iinclude -static -o t_helper_ret t_helper_ret.c libquark_big.a

echo "== building initramfs-helper.gz =="
rm -rf initramfs-helper
mkdir -p initramfs-helper/bin
cp init initramfs-helper/init
cp t_helper_ret initramfs-helper/
cp t_helper_ret.bpf.o initramfs-helper/
(cd initramfs-helper &&
	find . -print0 | cpio -0 -o --format=newc 2>/dev/null |
	gzip -9 > ../initramfs-helper.gz)

mkdir -p "$LOGDIR"
declare -A verdicts
failures=0

for t in "${targets[@]}"; do
	flavor=${t%%:*}
	ver=${t#*:}
	log="$LOGDIR/$flavor-$ver.log"
	echo
	echo "==== $t ===="
	if ! kernel=$(fetch_kernel "$flavor" "$ver"); then
		verdicts[$t]="HARNESS ERROR: kernel fetch failed"
		failures=$((failures+1))
		continue
	fi
	set +e
	./krun.sh initramfs-helper.gz "$kernel" t_helper_ret 2>&1 | tee "$log"
	set -e
	# Trust only the guest's explicit marker line, printed by init.
	rc=$(grep -oE '^t_helper_ret exited with [0-9]+' "$log" |
		tail -1 | awk '{print $4}')
	case "${rc:-none}" in
	0) verdicts[$t]="sign-extended: 64-bit compares WORK (premise disproven)";;
	1) verdicts[$t]="zero-extended: 64-bit compares BROKEN (premise confirmed)";;
	none) verdicts[$t]="HARNESS ERROR: guest never ran (see $log)"
	      failures=$((failures+1));;
	*) verdicts[$t]="guest error/inconclusive, exit $rc (see $log)"
	   failures=$((failures+1));;
	esac
done

echo
echo "==== summary ===="
for t in "${targets[@]}"; do
	printf "%-14s %s\n" "$t" "${verdicts[$t]}"
done

exit $failures
