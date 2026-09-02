// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Elastic NV

//go:build linux && (amd64 || arm64) && quark_synthetic

package quark

import (
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func syntheticTestAttr() QueueAttr {
	attr := DefaultQueueAttr()
	attr.Flags |= QQ_ENTRY_LEADER | QQ_FILE
	attr.HoldTime = 0
	attr.CacheGraceTime = 0
	return attr
}

func syntheticTestProcess() SyntheticProcess {
	return SyntheticProcess{
		Pid:            1000,
		Tid:            1001,
		Ppid:           1,
		Pgid:           1000,
		Sid:            1000,
		StartBoottime:  500,
		Uid:            1000,
		Gid:            1001,
		Suid:           1002,
		Sgid:           1003,
		Euid:           1004,
		Egid:           1005,
		CapInheritable: 1 << 1,
		CapPermitted:   1 << 2,
		CapEffective:   1 << 3,
		CapBset:        1 << 4,
		CapAmbient:     1 << 5,
		TtyMajor:       136,
		TtyMinor:       2,
		UtsInonum:      4026531838,
		IpcInonum:      4026531839,
		MntInonum:      4026531840,
		NetInonum:      4026531841,
		Comm:           "some-program",
		Cwd:            "/opt/app",
		Cgroup:         "/kubepods.slice/test.scope",
		Argv:           []string{"some-program", "", "--config=/etc/app.yml"},
		Env:            []string{"HOME=/opt/app", "PATH=/usr/local/bin:/usr/bin"},
		Executable:     "/usr/local/bin/some-program",
	}
}

func TestSyntheticQueueConversion(t *testing.T) {
	queue, err := OpenSyntheticQueue(syntheticTestAttr())
	require.NoError(t, err)
	defer queue.Close()

	process := syntheticTestProcess()
	require.NoError(t, queue.Inject(SyntheticEvent{
		Kind:    QUARK_SYNTHETIC_EXEC,
		Time:    1000,
		Process: process,
	}))

	event, ok := queue.GetEvent()
	require.True(t, ok)
	require.Equal(t, QUARK_EV_EXEC, event.Events)
	require.Equal(t, process.Pid, event.Process.Pid)
	require.Equal(t, process.CapInheritable, event.Process.Proc.CapInheritable)
	require.Equal(t, process.CapPermitted, event.Process.Proc.CapPermitted)
	require.Equal(t, process.CapEffective, event.Process.Proc.CapEffective)
	require.Equal(t, process.CapBset, event.Process.Proc.CapBset)
	require.Equal(t, process.CapAmbient, event.Process.Proc.CapAmbient)
	require.Equal(t, process.StartBoottime, event.Process.Proc.TimeBoot)
	require.Equal(t, process.Ppid, event.Process.Proc.Ppid)
	require.Equal(t, process.Uid, event.Process.Proc.Uid)
	require.Equal(t, process.Gid, event.Process.Proc.Gid)
	require.Equal(t, process.Suid, event.Process.Proc.Suid)
	require.Equal(t, process.Sgid, event.Process.Proc.Sgid)
	require.Equal(t, process.Euid, event.Process.Proc.Euid)
	require.Equal(t, process.Egid, event.Process.Proc.Egid)
	require.Equal(t, process.Pgid, event.Process.Proc.Pgid)
	require.Equal(t, process.Sid, event.Process.Proc.Sid)
	require.Equal(t, process.TtyMajor, event.Process.Proc.TtyMajor)
	require.Equal(t, process.TtyMinor, event.Process.Proc.TtyMinor)
	require.Equal(t, process.UtsInonum, event.Process.Proc.UtsInonum)
	require.Equal(t, process.IpcInonum, event.Process.Proc.IpcInonum)
	require.Equal(t, process.MntInonum, event.Process.Proc.MntInonum)
	require.Equal(t, process.NetInonum, event.Process.Proc.NetInonum)
	require.Equal(t, process.Comm, event.Process.Comm)
	require.Equal(t, process.Executable, event.Process.Exe)
	require.Equal(t, process.Argv, event.Process.Cmdline)
	require.Equal(t, process.Cwd, event.Process.Cwd)
	require.Equal(t, process.Cgroup, event.Process.Cgroup)
	require.Equal(t, QQ_SYNTHETIC, queue.Stats().Backend)

	file := SyntheticFile{
		Path:       "/var/log/app/output.log",
		OldPath:    "/var/log/app/output.old",
		SymTarget:  "/var/lib/app/output.log",
		Inode:      42,
		Atime:      10,
		Mtime:      20,
		Ctime:      30,
		Size:       4096,
		Mode:       0100640,
		Uid:        1000,
		Gid:        1001,
		ChangeMask: QUARK_FILE_CH_CONTENT | QUARK_FILE_CH_PERMS,
	}
	require.NoError(t, queue.Inject(SyntheticEvent{
		Kind:    QUARK_SYNTHETIC_FILE_CREATE,
		Time:    1001,
		Process: process,
		File:    file,
	}))

	event, ok = queue.GetEvent()
	require.True(t, ok)
	require.Equal(t, QUARK_EV_FILE, event.Events)
	require.NotNil(t, event.File)
	require.Equal(t, file.Path, event.File.Path)
	require.Equal(t, file.OldPath, event.File.OldPath)
	require.Equal(t, file.SymTarget, event.File.SymTarget)
	require.Equal(t, file.Inode, event.File.Inode)
	require.Equal(t, file.Atime, event.File.Atime)
	require.Equal(t, file.Mtime, event.File.Mtime)
	require.Equal(t, file.Ctime, event.File.Ctime)
	require.Equal(t, file.Size, event.File.Size)
	require.Equal(t, file.Mode, event.File.Mode)
	require.Equal(t, file.Uid, event.File.Uid)
	require.Equal(t, file.Gid, event.File.Gid)
	require.Equal(t, uint32(QUARK_FILE_OP_CREATE), event.File.OpMask)
	require.Equal(t, file.ChangeMask, event.File.ChangeMask)
}

func TestSyntheticQueueInvalidInput(t *testing.T) {
	queue, err := OpenSyntheticQueue(syntheticTestAttr())
	require.NoError(t, err)
	defer queue.Close()

	valid := SyntheticEvent{
		Kind:    QUARK_SYNTHETIC_EXEC,
		Time:    1000,
		Process: syntheticTestProcess(),
	}

	tests := []struct {
		name  string
		event SyntheticEvent
	}{
		{"invalid kind", func() SyntheticEvent { event := valid; event.Kind = QUARK_SYNTHETIC_INVALID; return event }()},
		{"zero time", func() SyntheticEvent { event := valid; event.Time = 0; return event }()},
		{"zero pid", func() SyntheticEvent { event := valid; event.Process.Pid = 0; return event }()},
		{"missing executable", func() SyntheticEvent { event := valid; event.Process.Executable = ""; return event }()},
		{"missing file path", SyntheticEvent{Kind: QUARK_SYNTHETIC_FILE_CREATE, Time: 1000, Process: syntheticTestProcess()}},
		{"missing comm on exec", func() SyntheticEvent { event := valid; event.Process.Comm = ""; return event }()},
		{"missing comm on fork", func() SyntheticEvent {
			event := valid
			event.Kind = QUARK_SYNTHETIC_FORK
			event.Process.Comm = ""
			return event
		}()},
		{"missing comm on exit", func() SyntheticEvent {
			event := valid
			event.Kind = QUARK_SYNTHETIC_EXIT
			event.Process.Comm = ""
			return event
		}()},
		{"missing comm on setsid", func() SyntheticEvent {
			event := valid
			event.Kind = QUARK_SYNTHETIC_SETSID
			event.Process.Comm = ""
			return event
		}()},
		{"NUL in argv", func() SyntheticEvent { event := valid; event.Process.Argv = []string{"bad\x00arg"}; return event }()},
		{"NUL in path", func() SyntheticEvent {
			event := valid
			event.Kind = QUARK_SYNTHETIC_FILE_CREATE
			event.File.Path = "bad\x00path"
			return event
		}()},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Error(t, queue.Inject(test.event))
		})
	}
	require.ErrorIs(t, (*Queue)(nil).Inject(valid), syscall.EINVAL)
}

// TestSyntheticCommSurvivesEventSequence verifies that the cached comm is
// stable across a sequence of process events for the same pid.
//
// raw_event_process1() copies raw_task->comm into the cache on every event.
// raw_task.comm is a char[16], not a pointer, so a zero-filled array is
// indistinguishable from "absent" and would silently clear the cached value.
// quark_queue_inject() therefore requires comm on every process event, which
// is the same contract the ebpf backend satisfies.
func TestSyntheticCommSurvivesEventSequence(t *testing.T) {
	queue, err := OpenSyntheticQueue(syntheticTestAttr())
	require.NoError(t, err)
	defer queue.Close()

	// One process reused across the whole lifecycle, which is how a caller
	// is expected to drive this queue.
	process := syntheticTestProcess()

	// Exit is deliberately not in this list: it marks the process for GC,
	// and syntheticTestAttr() uses CacheGraceTime 0, so the cache entry is
	// collected on the next GetEvent and later events see a miss.
	kinds := []SyntheticEventKind{
		QUARK_SYNTHETIC_EXEC,
		QUARK_SYNTHETIC_SETSID,
	}

	for i, kind := range kinds {
		require.NoError(t, queue.Inject(SyntheticEvent{
			Kind:    kind,
			Time:    uint64(1000 + i),
			Process: process,
		}))

		event, ok := queue.GetEvent()
		require.True(t, ok)
		require.NotZero(t, event.Events)
		require.Equal(t, process.Comm, event.Process.Comm,
			"comm was clobbered by event kind %d", kind)
	}

	// A file event carries no raw_task, so it must not disturb the comm the
	// preceding process events established.
	require.NoError(t, queue.Inject(SyntheticEvent{
		Kind:    QUARK_SYNTHETIC_FILE_CREATE,
		Time:    2000,
		Process: process,
		File:    SyntheticFile{Path: "/tmp/canary"},
	}))
	event, ok := queue.GetEvent()
	require.True(t, ok)
	require.Equal(t, uint64(QUARK_EV_FILE), event.Events)
	require.Equal(t, process.Comm, event.Process.Comm)

	// Exit still reports the comm on the event itself.
	require.NoError(t, queue.Inject(SyntheticEvent{
		Kind:    QUARK_SYNTHETIC_EXIT,
		Time:    2001,
		Process: process,
	}))
	event, ok = queue.GetEvent()
	require.True(t, ok)
	require.Equal(t, process.Comm, event.Process.Comm)
}

// TestSyntheticArgvOnlyAppliesToExec pins the documented behaviour: argv is
// recorded by an exec and ignored by every other event kind, since raw_exec
// is the only raw type with a place to put it. This is what the backends do,
// where argv is simply not a field of a fork, exit or setsid event.
//
// A fork still reports a cmdline, but it comes from process_cache_inherit()
// copying the parent's, not from the argv passed with the fork.
func TestSyntheticArgvOnlyAppliesToExec(t *testing.T) {
	queue, err := OpenSyntheticQueue(syntheticTestAttr())
	require.NoError(t, err)
	defer queue.Close()

	const parentPid = 4000

	// A setsid carrying argv is accepted, and the argv is not recorded.
	orphan := syntheticTestProcess()
	orphan.Pid = parentPid
	orphan.Tid = parentPid
	orphan.Argv = []string{"ignored", "--ignored"}

	require.NoError(t, queue.Inject(SyntheticEvent{
		Kind:    QUARK_SYNTHETIC_SETSID,
		Time:    3000,
		Process: orphan,
	}))
	event, ok := queue.GetEvent()
	require.True(t, ok)
	require.Empty(t, event.Process.Cmdline,
		"argv on a setsid must not be recorded")

	// An exec does record it.
	parent := syntheticTestProcess()
	parent.Pid = parentPid
	parent.Tid = parentPid

	require.NoError(t, queue.Inject(SyntheticEvent{
		Kind:    QUARK_SYNTHETIC_EXEC,
		Time:    3001,
		Process: parent,
	}))
	event, ok = queue.GetEvent()
	require.True(t, ok)
	require.Equal(t, parent.Argv, event.Process.Cmdline)

	// A fork inherits the parent's cmdline regardless of its own argv.
	child := syntheticTestProcess()
	child.Pid = parentPid + 1
	child.Tid = parentPid + 1
	child.Ppid = parentPid
	child.Argv = []string{"not-used"}

	require.NoError(t, queue.Inject(SyntheticEvent{
		Kind:    QUARK_SYNTHETIC_FORK,
		Time:    3002,
		Process: child,
	}))
	event, ok = queue.GetEvent()
	require.True(t, ok)
	require.Equal(t, parent.Argv, event.Process.Cmdline,
		"a fork's cmdline comes from the parent, not from its own argv")
}

// TestSyntheticExitTimeMatchesBumpedTime verifies that exit_time_event agrees
// with the event's own time even when the injected timestamp was taken.
//
// raw_event_insert() bumps raw->time until it finds a free slot, and warns
// that the time must not be copied before the event is in the tree. Reading
// exit_time_event before the insert left it one tick behind.
func TestSyntheticExitTimeMatchesBumpedTime(t *testing.T) {
	queue, err := OpenSyntheticQueue(syntheticTestAttr())
	require.NoError(t, err)
	defer queue.Close()

	const collideAt = 500000

	// Take the timestamp with an unrelated pid, so the exit below has to be
	// moved to collideAt+1. Distinct pids keep the two from aggregating.
	blocker := syntheticTestProcess()
	blocker.Pid, blocker.Tid = 7001, 7001
	require.NoError(t, queue.Inject(SyntheticEvent{
		Kind:    QUARK_SYNTHETIC_EXEC,
		Time:    collideAt,
		Process: blocker,
	}))

	dying := syntheticTestProcess()
	dying.Pid, dying.Tid = 7002, 7002
	dying.ExitCode = 23
	require.NoError(t, queue.Inject(SyntheticEvent{
		Kind:    QUARK_SYNTHETIC_EXIT,
		Time:    collideAt,
		Process: dying,
	}))

	var exit Exit
	for {
		event, ok := queue.GetEvent()
		if !ok {
			break
		}
		if event.Process.Exit.Valid {
			exit = event.Process.Exit
		}
	}

	require.True(t, exit.Valid, "no exit event was drained")
	require.Equal(t, int32(23), exit.ExitCode)
	require.EqualValues(t, collideAt+1, exit.ExitTimeProcess,
		"exit_time_event kept the pre-collision timestamp")
}

// TestSyntheticQueueTimestampExhaustion pins the documented EEXIST. An event
// landing on a taken timestamp moves to the next free one, but only for a
// thousand attempts; a fully taken run that long fails the injection.
func TestSyntheticQueueTimestampExhaustion(t *testing.T) {
	queue, err := OpenSyntheticQueue(syntheticTestAttr())
	require.NoError(t, err)
	defer queue.Close()

	const (
		base     = 900000
		runLen   = 1000
		firstPid = 8000
	)

	process := syntheticTestProcess()
	for i := 0; i < runLen; i++ {
		process.Pid = uint32(firstPid + i)
		process.Tid = process.Pid
		require.NoError(t, queue.Inject(SyntheticEvent{
			Kind:    QUARK_SYNTHETIC_EXEC,
			Time:    base + uint64(i),
			Process: process,
		}), "filling timestamp %d", base+i)
	}

	// Every slot from base to base+999 is taken, so this exhausts the walk.
	process.Pid, process.Tid = firstPid+runLen, firstPid+runLen
	require.ErrorIs(t, queue.Inject(SyntheticEvent{
		Kind:    QUARK_SYNTHETIC_EXEC,
		Time:    base,
		Process: process,
	}), syscall.EEXIST)

	// One past the run is still free, so this must succeed.
	require.NoError(t, queue.Inject(SyntheticEvent{
		Kind:    QUARK_SYNTHETIC_EXEC,
		Time:    base + runLen,
		Process: process,
	}))
}

// TestSyntheticFileEventUncachedPid verifies that a file injection for a pid
// that is not in the process cache still yields the event, with no process
// data attached.
//
// This mirrors the ebpf backend: an ebpf file event carries only a pid and the
// file fields, so raw_event_file() resolves the process through the cache and
// legitimately produces a NULL process on a miss. The synthetic queue must
// keep that behaviour, otherwise a benchmark never exercises the cache-miss
// path.
//
// GetEvent() used to treat a NULL process the same as "no event", which both
// dropped the file event and made the caller's drain loop exit early.
func TestSyntheticFileEventUncachedPid(t *testing.T) {
	queue, err := OpenSyntheticQueue(syntheticTestAttr())
	require.NoError(t, err)
	defer queue.Close()

	const uncachedPid = 9999

	process := syntheticTestProcess()
	process.Pid = uncachedPid
	process.Tid = uncachedPid

	file := SyntheticFile{
		Path:  "/tmp/canary",
		Inode: 42,
		Mode:  0100644,
	}

	require.NoError(t, queue.Inject(SyntheticEvent{
		Kind:    QUARK_SYNTHETIC_FILE_CREATE,
		Time:    5000,
		Process: process,
		File:    file,
	}))

	event, ok := queue.GetEvent()
	require.True(t, ok, "GetEvent returned false — file event for an uncached pid was dropped")
	require.Equal(t, uint64(QUARK_EV_FILE), event.Events)
	require.NotNil(t, event.File)
	require.Equal(t, file.Path, event.File.Path)

	// A cache miss leaves the process zero-valued, exactly as with ebpf. The
	// injected process payload is not consulted for file events.
	require.Zero(t, event.Process.Pid)
	require.Empty(t, event.Process.Comm)
}

// TestSyntheticFileEventCachedPid is the cache-hit counterpart: once an exec
// has populated the cache for a pid, a later file event resolves against it.
func TestSyntheticFileEventCachedPid(t *testing.T) {
	queue, err := OpenSyntheticQueue(syntheticTestAttr())
	require.NoError(t, err)
	defer queue.Close()

	process := syntheticTestProcess()

	require.NoError(t, queue.Inject(SyntheticEvent{
		Kind:    QUARK_SYNTHETIC_EXEC,
		Time:    1000,
		Process: process,
	}))
	event, ok := queue.GetEvent()
	require.True(t, ok)
	require.Equal(t, uint64(QUARK_EV_EXEC), event.Events)

	require.NoError(t, queue.Inject(SyntheticEvent{
		Kind:    QUARK_SYNTHETIC_FILE_CREATE,
		Time:    1001,
		Process: process,
		File:    SyntheticFile{Path: "/tmp/canary"},
	}))

	event, ok = queue.GetEvent()
	require.True(t, ok)
	require.Equal(t, uint64(QUARK_EV_FILE), event.Events)
	require.Equal(t, process.Pid, event.Process.Pid)
	require.Equal(t, process.Comm, event.Process.Comm)
	require.Equal(t, process.Executable, event.Process.Exe)
}

// TestSyntheticAllocationsFree pins down the receiver of free(). Inject() sets
// up `defer allocations.free()` before it allocates anything, so free() must
// see the appends that happen afterwards. A value receiver would snapshot the
// empty slice header at defer time and free nothing.
func TestSyntheticAllocationsFree(t *testing.T) {
	var allocations syntheticAllocations

	func() {
		defer allocations.free()

		comm, err := allocations.cString("comm", "some-program")
		require.NoError(t, err)
		require.NotNil(t, comm)

		argv, argvLen, err := allocations.cStringList("argv", []string{"a", "bb"})
		require.NoError(t, err)
		require.NotNil(t, argv)
		require.EqualValues(t, 5, argvLen)

		require.Len(t, allocations, 2)
	}()

	require.Empty(t, allocations, "free() did not observe the tracked allocations")
}

// rssKB reports the resident set size of the test process in kilobytes.
func rssKB(t *testing.T) int {
	t.Helper()

	// Hand pages we no longer need back to the OS so the reading reflects
	// what is still live rather than the Go heap's high water mark.
	debug.FreeOSMemory()

	status, err := os.ReadFile("/proc/self/status")
	require.NoError(t, err)

	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		require.Len(t, fields, 3, "unexpected VmRSS line %q", line)
		kb, err := strconv.Atoi(fields[1])
		require.NoError(t, err)
		return kb
	}

	t.Fatal("no VmRSS in /proc/self/status")
	return 0
}

// TestSyntheticQueueInjectDoesNotLeak guards the whole Inject() path against
// allocations that never make it back to free(). It measures the steady-state
// slope rather than the absolute growth, so the one-off cost of the process
// cache and the Go runtime warming up is not mistaken for a leak.
func TestSyntheticQueueInjectDoesNotLeak(t *testing.T) {
	const (
		warmupInjects  = 20000
		measureInjects = 200000
		// A leak of a single tracked allocation costs at least the size of
		// the environment below, so the real signal is hundreds of megabytes.
		// Keep the bound loose enough to absorb allocator noise.
		maxGrowthKB = 16 * 1024
		// Bounded so the process cache stays a fixed size.
		distinctPids = 50
	)

	queue, err := OpenSyntheticQueue(syntheticTestAttr())
	require.NoError(t, err)
	defer queue.Close()

	process := syntheticTestProcess()
	// A fat environment makes a leaked allocation obvious in RSS.
	process.Env = []string{"LEAK_CANARY=" + strings.Repeat("x", 4096)}

	// time must keep increasing: raw_event_insert() bumps colliding timestamps.
	time := uint64(1000)
	inject := func(injects int) {
		for i := 0; i < injects; i++ {
			process.Pid = uint32(1000 + i%distinctPids)
			process.Tid = process.Pid
			require.NoError(t, queue.Inject(SyntheticEvent{
				Kind:    QUARK_SYNTHETIC_EXEC,
				Time:    time,
				Process: process,
			}))
			time++

			// Drain, otherwise the queue itself grows and we measure that.
			for {
				if _, ok := queue.GetEvent(); !ok {
					break
				}
			}
		}
	}

	inject(warmupInjects)
	baseline := rssKB(t)
	inject(measureInjects)
	growth := rssKB(t) - baseline

	t.Logf("RSS grew %d kB over %d injects (%d kB baseline)", growth, measureInjects, baseline)
	require.Less(t, growth, maxGrowthKB,
		"RSS grew %d kB over %d injects, Inject() is leaking", growth, measureInjects)
}
