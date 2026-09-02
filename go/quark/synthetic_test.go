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
