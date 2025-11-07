// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Elastic NV

//go:build linux && (amd64 || arm64)

package quark

/*
   #cgo CFLAGS: -I${SRCDIR}/../../
   #cgo LDFLAGS: -Wl,--wrap=fmemopen ${SRCDIR}/../../libquark_big.a

   #include <stdlib.h>
   #include "quark.h"

   #ifdef __x86_64__
   __asm__(".symver fmemopen, fmemopen@GLIBC_2.2.5");
   #elif __aarch64__
   __asm__(".symver fmemopen, fmemopen@GLIBC_2.17");
   #else
   #error Add correct desired symbol version for your arch
   #endif

   FILE *
   __wrap_fmemopen(void *buf, size_t size, const char *mode)
   {
     return fmemopen(buf, size, mode);
   }

*/
import "C"

import (
	"bytes"
	"errors"
	"strings"
	"syscall"
	"unsafe"
)

// Proc carries data on the state of the process. Only vaid if `Valid` is set.
type Proc struct {
	CapInheritable  uint64
	CapPermitted    uint64
	CapEffective    uint64
	CapBset         uint64
	CapAmbient      uint64
	TimeBoot        uint64
	Ppid            uint32
	Uid             uint32
	Gid             uint32
	Suid            uint32
	Sgid            uint32
	Euid            uint32
	Egid            uint32
	Pgid            uint32
	Sid             uint32
	EntryLeader     uint32
	EntryLeaderType uint32
	TtyMajor        uint32
	TtyMinor        uint32
	UtsInonum       uint32
	IpcInonum       uint32
	MntInonum       uint32
	NetInonum       uint32
	Valid           bool
}

// Exit carries data on the exit behavior of the process. Only valid if `Valid` is set.
type Exit struct {
	ExitCode        int32
	ExitTimeProcess uint64
	Valid           bool
}

// Process represents a single process.
type Process struct {
	Pid      uint32   // Always present
	Proc     Proc     // Only meaningful if Proc.Valid (QUARK_F_PROC)
	Exit     Exit     // Only meaningful if Exit.Valid (QUARK_F_EXIT)
	Comm     string   // QUARK_F_COMM
	Filename string   // QUARK_F_FILENAME
	Cmdline  []string // QUARK_F_CMDLINE
	Cwd      string   // QUARK_F_CWD
	Cgroup   string   // QUARK_F_CGROUP
}

// Events is a bitmask of QUARK_EV_* and expresses what triggered this
// event, Process is the context of the Event.
type Event struct {
	Events  uint64
	Process Process
}

// Queue holds the state of a quark instance.
type Queue struct {
	quarkQueue *C.struct_quark_queue // pointer to the queue structure
	epollFd    int
}

const (
	// quark_queue_attr{} flags
	QQ_THREAD_EVENTS = int(C.QQ_THREAD_EVENTS)
	QQ_KPROBE        = int(C.QQ_KPROBE)
	QQ_EBPF          = int(C.QQ_EBPF)
	QQ_MIN_AGG       = int(C.QQ_MIN_AGG)
	QQ_ENTRY_LEADER  = int(C.QQ_ENTRY_LEADER)
	QQ_SOCK_CONN     = int(C.QQ_SOCK_CONN)
	QQ_DNS           = int(C.QQ_DNS)
	QQ_BYPASS        = int(C.QQ_BYPASS)
	QQ_FILE          = int(C.QQ_FILE)
	QQ_SHM           = int(C.QQ_SHM)
	QQ_TTY           = int(C.QQ_TTY)
	QQ_PTRACE        = int(C.QQ_PTRACE)
	QQ_MODULE_LOAD   = int(C.QQ_MODULE_LOAD)
	QQ_ALL_BACKENDS  = int(C.QQ_ALL_BACKENDS)

	// Event.events
	QUARK_EV_FORK             = uint64(C.QUARK_EV_FORK)
	QUARK_EV_EXEC             = uint64(C.QUARK_EV_EXEC)
	QUARK_EV_EXIT             = uint64(C.QUARK_EV_EXIT)
	QUARK_EV_SETPROCTITLE     = uint64(C.QUARK_EV_SETPROCTITLE)
	QUARK_EV_SOCK_CONN_CLOSED = uint64(C.QUARK_EV_SOCK_CONN_CLOSED)
	QUARK_EV_PACKET           = uint64(C.QUARK_EV_PACKET)
	QUARK_EV_BYPASS           = uint64(C.QUARK_EV_BYPASS)
	QUARK_EV_FILE             = uint64(C.QUARK_EV_FILE)
	QUARK_EV_PTRACE           = uint64(C.QUARK_EV_PTRACE)
	QUARK_EV_MODULE_LOAD      = uint64(C.QUARK_EV_MODULE_LOAD)
	QUARK_EV_SHM              = uint64(C.QUARK_EV_SHM)
	QUARK_EV_TTY              = uint64(C.QUARK_EV_TTY)

	// EntryLeaderType
	QUARK_ELT_UNKNOWN   = int(C.QUARK_ELT_UNKNOWN)
	QUARK_ELT_INIT      = int(C.QUARK_ELT_INIT)
	QUARK_ELT_KTHREAD   = int(C.QUARK_ELT_KTHREAD)
	QUARK_ELT_SSHD      = int(C.QUARK_ELT_SSHD)
	QUARK_ELT_SSM       = int(C.QUARK_ELT_SSM)
	QUARK_ELT_CONTAINER = int(C.QUARK_ELT_CONTAINER)
	QUARK_ELT_TERM      = int(C.QUARK_ELT_TERM)
	QUARK_ELT_CONSOLE   = int(C.QUARK_ELT_CONSOLE)
)

// QueueAttr defines the attributes for the Quark queue.
type QueueAttr struct {
	Flags          int
	MaxLength      int
	CacheGraceTime int
	HoldTime       int
}

// Documented in https://elastic.github.io/quark/quark_queue_get_stats.3.html.
type Stats struct {
	Insertions         uint64
	Removals           uint64
	Aggregations       uint64
	NonAggregations    uint64
	Lost               uint64
	GarbageCollections uint64
	Backend            int
}

const (
	QUARK_VL_SILENT = int(C.QUARK_VL_SILENT)
	QUARK_VL_WARN   = int(C.QUARK_VL_WARN)
	QUARK_VL_DEBUG  = int(C.QUARK_VL_DEBUG)
)

var ErrUndefined = errors.New("undefined")

func wrapErrno(err error) error {
	if err == nil {
		err = ErrUndefined
	}

	return err
}

// DefaultQueueAttr returns the default attributes for the queue.
func DefaultQueueAttr() QueueAttr {
	var attr C.struct_quark_queue_attr

	C.quark_queue_default_attr(&attr)

	return QueueAttr{
		Flags:          int(attr.flags),
		MaxLength:      int(attr.max_length),
		CacheGraceTime: int(attr.cache_grace_time),
		HoldTime:       int(attr.hold_time),
	}
}

// OpenQueue opens a Quark Queue with the given attributes.
func OpenQueue(attr QueueAttr) (*Queue, error) {
	var queue Queue
	var cattr C.struct_quark_queue_attr

	C.quark_queue_default_attr(&cattr)

	p, err := C.calloc(C.size_t(1), C.sizeof_struct_quark_queue)
	if p == nil {
		return nil, wrapErrno(err)
	}
	queue.quarkQueue = (*C.struct_quark_queue)(p)

	cattr.flags = C.int(attr.Flags)
	cattr.max_length = C.int(attr.MaxLength)
	cattr.cache_grace_time = C.int(attr.CacheGraceTime)
	cattr.hold_time = C.int(attr.HoldTime)
	ok, err := C.quark_queue_open(queue.quarkQueue, &cattr)
	if ok == -1 {
		C.free(unsafe.Pointer(queue.quarkQueue))
		return nil, wrapErrno(err)
	}

	queue.epollFd = int(C.quark_queue_get_epollfd(queue.quarkQueue))

	return &queue, nil
}

// Close closes the queue.
func (queue *Queue) Close() {
	C.quark_queue_close(queue.quarkQueue)
	C.free(unsafe.Pointer(queue.quarkQueue))
	queue.quarkQueue = nil
}

func (queue *Queue) GetEvent() (Event, bool) {
	cev := C.quark_queue_get_event(queue.quarkQueue)
	if cev == nil || cev.process == nil {
		return Event{}, false
	}

	return Event{
		Events:  uint64(cev.events),
		Process: processToGo(cev.process),
	}, true
}

// Lookup looks up for the Process associated with PID in quark's internal cache.
func (queue *Queue) Lookup(pid int) (Process, bool) {
	process, _ := C.quark_process_lookup(queue.quarkQueue, C.int(pid))

	if process == nil {
		return Process{}, false
	}

	return processToGo(process), true
}

// Block blocks until there are events or an undefined timeout
// expires. GetEvent should be called once Block returns.
func (queue *Queue) Block() error {
	event := make([]syscall.EpollEvent, 1)
	_, err := syscall.EpollWait(queue.epollFd, event, 100)
	if err != nil && errors.Is(err, syscall.EINTR) {
		err = nil
	}
	return err
}

// Snapshot returns a snapshot of all processes in the cache.
func (queue *Queue) Snapshot() []Process {
	var processes []Process
	var iter C.struct_quark_process_iter
	var qp *C.struct_quark_process

	C.quark_process_iter_init(&iter, queue.quarkQueue)
	for qp = C.quark_process_iter_next(&iter); qp != nil; qp = C.quark_process_iter_next(&iter) {
		processes = append(processes, processToGo(qp))
	}

	return processes
}

// Stats returns statistics of an active queue.
func (queue *Queue) Stats() Stats {
	var stats Stats
	var cStats C.struct_quark_queue_stats

	C.quark_queue_get_stats(queue.quarkQueue, &cStats)
	stats.Insertions = uint64(cStats.insertions)
	stats.Removals = uint64(cStats.removals)
	stats.Aggregations = uint64(cStats.aggregations)
	stats.NonAggregations = uint64(cStats.non_aggregations)
	stats.Lost = uint64(cStats.lost)
	stats.GarbageCollections = uint64(cStats.garbage_collections)
	stats.Backend = int(cStats.backend)

	return stats
}

// Sets quark verbosity globally, not per queue.
func SetVerbose(level int) {
	C.quark_verbose = C.int(level)
}

// processToGo converts the C process structure to a go process.
func processToGo(cProcess *C.struct_quark_process) Process {
	var process Process

	if cProcess == nil {
		return Process{}
	}

	process.Pid = uint32(cProcess.pid)
	if cProcess.flags&C.QUARK_F_PROC != 0 {
		process.Proc = Proc{
			CapInheritable:  uint64(cProcess.proc_cap_inheritable),
			CapPermitted:    uint64(cProcess.proc_cap_permitted),
			CapEffective:    uint64(cProcess.proc_cap_effective),
			CapBset:         uint64(cProcess.proc_cap_bset),
			CapAmbient:      uint64(cProcess.proc_cap_ambient),
			TimeBoot:        uint64(cProcess.proc_time_boot),
			Ppid:            uint32(cProcess.proc_ppid),
			Uid:             uint32(cProcess.proc_uid),
			Gid:             uint32(cProcess.proc_gid),
			Suid:            uint32(cProcess.proc_suid),
			Sgid:            uint32(cProcess.proc_sgid),
			Euid:            uint32(cProcess.proc_euid),
			Egid:            uint32(cProcess.proc_egid),
			Pgid:            uint32(cProcess.proc_pgid),
			Sid:             uint32(cProcess.proc_sid),
			EntryLeader:     uint32(cProcess.proc_entry_leader),
			EntryLeaderType: uint32(cProcess.proc_entry_leader_type),
			TtyMajor:        uint32(cProcess.proc_tty_major),
			TtyMinor:        uint32(cProcess.proc_tty_minor),
			UtsInonum:       uint32(cProcess.proc_uts_inonum),
			IpcInonum:       uint32(cProcess.proc_ipc_inonum),
			MntInonum:       uint32(cProcess.proc_mnt_inonum),
			NetInonum:       uint32(cProcess.proc_net_inonum),
			Valid:           true,
		}
	}
	if cProcess.flags&C.QUARK_F_EXIT != 0 {
		process.Exit = Exit{
			ExitCode:        int32(cProcess.exit_code),
			ExitTimeProcess: uint64(cProcess.exit_time_event),
			Valid:           true,
		}
	}
	if cProcess.flags&C.QUARK_F_COMM != 0 {
		process.Comm = C.GoString(&cProcess.comm[0])
	}
	if cProcess.flags&C.QUARK_F_FILENAME != 0 {
		process.Filename = C.GoString(cProcess.filename)
	}
	if cProcess.flags&C.QUARK_F_CMDLINE != 0 {
		b := C.GoBytes(unsafe.Pointer(cProcess.cmdline), C.int(cProcess.cmdline_len))
		nul := string(byte(0))
		b = bytes.TrimRight(b, nul)
		process.Cmdline = strings.Split(string(b), nul)
	}
	if cProcess.flags&C.QUARK_F_CWD != 0 {
		process.Cwd = C.GoString(cProcess.cwd)
	}
	if cProcess.flags&C.QUARK_F_CGROUP != 0 {
		process.Cgroup = C.GoString(cProcess.cgroup)
	}

	return process
}
