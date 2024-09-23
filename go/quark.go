// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Elastic NV

package quark

/*
   #cgo CFLAGS: -I${SRCDIR}/..
   #cgo LDFLAGS: ${SRCDIR}/../libquark_big.a

   #include <stdlib.h>
   #include "quark.h"
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
	Events   uint64   // Bitmask of events for this Event
	Proc     Proc     // Only meaningful if Proc.Valid (QUARK_F_PROC)
	Exit     Exit     // Only meaningful if Exit.Valid (QUARK_F_EXIT)
	Comm     string   // QUARK_F_COMM
	Filename string   // QUARK_F_FILENAME
	Cmdline  []string // QUARK_F_CMDLINE
	Cwd      string   // QUARK_F_CWD
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
	cEvents    *C.struct_quark_event
	numCevents int
	epollFd    int
}

const (
	// quark_queue_attr{} flags
	QQ_THREAD_EVENTS = int(C.QQ_THREAD_EVENTS)
	QQ_KPROBE        = int(C.QQ_KPROBE)
	QQ_EBPF          = int(C.QQ_EBPF)
	QQ_NO_SNAPSHOT   = int(C.QQ_NO_SNAPSHOT)
	QQ_MIN_AGG       = int(C.QQ_MIN_AGG)
	QQ_ENTRY_LEADER  = int(C.QQ_ENTRY_LEADER)
	QQ_ALL_BACKENDS  = int(C.QQ_ALL_BACKENDS)

	// Event.events
	QUARK_EV_FORK         = uint64(C.QUARK_EV_FORK)
	QUARK_EV_EXEC         = uint64(C.QUARK_EV_EXEC)
	QUARK_EV_EXIT         = uint64(C.QUARK_EV_EXIT)
	QUARK_EV_SETPROCTITLE = uint64(C.QUARK_EV_SETPROCTITLE)
	QUARK_EV_SNAPSHOT     = uint64(C.QUARK_EV_SNAPSHOT)

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
func OpenQueue(attr QueueAttr, slots int) (*Queue, error) {
	var queue Queue

	p, err := C.calloc(C.size_t(1), C.sizeof_struct_quark_queue)
	if p == nil {
		return nil, wrapErrno(err)
	}
	queue.quarkQueue = (*C.struct_quark_queue)(p)
	p = nil

	cattr := C.struct_quark_queue_attr{
		flags:            C.int(attr.Flags),
		max_length:       C.int(attr.MaxLength),
		cache_grace_time: C.int(attr.CacheGraceTime),
		hold_time:        C.int(attr.HoldTime),
	}
	ok, err := C.quark_queue_open(queue.quarkQueue, &cattr)
	if ok == -1 {
		C.free(unsafe.Pointer(queue.quarkQueue))
		return nil, wrapErrno(err)
	}

	p, err = C.calloc(C.size_t(slots), C.sizeof_struct_quark_event)
	if p == nil {
		C.quark_queue_close(queue.quarkQueue)
		C.free(unsafe.Pointer(queue.quarkQueue))
		return nil, wrapErrno(err)
	}
	queue.cEvents = (*C.struct_quark_event)(p)
	queue.numCevents = slots
	p = nil

	queue.epollFd = int(C.quark_queue_get_epollfd(queue.quarkQueue))

	return &queue, nil
}

// Close closes the queue.
func (queue *Queue) Close() {
	C.quark_queue_close(queue.quarkQueue)
	C.free(unsafe.Pointer(queue.quarkQueue))
	C.free(unsafe.Pointer(queue.cEvents))
	queue.quarkQueue = nil
	queue.cEvents = nil
}

func eventOfIndex(cEvents *C.struct_quark_event, idx int) *C.struct_quark_event {
	return (*C.struct_quark_event)(unsafe.Add(unsafe.Pointer(cEvents), idx*C.sizeof_struct_quark_event))
}

// GetEvents returns a number of events, up to a maximum of `slots` passed to OpenQueue.
func (queue *Queue) GetEvents() ([]Event, error) {
	n, err := C.quark_queue_get_events(queue.quarkQueue, queue.cEvents, C.int(queue.numCevents))
	if n == -1 {
		return nil, wrapErrno(err)
	}

	events := make([]Event, n)
	for i := range events {
		events[i] = eventToGo(eventOfIndex(queue.cEvents, i))
	}

	return events, nil
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
// expires. GetEvents should be called once Block returns.
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
		process.Filename = C.GoString(&cProcess.filename[0])
	}
	if cProcess.flags&C.QUARK_F_CMDLINE != 0 {
		b := C.GoBytes(unsafe.Pointer(&cProcess.cmdline[0]), C.int(cProcess.cmdline_len))
		nul := string(byte(0))
		b = bytes.TrimRight(b, nul)
		process.Cmdline = strings.Split(string(b), nul)
	}
	if cProcess.flags&C.QUARK_F_CWD != 0 {
		process.Cwd = C.GoString(&cProcess.cwd[0])
	}

	return process
}

func eventToGo(cEvent *C.struct_quark_event) Event {
	return Event{
		Events:  uint64(cEvent.events),
		Process: processToGo(cEvent.process),
	}
}
