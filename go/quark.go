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

// Exit carries data on the exit behavior of the process. Only valid if `Valid` is true
type Exit struct {
	ExitCode      int32
	ExitTimeEvent uint64
	Valid         bool
}

// Event represents a single process
type Event struct {
	Pid      uint32   // Always present
	Events   uint64   // Bitmask of events for this Event
	Proc     Proc     // Only meaningful if Proc.Valid (QUARK_F_PROC)
	Exit     Exit     // Only meaningful if Exit.Valid (QUARK_F_EXIT)
	Comm     string   // QUARK_F_COMM
	Filename string   // QUARK_F_FILENAME
	Cmdline  []string // QUARK_F_CMDLINE
	Cwd      string   // QUARK_F_CWD
}

// Queue represents a queue of events
type Queue struct {
	quarkQueue *C.struct_quark_queue // pointer to the queue structure
	cEvents    *C.struct_quark_event
	numCevents int
	epollFd    int
	cTmpEvent  *C.struct_quark_event      // Used as storage for lookups
	cTmpIter   *C.struct_quark_event_iter // Used as storage for snapshots
}

const (
	// quark_queue_attr{} flags
	QQ_THREAD_EVENTS = int(C.QQ_THREAD_EVENTS)
	QQ_NO_CACHE      = int(C.QQ_NO_CACHE)
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

// QueueAttr defines the attributes for the Quark queue
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

// DefaultQueueAttr returns the default attributes for the queue
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

// OpenQueue opens a Quark Queue with the given attributes
func OpenQueue(attr QueueAttr, slots int) (*Queue, error) {
	var queue Queue

	queuePointer, err := C.calloc(C.size_t(1), C.sizeof_struct_quark_queue)
	if queuePointer == nil {
		return nil, wrapErrno(err)
	}
	queue.quarkQueue = (*C.struct_quark_queue)(queuePointer)
	queuePointer = nil

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

	queuePointer, err = C.calloc(C.size_t(slots), C.sizeof_struct_quark_event)
	if queuePointer == nil {
		C.quark_queue_close(queue.quarkQueue)
		C.free(unsafe.Pointer(queue.quarkQueue))
		return nil, wrapErrno(err)
	}
	queue.cEvents = (*C.struct_quark_event)(queuePointer)
	queue.numCevents = slots
	queuePointer = nil

	queue.epollFd = int(C.quark_queue_get_epollfd(queue.quarkQueue))
	queue.cTmpEvent = (*C.struct_quark_event)(C.malloc(C.sizeof_struct_quark_event))
	queue.cTmpIter = (*C.struct_quark_event_iter)(C.malloc(C.sizeof_struct_quark_event_iter))

	return &queue, nil
}

// Close closes the queue
func (queue *Queue) Close() {
	C.quark_queue_close(queue.quarkQueue)
	C.free(unsafe.Pointer(queue.quarkQueue))
	C.free(unsafe.Pointer(queue.cEvents))
	C.free(unsafe.Pointer(queue.cTmpEvent))
	C.free(unsafe.Pointer(queue.cTmpIter))
	queue.quarkQueue = nil
}

func eventOfIndex(cEvents *C.struct_quark_event, idx int) *C.struct_quark_event {
	return (*C.struct_quark_event)(unsafe.Add(unsafe.Pointer(cEvents), idx*C.sizeof_struct_quark_event))
}

// GetEvents returns a number of events based on the `slots` attribute when the queue was initialized
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

// Lookup returns an event for the given PID
func (queue *Queue) Lookup(pid int) (Event, bool) {
	r, _ := C.quark_event_lookup(queue.quarkQueue, queue.cTmpEvent, C.int(pid))

	if r != 0 {
		return Event{}, false
	}

	return eventToGo(queue.cTmpEvent), true
}

// Block blocks until an event reaches the bpf buffer queue
func (queue *Queue) Block() error {
	event := make([]syscall.EpollEvent, 1)
	_, err := syscall.EpollWait(queue.epollFd, event, 100)
	if err != nil && errors.Is(err, syscall.EINTR) {
		err = nil
	}
	return err
}

// Snapshot returns a list of current events in quark
func (queue *Queue) Snapshot() []Event {
	var events []Event

	C.quark_event_iter_init(queue.cTmpIter, queue.quarkQueue)

	for C.quark_event_iter_next(queue.cTmpIter, queue.cTmpEvent) == 1 {
		events = append(events, eventToGo(queue.cTmpEvent))
	}

	return events
}

// eventToGo converts the C event structure to a go event
func eventToGo(cEvent *C.struct_quark_event) Event {
	var event Event

	event.Pid = uint32(cEvent.pid)
	event.Events = uint64(cEvent.events)
	if cEvent.flags&C.QUARK_F_PROC != 0 {
		event.Proc = Proc{
			CapInheritable:  uint64(cEvent.proc_cap_inheritable),
			CapPermitted:    uint64(cEvent.proc_cap_permitted),
			CapEffective:    uint64(cEvent.proc_cap_effective),
			CapBset:         uint64(cEvent.proc_cap_bset),
			CapAmbient:      uint64(cEvent.proc_cap_ambient),
			TimeBoot:        uint64(cEvent.proc_time_boot),
			Ppid:            uint32(cEvent.proc_ppid),
			Uid:             uint32(cEvent.proc_uid),
			Gid:             uint32(cEvent.proc_gid),
			Suid:            uint32(cEvent.proc_suid),
			Sgid:            uint32(cEvent.proc_sgid),
			Euid:            uint32(cEvent.proc_euid),
			Egid:            uint32(cEvent.proc_egid),
			Pgid:            uint32(cEvent.proc_pgid),
			Sid:             uint32(cEvent.proc_sid),
			EntryLeader:     uint32(cEvent.proc_entry_leader),
			EntryLeaderType: uint32(cEvent.proc_entry_leader_type),
			TtyMajor:        uint32(cEvent.proc_tty_major),
			TtyMinor:        uint32(cEvent.proc_tty_minor),
			Valid:           true,
		}
	}
	if cEvent.flags&C.QUARK_F_EXIT != 0 {
		event.Exit = Exit{
			ExitCode:      int32(cEvent.exit_code),
			ExitTimeEvent: uint64(cEvent.exit_time_event),
			Valid:         true,
		}
	}
	if cEvent.flags&C.QUARK_F_COMM != 0 {
		event.Comm = C.GoString(&cEvent.comm[0])
	}
	if cEvent.flags&C.QUARK_F_FILENAME != 0 {
		event.Filename = C.GoString(&cEvent.filename[0])
	}
	if cEvent.flags&C.QUARK_F_CMDLINE != 0 {
		b := C.GoBytes(unsafe.Pointer(&cEvent.cmdline[0]), C.int(cEvent.cmdline_len))
		nul := string(byte(0))
		b = bytes.TrimRight(b, nul)
		event.Cmdline = strings.Split(string(b), nul)
	}
	if cEvent.flags&C.QUARK_F_CWD != 0 {
		event.Cwd = C.GoString(&cEvent.cwd[0])
	}

	return event
}
