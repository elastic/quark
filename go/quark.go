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
}

type Exit struct {
	ExitCode      int32
	ExitTimeEvent uint64
}

type Event struct {
	Pid       uint32   // Always present
	Events    uint64   // Bitmask of events for this Event
	Proc      *Proc    // QUARK_F_PROC
	ExitEvent *Exit    // QUARK_F_EXIT
	Comm      string   // QUARK_F_COMM
	Filename  string   // QUARK_F_FILENAME
	Cmdline   []string // QUARK_F_CMDLINE
	Cwd       string   // QUARK_F_CWD
}

type Queue struct {
	cqq        *C.struct_quark_queue
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
	QUARK_EV_FORK         = int(C.QUARK_EV_FORK)
	QUARK_EV_EXEC         = int(C.QUARK_EV_EXEC)
	QUARK_EV_EXIT         = int(C.QUARK_EV_EXIT)
	QUARK_EV_SETPROCTITLE = int(C.QUARK_EV_SETPROCTITLE)
	QUARK_EV_SNAPSHOT     = int(C.QUARK_EV_SNAPSHOT)

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

func OpenQueue(attr QueueAttr, slots int) (*Queue, error) {
	var qq Queue

	p, err := C.calloc(C.size_t(1), C.sizeof_struct_quark_queue)
	if p == nil {
		return nil, wrapErrno(err)
	}
	qq.cqq = (*C.struct_quark_queue)(p)
	p = nil

	cattr := C.struct_quark_queue_attr{
		flags:            C.int(attr.Flags),
		max_length:       C.int(attr.MaxLength),
		cache_grace_time: C.int(attr.CacheGraceTime),
		hold_time:        C.int(attr.HoldTime),
	}
	r, err := C.quark_queue_open(qq.cqq, &cattr)
	if r == -1 {
		C.free(unsafe.Pointer(qq.cqq))
		return nil, wrapErrno(err)
	}

	p, err = C.calloc(C.size_t(slots), C.sizeof_struct_quark_event)
	if p == nil {
		C.quark_queue_close(qq.cqq)
		C.free(unsafe.Pointer(qq.cqq))
		return nil, wrapErrno(err)
	}
	qq.cEvents = (*C.struct_quark_event)(p)
	qq.numCevents = slots
	p = nil

	qq.epollFd = int(C.quark_queue_get_epollfd(qq.cqq))
	qq.cTmpEvent = (*C.struct_quark_event)(C.malloc(C.sizeof_struct_quark_event))
	qq.cTmpIter = (*C.struct_quark_event_iter)(C.malloc(C.sizeof_struct_quark_event_iter))

	return &qq, nil
}

func (qq *Queue) Close() {
	C.quark_queue_close(qq.cqq)
	C.free(unsafe.Pointer(qq.cqq))
	C.free(unsafe.Pointer(qq.cEvents))
	C.free(unsafe.Pointer(qq.cTmpEvent))
	C.free(unsafe.Pointer(qq.cTmpIter))
	qq.cqq = nil
}

func eventOfIndex(cEvents *C.struct_quark_event, idx int) *C.struct_quark_event {
	return (*C.struct_quark_event)(unsafe.Add(unsafe.Pointer(cEvents), idx*C.sizeof_struct_quark_event))
}

func (qq *Queue) GetEvents() ([]Event, error) {
	n, err := C.quark_queue_get_events(qq.cqq, qq.cEvents, C.int(qq.numCevents))
	if n == -1 {
		return nil, wrapErrno(err)
	}

	events := make([]Event, n)
	for i := range events {
		events[i] = eventToGo(eventOfIndex(qq.cEvents, i))
	}

	return events, nil
}

func (qq *Queue) Lookup(pid int) (Event, bool) {
	r, _ := C.quark_event_lookup(qq.cqq, qq.cTmpEvent, C.int(pid))

	if r != 0 {
		return Event{}, false
	}

	return eventToGo(qq.cTmpEvent), true
}

func (qq *Queue) Block() error {
	event := make([]syscall.EpollEvent, 1)
	_, err := syscall.EpollWait(qq.epollFd, event, 100)
	if err != nil && errors.Is(err, syscall.EINTR) {
		err = nil
	}
	return err
}

func (qq *Queue) Snapshot() []Event {
	var events []Event

	C.quark_event_iter_init(qq.cTmpIter, qq.cqq)

	for C.quark_event_iter_next(qq.cTmpIter, qq.cTmpEvent) == 1 {
		events = append(events, eventToGo(qq.cTmpEvent))
	}

	return events
}

func eventToGo(cEvent *C.struct_quark_event) Event {
	var event Event

	event.Pid = uint32(cEvent.pid)
	event.Events = uint64(cEvent.events)
	if cEvent.flags&C.QUARK_F_PROC != 0 {
		event.Proc = &Proc{
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
		}
	}
	if cEvent.flags&C.QUARK_F_EXIT != 0 {
		var exit Exit
		exit.ExitCode = int32(cEvent.exit_code)
		exit.ExitTimeEvent = uint64(cEvent.exit_time_event)
		event.ExitEvent = &exit
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
