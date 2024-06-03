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
	CapInheritable uint64
	CapPermitted   uint64
	CapEffective   uint64
	CapBset        uint64
	CapAmbient     uint64
	TimeBoot       uint64
	Ppid           uint32
	Uid            uint32
	Gid            uint32
	Suid           uint32
	Sgid           uint32
	Euid           uint32
	Egid           uint32
	Pgid           uint32
	Sid            uint32
	TtyMajor       uint32
	TtyMinor       uint32
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
	qqc      *C.struct_quark_queue
	cevs     *C.struct_quark_event
	num_cevs int
	epollfd  int
	tmpev    *C.struct_quark_event // Used as storage for lookups
}

const (
	// quark_queue_attr{} flags
	QQ_THREAD_EVENTS = int(C.QQ_THREAD_EVENTS)
	QQ_NO_CACHE      = int(C.QQ_NO_CACHE)
	QQ_KPROBE        = int(C.QQ_KPROBE)
	QQ_EBPF          = int(C.QQ_EBPF)
	QQ_NO_SNAPSHOT   = int(C.QQ_NO_SNAPSHOT)
	QQ_ALL_BACKENDS  = int(C.QQ_ALL_BACKENDS)

	// Event.events
	QUARK_EV_FORK         = int(C.QUARK_EV_FORK)
	QUARK_EV_EXEC         = int(C.QUARK_EV_EXEC)
	QUARK_EV_EXIT         = int(C.QUARK_EV_EXIT)
	QUARK_EV_SETPROCTITLE = int(C.QUARK_EV_SETPROCTITLE)
	QUARK_EV_SNAPSHOT     = int(C.QUARK_EV_SNAPSHOT)
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
	qq.qqc = (*C.struct_quark_queue)(p)
	p = nil

	cattr := C.struct_quark_queue_attr{
		flags:            C.int(attr.Flags),
		max_length:       C.int(attr.MaxLength),
		cache_grace_time: C.int(attr.CacheGraceTime),
		hold_time:        C.int(attr.HoldTime),
	}
	r, err := C.quark_queue_open(qq.qqc, &cattr)
	if r == -1 {
		C.free(unsafe.Pointer(qq.qqc))
		return nil, wrapErrno(err)
	}

	p, err = C.calloc(C.size_t(slots), C.sizeof_struct_quark_event)
	if p == nil {
		C.quark_queue_close(qq.qqc)
		C.free(unsafe.Pointer(qq.qqc))
		return nil, wrapErrno(err)
	}
	qq.cevs = (*C.struct_quark_event)(p)
	qq.num_cevs = slots
	p = nil

	qq.epollfd = int(C.quark_queue_get_epollfd(qq.qqc))
	qq.tmpev = (*C.struct_quark_event)(C.malloc(C.sizeof_struct_quark_event))

	return &qq, nil
}

func (qq *Queue) Close() {
	C.quark_queue_close(qq.qqc)
	C.free(unsafe.Pointer(qq.qqc))
	C.free(unsafe.Pointer(qq.cevs))
	C.free(unsafe.Pointer(qq.tmpev))
	qq.qqc = nil
}

func cEventOfIdx(cevs *C.struct_quark_event, idx int) *C.struct_quark_event {
	return (*C.struct_quark_event)(unsafe.Add(unsafe.Pointer(cevs), idx*C.sizeof_struct_quark_event))
}

func (qq *Queue) GetEvents() ([]Event, error) {
	n, err := C.quark_queue_get_events(qq.qqc, qq.cevs, C.int(qq.num_cevs))
	if n == -1 {
		return nil, wrapErrno(err)
	}

	qqevs := make([]Event, n)
	for i := range qqevs {
		qev, err := cEventToGo(cEventOfIdx(qq.cevs, i))
		if err != nil {
			panic(err) // XXX remove me
		}
		qqevs[i] = qev
	}

	return qqevs, nil
}

func (qq *Queue) Lookup(pid int) *Event {
	r, _ := C.quark_event_lookup(qq.qqc, qq.tmpev, C.int(pid))

	if r != 0 {
		return nil
	}

	qev, err := cEventToGo(qq.tmpev)
	if err != nil {
		panic(err) // XXX remove me
	}

	return &qev
}

func (qq *Queue) Block() error {
	event := make([]syscall.EpollEvent, 1)
	_, err := syscall.EpollWait(qq.epollfd, event, 100)
	if err != nil && errors.Is(err, syscall.EINTR) {
		err = nil
	}
	return err
}

func cEventToGo(cev *C.struct_quark_event) (Event, error) {
	var qev Event

	qev.Pid = uint32(cev.pid)
	qev.Events = uint64(cev.events)
	if cev.flags&C.QUARK_F_PROC != 0 {
		qev.Proc = &Proc{
			CapInheritable: uint64(cev.proc_cap_inheritable),
			CapPermitted:   uint64(cev.proc_cap_permitted),
			CapEffective:   uint64(cev.proc_cap_effective),
			CapBset:        uint64(cev.proc_cap_bset),
			CapAmbient:     uint64(cev.proc_cap_ambient),
			TimeBoot:       uint64(cev.proc_time_boot),
			Ppid:           uint32(cev.proc_ppid),
			Uid:            uint32(cev.proc_uid),
			Gid:            uint32(cev.proc_gid),
			Suid:           uint32(cev.proc_suid),
			Sgid:           uint32(cev.proc_sgid),
			Euid:           uint32(cev.proc_euid),
			Egid:           uint32(cev.proc_egid),
			Pgid:           uint32(cev.proc_pgid),
			Sid:            uint32(cev.proc_sid),
			TtyMajor:       uint32(cev.proc_tty_major),
			TtyMinor:       uint32(cev.proc_tty_minor),
		}
	}
	if cev.flags&C.QUARK_F_EXIT != 0 {
		var exit Exit
		exit.ExitCode = int32(cev.exit_code)
		exit.ExitTimeEvent = uint64(cev.exit_time_event)
		qev.ExitEvent = &exit
	}
	if cev.flags&C.QUARK_F_COMM != 0 {
		qev.Comm = C.GoString(&cev.comm[0])
	}
	if cev.flags&C.QUARK_F_FILENAME != 0 {
		qev.Filename = C.GoString(&cev.filename[0])
	}
	if cev.flags&C.QUARK_F_CMDLINE != 0 {
		b := C.GoBytes(unsafe.Pointer(&cev.cmdline[0]), C.int(cev.cmdline_len))
		nul := string(byte(0))
		b = bytes.TrimRight(b, nul)
		qev.Cmdline = strings.Split(string(b), nul)
	}
	if cev.flags&C.QUARK_F_CWD != 0 {
		qev.Cwd = C.GoString(&cev.cwd[0])
	}

	return qev, nil
}
