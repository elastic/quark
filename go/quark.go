package quark

/*
   #cgo CFLAGS: -I${SRCDIR}/..
   #cgo LDFLAGS: ${SRCDIR}/../libquark.a ${SRCDIR}/../libbpf/src/libbpf.a -lelf -lz

   #include <stdlib.h>
   #include "quark.h"
*/
import "C"

import (
	"errors"
	"golang.org/x/sys/unix"
	"unsafe"
)

type QuarkProc struct {
	CapInheritable uint64
	CapPermitted   uint64
	CapEffective   uint64
	CapBset        uint64
	CapAmbient     uint64
	TimeBoot       uint64
	TimeEvent      uint64
	TimeStart      uint64
	Ppid           uint32
	Uid            uint32
	Gid            uint32
	Suid           uint32
	Sgid           uint32
	Euid           uint32
	Egid           uint32
}

type QuarkExit struct {
	ExitCode      int32
	ExitTimeEvent uint64
}

type QuarkEvent struct {
	Pid       uint32     // Always present
	Proc      *QuarkProc // QUARK_F_PROC
	ExitEvent *QuarkExit // QUARK_F_EXIT
	Comm      string     // QUARK_F_COMM
	Filename  string     // QUARK_F_FILENAME
	Cmdline   string     // QUARK_F_CMDLINE
	Cwd       string     // QUARK_F_CWD
}

type QuarkQueue struct {
	qqc      *C.struct_quark_queue
	cevs     *C.struct_quark_event
	num_cevs int
	fds      []unix.PollFd
}

var ErrUndefined = errors.New("undefined")

func wrapErrno(err error) error {
	if err == nil {
		err = ErrUndefined
	}

	return err
}

func QuarkInit() error {
	r, err := C.quark_init()
	if r == -1 {
		return wrapErrno(err)
	}

	return nil
}

func QuarkClose() {
	C.quark_close()
}

func QuarkQueueOpen(slots int) (*QuarkQueue, error) {
	var qq QuarkQueue

	p, err := C.calloc(C.size_t(1), C.sizeof_struct_quark_queue)
	if p == nil {
		return nil, wrapErrno(err)
	}
	qq.qqc = (*C.struct_quark_queue)(p)
	p = nil

	r, err := C.quark_queue_open(qq.qqc, C.int(0))
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

	var fdsa [1024]C.int
	nfds, err := C.quark_queue_get_fds(qq.qqc, &fdsa[0], C.int(len(fdsa)))
	if nfds == -1 {
		C.free(unsafe.Pointer(qq.qqc))
		C.free(unsafe.Pointer(qq.cevs))
		return nil, wrapErrno(err)
	}
	qq.fds = make([]unix.PollFd, nfds)
	for i := range qq.fds {
		qq.fds[i] = unix.PollFd{
			Fd:     int32(fdsa[i]),
			Events: unix.POLLIN | unix.POLLHUP,
		}
	}

	return &qq, nil
}

func (qq *QuarkQueue) Close() {
	C.quark_queue_close(qq.qqc)
	C.free(unsafe.Pointer(qq.qqc))
	C.free(unsafe.Pointer(qq.cevs))
	qq.qqc = nil
}

func cEventOfIdx(cevs *C.struct_quark_event, idx int) *C.struct_quark_event {
	return (*C.struct_quark_event)(unsafe.Add(unsafe.Pointer(cevs), idx*C.sizeof_struct_quark_event))
}

func (qq *QuarkQueue) GetEvents() ([]QuarkEvent, error) {
	n, err := C.quark_queue_get_events(qq.qqc, qq.cevs, C.int(qq.num_cevs))
	if n == -1 {
		return nil, wrapErrno(err)
	}

	qqevs := make([]QuarkEvent, n)
	for i := range qqevs {
		qev, err := cEventToGo(cEventOfIdx(qq.cevs, i))
		if err != nil {
			panic(err)
		}
		qqevs[i] = qev
	}

	return qqevs, nil
}

func (qq *QuarkQueue) Block() {
	unix.Poll(qq.fds, 100)
	// TODO scan all fds for errors
}

func cEventToGo(cev *C.struct_quark_event) (QuarkEvent, error) {
	var qev QuarkEvent

	qev.Pid = uint32(cev.pid)
	if cev.flags&C.QUARK_F_PROC != 0 {
		qev.Proc = &QuarkProc{
			CapInheritable: uint64(cev.proc_cap_inheritable),
			CapPermitted:   uint64(cev.proc_cap_permitted),
			CapEffective:   uint64(cev.proc_cap_effective),
			CapBset:        uint64(cev.proc_cap_bset),
			CapAmbient:     uint64(cev.proc_cap_ambient),
			TimeBoot:       uint64(cev.proc_time_boot),
			TimeEvent:      uint64(cev.proc_time_start_event),
			TimeStart:      uint64(cev.proc_time_start),
			Ppid:           uint32(cev.proc_ppid),
			Uid:            uint32(cev.proc_uid),
			Gid:            uint32(cev.proc_gid),
			Suid:           uint32(cev.proc_suid),
			Sgid:           uint32(cev.proc_sgid),
			Euid:           uint32(cev.proc_euid),
			Egid:           uint32(cev.proc_egid),
		}
	}
	if cev.flags&C.QUARK_F_EXIT != 0 {
		var exit QuarkExit
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
		qev.Cmdline = C.GoString(&cev.cmdline[0])
	}
	if cev.flags&C.QUARK_F_CWD != 0 {
		qev.Cwd = C.GoString(&cev.cwd[0])
	}

	return qev, nil
}
