package main
/*
   #cgo CFLAGS: -I../
   #cgo LDFLAGS: ./../libquark.a ./../libbpf/src/libbpf.a -lelf -lz

   #include <stdlib.h>
   #include "quark.h"
*/
import "C"
import "fmt"
import "errors"
import "golang.org/x/sys/unix"

type QuarkProcEvent struct {
	cap_inheritable uint64
	cap_permitted uint64
	cap_effective uint64
	cap_bset uint64
	cap_ambient uint64
	ppid uint32
	uid uint32
	gid uint32
	suid uint32
	sgid uint32
	euid uint32
	egid uint32
}

type QuarkEvent struct {
	/* Always present */
	pid uint32
	/* QUARK_EV_PROC */
	proc *QuarkProcEvent
	/* QUARK_EV_EXIT */
	exit_code *int32
	/* QUARK_EV_COMM */
	comm string
	/* QUARK_EV_FILENAME */
	filename string
	/* QUARK_EV_CMDLINE */
	cmdline string
	/* QUARK_EV_CWD */
	cwd string
}

type QuarkQueue struct {
	qqc C.struct_quark_queue
	cevs []C.struct_quark_event
	fds []unix.PollFd
}

var ErrUndefined = errors.New("Undefined")

func wrapErrno(err error) error {
	if err != nil {
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
	qq := QuarkQueue{}

	r, err := C.quark_queue_open(&qq.qqc, 0)
	if r == -1 {
		return nil, wrapErrno(err)
	}
	for ; slots > 0; slots-- {
		qq.cevs = append(qq.cevs, C.struct_quark_event{})
	}
	var fdsa [1024]C.int
	nfds, err := C.quark_queue_get_fds(&qq.qqc, &fdsa[0], C.int(len(fdsa)))
	if nfds == -1 {
		return nil, wrapErrno(err)
	}
	for i := 0; i < int(nfds); i++ {
		pfd := unix.PollFd{
			Fd: int32(fdsa[i]),
			Events: unix.POLLIN | unix.POLLHUP,
		}
		qq.fds = append(qq.fds, pfd)
	}

	return &qq, nil
}

func (qq *QuarkQueue) Close() {
	C.quark_queue_close(&qq.qqc)
}

func (qq *QuarkQueue) GetEvents() ([]QuarkEvent, error) {
	nc, err := C.quark_queue_get_events(&qq.qqc, &qq.cevs[0],
		C.int(len(qq.cevs)))
	n := int(nc)
	if n == -1 {
		return nil, wrapErrno(err)
	}

	qqevs := make([]QuarkEvent, n)
	for i := 0; i < n; i++ {
		qev, err := eventToGo(&qq.cevs[i])
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

func eventToGo(cev *C.struct_quark_event) (QuarkEvent, error) {
	var qev QuarkEvent

	qev.pid = uint32(cev.pid)
	if cev.flags & C.QUARK_EV_PROC != 0 {
		qev.proc = &QuarkProcEvent{
			cap_inheritable: uint64(cev.proc_cap_inheritable),
			cap_permitted: uint64(cev.proc_cap_permitted),
			cap_effective: uint64(cev.proc_cap_effective),
			cap_bset: uint64(cev.proc_cap_bset),
			cap_ambient: uint64(cev.proc_cap_ambient),
			ppid: uint32(cev.proc_ppid),
			uid: uint32(cev.proc_uid),
			gid: uint32(cev.proc_gid),
			suid: uint32(cev.proc_suid),
			sgid: uint32(cev.proc_sgid),
			euid: uint32(cev.proc_euid),
			egid: uint32(cev.proc_egid),
		}
	}
	if cev.flags & C.QUARK_EV_EXIT != 0 {
		exit_code := int32(cev.exit_code)
		qev.exit_code = &exit_code
	}
	if cev.flags & C.QUARK_EV_COMM != 0 {
		qev.comm = C.GoString(&cev.comm[0])
	}
	if cev.flags & C.QUARK_EV_FILENAME != 0 {
		qev.filename = C.GoString(&cev.filename[0])
	}
	if cev.flags & C.QUARK_EV_CMDLINE != 0 {
		qev.cmdline = C.GoString(&cev.cmdline[0])
	}
	if cev.flags & C.QUARK_EV_CWD != 0 {
		qev.cwd = C.GoString(&cev.cwd[0])
	}

	return qev, nil
}

func main() {
	err := QuarkInit()
	if err != nil {
		panic(err)
	}
	qq, err := QuarkQueueOpen(64)
	if err != nil {
		panic(err)
	}
	for {
		qevs, err := qq.GetEvents()
		if err != nil {
			panic("GetEvents")
		}
		for _, qev := range qevs {
			fmt.Printf("%#v", qev)
			if qev.proc != nil {
				fmt.Printf(" %#v", qev.proc)
			}
			fmt.Printf("\n")
		}
		if len(qevs) == 0 {
			qq.Block()
		}
	}
	qq.Close()
	QuarkClose()
}
