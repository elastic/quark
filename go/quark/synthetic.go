// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Elastic NV

//go:build linux && (amd64 || arm64) && quark_synthetic

package quark

/*
#cgo CFLAGS: -DWITH_SYNTHETIC

#include <stdlib.h>
#include "quark.h"
*/
import "C"

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// SyntheticEventKind identifies a decoded event that can be injected into a
// synthetic queue.
type SyntheticEventKind int

const (
	QUARK_SYNTHETIC_INVALID     SyntheticEventKind = C.QUARK_SYNTHETIC_INVALID
	QUARK_SYNTHETIC_FORK        SyntheticEventKind = C.QUARK_SYNTHETIC_FORK
	QUARK_SYNTHETIC_EXEC        SyntheticEventKind = C.QUARK_SYNTHETIC_EXEC
	QUARK_SYNTHETIC_EXIT        SyntheticEventKind = C.QUARK_SYNTHETIC_EXIT
	QUARK_SYNTHETIC_SETSID      SyntheticEventKind = C.QUARK_SYNTHETIC_SETSID
	QUARK_SYNTHETIC_FILE_CREATE SyntheticEventKind = C.QUARK_SYNTHETIC_FILE_CREATE
	QUARK_SYNTHETIC_FILE_MODIFY SyntheticEventKind = C.QUARK_SYNTHETIC_FILE_MODIFY
	QUARK_SYNTHETIC_FILE_DELETE SyntheticEventKind = C.QUARK_SYNTHETIC_FILE_DELETE

	QQ_SYNTHETIC = int(C.QQ_SYNTHETIC)
)

// SyntheticProcess is the decoded process data for a synthetic event.
type SyntheticProcess struct {
	Pid            uint32
	Tid            uint32
	Ppid           uint32
	Pgid           uint32
	Sid            uint32
	StartBoottime  uint64
	Uid            uint32
	Gid            uint32
	Suid           uint32
	Sgid           uint32
	Euid           uint32
	Egid           uint32
	CapInheritable uint64
	CapPermitted   uint64
	CapEffective   uint64
	CapBset        uint64
	CapAmbient     uint64
	TtyMajor       uint32
	TtyMinor       uint32
	UtsInonum      uint32
	IpcInonum      uint32
	MntInonum      uint32
	NetInonum      uint32
	ExitCode       int32
	ExitTimeEvent  uint64
	Comm           string
	Cwd            string
	Cgroup         string
	Argv           []string
	Env            []string
	Executable     string
}

// SyntheticFile is the decoded file data for a synthetic file event.
type SyntheticFile struct {
	Path       string
	OldPath    string
	SymTarget  string
	Inode      uint64
	Atime      uint64
	Mtime      uint64
	Ctime      uint64
	Size       uint64
	Mode       uint32
	Uid        uint32
	Gid        uint32
	ChangeMask uint32
}

// SyntheticEvent is a decoded event for a synthetic queue. Time is in
// CLOCK_BOOTTIME nanoseconds.
type SyntheticEvent struct {
	Kind    SyntheticEventKind
	Time    uint64
	Process SyntheticProcess
	File    SyntheticFile
}

// OpenSyntheticQueue opens a probe-free queue for benchmarks and tests. It
// keeps all non-backend flags, aggregation settings, and rules from attr.
func OpenSyntheticQueue(attr QueueAttr) (*Queue, error) {
	attr.Flags &^= QQ_EBPF | QQ_KPROBE | int(C.QQ_NOVA) | QQ_SYNTHETIC
	attr.Flags |= QQ_SYNTHETIC
	return OpenQueue(attr)
}

type syntheticAllocations []unsafe.Pointer

func (allocations *syntheticAllocations) cString(field, value string) (*C.char, error) {
	if strings.IndexByte(value, 0) != -1 {
		return nil, fmt.Errorf("%s contains a NUL byte", field)
	}
	if value == "" {
		return nil, nil
	}

	p := C.CString(value)
	*allocations = append(*allocations, unsafe.Pointer(p))
	return p, nil
}

func (allocations *syntheticAllocations) cStringList(field string, values []string) (*C.char, C.size_t, error) {
	if len(values) == 0 {
		return nil, 0, nil
	}

	length := len(values)
	for _, value := range values {
		if strings.IndexByte(value, 0) != -1 {
			return nil, 0, fmt.Errorf("%s contains a NUL byte", field)
		}
		length += len(value)
	}

	buf := make([]byte, 0, length)
	for _, value := range values {
		buf = append(buf, value...)
		buf = append(buf, 0)
	}
	p := C.CBytes(buf)
	*allocations = append(*allocations, p)
	return (*C.char)(p), C.size_t(len(buf)), nil
}

func (allocations syntheticAllocations) free() {
	for _, p := range allocations {
		C.free(p)
	}
}

// Inject copies event into queue immediately before Quark's raw-event insert
// step. Injection is synchronous. A queue is not safe for concurrent calls.
func (queue *Queue) Inject(event SyntheticEvent) error {
	if queue == nil || queue.quarkQueue == nil {
		return syscall.EINVAL
	}

	var cevent C.struct_quark_synthetic_event
	var allocations syntheticAllocations
	defer allocations.free()

	cevent.kind = C.enum_quark_synthetic_event_kind(event.Kind)
	cevent.time = C.u64(event.Time)

	process := &cevent.process
	process.pid = C.u32(event.Process.Pid)
	process.tid = C.u32(event.Process.Tid)
	process.ppid = C.u32(event.Process.Ppid)
	process.pgid = C.u32(event.Process.Pgid)
	process.sid = C.u32(event.Process.Sid)
	process.start_boottime = C.u64(event.Process.StartBoottime)
	process.uid = C.u32(event.Process.Uid)
	process.gid = C.u32(event.Process.Gid)
	process.suid = C.u32(event.Process.Suid)
	process.sgid = C.u32(event.Process.Sgid)
	process.euid = C.u32(event.Process.Euid)
	process.egid = C.u32(event.Process.Egid)
	process.cap_inheritable = C.u64(event.Process.CapInheritable)
	process.cap_permitted = C.u64(event.Process.CapPermitted)
	process.cap_effective = C.u64(event.Process.CapEffective)
	process.cap_bset = C.u64(event.Process.CapBset)
	process.cap_ambient = C.u64(event.Process.CapAmbient)
	process.tty_major = C.u32(event.Process.TtyMajor)
	process.tty_minor = C.u32(event.Process.TtyMinor)
	process.uts_inonum = C.u32(event.Process.UtsInonum)
	process.ipc_inonum = C.u32(event.Process.IpcInonum)
	process.mnt_inonum = C.u32(event.Process.MntInonum)
	process.net_inonum = C.u32(event.Process.NetInonum)
	process.exit_code = C.s32(event.Process.ExitCode)
	process.exit_time_event = C.u64(event.Process.ExitTimeEvent)

	var err error
	if process.comm, err = allocations.cString("process comm", event.Process.Comm); err != nil {
		return err
	}
	if process.cwd, err = allocations.cString("process cwd", event.Process.Cwd); err != nil {
		return err
	}
	if process.cgroup, err = allocations.cString("process cgroup", event.Process.Cgroup); err != nil {
		return err
	}
	if process.argv, process.argv_len, err = allocations.cStringList("process argv", event.Process.Argv); err != nil {
		return err
	}
	if process.env, process.env_len, err = allocations.cStringList("process environment", event.Process.Env); err != nil {
		return err
	}
	if process.executable, err = allocations.cString("process executable", event.Process.Executable); err != nil {
		return err
	}

	file := &cevent.file
	if file.path, err = allocations.cString("file path", event.File.Path); err != nil {
		return err
	}
	if file.old_path, err = allocations.cString("file old path", event.File.OldPath); err != nil {
		return err
	}
	if file.sym_target, err = allocations.cString("file symlink target", event.File.SymTarget); err != nil {
		return err
	}
	file.inode = C.u64(event.File.Inode)
	file.atime = C.u64(event.File.Atime)
	file.mtime = C.u64(event.File.Mtime)
	file.ctime = C.u64(event.File.Ctime)
	file.size = C.u64(event.File.Size)
	file.mode = C.u32(event.File.Mode)
	file.uid = C.u32(event.File.Uid)
	file.gid = C.u32(event.File.Gid)
	file.change_mask = C.u32(event.File.ChangeMask)

	ret, errno := C.quark_queue_inject(queue.quarkQueue, &cevent)
	if ret == -1 {
		return wrapErrno(errno)
	}
	return nil
}
