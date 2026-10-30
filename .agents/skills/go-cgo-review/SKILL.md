---
name: go-cgo-review
description: Go and cgo review checklist for pull requests that change *.go files. Covers the cgo pointer-passing rules, pinning, C memory ownership and leaks, callbacks and exported functions, threads and signals, C.int/size_t ABI traps, and races across goroutines and subsystems that the race detector cannot see. Load it before reviewing any Go change; in this repository every Go file under go/quark imports "C".
---

# Go and cgo review checklist

Go hides most memory management, which makes the places where it does not hide it
(cgo, unsafe, goroutines sharing state) disproportionately dangerous. Treat every
`import "C"` file as C code with a garbage collector pointed at it. If the C side of a
cgo call changed in the same PR, load the `c-review` skill as well.

## 1. The cgo pointer-passing rules

The runtime enforces these only partially (`GODEBUG=cgocheck=1` catches some at run time,
`cgocheck=2` more, but neither catches everything). Check them by reading:

- **Go memory may be passed to C only if it contains no Go pointers.** Passing
  `&buf[0]` for a `[]byte` is fine. Passing a pointer to a struct that itself holds a
  Go pointer, slice, string, map, chan, func, or interface is not. Look at the struct
  definition, not just the call site.
- **C must not keep the Go pointer after the call returns.** If the C side stores it in
  a global, a struct field, a callback registration, or a queue, that is a violation:
  the GC may move or free it. Ask of every pointer argument: does the C function retain
  it? Read the C function if the answer is not obvious from its documentation.
- **C memory must never hold a Go pointer**, even temporarily, even if the Go object is
  reachable elsewhere. `cStruct.cb_data = unsafe.Pointer(&goObj)` is the canonical bug.
- **Go code must not store Go pointers in C memory** and must not pass C memory that
  contains Go pointers back to C.

The idiomatic escapes: pass an integer handle instead (`runtime/cgo.Handle`, or your
own map under a mutex), and look the Go value up when the callback fires. Delete the
handle when the C side is done with it, or it leaks forever.

Also check `unsafe.Pointer` arithmetic follows the six patterns in the `unsafe` package
docs. `uintptr` round-trips through a variable are a GC bug: the object can move or be
collected between the conversion and the use.

## 2. Pinning

Since Go 1.21, `runtime.Pinner` is the correct tool when:

- A Go pointer must be passed inside a struct that C reads (pin the pointee, so the
  struct can legally contain it for the duration of the call).
- C needs the memory to stay put across multiple calls (pin, then `Unpin` when C is
  done). Check that `Unpin` runs on every path, including error returns and panics.
- A Go-allocated buffer is handed to an asynchronous C API (ring buffer, io_uring,
  epoll user data, a thread C spawned).

Without a Pinner, the alternatives are C-allocated memory (`C.malloc`) with an
explicit free, or copying. Flag any case where the code relies on "the GC probably
won't move it" or on the current non-moving collector. That is an implementation
detail, not a contract.

## 3. Memory ownership and leaks

Every `C.CString`, `C.CBytes`, and `C.malloc` has exactly one owner and exactly one
free. Check:

- Is there a `C.free` on every path, including early returns and the error branch of
  the very call the string was created for? `defer C.free(unsafe.Pointer(p))` right
  after allocation is the safe idiom. A bare `C.free` at the end of the function is a
  leak waiting for the next early return.
- Does the C function take ownership (and therefore free it), or copy it? If the C API
  frees the argument, a `defer C.free` is a double free. Read the C side.
- For memory returned from C: who frees it, with what? `C.GoString`/`C.GoBytes` copy,
  so the C buffer still needs freeing. Memory freed with the wrong allocator (Go
  `C.free` on something from a custom pool, or vice versa) is undefined behavior.
- Go objects that wrap a C resource (a queue, a handle, an fd) need an explicit
  `Close`. A finalizer is a backstop, not a strategy: it runs at an unpredictable time
  and not at all on exit. If a finalizer exists, check it is cleared on explicit close
  so the resource is not freed twice.
- `runtime.KeepAlive(obj)` after the last C call that uses a pointer derived from `obj`.
  Without it, the GC may finalize `obj` while C is still using the pointer, because the
  Go side no longer references `obj` after the pointer was extracted.
- Error paths that allocate partway through a multi-step C initialization must unwind
  what succeeded. Look for a `goto`-style cleanup equivalent in Go: usually a sequence
  of `if err != nil { C.free(a); C.free(b); return }` that is missing one.

## 4. Callbacks and exported functions

When C calls back into Go (`//export`):

- The callback runs on whatever thread C called it from, possibly one Go has never seen.
  It must not assume any goroutine-local state.
- Panics must not cross the boundary. A panic in an exported function called from C
  crashes the process with no useful stack. Recover at the boundary and translate into
  an error return C can understand.
- The callback must not retain C pointers past its return unless the C API documents
  that lifetime.
- `cgo.Handle` or a map is the only safe way to find the Go object the callback is
  about. If the code passes `unsafe.Pointer(&goObj)` as `user_data`, see section 1.
- Blocking in the callback blocks the C caller. If C holds a lock while calling back,
  and the Go callback tries to take a Go lock that another goroutine holds while
  calling into the same C library, that is a deadlock. Trace lock order across the
  language boundary.

## 5. Threads, signals, and blocking

- A goroutine in a C call occupies an OS thread. Many goroutines in slow C calls means
  many threads; the runtime will create them up to the 10,000 default limit. Long
  blocking C calls that never return (an event loop) should be documented as such and
  probably live on a dedicated goroutine with `runtime.LockOSThread`.
- C code that uses thread-local storage, `setns`, `unshare`, or changes signal masks
  needs `LockOSThread`, or the next scheduling decision silently undoes it.
- Signal handlers installed by C fight with the Go runtime's. Check for `SA_ONSTACK`
  and whether the C side was built expecting to own signals.
- `errno`: only the two-value form `ret, err := C.fn()` reads it safely. Reading
  `C.errno` or calling a C helper afterward is racy.

## 6. Type and ABI traps

- `C.int` is 32-bit; Go `int` is 64-bit on 64-bit platforms. Conversions in either
  direction can truncate. Check lengths and sizes especially: `C.int(len(buf))` on a
  buffer over 2 GiB is wrong.
- `C.size_t` and `C.ssize_t` differ in signedness. Comparing them or converting a
  negative error return into `size_t` produces a huge positive number.
- Struct layout: Go-side `C.struct_foo` follows the C ABI including padding, but
  bitfields and unions are not accessible as fields; code that overlays Go structs on C
  memory with `unsafe` depends on layout that `go vet` does not check.
- Empty slices: `&buf[0]` panics when `len(buf) == 0`. Check for a guard or use
  `unsafe.SliceData`.
- Strings: `C.CString` adds a NUL; Go strings may contain NUL, which truncates on the C
  side. If the string came from user input or a kernel buffer, check for embedded NUL.
- `C.GoString` on a non-terminated buffer reads until it finds a zero. If the buffer is
  length-delimited, use `C.GoStringN` or `C.GoBytes`.

## 7. Race conditions across goroutines and subsystems

The race detector catches data races in Go code it executes, nothing more. Reason about
these by hand:

- **Is the C library thread-safe?** Most are not. If a Go wrapper lets two goroutines
  call into the same C object (a queue, a parser, a connection), there must be a mutex
  on the Go side, and every entry point must take it. Look for the one method that
  forgot.
- **Maps** are never safe for concurrent write, or for concurrent read-and-write. Any
  map reachable from more than one goroutine needs a lock or `sync.Map`. Check lazily
  initialized caches especially.
- **Lock coverage, not just lock presence.** A field protected by a mutex in three
  methods and read without it in a fourth is a race. For each shared field, list the
  accessors and confirm each holds the lock. Returning a slice or map from under a lock
  hands the caller an unprotected alias.
- **Close and shutdown.** What happens if `Close` runs while another goroutine is in
  `Next`, `Read`, or a C call on the same object? Freed C memory under a running call is
  a use-after-free that the race detector will not see. A closed channel sent to twice,
  or closed twice, panics. `sync.WaitGroup` usage: `Add` must happen before the
  goroutine starts, not inside it.
- **Context and cancellation.** A goroutine that blocks in C cannot be cancelled by a
  context. Check that cancellation has a path to actually unblock it (a pipe, an
  eventfd, a close on the fd it is waiting on), or document that it does not.
- **Goroutine leaks.** Every `go func()` needs an answer to "how does this exit?" A
  goroutine blocked forever on a channel nobody will send to is a leak that grows per
  request.
- **Cross-subsystem ordering.** When one subsystem publishes state another reads (a
  process table and an event consumer, a cache and its invalidator), check the
  happens-before relationship. "The event will always arrive after the insert" is a
  claim that needs a channel, a lock, or an atomic to back it, not a comment.
- **Atomics.** A field read with `atomic.Load` in one place and plainly in another is a
  race. A check-then-act on an atomic (`if atomic.Load(&x) == 0 { atomic.Store(&x, 1) }`)
  needs `CompareAndSwap`.
- **Callback reentrancy.** If C calls a Go callback while the Go side holds a lock
  around the C call, and the callback takes the same lock, it deadlocks. If it does not
  take the lock, it is accessing the state unprotected.

## 8. What the toolchain already catches

You cannot run `go vet`, `go test -race`, or `cgocheck=2`, so know their limits and
read for what they miss:

- `go vet` runs the `cgocall` and `unsafeptr` analyzers, which catch the obvious
  syntactic violations of section 1 (a Go pointer to a struct with pointer fields
  passed directly). It does not see a Go pointer that reaches C through a `uintptr`,
  a `cb_data` field, or a struct overlay.
- The race detector only reports races on paths the tests execute, and never a race
  between Go code and C code touching the same memory. Sections 1, 3 and 7 are
  read-only work.
- CI runs the Go tests (`runtestgo.sh`), not `-race` or `cgocheck=2`. Treat every
  lifetime and ownership claim in a cgo change as unverified until you have traced it
  into the C side.
