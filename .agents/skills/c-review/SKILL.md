---
name: c-review
description: C review checklist for pull requests that change *.c, *.h, *.y or *.bpf.c files. Hunts for undefined behavior (memory, arithmetic, lifetime), memory and descriptor leaks on error paths, integer promotion and signedness traps, and the smaller C idioms that still bite. Load it before reviewing any C change; it supplies the specific failure modes to look for and the question to ask of each suspicious line.
---

# C review checklist

C gives the compiler permission to assume the program never does certain things.
When it does them anyway, the result is not "a wrong value" but "any behavior at all,"
including the optimizer deleting the check that would have caught it. Review C as if
the optimizer is an adversary looking for permission to miscompile.

## 1. Undefined behavior

Hunt for these specifically. Each is a P1 finding when reachable with realistic
input, because the consequences are not bounded.

**Memory**
- Out-of-bounds read or write, including the off-by-one on `<=` vs `<` and on
  `strlen` vs `sizeof`. Check every index against its array's actual length, not the
  length the author assumed.
- Use after free, including the subtle form where a pointer into a buffer survives a
  `realloc` of that buffer. Any `realloc` invalidates every pointer into the old block.
- Reading uninitialized memory. Struct padding is uninitialized even after assigning
  every field; `memcmp` on such a struct, or writing it to a file or socket, is a bug.
  Local variables are uninitialized; a `goto out` that skips an initialization and
  then frees the variable is the classic.
- NULL dereference, including `memcpy(NULL, x, 0)` and `memset(NULL, 0, 0)`, which are
  UB before C2y even with zero length.
- Misaligned access: casting a `char *` into a buffer to `uint32_t *` and dereferencing.
  Fine on x86, a SIGBUS on some ARM, and UB everywhere. Use `memcpy`.
- Strict aliasing: accessing an object through a pointer of an incompatible type.
  `*(uint32_t *)&float_var` and most "type punning through pointers" is UB; punning
  through `memcpy` or a union is the sanctioned route. This project builds with
  `-fno-strict-aliasing`, which makes the compiler tolerate it, but code copied into
  the Go side or another consumer does not inherit that flag.
- Modifying a string literal, or passing one to a function that might.
- Flexible array members: allocation size must be `sizeof(struct) + n * sizeof(elem)`,
  and `sizeof(struct)` already includes trailing padding, which is not the same as
  `offsetof(struct, fam)`. Check which one the code uses and whether that is right.
- Overlapping `memcpy` (use `memmove`), `strcpy` from a buffer that aliases the
  destination.
- Variadic functions called with the wrong argument types: `printf("%d", size_t_val)`,
  `printf("%lu", int_val)`, or passing `NULL` (an `int` 0 on some platforms) where a
  pointer sentinel is expected.

**Arithmetic**
- Signed integer overflow. `int` arithmetic that can exceed `INT_MAX` is UB, and the
  compiler will assume it cannot: `if (x + 1 < x)` is deleted as always-false. Check
  additions on lengths, sizes, and counters that come from outside.
- Shifting a negative value, shifting by the type's width or more, or shifting a
  value so that a set bit lands in the sign position (`1 << 31` is UB; `1u << 31` is
  not).
- Division by zero, and `INT_MIN / -1`, `INT_MIN % -1`.
- Converting a floating value out of range for the integer target.
- Pointer arithmetic past one-past-the-end, or between pointers into different objects.
  `p - q` where they point into different buffers is UB even if you only compare the
  result to zero.

**Control flow and lifetime**
- Returning the address of a local, or storing it somewhere that outlives the frame
  (including into a struct that is returned or queued).
- Reading a variable modified in the same expression without a sequence point in
  between (`i = i++`, `a[i] = i++`, `f(x++, x)`).
- Missing `return` in a non-void function (the caller gets garbage).
- Accessing a `volatile`-free variable from a signal handler, or calling anything not
  async-signal-safe from one.
- Unsequenced side effects in macro arguments: `MAX(a++, b)`.
- `longjmp` across frames with VLAs or that need cleanup.

## 2. Memory and resource leaks

Most C leaks are in error paths. For every function that acquires more than one
resource, draw the acquisition order and confirm that every failure after resource N
releases resources 1 through N:

- Does the function use a single cleanup label (`out:` / `fail:`) that frees everything,
  with pointers initialized to `NULL` so `free(NULL)` is safe? Or does each error branch
  free by hand? The second style is where leaks live; check each branch against the
  list of what has been acquired at that point.
- `p = realloc(p, n)`: on failure `realloc` returns `NULL` and the original block is
  still allocated, now unreachable. Use a temporary.
- Unchecked `malloc`/`calloc`/`strdup`/`asprintf` returns. `asprintf` leaves the
  pointer undefined on failure; check the return value, not the pointer.
- Resources that are not heap memory: file descriptors, `FILE *`, `DIR *`, mmaps,
  sockets, mutexes, reference counts, epoll registrations, BPF map and link handles.
  A leaked fd per event exhausts the process in minutes.
- Ownership transfer. When a function takes ownership of a pointer on success, does it
  also take ownership on failure, or does the caller still own it? Whichever convention
  holds, is it documented, and does every caller agree? Mismatch here is both a leak
  and a double free depending on the path.
- Double free: a pointer freed in cleanup that was already freed in an inner error
  path, or a pointer freed and not set to `NULL` in a struct that is cleaned up again
  later.
- Partially initialized structures freed with the full destructor. If `foo_free` calls
  `close(foo->fd)` and `fd` was never set (still 0, or garbage), the destructor closes
  stdin or a random fd.
- Containers: removing an element from a list or tree without freeing it, or freeing
  it without removing it (the tree now holds a dangling pointer). The `freebsd_tree.h`
  and `freebsd_queue.h` macros do not free for you.

## 3. Integer promotion and conversion

The rules are: anything narrower than `int` promotes to `int` before arithmetic; in a
mixed signed/unsigned operation of the same rank, the signed side converts to unsigned;
a signed value converted to a narrower type is implementation-defined; an unsigned value
is reduced modulo 2^N. These produce bugs that look nothing like the rules:

- `uint8_t a = 200, b = 100; (a + b) > 255` is **true** because the addition happens in
  `int`. Whether that is the intended behavior depends on the code; check that
  intermediate results are the width the author thinks they are.
- `uint8_t x; x << 24` promotes `x` to `int`, and if bit 7 is set, the shift lands in
  the sign bit: UB. Cast to `uint32_t` (or `unsigned`) first.
- `~` on a `uint8_t` or `uint16_t` yields a negative `int`. `if (~mask & flag)` and
  `x = ~y` on narrow types rarely mean what they say. Compare `(uint8_t)~mask`.
- `-1 < sizeof(x)` is **false**: `-1` converts to `size_t`. Any comparison between a
  signed error-returning value (`ssize_t`, `int`) and a `size_t` is suspect. Look for
  `if (ret < len)` where `ret` is `ssize_t` from `read` and `len` is `size_t`.
- `int` compared against `unsigned`: `for (int i = 0; i < vec.len; i++)` where `len`
  is `size_t` is fine, but `if (i - 1 < vec.len)` is not when `i == 0`.
- Narrowing stores: `uint16_t len = some_size_t` silently truncates. If the source can
  exceed the target, that is a bounds check that passes and a copy that overflows.
  Especially: `int` lengths from `snprintf`, `strlen` results stored in `int`, 64-bit
  offsets stored in `off_t` on 32-bit builds, `u64` kernel values into `unsigned long`.
- `char` signedness is implementation-defined. `char c = buf[i]; if (c > 127)` is
  always false on x86 (signed char) and always possible on arm64 (unsigned char); this
  project ships on both. Using a `char` as an array index (`table[c]`) is negative for
  bytes over 127. Use `unsigned char` for byte data.
- `(uint64_t)a * b` vs `(uint64_t)(a * b)`: the cast must be applied before the
  multiplication, or the overflow has already happened in 32 bits.
- Function-like macros with narrow arguments: `MIN(u8, int)` compares after promotion.
- Enum values and bitfields: enum underlying type is implementation-defined; a bitfield
  of `int` type with width 1 holds `-1` and `0`, not `1` and `0`.
- `errno`-style negative returns through unsigned types: `size_t n = read(...)` turns
  `-1` into `SIZE_MAX` and the subsequent loop runs until it faults.
- Format specifiers vs promoted types: `%hhu` for `uint8_t` is fine because the
  value promoted to `int` and the specifier narrows it back, but `%u` for an `int` that
  can be negative prints garbage, and `%d` for `uint32_t` over `INT_MAX` prints negative.
  Use `PRIu64` and friends for fixed-width types.

Ask of every arithmetic expression on something narrower than `int`, or mixing
signedness: what is the type after promotion, and does the result get compared,
stored, or shifted in a way where that matters?

## 4. Smaller things that still bite

- `sizeof(ptr)` where `sizeof(*ptr)` or `sizeof(array)` was meant. `sizeof` on a
  function parameter declared as an array gives pointer size.
- `strncpy` does not NUL-terminate when the source fills the buffer; `strlcpy` and
  `snprintf` do, but `snprintf` returns the length it *would* have written, so
  `len += snprintf(buf + len, sizeof(buf) - len, ...)` goes negative on truncation.
- `memset(s, 0, sizeof(s))` on a struct does not reset heap-owned members, and
  `memcmp` on structs compares padding.
- Checking `errno` after a call that did not fail, or after a call that may have
  clobbered it (anything that calls `printf`).
- Return value of `close` ignored on a file opened for writing (data may not be
  flushed). Return value of `fclose` similarly.
- `switch` fallthrough without a comment; missing `default` where the enum may grow.
- Static buffers returned from functions (not reentrant, not thread-safe).
- `assert` with side effects: compiled out under `NDEBUG`.
- Macros that evaluate arguments more than once, or are not wrapped in `do { } while (0)`
  so an `if` without braces breaks them.

## 5. What the toolchain already catches

You cannot build or run anything, so know what CI does and does not cover, and spend
your attention on the gap:

- The build uses `-Wall -Wextra -Werror` plus `-Wshadow -Wsign-compare
  -Wformat-security -Wimplicit-fallthrough -Wmissing-prototypes -Wstrict-prototypes
  -Wpointer-arith -Wchar-subscripts` (see `CDIAGFLAGS` in the `Makefile`). A PR that
  merged green cannot contain an unannotated fallthrough, a signed/unsigned
  comparison, or a shadowed variable, so do not report those. It does not use
  `-Wconversion`, so narrowing stores and promotion traps in section 3 are entirely
  on you.
- CI runs the test suite under valgrind (`make test-valgrind`) but not under ASan or
  UBSan. Valgrind sees heap misuse and definite leaks on the paths the tests exercise;
  it does not see signed overflow, bad shifts, misaligned access, or anything on an
  error path the tests never take. Error paths are where to look.
- `-fno-strict-aliasing` is set, so pointer punning is tolerated by this build, as
  noted in section 1.
