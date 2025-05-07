# quark — unified system process telemetry library

- [DESCRIPTION](#DESCRIPTION)
- [QUICKSTART](#QUICKSTART)
- [FEATURES](#FEATURES)
- [BUILDING](#BUILDING)
- [LINKING](#LINKING)
- [TESTING](#TESTING)
- [INCLUDED BINARIES](#INCLUDED_BINARIES)
- [CONVENTIONS](#CONVENTIONS)
- [BASIC USAGE](#BASIC_USAGE)
- [EXAMPLES](#EXAMPLES)
- [API](#API)
- [FURTHER READING](#FURTHER_READING)
- [SEE ALSO](#SEE_ALSO)
- [LICENSE](#LICENSE)
- [HISTORY](#HISTORY)

# [DESCRIPTION](#DESCRIPTION)

quark is a library that provides a way to retrieve and listen to process events in linux systems. Its main purpose is to abstract different backends and to provide a common API for listening to system-wide events like [fork(2)](https://linux.die.net/man/2/fork), [exec(3)](https://linux.die.net/man/3/exec), [exit(3)](https://linux.die.net/man/3/exit) and others.

quark not only provides an API for listening to events, but also handles ordering, buffering and aggregation of said events. In its most basic form, a short lived process consisting of [fork(2)](https://linux.die.net/man/2/fork) + [exec(3)](https://linux.die.net/man/3/exec) + [exit(3)](https://linux.die.net/man/3/exit) will be aggregated into one `quark_event`. An internal process cache is also kept that can be looked up via [quark\_process\_lookup(3)](https://elastic.github.io/quark/quark_process_lookup.3.html).

# [QUICKSTART](#QUICKSTART)

Clone the repository, compile and run quark's test utility [quark-mon(8)](https://elastic.github.io/quark/quark-mon.8.html):

```
$ git clone --recursive https://github.com/elastic/quark
$ cd quark
$ make
$ sudo ./quark-mon

On another shell, create any process like:
$ ls -1 /tmp | wc -l
```

See [BUILDING](#BUILDING) for a list of dependencies if you're having trouble building. Also see [INCLUDED BINARIES](#INCLUDED_BINARIES) and [quark-mon(8)](https://elastic.github.io/quark/quark-mon.8.html).

# [FEATURES](#FEATURES)

[*ORDERING*](#ORDERING)

quark tries to guarantee event ordering as much as possible. Ordering must be done in userland for some backends, notably anything that uses perf-rings. quark uses two [*Rank Balanced Trees*](#Rank) for ordering and aggregation.

The first tree is basically a priority queue, ordered by the time of the event. The second tree is ordered by time of the event + pid and it's used for event aggregation.

[*AGGREGATION*](#AGGREGATION)

quark buffers and aggregates related events that happened close enough. The common case is generating a single event for the triple: [fork(2)](https://linux.die.net/man/2/fork), [exec(3)](https://linux.die.net/man/3/exec), [exit(3)](https://linux.die.net/man/3/exit). There are rules on what can be aggregated, and only events of the same pid are aggregated. For example: quark won't aggregate two [exec(3)](https://linux.die.net/man/3/exec) events, otherwise we would lose the effects of the first one. These rules will be exposed and configurable in the future.

[*BUFFERING*](#BUFFERING)

For aggregation and ordering to work, quark needs to be able to buffer events, this means holding them before presenting them to the user. quark employs an ageing timeout that is a stepped function of the number of currently buffered events, the more events you have, the shorter the timeout will be, so memory can be bound. A `quark_event` is only given to the user when it has a certain age. From quark.c:

```
/*
 * Target age is the duration in ns of how long should we hold the event in the
 * tree before processing it. It's a function of the number of items in the tree
 * and its maximum capacity:
 * from [0; 10%]    -> 1000ms
 * from [90%; 100%] -> 0ms
 * from (10%; 90%)  -> linear from 1000ms -> 100ms
 */
```

[*ENRICHMENT*](#ENRICHMENT)

The library tries to give as much context for an event as possible. Depending on the backend, the events we read from the kernel can be limited in context. quark maintains an internal process table with what has been learned about the process so far, this context is then included in each event given to the user. The process table can also be queried, see below.

[*PROCESS CACHE*](#PROCESS)

An internal cache of processes is kept that can be looked up via [quark\_process\_lookup(3)](https://elastic.github.io/quark/quark_process_lookup.3.html). This cache keeps soon-to-be-purged elements for a little while so that you can still lookup a process that just exited. The table is initialized by scraping /proc.

[*TRANSPARENCY*](#TRANSPARENCY)

quark tries to be as transparent as possible about what it knows, there are counters for lost events, and each piece of information of a `quark_event` is guarded by a flag, meaning the user might get incomplete events in the case of lost events, it's the user responsability to decide what to do with it.

Depending on load, the user might see an event as the aggregation of multiple events, or as independent events. The content remains the same.

[*LANGUAGE BINDINGS*](#LANGUAGE)

quark is written in C, but Go bindings are also provided. Ideally we will be able to provide bindings for other languages in the future.

[*MULTIPLE BACKENDS*](#MULTIPLE)

Currently, EBPF and a kprobe-based backend are provided, but we would like to add AUDIT support as well. The backend in use is transparent to the user and unless specified, quark will try to use the EBPF, falling back to KPROBE if it failed.

# [BUILDING](#BUILDING)

quark can be built natively or via a container, native is preferred and depends on:

- bpftool
- clang
- gnumake
- gcc
- mandoc (for docs).
- m4

Make sure to clone the repository recursively: [*git clone --recursive*](#git).

*make* builds the repository, including quark-mon, libquark\_big.a and a libquark.a.

libquark\_big.a includes all needed dependencies in one big archive. This includes a libbpf.a, libelf\_pic.a (from the elftoolchain project, BSD license), and a libz.a (see zlib/LICENSE). See [LINKING](#LINKING) to learn how to link either.

While quark doesn't build *elastic/ebpf*, it does use the EBPF programs from that repository, only the files needed are included in quark, as *elastic/ebpf* is quite big.

Other useful build targets include:

[*clean*](#clean)

Clean object files from quark.

[*docker*](#docker)

Builds quark inside a docker container, so you don't have to worry about having build dependencies.

[*docker-cross-arm64*](#docker-cross-arm64)

Builds quark for arm64 inside a docker container.

[*centos7*](#centos7)

Builds quark inside a centos7 docker container, useful for linking against ancient glibc-2.17.

[*alpine*](#alpine)

Builds quark inside an alpine docker container, so we can track musl builds.

[*test*](#test)

Builds and runs [quark-test(8)](https://elastic.github.io/quark/quark-test.8.html).

[*test-kernel*](#test-kernel)

Runs [quark-test(8)](https://elastic.github.io/quark/quark-test.8.html) over all kernels in kernel\_images/.

[*test-all*](#test-all)

Shortcut for test + test-kernels.

[*btfhub*](#btfhub)

Regenerates btfhub.c. Usage:

```
$ make btfhub BTFHUB_ARCHIVE_PATH=/my/path/to/btfhub-archive
```

[*clean-all*](#clean-all)

Clean all object files, including the ones from [*libbpf*](#libbpf), [*libz*](#libz) and [*libelf*](#libelf).

[*docs*](#docs)

Lints and generates all the documentation from manpages in docs/.

[*svg*](#svg)

Builds an SVG out of the DOT files produced by [quark-mon(8)](https://elastic.github.io/quark/quark-mon.8.html).

[*README.md*](#README.md)

Generates README.md out of quark.7.

[*eebpf-sync*](#eebpf-sync)

Copies the files from EEBPF\_PATH used by quark. Usage:

```
$ make eebpf-sync EEBPF_PATH=/my/path/to/elastic/ebpf
```

[*initramfs.gz*](#initramfs.gz)

Builds an initramfs file containing all quark binaries so that it can be run as the init process on boot, useful for testing any kernel under qemu. See [TESTING](#TESTING).

All the targets above can generate debug output by specifying [*V=1*](#V=1), as in:

```
$ make V=1
```

# [LINKING](#LINKING)

```
$ cc -o myprogram myprogram.c libquark_big.a
OR
$ cc -o myprogram myprogram.c libquark.a libbpf/src/libbpf.a elftoolchain/libelf/libelf_pic.a zlib/libz.a
```

# [TESTING](#TESTING)

[quark-test(8)](https://elastic.github.io/quark/quark-test.8.html) is the main test utility ran by the CI, can be invoked via *make test*. All tests are self-contained in this binary.

Some included kernels can be tested in qemu via *make test-kernel*. Any quark utility can be run on a custom kernel via the krun.sh script, as in:

```
$ make initramfs.gz
$ ./krun.sh initramfs.gz kernel-images/amd64/linux-4.18.0-553.el8_10.x86_64 quark-test -vvv
```

Note that you can pass arguments to the utility and you have to make initramfs.gz first.

# [INCLUDED BINARIES](#INCLUDED_BINARIES)

[quark-mon(8)](https://elastic.github.io/quark/quark-mon.8.html) is a program that dumps `quark_events` to stdout and can be used for demo and debugging. It has a neat feature: can be run without priviledges, while useless in this small program, it aims to demonstrate how a user could implement the same.

[quark-btf(8)](https://elastic.github.io/quark/quark-btf.8.html) is a program for dumping BTF information used by quark.

[quark-test(8)](https://elastic.github.io/quark/quark-test.8.html) is a program for running tests during development.

# [CONVENTIONS](#CONVENTIONS)

- Library calls fail with -1 unless otherwise stated, and `errno` is set.
- Quark returns pointers to internal state, which must not be modified and/or stored. In the case of multithreading, these pointers should not be accessed if another thread is driving quark through [quark\_queue\_get\_event(3)](https://elastic.github.io/quark/quark_queue_get_event.3.html).
- No threads are created, the library is driven solely through [quark\_queue\_get\_event(3)](https://elastic.github.io/quark/quark_queue_get_event.3.html).
- Access to a `quark_queue` must be synchronized by the user in the case of multithreading.

# [BASIC USAGE](#BASIC_USAGE)

The ball starts with [quark\_queue\_open(3)](https://elastic.github.io/quark/quark_queue_open.3.html).

[quark\_queue\_open(3)](https://elastic.github.io/quark/quark_queue_open.3.html) initializes a `quark_queue` which holds the majority of runtime state used by library, this includes perf-rings, file descriptors, EBPF programs buffering data-structures and the like. It must be paired with a [quark\_queue\_close(3)](https://elastic.github.io/quark/quark_queue_close.3.html) on exit.

[quark\_queue\_get\_event(3)](https://elastic.github.io/quark/quark_queue_get_event.3.html) is the main driver of the library, it does the buffering, per-ring scanning, aggregation and event cache garbage collection. In case there are no events it returns NULL and the user is expected to call [quark\_queue\_block(3)](https://elastic.github.io/quark/quark_queue_block.3.html) or equivalent.

# [EXAMPLES](#EXAMPLES)

```
#include <err.h>
#include <quark.h>
#include <stdio.h>

int
main(void)
{
	struct quark_queue	 	 qq;
	const struct quark_event	*qev;

	if (quark_queue_open(&qq, NULL) == -1)
		err(1, "quark_queue_open");

	for (; ;) {
		qev = quark_queue_get_event(&qq);

		/* No events, just block */
		if (qev == NULL) {
			quark_queue_block(qq);
			continue;
		}

		quark_event_dump(qev, stdout);
	}

	quark_queue_close(&qq);

	return (1);
}
```

# [API](#API)

[quark\_queue\_open(3)](https://elastic.github.io/quark/quark_queue_open.3.html)

open a queue to receive events, initial library call.

[quark\_queue\_default\_attr(3)](https://elastic.github.io/quark/quark_queue_default_attr.3.html)

get default attributes of [quark\_queue\_open(3)](https://elastic.github.io/quark/quark_queue_open.3.html).

[quark\_queue\_get\_event(3)](https://elastic.github.io/quark/quark_queue_get_event.3.html)

get event, main library call.

[quark\_process\_lookup(3)](https://elastic.github.io/quark/quark_process_lookup.3.html)

lookup a process in quark's internal cache

[quark\_event\_dump(3)](https://elastic.github.io/quark/quark_event_dump.3.html)

dump event, mainly a debugging utility.

[quark\_process\_iter(3)](https://elastic.github.io/quark/quark_process_iter.3.html)

iterate over existing processes.

[quark\_queue\_get\_epollfd(3)](https://elastic.github.io/quark/quark_queue_get_epollfd.3.html)

get a descriptor suitable for blocking.

[quark\_queue\_block(3)](https://elastic.github.io/quark/quark_queue_block.3.html)

block for an unspecified amount of time.

[quark\_queue\_get\_stats(3)](https://elastic.github.io/quark/quark_queue_get_stats.3.html)

basic queue statistics.

[quark\_queue\_close(3)](https://elastic.github.io/quark/quark_queue_close.3.html)

close a queue.

# [FURTHER READING](#FURTHER_READING)

[quark\_queue\_get\_event(3)](https://elastic.github.io/quark/quark_queue_get_event.3.html) is the meat of the library and contains further useful documentation.

[quark-mon(8)](https://elastic.github.io/quark/quark-mon.8.html) is the easiest way to get started with quark.

[quark\_queue\_open(3)](https://elastic.github.io/quark/quark_queue_open.3.html) describes initialization options that can be useful.

# [SEE ALSO](#SEE_ALSO)

[quark\_event\_dump(3)](https://elastic.github.io/quark/quark_event_dump.3.html), [quark\_process\_iter(3)](https://elastic.github.io/quark/quark_process_iter.3.html), [quark\_process\_lookup(3)](https://elastic.github.io/quark/quark_process_lookup.3.html), [quark\_queue\_block(3)](https://elastic.github.io/quark/quark_queue_block.3.html), [quark\_queue\_close(3)](https://elastic.github.io/quark/quark_queue_close.3.html), [quark\_queue\_get\_epollfd(3)](https://elastic.github.io/quark/quark_queue_get_epollfd.3.html), [quark\_queue\_get\_event(3)](https://elastic.github.io/quark/quark_queue_get_event.3.html), [quark\_queue\_get\_stats(3)](https://elastic.github.io/quark/quark_queue_get_stats.3.html), [quark\_queue\_open(3)](https://elastic.github.io/quark/quark_queue_open.3.html), [quark-btf(8)](https://elastic.github.io/quark/quark-btf.8.html), [quark-mon(8)](https://elastic.github.io/quark/quark-mon.8.html), [quark-test(8)](https://elastic.github.io/quark/quark-test.8.html)

# [LICENSE](#LICENSE)

quark is released under the Apache-2.0 license and contains code under BSD-2, BSD-3, ISC, and zlib Licenses.

# [HISTORY](#HISTORY)

quark started in April 2024.
