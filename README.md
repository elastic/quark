QUARK(7) - Miscellaneous Information Manual

# NAME

**quark** - unified system process telemetry library

# DESCRIPTION

**quark**
is a library that provides a way to retrieve and listen to process events in
linux systems.
Its main purpose is to abstract different backends and to provide a common
API for listening to system-wide events like
**fork**(*2*),
**exec**(*3*),
**exit**(*3*)
and others.

**quark**
not only provides an API for listening to events, but also handles ordering,
buffering and aggregation of said events.
In its most basic form, a short lived process consisting of
**fork**(*2*)
\+
**exec**(*3*)
\+
**exit**(*3*)
will be aggregated into one
*quark\_event*.
An internal event cache is also kept that can be looked up via
**quark\_event\_lookup**(*3*).

# FEATURES

*ORDERING*  
**quark**
tries to guarantee event ordering as much as possible.
Ordering must be done in userland for some backends, notably anything that
uses perf-rings.
**quark**
uses two
*Rank Balanced Trees*
for ordering and aggregation.

The first tree is basically a priority queue, ordered by the time of the
event.
The second tree is ordered by time of the event + pid and it's used for event
aggregation.

*AGGREGATION*  
**quark**
buffers and aggregates related events that happened close enough.
The common case is generating a single event for the triple:
**fork**(*2*),
**exec**(*3*),
**exit**(*3*).
There are rules on what can be aggregated, and only events of the same pid are
aggregated.
For example:
**quark**
won't aggregate two
**exec**(*3*)
events, otherwise we would lose the effects of the first one.
These rules will be exposed and configurable in the future.

*BUFFERING*  
For aggregation and ordering to work,
**quark**
needs to be able to buffer events, this means holding them before presenting
them to the user.
**quark**
employs an ageing timeout that is a stepped function of the number of currently
buffered events, the more events you have, the shorter the timeout will be, so
memory can be bound.
A
*quark\_event*
is only given to the user when it has a certain age.
From quark.c:

	/*
	 * Target age is the duration in ns of how long should we hold the event in the
	 * tree before processing it. It's a function of the number of items in the tree
	 * and its maximum capacity:
	 * from [0; 10%]    -> 1000ms
	 * from [90%; 100%] -> 0ms
	 * from (10%; 90%)  -> linear from 1000ms -> 100ms
	 */

*ENRICHMENT*  
The library tries to give as much context for an event as possible.
Depending on the backend, the events we read from the kernel can be limited in
context.
**quark**
maintains an internal process table with what has been learned about the process
so far, this context is then included in each event given to the user.
The process table can also be queried, see below.

*PROCESS TABLE*  
An internal cache of process events is kept that can be looked up via
**quark\_event\_lookup**(*3*).
This cache keeps soon-to-be-purged elements for a little while so that you can
still lookup a process that just exited.
The table is initialized by scraping
*/proc*.

*TRANSPARENCY*  
**quark**
tries to be as transparent as possible about what it knows, there are counters
for lost events, and each piece of information of a
*quark\_event*
is guarded by a flag, meaning the user might get incomplete events in the case
of lost events, it's the user responsability to decide what to do with it.

Depending on load, the user might see an event as the aggregation of multiple
events, or as independent events.
The content remains the same.

*LANGUAGE BINDINGS*  
**quark**
is written in C, but Go bindings are also provided.
Ideally we will be able to provide bindings for other languages in the future.

*MULTIPLE BACKENDS* (future)  
Currently only a kprobe-based backend is provided, but we would like to add
eBPF and AUDIT support as well.
The user API should remain the same, so if we do this right, the user shouldn't
even know which backend is being used.
Proper runtime discovery is needed to know what we can use.

# BUILDING

*make*
generates a
*libquark.a*
that can be linked with the user binary, be sure to clone the repository with
*git clone --recursive*.

**quark**
builds its own
*libbpf*
since it needs BTF support from it.
At the time of this writing,
*libquark.a*
also needs symbols from
*libz*
and
*libelf*.
An option will be given in the future to include both in the archive.

Other useful build targets include:

*manlint*

> Calls the linter for all manpages.

*svg*

> Builds an SVG out of the DOT files produced by
> quark-mon(8).

*README.md*

> Generate
> *README.md*
> out of
> *quark.7*.

# LINKING

	cc -o myprogram myprogram.c -lelf -lz libquark.a libbpf/src/libbpf.a

# INCLUDED BINARIES

quark-mon(8)
is a program that dumps
*quark\_events*
to stdout and can be used for demo and debugging.
It has a neat feature: can be run without priviledges, while useless in this
small program, it aims to demonstrate how a user could implement the same.

quark-btf(8)
is a program for dumping BTF information used by
**quark**.

# CONVENTIONS

*	Library calls fail with -1 unless otherwise stated, and
	*errno*
	is set.

*	No pointers to internal state are returned, data is allocated by the caller and
	the library copies out.

*	No threads are created, the library is driven solely through
	**quark\_queue\_get\_events**(*3*).

*	Access to a
	*quark\_queue*
	must be synchronized by the user in the case of multithreading.

# BASIC USAGE

The ball starts with
**quark\_init**(*3*)
followed by
**quark\_queue\_open**(*3*).

**quark\_init**(*3*)
initializes internal global state for the library that should be paired with
**quark\_close**(*3*)
on exit.
At the time of this writing, this is basically initializing some
per-host state, trying to read
*BTF*
from the host and initilizing kprobes .

**quark\_queue\_open**(*3*)
initializes a
*quark\_queue*
which holds the majority of runtime state used by library, this includes
perf-rings, file descriptors, buffering data-structures and the like.
It must be paired with a
**quark\_queue\_close**(*3*)
on exit.

**quark\_queue\_get\_events**(*3*)
Is the main driver of the library, it does the buffering, per-ring scanning,
aggregation and event cache garbage collecting.
In case there are no events it
returns zero and the user is expected to call
**quark\_queue\_block**(*3*)
or equivalent.

# EXAMPLES

	#include <err.h>
	#include <quark.h>
	#include <stdio.h>
	
	int
	main(void)
	{
		struct quark_queue	qq;
		struct quark_event	qevs[32], *qev;
		int			n, i;
	
		if (quark_init() == -1)
			err(1, "quark_init");
		if (quark_queue_open(&qq, 0) == -1)
			err(1, "quark_queue_open");
	
		for (; ;) {
			n = quark_queue_get_events(&qq, qevs, 32);
			if (n == -1) {
				warn("quark_queue_get_events");
				break;
			}
			/* Scan each event */
			for (i = 0, qev = qevs; i < n; i++, qev++)
				quark_event_dump(qev, stdout);
			if (n == 0)
				quark_queue_block(&qq);
		}
	
		quark_queue_close(&qq);
		quark_close();
	
		return (1);
	}

# FURTHER READING

quark\_queue\_get\_events(3)
is the meat of the library and contains further useful documentation.

quark-mon(8)
is the easiest way to get started with
**quark**.

# SEE ALSO

quark\_close(3),
quark\_event\_dump(3),
quark\_event\_lookup(3),
quark\_init(3),
quark\_queue\_block(3),
quark\_queue\_close(3),
quark\_queue\_get\_events(3),
quark\_queue\_get\_fds(3),
quark\_queue\_open(3),
quark-btf(8),
quark-mon(8)

# HISTORY

**quark**
started in April 2024.

Linux - April 8, 2024
