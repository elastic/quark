QUARK(7) - Miscellaneous Information Manual

# NAME

**quark** - unified system process telemetry library

# DESCRIPTION

The
**quark**
library provides a way to retrieve and listen to process events in linux
systems.
Its main purpose is to abstract different backends and providing common
API for listening to system-wide events like
**fork**(*2*),
**exec**(*3*),
**exit**(*2*)
and others.

**quark**
not only provides an API for listening to events, but also handles ordering,
buffering and aggregation of said events.
In its most basic form, a short lived process consisting of
**fork**()
\+
**exec**()
\+
**exit**()
will be aggregated into one
*quark\_event*.
An internal event cache is also kept that can be looked up via
**quark\_event\_lookup**(*3*).
This cache keeps soon-to-be-purged elements for a little while so that you can
still lookup a process that just exited.

# CONVENTIONS

**quark**
library calls all fail with -1 unless otherwise stated, and
*errno*
is set.

**quark**
does not create any threads and does not return pointers to internal state
during runtime, the data is allocated by the caller and the library copies the
data out.
Access to a
*quark\_queue*
must be synchronized by the caller in the case of multithreading.

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
which holds majority of runtime state used by library, this includes creating
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

# EXAMPLE

	struct quark_queue qq;
	struct quark_event qevs[32], *qev;
	int n, i;
	
	if (quark_init() == -1)
		err(1, "quark_init");
	if (quark_queue_open(qq, 0) == -1)
		err(1, "quark_queue_open");
	
	for (; ;) {
		n = quark_queue_get_events(&qq, qevs, 32);
		if (n == -1)
			err(1, "quark_queue_get_events");
		/* Scan each event */
		for (i = 0, qev = qevs; i < n; i++, qev++)
			quark_event_dump(qev);
		if (n == 0)
			quark_queue_block(&qq);
	}
	
	quark_queue_close(&qq);
	quark_close();

# SEE ALSO

quark\_close(3),
quark\_event\_dump(3),
quark\_event\_lookup(3),
quark\_init(3),
quark\_queue\_close(3),
quark\_queue\_get\_fds(3),
quark\_queue\_get\_events(3),
quark\_queue\_open(3),
quark-btf(8),
quark-mon(8)

# HISTORY

**quark**
started in April 2024.

Linux 6.7.11-100.fc38.x86\_64 - April 3, 2024
