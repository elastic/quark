#ifndef _QUARK_H_
#define _QUARK_H_

/* Linux specific */
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

/* Sys */
#include <sys/param.h>		/* MAXPATHLEN */

/* Compat, tree.h, queue.h */
#include "compat.h"

/* quark_btf.c */
int	quark_btf_init(void);
ssize_t	quark_btf_offset(const char *);

/*
 * Time helpers
 */
#ifndef NS_PER_S
#define NS_PER_S	1000000000L
#endif /* NS_PER_S */

#ifndef NS_PER_MS
#define NS_PER_MS	1000000L
#endif /* NS_PER_MS */

#ifndef MS_TO_NS
#define MS_TO_NS(_x)	((_x) * NS_PER_MS)
#endif /* MS_TO_NS */

/*
 * Perf related declarations
 */
struct perf_sample_id {
	u32	pid;
	u32	tid;
	u64	time;		/* See raw_evenr_insert() */
	u64	stream_id;	/* We can likely get rid of this */
	u32	cpu;
	u32	cpu_unused;
};

struct perf_record_fork {
	struct perf_event_header	header;
	u32				pid;
	u32				ppid;
	u32				tid;
	u32				ptid;
	u64				time;
	struct perf_sample_id		sample_id;
};

struct perf_record_exit {
	struct perf_event_header	header;
	u32				pid;
	u32				ppid;
	u32				tid;
	u32				ptid;
	u64				time;
	struct perf_sample_id		sample_id;
};

enum sample_kinds {
	SAMPLE_EXEC = 1
};

/*
 * Kprobe relate declarations
 */
struct kprobe_arg {
	const char	*name;
	const char	*reg;
	const char	*typ;
	const char	*v[4];	/* maximum is 3, last is sentinel */
};

struct kprobe {
	const char		*name;
	const char		*target;
	int		 	 is_kret;
	struct kprobe_arg	 args[];
};

/*
 * Kernels might actually have a different common area, so far we only
 * need common_type, so hold onto that
 */
struct perf_sample_data {
	/* this is the actual id from tracefs eg: sched_process_exec/id */
	u16	 common_type;
	/* ... */
};

struct perf_sample_data_loc {
	u16	offset;
	u16	size;
};

struct perf_record_sample {
	struct perf_event_header	header;
	struct perf_sample_id		sample_id;
	u32				size;
	struct perf_sample_data		data;
};

struct perf_event {
	union {
		struct perf_event_header	header;
		struct perf_record_fork		fork;
		struct perf_record_exit		exit;
		struct perf_record_sample	sample;
	};
};

struct perf_mmap {
	struct perf_event_mmap_page	*metadata;
	size_t				 mapped_size;
	size_t				 data_size;
	size_t				 data_mask;
	u8				*data_start;
	u64				 data_tmp_tail;
	u8				 wrapped_event_buf[4096] __aligned(8);
};

/* More local perf related declarations */

struct perf_group_leader {
	TAILQ_ENTRY(perf_group_leader)	 entry;
	int				 fd;
	int				 cpu;
	struct perf_event_attr		 attr;
	struct perf_mmap		 mmap;
};

enum {
	RAW_FORK = 1,
	RAW_EXEC,
	RAW_EXIT
};

struct raw_exec {
	char			filename[MAXPATHLEN];
};

struct raw_fork {
	u32			parent_pid;
	u32			child_pid;
};

struct raw_event {
	RB_ENTRY(raw_event)	entry_by_time;
	RB_ENTRY(raw_event)	entry_by_pidtime;
	u32			opid;
	u32			pid;
	u32			tid;
	u32			cpu;
	u64			time;
	int			type;
	union {
		struct raw_exec exec;
		struct raw_fork fork;
	};
};

/*
 * Raw Event Tree by time, where RB_MIN() is the oldest element in the tree, no
 * clustering of pids so we can easily get the oldest event.
 */
RB_HEAD(raw_event_by_time, raw_event);

/*
 * Raw Event Tree by pid and time, this creates clusters of the same pid which
 * are then organized by time, this is used in assembly and aggregation, if we
 * used the 'by_time' tree, we would have to traverse the full tree in case of a
 * miss.
 */
/* XXX this should be by tid, but we're not there yet XXX */
RB_HEAD(raw_event_by_pidtime, raw_event);

/*
 * List of all ring buffer leaders, we have on per cpu.
 */
TAILQ_HEAD(perf_group_leaders, perf_group_leader);

/*
 * Quark Queue (qq) is the main structure the user interacts with, it acts as
 * our main storage datastructure.
 */
struct quark_queue {
	struct perf_group_leaders	perf_group_leaders;
	struct raw_event_by_time	raw_event_by_time;
	struct raw_event_by_pidtime	raw_event_by_pidtime;
};

#endif /* _QUARK_H_ */
