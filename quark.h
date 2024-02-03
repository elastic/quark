#ifndef _QUARK_H_
#define _QUARK_H_

/* Linux specific */
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

/* Sys */
#include <sys/param.h>		/* MAXPATHLEN */

/* Compat, tree.h, queue.h, BSD string and more */
#include "compat.h"

/*
 * Perf related declarations
 */
struct perf_sample_id {
	__u32 pid;
	__u32 tid;
	__u64 time;	/* see raw_event_tree_insert_nocol() */
	__u64 stream_id;
	__u32 cpu;
	__u32 cpu_unused;
};

struct perf_record_fork {
	struct perf_event_header	header;
	__u32				pid;
	__u32				ppid;
	__u32				tid;
	__u32				ptid;
	__u64				time;
	struct perf_sample_id		sample_id;
};

struct perf_record_exit {
	struct perf_event_header	header;
	__u32				pid;
	__u32				ppid;
	__u32				tid;
	__u32				ptid;
	__u64				time;
	struct perf_sample_id		sample_id;
};

struct perf_data_loc {
	__u16	offset;
	__u16	size;
};

struct perf_record_sample {
	struct perf_event_header	header;
	struct perf_sample_id		sample_id;
	__u32				size;
	char				data[];
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
	size_t				 data_mask;
	uint8_t				*data_start;
	__u64				 data_tmp_tail;
	__u8				 wrapped_event_buf[4096] __aligned(8);
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
	/* XXX what type are we going to use to store pids?
	   The kernel seems sloppy. */
	pid_t			child_pid;
};

struct raw_event {
	RB_ENTRY(raw_event)	entry_by_time;
	RB_ENTRY(raw_event)	entry_by_pidtime;
	struct perf_sample_id	sample_id;
	int			type;
	union {
		struct raw_exec exec;
		struct raw_fork fork;
	};
};

#endif /* _QUARK_H_ */
