#ifndef _QUARK_H_
#define _QUARK_H_

/* Misc types */
#include <stdio.h>

/* Compat, tree.h, queue.h */
#include "compat.h"

/* Misc */
#ifndef ALIGN_UP
#define ALIGN_UP(_p, _b) (((u64)(_p) + ((_b) - 1)) & ~((_b) - 1))
#endif

/* Temporary until we have proper env debugging */
extern int	quark_verbose;

/* quark.c */
struct raw_event;
struct quark_event;
struct quark_queue;
struct quark_queue_attr;
struct quark_queue_stats;
struct raw_event *raw_event_alloc(int);
void	raw_event_free(struct raw_event *);
void	raw_event_insert(struct quark_queue *, struct raw_event *);
void	quark_queue_default_attr(struct quark_queue_attr *);
int	quark_queue_open(struct quark_queue *, struct quark_queue_attr *);
void	quark_queue_close(struct quark_queue *);
int	quark_queue_populate(struct quark_queue *);
int	quark_queue_block(struct quark_queue *);
int	quark_queue_get_events(struct quark_queue *, struct quark_event *, int);
int	quark_queue_get_epollfd(struct quark_queue *);
void	quark_queue_get_stats(struct quark_queue *, struct quark_queue_stats *);
int	quark_dump_graphviz(struct quark_queue *, FILE *, FILE *);
int	quark_event_lookup(struct quark_queue *, struct quark_event *, int);
int	quark_event_dump(struct quark_event *, FILE *);

/* btf.c */
struct quark_btf_target {
	const char	*dotname;
	ssize_t		 offset; /* in bytes, not bits */
};

struct quark_btf {
	char			*kname;
	struct quark_btf_target	 targets[];
};
struct quark_btf	*quark_btf_open(const char *, const char *);
void			 quark_btf_close(struct quark_btf *);
ssize_t			 quark_btf_offset(struct quark_btf *, const char *);

/* bpf_queue.c */
int	bpf_queue_open(struct quark_queue *);

/* kprobe_queue.c */
int	kprobe_queue_open(struct quark_queue *);

/* XXX terrible name XXX */
struct args {
	char		*buf;
	size_t		 buf_len;
	int		 argc;
	const char	*argv[];
};

/* qutil.c */
struct qstr {
	char	*p;
	char	 small[64];
};

ssize_t	 qread(int, void *, size_t);
int	 qwrite(int, const void *, size_t);
ssize_t	 qreadlinkat(int, const char *, char *, size_t);
void	 qstr_init(struct qstr *);
int	 qstr_ensure(struct qstr *, size_t);
int	 qstr_memcpy(struct qstr *, const void *, size_t);
int	 qstr_strcpy(struct qstr *, const char *);
void	 qstr_free(struct qstr *);
int	 isnumber(const char *);
ssize_t	 readlineat(int, const char *, char *, size_t);
int	 strtou64(u64 *, const char *, int);
char 	*find_line(FILE *, const char *);
char	*find_line_p(const char *, const char *);
char	*load_file_nostat(int, size_t *);
struct args *args_make(struct quark_event *);
void	 args_free(struct args *);

/*
 * Time helpers
 */
#ifndef NS_PER_S
#define NS_PER_S	1000000000ULL
#endif /* NS_PER_S */

#ifndef NS_PER_MS
#define NS_PER_MS	1000000ULL
#endif /* NS_PER_MS */

#ifndef MS_TO_NS
#define MS_TO_NS(_x)	((u64)(_x) * NS_PER_MS)
#endif /* MS_TO_NS */

/*
 * Raw events
 */
enum {
	RAW_INVALID,
	RAW_EXEC,
	RAW_WAKE_UP_NEW_TASK,
	RAW_EXIT_THREAD,
	RAW_COMM,
	RAW_EXEC_CONNECTOR,
	RAW_NUM_TYPES		/* must be last */
};

struct raw_comm {
	char			comm[16];
};

struct raw_task {
	u64		cap_inheritable;
	u64		cap_permitted;
	u64		cap_effective;
	u64		cap_bset;
	u64		cap_ambient;
	u64		start_boottime;
	u32		uid;
	u32		gid;
	u32		suid;
	u32		sgid;
	u32		euid;
	u32		egid;
	u32		pgid;
	u32		sid;
	u32		ppid;			/* Unavailable at exit */
	s32		exit_code;		/* Unavailable at fork */
	u64		exit_time_event;	/* Unavailable at fork */
	u32		tty_major;
	u32		tty_minor;
	struct qstr	cwd;
	char		comm[16];
};

struct raw_exec {
#define RAW_EXEC_F_EXT	(1 << 0)
	int		flags;
	struct qstr	filename;

	/* available if RAW_EXEC_F_EXT */
	struct {
		struct raw_task task;
		struct qstr	args;
		size_t		args_len;
		char		comm[16]; /* XXX move me inside task */
	} ext;
};

struct raw_exec_connector {
	struct qstr	args;
	size_t		args_len;
	u64		cap_inheritable;
	u64		cap_permitted;
	u64		cap_effective;
	u64		cap_bset;
	u64		cap_ambient;
	u64		start_boottime;
	/* XXX missing ppid see how raw_task derives it */
	u32		uid;
	u32		gid;
	u32		suid;
	u32		sgid;
	u32		euid;
	u32		egid;
	u32		pgid;
	u32		sid;
	u32		tty_major;
	u32		tty_minor;
	char		comm[16];
};

struct raw_event {
	RB_ENTRY(raw_event)			entry_by_time;
	RB_ENTRY(raw_event)			entry_by_pidtime;
	TAILQ_HEAD(agg_queue, raw_event)	agg_queue;
	TAILQ_ENTRY(raw_event)			agg_entry;
	u32					opid;
	u32					pid;
	u32					tid;
	u32					cpu;
	u64					time;
	int					type;
	union {
		struct raw_exec			exec;
		struct raw_comm			comm;
		struct raw_task			task;
		struct raw_exec_connector	exec_connector;
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
 * Event cache, used to enrich single events
 */
RB_HEAD(event_by_pid, quark_event);

/*
 * Event cache gc list, after they are marked for deletion, they still get a
 * grace time of qq->cache_grace_time before removal, this is to allow lookups
 * from users on processes that just vanished.
 */
TAILQ_HEAD(quark_event_list, quark_event);

/*
 * Main external working set, user passes this back and forth, members only have
 * a meaning if its respective flag is set, say proc_cap_inheritable should only
 * be meaningful if flags & QUARK_F_PROC.
 */

struct quark_event {
#define quark_event_zero_start	 entry_by_pid
	RB_ENTRY(quark_event)	 entry_by_pid;
	TAILQ_ENTRY(quark_event) entry_gc;
	u64			 gc_time;
#define QUARK_EV_FORK		(1 << 0)
#define QUARK_EV_EXEC		(1 << 1)
#define QUARK_EV_EXIT		(1 << 2)
#define QUARK_EV_SETPROCTITLE	(1 << 3)
#define QUARK_EV_SNAPSHOT	(1 << 4)
	u64	events;
#define quark_event_zero_end	 pid

	/* Always present */
	u32	pid;

#define QUARK_F_PROC		(1 << 0)
#define QUARK_F_EXIT		(1 << 1)
#define QUARK_F_COMM		(1 << 2)
#define QUARK_F_FILENAME	(1 << 3)
#define QUARK_F_CMDLINE		(1 << 4)
#define QUARK_F_CWD		(1 << 5)
	u64	flags;

	/* QUARK_F_PROC */
	u64	proc_cap_inheritable;
	u64	proc_cap_permitted;
	u64	proc_cap_effective;
	u64	proc_cap_bset;
	u64	proc_cap_ambient;
	u64	proc_time_boot;
	u32	proc_ppid;
	u32	proc_uid;
	u32	proc_gid;
	u32	proc_suid;
	u32	proc_sgid;
	u32	proc_euid;
	u32	proc_egid;
	u32	proc_pgid;
	u32	proc_sid;
	u32	proc_tty_major;
	u32	proc_tty_minor;
	/* QUARK_F_EXIT */
	s32	exit_code;
	u64	exit_time_event;
	/* QUARK_F_COMM */
	char	comm[16];
	/* QUARK_F_FILENAME */
	char	filename[1024];
	/* QUARK_F_CMDLINE */
	size_t	cmdline_len;
	char	cmdline[1024];
	/* QUARK_F_CWD */
	char	cwd[1024];
};

struct quark_queue_stats {
	u64	insertions;
	u64	removals;
	u64	aggregations;
	u64	non_aggregations;
	u64	lost;
	/* TODO u64	peak_nodes; */
};

struct quark_queue_ops {
	int	(*open)(struct quark_queue *);
	int	(*populate)(struct quark_queue *);
	void	(*close)(struct quark_queue *);
};

struct quark_queue_attr {
#define QQ_THREAD_EVENTS	(1 << 0)
#define QQ_NO_CACHE		(1 << 1)
#define QQ_KPROBE		(1 << 2)
#define QQ_EBPF			(1 << 3)
#define QQ_NO_SNAPSHOT		(1 << 4)
#define QQ_MIN_AGG		(1 << 5)
#define QQ_ALL_BACKENDS		(QQ_KPROBE | QQ_EBPF)
	int	flags;
	int	max_length;
	int	cache_grace_time;	/* in ms */
	int	hold_time;		/* in ms */
};

/*
 * Quark Queue (qq) is the main structure the user interacts with, it acts as
 * our main storage datastructure.
 */
struct quark_queue {
	struct raw_event_by_time	 raw_event_by_time;
	struct raw_event_by_pidtime	 raw_event_by_pidtime;
	struct event_by_pid		 event_by_pid;
	struct quark_event_list		 event_gc;
	struct quark_queue_stats	 stats;
	const u8			(*agg_matrix)[RAW_NUM_TYPES];
	int				 flags;
	int				 length;
	int				 max_length;
	u64				 cache_grace_time;	/* in ns */
	int				 hold_time;		/* in ms */
	/* Next pid to be sent out of a snapshot */
	int				 snap_pid;
	int				 epollfd;
	/* Backend related state */
	struct quark_queue_ops		*queue_ops;
	void				*queue_be;
};

#endif /* _QUARK_H_ */
