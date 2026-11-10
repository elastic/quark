/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2024-2026 Elastic NV */

#ifndef _KPROBE_DEFS_H
#define _KPROBE_DEFS_H

#define RPT0(_x)
#define RPT1(_x) _x
#define RPT2(_x) RPT1(_x) _x
#define RPT3(_x) RPT2(_x) _x
#define RPT4(_x) RPT3(_x) _x
#define RPT5(_x) RPT4(_x) _x
#define RPT6(_x) RPT5(_x) _x
#define RPT7(_x) RPT6(_x) _x
#define RPT8(_x) RPT7(_x) _x
#define RPT9(_x) RPT8(_x) _x
#define RPT10(_x) RPT9(_x) _x
#define RPT(TENS,ONES,X) RPT##TENS(RPT10(X)) RPT##ONES(X)

#if defined(__amd64__)
#define ARG_0	di
#elif defined(__aarch64__)
#define ARG_0	x0
#else
#error unknown architecture
#endif	/* ARG_* */

#define S(_a)		#_a
#define XS(_a)		S(_a)
#define PWD_K(_t, _o)	"task_struct.fs fs_struct.pwd.dentry " XS(RPT(_t, _o, dentry.d_parent))
#define PWD_S(_t, _o)	"task_struct.fs fs_struct.pwd.dentry " XS(RPT(_t, _o, dentry.d_parent)) " dentry.d_name.name +0"

/*
 * 16 is sizeof(struct hlist_node), which is in the beginning of struct
 * pid_link. sizeof(struct pid_link) is 24, 16 for hlist_node + pid pointer.
 * PIDTYPE_PGID is `1`, this puts us on 16 + (24 * 1) = 40 bytes.
 */
struct kprobe_arg ka_task_old_pgid = {
	"pgid", XS(ARG_0), "u32", "task_struct.group_leader ((task_struct.pids+16)+(24*pid_type.PIDTYPE_PGID)) (pid.numbers+0).upid.nr"
};

/* 16 + 2*24 = 64 */
struct kprobe_arg ka_task_old_sid = {
	"sid", XS(ARG_0), "u32", "task_struct.group_leader ((task_struct.pids+16)+(24*pid_type.PIDTYPE_SID)) (pid.numbers+0).upid.nr"
};

/*
 * New structure is just an array of pointers, not a pid_link array like above.
 * RHEL8 uses the new scheme in task_struct.signal, but has the old value for
 * PIDTYPE_PGID=1, newer kernels have a PIDTYPE_TGID=1 and PIDTYPE_PGID=2.
 */
struct kprobe_arg ka_task_new_pgid = {
	"pgid", XS(ARG_0), "u32", "task_struct.group_leader task_struct.signal (signal_struct.pids+(8*pid_type.PIDTYPE_PGID)) (pid.numbers+0).upid.nr"
};

struct kprobe_arg ka_task_new_sid = {
	"sid", XS(ARG_0), "u32", "task_struct.group_leader task_struct.signal (signal_struct.pids+(8*pid_type.PIDTYPE_SID)) (pid.numbers+0).upid.nr"
};

#define TASK_SAMPLE(_r)																	   \
	{ "cap_inheritable",	XS(_r), "u64",		"task_struct.cred cred.cap_inheritable"								}, \
	{ "cap_permitted",	XS(_r), "u64",		"task_struct.cred cred.cap_permitted",								}, \
	{ "cap_effective",	XS(_r), "u64",		"task_struct.cred cred.cap_effective"								}, \
	{ "cap_bset",		XS(_r), "u64",		"task_struct.cred cred.cap_bset"								}, \
	{ "cap_ambient",	XS(_r), "u64",		"task_struct.cred cred.cap_ambient"								}, \
	{ "start_boottime",	XS(_r), "u64",		"task_struct.start_boottime"									}, \
	{ "tty_addr",		XS(_r), "u64",		"task_struct.signal signal_struct.tty"								}, \
	{ "root_k",		XS(_r), "u64",		"task_struct.fs fs_struct.root.dentry"								}, \
	{ "mnt_root_k",		XS(_r), "u64",		"task_struct.fs fs_struct.pwd.mnt vfsmount.mnt_root"						}, \
	{ "mnt_mountpoint_k",	XS(_r), "u64",		"task_struct.fs fs_struct.pwd.mnt (mount.mnt_mountpoint-mount.mnt)"				}, \
	{ "pwd_k0",		XS(_r), "u64",		PWD_K(0, 0)											}, \
	{ "pwd_k1",		XS(_r), "u64",		PWD_K(0, 1)											}, \
	{ "pwd_k2",		XS(_r), "u64",		PWD_K(0, 2)											}, \
	{ "pwd_k3",		XS(_r), "u64",		PWD_K(0, 3)											}, \
	{ "pwd_k4",		XS(_r), "u64",		PWD_K(0, 4)											}, \
	{ "pwd_k5",		XS(_r), "u64",		PWD_K(0, 5)											}, \
	{ "pwd_k6",		XS(_r), "u64",		PWD_K(0, 6)											}, \
	{ "root_s",		XS(_r), "string",	"task_struct.fs fs_struct.root.dentry dentry.d_name.name +0"					}, \
	{ "mnt_root_s",		XS(_r), "string",	"task_struct.fs fs_struct.pwd.mnt vfsmount.mnt_root dentry.d_name.name +0"			}, \
	{ "mnt_mountpoint_s",	XS(_r), "string",	"task_struct.fs fs_struct.pwd.mnt (mount.mnt_mountpoint-mount.mnt) dentry.d_name.name +0"	}, \
	{ "pwd_s0",		XS(_r), "string",	PWD_S(0, 0)											}, \
	{ "pwd_s1",		XS(_r), "string",	PWD_S(0, 1)											}, \
	{ "pwd_s2",		XS(_r), "string",	PWD_S(0, 2)											}, \
	{ "pwd_s3",		XS(_r), "string",	PWD_S(0, 3)											}, \
	{ "pwd_s4",		XS(_r), "string",	PWD_S(0, 4)											}, \
	{ "pwd_s5",		XS(_r), "string",	PWD_S(0, 5)											}, \
	{ "pwd_s6",		XS(_r), "string",	PWD_S(0, 6)											}, \
	{ "comm",		XS(_r), "string",	"task_struct.comm"										}, \
	{ "uid",		XS(_r), "u32",		"task_struct.cred cred.uid"									}, \
	{ "gid",		XS(_r), "u32",		"task_struct.cred cred.gid"									}, \
	{ "suid",		XS(_r), "u32",		"task_struct.cred cred.suid"									}, \
	{ "sgid",		XS(_r), "u32",		"task_struct.cred cred.sgid"									}, \
	{ "euid",		XS(_r), "u32",		"task_struct.cred cred.euid"									}, \
	{ "egid",		XS(_r), "u32",		"task_struct.cred cred.egid"									}, \
	{ "pgid",		XS(_r), "u32",		"KLUDGE - see kprobe_kludge_arg()"								}, \
	{ "sid",		XS(_r), "u32",		"KLUDGE - see kprobe_kludge_arg()"								}, \
	{ "pid",		XS(_r), "u32",		"task_struct.tgid"										}, \
	{ "tid",		XS(_r), "u32",		"task_struct.pid"										}, \
	{ "ppid",		XS(_r), "u32",		"task_struct.group_leader task_struct.real_parent task_struct.tgid"				}, \
	{ "exit_code",		XS(_r), "s32",		"task_struct.exit_code"										}, \
	{ "tty_major",		XS(_r), "u32",		"task_struct.signal signal_struct.tty tty_struct.driver tty_driver.major"			}, \
	{ "tty_minor_start",	XS(_r), "u32",		"task_struct.signal signal_struct.tty tty_struct.driver tty_driver.minor_start"			}, \
	{ "tty_minor_index",	XS(_r), "u32",		"task_struct.signal signal_struct.tty tty_struct.index"						}, \
	{ "uts_inonum",		XS(_r), "u32",		"task_struct.nsproxy nsproxy.uts_ns uts_namespace.proc_inum"					}, \
	{ "ipc_inonum",		XS(_r), "u32",		"task_struct.nsproxy nsproxy.ipc_ns ipc_namespace.proc_inum"					}, \
	{ "mnt_inonum",		XS(_r), "u32",		"task_struct.nsproxy nsproxy.mnt_ns mnt_namespace.proc_inum"					}, \
	{ "net_inonum",		XS(_r), "u32",		"task_struct.nsproxy nsproxy.net_ns net_namespace.proc_inum"					}

struct kprobe kp_wake_up_new_task = {
	"wake_up_new_task",
	WAKE_UP_NEW_TASK_SAMPLE,
	0,
	{
		TASK_SAMPLE(ARG_0),
		{ NULL, NULL, NULL, NULL },
	}
};

struct kprobe kp_exit = {
	"taskstats_exit",
	EXIT_THREAD_SAMPLE,
	0,
	{
		TASK_SAMPLE(ARG_0),
		{ NULL, NULL, NULL, NULL },
	}
};

/*
 * The kernel takes at most 4095 bytes for one kprobe definition and this one
 * is close to that, so the stack words get short names. Nothing reads the
 * names, a sample is decoded by position.
 */
struct kprobe kp_exec_connector = {
	"proc_exec_connector",
	EXEC_CONNECTOR_SAMPLE,
	0,
{
	TASK_SAMPLE(ARG_0),
	{ "argc",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +0"		},
	{ "s0",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +0"		},
	{ "s1",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +8"		},
	{ "s2",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +16"		},
	{ "s3",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +24"		},
	{ "s4",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +32"		},
	{ "s5",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +40"		},
	{ "s6",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +48"		},
	{ "s7",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +56"		},
	{ "s8",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +64"		},
	{ "s9",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +72"		},
	{ "s10",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +80"		},
	{ "s11",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +88"		},
	{ "s12",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +96"		},
	{ "s13",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +104"	},
	{ "s14",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +112"	},
	{ "s15",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +120"	},
	{ "s16",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +128"	},
	{ "s17",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +136"	},
	{ "s18",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +144"	},
	{ "s19",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +152"	},
	{ "s20",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +160"	},
	{ "s21",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +168"	},
	{ "s22",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +176"	},
	{ "s23",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +184"	},
	{ "s24",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +192"	},
	{ "s25",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +200"	},
	{ "s26",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +208"	},
	{ "s27",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +216"	},
	{ "s28",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +224"	},
	{ "s29",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +232"	},
	{ "s30",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +240"	},
	{ "s31",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +248"	},
	{ "s32",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +256"	},
	{ "s33",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +264"	},
	{ "s34",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +272"	},
	{ "s35",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +280"	},
	{ "s36",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +288"	},
	{ "s37",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +296"	},
	{ "s38",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +304"	},
	{ "s39",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +312"	},
	{ "s40",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +320"	},
	{ "s41",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +328"	},
	{ "s42",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +336"	},
	{ "s43",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +344"	},
	{ "s44",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +352"	},
	{ "s45",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +360"	},
	{ "s46",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +368"	},
	{ "s47",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +376"	},
	{ "s48",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +384"	},
	{ "s49",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +400"	},
	{ "s50",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +408"	},
	{ "s51",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +416"	},
	{ "s52",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +424"	},
	{ "s53",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +432"	},
	{ "s54",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.start_stack +8 +440"	},
	{ NULL,			NULL,		NULL,	  NULL							},
}};

#undef PWD_S
#undef PWD_K
#undef XS
#undef S

#undef ARG_0

#undef RPT
#undef RPT10
#undef RPT9
#undef RPT8
#undef RPT7
#undef RPT6
#undef RPT5
#undef RPT4
#undef RPT3
#undef RPT2
#undef RPT1
#undef RPT0

struct kprobe *all_kprobes[] = {
	&kp_wake_up_new_task,
	&kp_exit,
	&kp_exec_connector,
	NULL
};

#endif	/* _KPROBE_DEFS_H */
