/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2024 Elastic NV */

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

struct kprobe_arg ka_task_old_pgid = {
	"pgid", XS(ARG_0), "u32", "task_struct.group_leader (task_struct.pids+40) (pid.numbers+0).upid.nr"
};

struct kprobe_arg ka_task_old_sid = {
	"sid", XS(ARG_0), "u32", "task_struct.group_leader (task_struct.pids+64) (pid.numbers+0).upid.nr"
};

struct kprobe_arg ka_task_new_pgid = {
	"pgid", XS(ARG_0), "u32", "task_struct.group_leader task_struct.signal (signal_struct.pids+16) (pid.numbers+0).upid.nr"
};

struct kprobe_arg ka_task_new_sid = {
	"sid", XS(ARG_0), "u32", "task_struct.group_leader task_struct.signal (signal_struct.pids+24) (pid.numbers+0).upid.nr"
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
	{ "tty_minor_index",	XS(_r), "u32",		"task_struct.signal signal_struct.tty tty_struct.index"						}

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
	"perf_event_exit_task",
	EXIT_THREAD_SAMPLE,
	0,
	{
		TASK_SAMPLE(ARG_0),
		{ NULL, NULL, NULL, NULL },
	}
};

struct kprobe kp_exec_connector = {
	"proc_exec_connector",
	EXEC_CONNECTOR_SAMPLE,
	0,
{
	TASK_SAMPLE(ARG_0),
	{ "argc",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +0"	},
	{ "stack_0",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +0"	},
	{ "stack_1",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +8"	},
	{ "stack_2",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +16"	},
	{ "stack_3",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +24"	},
	{ "stack_4",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +32"	},
	{ "stack_5",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +40"	},
	{ "stack_6",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +48"	},
	{ "stack_7",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +56"	},
	{ "stack_8",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +64"	},
	{ "stack_9",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +72"	},
	{ "stack_10",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +80"	},
	{ "stack_11",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +88"	},
	{ "stack_12",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +96"	},
	{ "stack_13",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +104"	},
	{ "stack_14",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +112"	},
	{ "stack_15",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +120"	},
	{ "stack_16",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +128"	},
	{ "stack_17",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +136"	},
	{ "stack_18",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +144"	},
	{ "stack_19",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +152"	},
	{ "stack_20",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +160"	},
	{ "stack_21",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +168"	},
	{ "stack_22",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +176"	},
	{ "stack_23",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +184"	},
	{ "stack_24",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +192"	},
	{ "stack_25",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +200"	},
	{ "stack_26",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +208"	},
	{ "stack_27",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +216"	},
	{ "stack_28",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +224"	},
	{ "stack_29",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +232"	},
	{ "stack_30",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +240"	},
	{ "stack_31",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +248"	},
	{ "stack_32",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +256"	},
	{ "stack_33",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +264"	},
	{ "stack_34",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +272"	},
	{ "stack_35",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +280"	},
	{ "stack_36",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +288"	},
	{ "stack_37",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +296"	},
	{ "stack_38",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +304"	},
	{ "stack_39",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +312"	},
	{ "stack_40",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +320"	},
	{ "stack_41",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +328"	},
	{ "stack_42",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +336"	},
	{ "stack_43",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +344"	},
	{ "stack_44",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +352"	},
	{ "stack_45",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +360"	},
	{ "stack_46",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +368"	},
	{ "stack_47",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +376"	},
	{ "stack_48",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +384"	},
	{ "stack_49",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +400"	},
	{ "stack_50",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +408"	},
	{ "stack_51",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +416"	},
	{ "stack_52",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +424"	},
	{ "stack_53",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +432"	},
	{ "stack_54",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +440"	},
	{ "stack_55",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +448"	},
	{ "stack_56",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +456"	},
	{ "stack_57",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +464"	},
	{ "stack_58",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +472"	},
	{ "stack_59",		XS(ARG_0),	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +480"	},
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
