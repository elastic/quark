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

#define S(_a)		#_a
#define XS(_a)		S(_a)
#define PWD_K(_t, _o)	"task_struct.fs fs_struct.pwd.dentry " XS(RPT(_t, _o, dentry.d_parent))
#define PWD_S(_t, _o)	"task_struct.fs fs_struct.pwd.dentry " XS(RPT(_t, _o, dentry.d_parent)) " dentry.d_name.name +0"
#define TTY_MAJOR	"task_struct.signal signal_struct.tty tty_struct.driver tty_driver.major"
#define TTY_MINOR_START	"task_struct.signal signal_struct.tty tty_struct.driver tty_driver.minor_start"
#define TTY_MINOR_INDEX	"task_struct.signal signal_struct.tty tty_struct.index"

struct kprobe_arg ka_task_old_pgid = {
	"pgid", "di", "u32", "task_struct.group_leader (task_struct.pids+8) (pid.numbers+0).upid.nr"
};

struct kprobe_arg ka_task_old_sid = {
	"sid", "di", "u32", "task_struct.group_leader (task_struct.pids+16) (pid.numbers+0).upid.nr"
};

struct kprobe_arg ka_task_new_pgid = {
	"pgid", "di", "u32", "task_struct.group_leader task_struct.signal (signal_struct.pids+16) (pid.numbers+0).upid.nr"
};

struct kprobe_arg ka_task_new_sid = {
	"sid", "di", "u32", "task_struct.group_leader task_struct.signal (signal_struct.pids+24) (pid.numbers+0).upid.nr"
};


#define TASK_SAMPLE {																   \
	{ "cap_inheritable",	"di", "u64",	"task_struct.cred cred.cap_inheritable"								}, \
	{ "cap_permitted",	"di", "u64",	"task_struct.cred cred.cap_permitted",								}, \
	{ "cap_effective",	"di", "u64",	"task_struct.cred cred.cap_effective"								}, \
	{ "cap_bset",		"di", "u64",	"task_struct.cred cred.cap_bset"								}, \
	{ "cap_ambient",	"di", "u64",	"task_struct.cred cred.cap_ambient"								}, \
	{ "start_boottime",	"di", "u64",	"task_struct.start_boottime"									}, \
	{ "tty_addr",		"di", "u64",	"task_struct.signal signal_struct.tty"								}, \
	{ "root_k",		"di", "u64",	"task_struct.fs fs_struct.root.dentry"								}, \
	{ "mnt_root_k",		"di", "u64",	"task_struct.fs fs_struct.pwd.mnt vfsmount.mnt_root"						}, \
	{ "mnt_mountpoint_k",	"di", "u64",	"task_struct.fs fs_struct.pwd.mnt (mount.mnt_mountpoint-mount.mnt)"				}, \
	{ "pwd_k0",		"di", "u64",	PWD_K(0, 0)											}, \
	{ "pwd_k1",		"di", "u64",	PWD_K(0, 1)											}, \
	{ "pwd_k2",		"di", "u64",	PWD_K(0, 2)											}, \
	{ "pwd_k3",		"di", "u64",	PWD_K(0, 3)											}, \
	{ "pwd_k4",		"di", "u64",	PWD_K(0, 4)											}, \
	{ "pwd_k5",		"di", "u64",	PWD_K(0, 5)											}, \
	{ "pwd_k6",		"di", "u64",	PWD_K(0, 6)											}, \
	{ "root_s",		"di", "string",	"task_struct.fs fs_struct.root.dentry dentry.d_name.name +0"					}, \
	{ "mnt_root_s",		"di", "string",	"task_struct.fs fs_struct.pwd.mnt vfsmount.mnt_root dentry.d_name.name +0"			}, \
	{ "mnt_mountpoint_s",	"di", "string",	"task_struct.fs fs_struct.pwd.mnt (mount.mnt_mountpoint-mount.mnt) dentry.d_name.name +0"	}, \
	{ "pwd_s0",		"di", "string",	PWD_S(0, 0)											}, \
	{ "pwd_s1",		"di", "string",	PWD_S(0, 1)											}, \
	{ "pwd_s2",		"di", "string",	PWD_S(0, 2)											}, \
	{ "pwd_s3",		"di", "string",	PWD_S(0, 3)											}, \
	{ "pwd_s4",		"di", "string",	PWD_S(0, 4)											}, \
	{ "pwd_s5",		"di", "string",	PWD_S(0, 5)											}, \
	{ "pwd_s6",		"di", "string",	PWD_S(0, 6)											}, \
	{ "comm",		"di", "string",	"task_struct.comm"										}, \
	{ "uid",		"di", "u32",	"task_struct.cred cred.uid"									}, \
	{ "gid",		"di", "u32",	"task_struct.cred cred.gid"									}, \
	{ "suid",		"di", "u32",	"task_struct.cred cred.suid"									}, \
	{ "sgid",		"di", "u32",	"task_struct.cred cred.sgid"									}, \
	{ "euid",		"di", "u32",	"task_struct.cred cred.euid"									}, \
	{ "egid",		"di", "u32",	"task_struct.cred cred.egid"									}, \
	{ "pgid",		"di", "u32",	"KLUDGE - see kprobe_kludge_arg()"								}, \
	{ "sid",		"di", "u32",	"KLUDGE - see kprobe_kludge_arg()"								}, \
	{ "pid",		"di", "u32",	"task_struct.tgid"										}, \
	{ "tid",		"di", "u32",	"task_struct.pid"										}, \
	{ "exit_code",		"di", "s32",	"task_struct.exit_code"										}, \
	{ "tty_major",		"di", "u32",	TTY_MAJOR											}, \
	{ "tty_minor_start",	"di", "u32",	TTY_MINOR_START											}, \
	{ "tty_minor_index",	"di", "u32",	TTY_MINOR_INDEX											}, \
	{ NULL,			NULL, NULL,	NULL												}}

struct kprobe kp_wake_up_new_task = {
	"quark_wake_up_new_task",
	"wake_up_new_task",
	WAKE_UP_NEW_TASK_SAMPLE,
	0,
	TASK_SAMPLE
};

struct kprobe kp_exit_thread = {
	"quark_exit_thread",
	"exit_thread",
	EXIT_THREAD_SAMPLE,
	0,
	TASK_SAMPLE
};

struct kprobe kp_exec_connector = {
	"quark_exec_connector",
	"proc_exec_connector",
	EXEC_CONNECTOR_SAMPLE,
	0,
{
	{ "argc",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +0"	},
	{ "stack_0",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +0"	},
	{ "stack_1",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +8"	},
	{ "stack_2",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +16"	},
	{ "stack_3",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +24"	},
	{ "stack_4",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +32"	},
	{ "stack_5",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +40"	},
	{ "stack_6",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +48"	},
	{ "stack_7",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +56"	},
	{ "stack_8",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +64"	},
	{ "stack_9",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +72"	},
	{ "stack_10",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +80"	},
	{ "stack_11",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +88"	},
	{ "stack_12",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +96"	},
	{ "stack_13",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +104"	},
	{ "stack_14",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +112"	},
	{ "stack_15",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +120"	},
	{ "stack_16",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +128"	},
	{ "stack_17",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +136"	},
	{ "stack_18",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +144"	},
	{ "stack_19",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +152"	},
	{ "stack_20",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +160"	},
	{ "stack_21",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +168"	},
	{ "stack_22",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +176"	},
	{ "stack_23",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +184"	},
	{ "stack_24",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +192"	},
	{ "stack_25",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +200"	},
	{ "stack_26",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +208"	},
	{ "stack_27",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +216"	},
	{ "stack_28",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +224"	},
	{ "stack_29",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +232"	},
	{ "stack_30",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +240"	},
	{ "stack_31",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +248"	},
	{ "stack_32",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +256"	},
	{ "stack_33",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +264"	},
	{ "stack_34",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +272"	},
	{ "stack_35",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +280"	},
	{ "stack_36",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +288"	},
	{ "stack_37",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +296"	},
	{ "stack_38",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +304"	},
	{ "stack_39",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +312"	},
	{ "stack_40",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +320"	},
	{ "stack_41",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +328"	},
	{ "stack_42",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +336"	},
	{ "stack_43",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +344"	},
	{ "stack_44",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +352"	},
	{ "stack_45",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +360"	},
	{ "stack_46",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +368"	},
	{ "stack_47",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +376"	},
	{ "stack_48",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +384"	},
	{ "stack_49",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +400"	},
	{ "stack_50",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +408"	},
	{ "stack_51",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +416"	},
	{ "stack_52",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +424"	},
	{ "stack_53",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +432"	},
	{ "stack_54",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +440"	},
	{ "stack_55",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +448"	},
	{ "stack_56",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +456"	},
	{ "stack_57",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +464"	},
	{ "stack_58",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +472"	},
	{ "stack_59",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +480"	},
	{ "stack_60",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +488"	},
	{ "stack_61",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +496"	},
	{ "stack_62",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +504"	},
	{ "stack_63",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +512"	},
	{ "stack_64",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +520"	},
	{ "stack_65",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +528"	},
	{ "stack_66",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +536"	},
	{ "stack_67",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +544"	},
	{ "stack_68",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +552"	},
	{ "stack_69",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +560"	},
	{ "stack_70",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +568"	},
	{ "stack_71",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +576"	},
	{ "stack_72",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +584"	},
	{ "stack_73",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +592"	},
	{ "stack_74",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +600"	},
	{ "stack_75",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +608"	},
	{ "stack_76",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +616"	},
	{ "stack_77",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +624"	},
	{ "stack_78",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +632"	},
	{ "stack_79",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +640"	},
	{ "stack_80",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +648"	},
	{ "stack_81",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +656"	},
	{ "stack_82",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +664"	},
	{ "stack_83",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +672"	},
	{ "stack_84",		"di",	"u64",	  "task_struct.mm mm_struct.(anon).start_stack +8 +680"	},
	{ "cap_inheritable",	"di",	"u64",	  "task_struct.cred cred.cap_inheritable"		},
	{ "cap_permitted",	"di",	"u64",	  "task_struct.cred cred.cap_permitted",		},
	{ "cap_effective",	"di",	"u64",	  "task_struct.cred cred.cap_effective"			},
	{ "cap_bset",		"di",	"u64",	  "task_struct.cred cred.cap_bset"			},
	{ "cap_ambient",	"di",	"u64",	  "task_struct.cred cred.cap_ambient"			},
	{ "start_boottime",	"di",	"u64",	  "task_struct.start_boottime"				},
	{ "tty_addr",		"di",	"u64",	  "task_struct.signal signal_struct.tty"		},
	{ "comm",		"di",	"string", "task_struct.comm"					},
	{ "uid",		"di",	"u32",	  "task_struct.cred cred.uid"				},
	{ "gid",		"di",	"u32",	  "task_struct.cred cred.gid"				},
	{ "suid",		"di",	"u32",	  "task_struct.cred cred.suid"				},
	{ "sgid",		"di",	"u32",	  "task_struct.cred cred.sgid"				},
	{ "euid",		"di",	"u32",	  "task_struct.cred cred.euid"				},
	{ "egid",		"di",	"u32",	  "task_struct.cred cred.egid"				},
	{ "pgid",		"di",	"u32",	  "task_struct.group_leader task_struct.signal (signal_struct.pids+16) (pid.numbers+0).upid.nr"	}, \
	{ "sid",		"di",	"u32",	  "task_struct.group_leader task_struct.signal (signal_struct.pids+24) (pid.numbers+0).upid.nr"	}, \
	{ "tty_major",		"di",	"u32",	  TTY_MAJOR						},
	{ "tty_minor_start",	"di",	"u32",	  TTY_MINOR_START					},
	{ "tty_minor_index",	"di",	"u32",	  TTY_MINOR_INDEX					},
	{ NULL,			NULL,	NULL,	  NULL							},
}};

#undef TTY_MINOR_INDEX
#undef TTY_MINOR_START
#undef TTY_MAJOR
#undef PWD_S
#undef PWD_K
#undef XS
#undef S

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
	&kp_exit_thread,
	&kp_exec_connector,
	NULL
};

#endif	/* _KPROBE_DEFS_H */
