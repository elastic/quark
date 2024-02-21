#include "quark.h"

#define S(_a)		#_a
#define XS(_a)		S(_a)
#define PWD_K(_t, _o)	"task_struct.fs fs_struct.pwd.dentry " XS(RPT(_t, _o, dentry.d_parent))
#define PWD_S(_t, _o)	"task_struct.fs fs_struct.pwd.dentry " XS(RPT(_t, _o, dentry.d_parent)) " dentry.d_name.name +0"

#define TASK_SAMPLE {							\
	{ "cap_inheritable",	"di", "u64",	"task_struct.cred cred.cap_inheritable"								}, \
	{ "cap_permitted",	"di", "u64",	"task_struct.cred cred.cap_permitted",								}, \
	{ "cap_effective",	"di", "u64",	"task_struct.cred cred.cap_effective"								}, \
	{ "cap_bset",		"di", "u64",	"task_struct.cred cred.cap_bset"								}, \
	{ "cap_ambient",	"di", "u64",	"task_struct.cred cred.cap_ambient"								}, \
	{ "start_time",		"di", "u64",	"task_struct.start_time"									}, \
	{ "start_boottime",	"di", "u64",	"task_struct.start_boottime"									}, \
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
       	{ "uid",		"di", "u32",	"task_struct.cred cred.uid"									}, \
       	{ "gid",		"di", "u32",	"task_struct.cred cred.gid"									}, \
       	{ "suid",		"di", "u32",	"task_struct.cred cred.suid"									}, \
       	{ "sgid",		"di", "u32",	"task_struct.cred cred.sgid"									}, \
	{ "euid",		"di", "u32",	"task_struct.cred cred.euid"									}, \
	{ "egid",		"di", "u32",	"task_struct.cred cred.egid"									}, \
	{ "pid",		"di", "u32",	"task_struct.tgid"										}, \
	{ "tid",		"di", "u32",	"task_struct.pid"										}, \
	{ "exit_code",		"di", "s32",	"task_struct.exit_code"										}, \
	{ NULL,			NULL, NULL,  	NULL												}}

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

#undef PWD_S
#undef PWD_K
#undef XS
#undef S

struct kprobe *all_kprobes[] = {
	&kp_wake_up_new_task,
	&kp_exit_thread,
	NULL
};

