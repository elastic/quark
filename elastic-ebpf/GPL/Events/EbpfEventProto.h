// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2021 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

#ifndef EBPF_EVENTPROBE_EBPFEVENTPROTO_H
#define EBPF_EVENTPROBE_EBPFEVENTPROTO_H

#define TASK_COMM_LEN 16
// The theoretical max size of DNS packets over UDP is 512.
// Like so many things in DNS this number probaby isn't 100% accurate.
// DNS extensions in RFC2671 and RFC6891 mean the actual size can be larger.
#define MAX_DNS_PACKET 4096

#ifndef __KERNEL__
#include <stdint.h>
#else
#include "vmlinux.h"
#endif

enum ebpf_event_type {
    EBPF_EVENT_PROCESS_INVALID              = 0,
    EBPF_EVENT_PROCESS_FORK                 = (1 << 0),
    EBPF_EVENT_PROCESS_EXEC                 = (1 << 1),
    EBPF_EVENT_PROCESS_EXIT                 = (1 << 2),
    EBPF_EVENT_PROCESS_SETSID               = (1 << 3),
    EBPF_EVENT_PROCESS_SETUID               = (1 << 4),
    EBPF_EVENT_PROCESS_SETGID               = (1 << 5),
    EBPF_EVENT_PROCESS_TTY_WRITE            = (1 << 6),
    EBPF_EVENT_FILE_DELETE                  = (1 << 7),
    EBPF_EVENT_FILE_CREATE                  = (1 << 8),
    EBPF_EVENT_FILE_RENAME                  = (1 << 9),
    EBPF_EVENT_FILE_MODIFY                  = (1 << 10),
    EBPF_EVENT_FILE_MEMFD_OPEN              = (1 << 11),
    EBPF_EVENT_FILE_SHMEM_OPEN              = (1 << 12),
    EBPF_EVENT_NETWORK_CONNECTION_ACCEPTED  = (1 << 13),
    EBPF_EVENT_NETWORK_CONNECTION_ATTEMPTED = (1 << 14),
    EBPF_EVENT_NETWORK_CONNECTION_CLOSED    = (1 << 15),
    EBPF_EVENT_PROCESS_MEMFD_CREATE         = (1 << 16),
    EBPF_EVENT_PROCESS_SHMGET               = (1 << 17),
    EBPF_EVENT_PROCESS_PTRACE               = (1 << 18),
    EBPF_EVENT_PROCESS_LOAD_MODULE          = (1 << 19),
    EBPF_EVENT_NETWORK_DNS_PKT              = (1 << 20),
};

struct ebpf_event_header {
    uint64_t ts;
    uint64_t ts_boot;
    uint64_t type;
} __attribute__((packed));

// Some fields passed up (e.g. argv, path names) have a high maximum size but
// most instances of them won't come close to hitting the maximum. Instead of
// wasting a huge amount of memory by using a fixed-size buffer that's the
// maximum possible size, we pack these fields into variable-length buffers at
// the end of each event. If a new field to be added has a large maximum size
// that won't often be reached, it should be added as a variable length field.
enum ebpf_varlen_field_type {
    EBPF_VL_FIELD_CWD,
    EBPF_VL_FIELD_ARGV,
    EBPF_VL_FIELD_ENV,
    EBPF_VL_FIELD_FILENAME,
    EBPF_VL_FIELD_PATH,
    EBPF_VL_FIELD_OLD_PATH,
    EBPF_VL_FIELD_NEW_PATH,
    EBPF_VL_FIELD_TTY_OUT,
    EBPF_VL_FIELD_PIDS_SS_CGROUP_PATH,
    EBPF_VL_FIELD_SYMLINK_TARGET_PATH,
    EBPF_VL_FIELD_MOD_VERSION,
    EBPF_VL_FIELD_MOD_SRCVERSION,
    EBPF_VL_FIELD_DNS_BODY,
};

// Convenience macro to iterate all the variable length fields in an event
#define FOR_EACH_VARLEN_FIELD(vl_fields_start, cursor)                                             \
    cursor = (struct ebpf_varlen_field *)vl_fields_start.data;                                     \
    for (uint32_t __i = 0; __i < vl_fields_start.nfields;                                          \
         cursor       = (struct ebpf_varlen_field *)((char *)cursor + cursor->size +               \
                                               sizeof(struct ebpf_varlen_field)),            \
                  __i++)

#define FOR_EACH_VARLEN_FIELD_PTR(_vl, _c, _i)				\
	for (_i = 0, (_c) = (struct ebpf_varlen_field *)(_vl)->data;	\
	     _i < (_vl)->nfields;					\
	     (_c) = (struct ebpf_varlen_field *)((char *)(_c) + (_c)->size + sizeof(struct ebpf_varlen_field)), \
		 _i++)

struct ebpf_varlen_fields_start {
    uint32_t nfields;
    size_t size;
    char data[];
} __attribute__((packed));

struct ebpf_varlen_field {
    enum ebpf_varlen_field_type type;
    uint32_t size;
    char data[];
} __attribute__((packed));

struct ebpf_pid_info {
    uint64_t start_time_ns;
    uint32_t tid;
    uint32_t tgid;
    uint32_t ppid;
    uint32_t pgid;
    uint32_t sid;
} __attribute__((packed));

struct ebpf_cred_info {
    uint32_t ruid; // Real user ID
    uint32_t rgid; // Real group ID
    uint32_t euid; // Effective user ID
    uint32_t egid; // Effective group ID
    uint32_t suid; // Saved user ID
    uint32_t sgid; // Saved group ID
    uint64_t cap_permitted;
    uint64_t cap_effective;
} __attribute__((packed));

struct ebpf_tty_winsize {
    uint16_t rows;
    uint16_t cols;
} __attribute__((packed));

struct ebpf_tty_termios {
    uint32_t c_iflag;
    uint32_t c_oflag;
    uint32_t c_lflag;
    uint32_t c_cflag;
} __attribute__((packed));

struct ebpf_tty_dev {
    uint16_t minor;
    uint16_t major;
    struct ebpf_tty_winsize winsize;
    struct ebpf_tty_termios termios;
} __attribute__((packed));

enum ebpf_file_type {
    EBPF_FILE_TYPE_UNKNOWN          = 0,
    EBPF_FILE_TYPE_FILE             = 1,
    EBPF_FILE_TYPE_DIR              = 2,
    EBPF_FILE_TYPE_SYMLINK          = 3,
    EBPF_FILE_TYPE_CHARACTER_DEVICE = 4,
    EBPF_FILE_TYPE_BLOCK_DEVICE     = 5,
    EBPF_FILE_TYPE_NAMED_PIPE       = 6,
    EBPF_FILE_TYPE_SOCKET           = 7,
};

struct ebpf_file_info {
    enum ebpf_file_type type;
    uint64_t inode;
    uint16_t mode;
    uint64_t size;
    uint32_t uid;
    uint32_t gid;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
} __attribute__((packed));

struct ebpf_namespace_info {
    uint32_t uts_inonum;
    uint32_t ipc_inonum;
    uint32_t mnt_inonum;
    uint32_t net_inonum;
    uint32_t cgroup_inonum;
    uint32_t time_inonum;
    uint32_t pid_inonum;
} __attribute__((packed));

// Full events follow
struct ebpf_file_delete_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    struct ebpf_cred_info creds;
    struct ebpf_file_info finfo;
    uint32_t mntns;
    char comm[TASK_COMM_LEN];

    // Variable length fields: path, symlink_target_path, pids_ss_cgroup_path
    struct ebpf_varlen_fields_start vl_fields;
} __attribute__((packed));

// reused by memfd_open and shmem_open events
struct ebpf_file_create_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    struct ebpf_cred_info creds;
    struct ebpf_file_info finfo;
    uint32_t mntns;
    char comm[TASK_COMM_LEN];

    // Variable length fields: path, symlink_target_path, pids_ss_cgroup_path
    struct ebpf_varlen_fields_start vl_fields;
} __attribute__((packed));

struct ebpf_file_rename_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    struct ebpf_cred_info creds;
    struct ebpf_file_info finfo;
    uint32_t mntns;
    char comm[TASK_COMM_LEN];

    // Variable length fields: old_path, new_path, symlink_target_path, pids_ss_cgroup_path
    struct ebpf_varlen_fields_start vl_fields;
} __attribute__((packed));

enum ebpf_file_change_type {
    EBPF_FILE_CHANGE_TYPE_UNKNOWN     = 0,
    EBPF_FILE_CHANGE_TYPE_CONTENT     = 1,
    EBPF_FILE_CHANGE_TYPE_PERMISSIONS = 2,
    EBPF_FILE_CHANGE_TYPE_OWNER       = 3,
    EBPF_FILE_CHANGE_TYPE_XATTRS      = 4,
};

struct ebpf_file_modify_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    struct ebpf_cred_info creds;
    struct ebpf_file_info finfo;
    enum ebpf_file_change_type change_type;
    uint32_t mntns;
    char comm[TASK_COMM_LEN];

    // Variable length fields: path, symlink_target_path, pids_ss_cgroup_path
    struct ebpf_varlen_fields_start vl_fields;
} __attribute__((packed));

struct ebpf_process_fork_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info parent_pids;
    struct ebpf_pid_info child_pids;
    struct ebpf_cred_info creds;
    struct ebpf_tty_dev ctty;
    char comm[TASK_COMM_LEN];
    struct ebpf_namespace_info ns;

    // Variable length fields: pids_ss_cgroup_path
    struct ebpf_varlen_fields_start vl_fields;
} __attribute__((packed));

#define EXEC_F_SETUID (1 << 0)
#define EXEC_F_SETGID (1 << 1)
#define EXEC_F_MEMFD (1 << 2)

struct ebpf_process_exec_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    struct ebpf_cred_info creds;
    struct ebpf_tty_dev ctty;
    char comm[TASK_COMM_LEN];
    struct ebpf_namespace_info ns;
    uint32_t inode_nlink;
    uint32_t flags;

    // Variable length fields: cwd, argv, env, filename, pids_ss_cgroup_path
    struct ebpf_varlen_fields_start vl_fields;
} __attribute__((packed));

struct ebpf_process_exit_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    struct ebpf_cred_info creds;
    struct ebpf_tty_dev ctty;
    char comm[TASK_COMM_LEN];
    struct ebpf_namespace_info ns;
    int32_t exit_code;

    // Variable length fields: pids_ss_cgroup_path
    struct ebpf_varlen_fields_start vl_fields;
} __attribute__((packed));

struct ebpf_process_setsid_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
} __attribute__((packed));

struct ebpf_process_setuid_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    uint32_t new_ruid;
    uint32_t new_euid;
    uint32_t new_rgid;
    uint32_t new_egid;
} __attribute__((packed));

struct ebpf_process_tty_write_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    uint64_t tty_out_truncated;

    // Controlling TTY.
    struct ebpf_tty_dev ctty;

    // Destination TTY.
    struct ebpf_tty_dev tty;
    char comm[TASK_COMM_LEN];

    // Variable length fields: tty_out
    struct ebpf_varlen_fields_start vl_fields;
} __attribute__((packed));

struct ebpf_process_setgid_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    uint32_t new_rgid;
    uint32_t new_egid;
    uint32_t new_ruid;
    uint32_t new_euid;
} __attribute__((packed));

// from linux/memfd.h:
//
/* flags for memfd_create(2) (unsigned int) */
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif
#ifndef MFD_HUGETLB
#define MFD_HUGETLB 0x0004U
#endif
/* not executable and sealed to prevent changing to executable. */
#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 0x0008U
#endif
/* executable */
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif
struct ebpf_process_memfd_create_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    uint32_t flags; // memfd_create flags
    // Variable length fields: memfd name
    struct ebpf_varlen_fields_start vl_fields;
} __attribute__((packed));

struct ebpf_process_shmget_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    int64_t key;
    uint64_t size;
    int64_t shmflg; // shmget() flags
} __attribute__((packed));

struct ebpf_process_ptrace_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    uint32_t child_pid;
    int64_t request;
} __attribute__((packed));

struct ebpf_process_load_module_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    // Variable length fields: filename, mod version, mod srcversion
    struct ebpf_varlen_fields_start vl_fields;
} __attribute__((packed));

enum ebpf_net_info_transport {
    EBPF_NETWORK_EVENT_TRANSPORT_TCP = 1,
    EBPF_NETWORK_EVENT_TRANSPORT_UDP = 2,
};

enum ebpf_net_info_af {
    EBPF_NETWORK_EVENT_AF_INET  = 1,
    EBPF_NETWORK_EVENT_AF_INET6 = 2,
};

enum ebpf_net_udp_info {
    EBPF_NETWORK_EVENT_SKB_CONSUME_UDP = 1,
    EBPF_NETWORK_EVENT_IP_SEND_UDP     = 2,
};

enum ebpf_net_packet_direction {
    EBPF_NETWORK_DIR_EGRESS  = 1,
    EBPF_NETWORK_DIR_INGRESS = 2,
};

struct ebpf_net_info_tcp_close {
    uint64_t bytes_sent;
    uint64_t bytes_received;
} __attribute__((packed));

struct ebpf_net_info {
    enum ebpf_net_info_transport transport;
    enum ebpf_net_info_af family;
    union {
        uint8_t saddr[4];
        uint8_t saddr6[16];
    }; // Network byte order
    union {
        uint8_t daddr[4];
        uint8_t daddr6[16];
    };              // Network byte order
    uint16_t sport; // Host byte order
    uint16_t dport; // Host byte order
    uint32_t netns;
    union {
        struct ebpf_net_info_tcp_close close;
    } tcp;
} __attribute__((packed));

struct ebpf_net_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    struct ebpf_net_info net;
    char comm[TASK_COMM_LEN];
} __attribute__((packed));

struct ebpf_dns_event {
    struct ebpf_event_header hdr;
    uint32_t tgid;
    uint32_t cap_len;
    uint32_t orig_len;
    enum ebpf_net_packet_direction direction;
    struct ebpf_varlen_fields_start vl_fields;
} __attribute__((packed));

// Basic event statistics
struct ebpf_event_stats {
    uint64_t lost;          // lost events due to a full ringbuffer
    uint64_t sent;          // events sent through the ringbuffer
    uint64_t dns_zero_body; // indicates that the dns body of a sk_buff was unavailable
};

#endif // EBPF_EVENTPROBE_EBPFEVENTPROTO_H
