#ifndef _VMLINUX_EXTRA_H_
#define _VMLINUX_EXTRA_H_

enum tty_driver_type {
	TTY_DRIVER_TYPE_SYSTEM,
	TTY_DRIVER_TYPE_CONSOLE,
	TTY_DRIVER_TYPE_SERIAL,
	TTY_DRIVER_TYPE_PTY,
	TTY_DRIVER_TYPE_SCC,
	TTY_DRIVER_TYPE_SYSCONS,
};

enum tty_driver_subtype {
	SYSTEM_TYPE_TTY = 1,
	SYSTEM_TYPE_CONSOLE,
	SYSTEM_TYPE_SYSCONS,
	SYSTEM_TYPE_SYSPTMX,

	PTY_TYPE_MASTER = 1,
	PTY_TYPE_SLAVE,

	SERIAL_TYPE_NORMAL = 1,
};

/*
 * kernel 6.15: 52443558adcdb11cff76beec34bf75f6779e1a08
 * type and subtype changed size, so we can't just BPF_CORE_READ them.
 */
struct tty_driver___6_16 {
	struct kref kref;
	struct cdev **cdevs;
	struct module	*owner;
	const char	*driver_name;
	const char	*name;
	int	name_base;
	int	major;
	int	minor_start;
	unsigned int	num;
	enum tty_driver_type type;
	enum tty_driver_subtype subtype;
	struct ktermios init_termios;
	unsigned long	flags;
	struct proc_dir_entry *proc_entry;
	struct tty_driver *other;
	struct tty_struct **ttys;
	struct tty_port **ports;
	struct ktermios **termios;
	void *driver_state;
	const struct tty_operations *ops;
	struct list_head tty_drivers;
};

/*
 * kernel 6.15: 633488947ef66b194377411322dc9e12aab79b65
 * __parent instead of parent
 */
struct kernfs_node___6_15 {
	atomic_t		count;
	atomic_t		active;
	struct lockdep_map	dep_map;
	const char		*name;
	struct kernfs_node	*__parent;
	struct rb_node		rb;
	const void		*ns;	/* namespace tag */
	unsigned int		hash;	/* ns + name hash */
	unsigned short		flags;
	umode_t			mode;
	union {
		struct kernfs_elem_dir		dir;
		struct kernfs_elem_symlink	symlink;
		struct kernfs_elem_attr		attr;
	};
	u64			id;
	void			*priv;
	struct kernfs_iattrs	*iattr;
	/* struct rcu_head		rcu; */
};


/*
 * kernel 6.6: 13bc24457850583a2e7203ded05b7209ab4bc5ef introduced __i_ctime
 * __i_atime and __i_mtime followed soon, we can still support 6.6 with
 * inode___6_8 as long as we test each member individually.
 */
struct inode___6_8 {
	umode_t			i_mode;
	unsigned short		i_opflags;
	kuid_t			i_uid;
	kgid_t			i_gid;
	unsigned int		i_flags;
	struct posix_acl	*i_acl;
	struct posix_acl	*i_default_acl;
	const struct inode_operations	*i_op;
	struct super_block	*i_sb;
	struct address_space	*i_mapping;
	void			*i_security;
	unsigned long		i_ino;
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t			i_rdev;
	loff_t			i_size;
	struct timespec64	__i_atime;
	struct timespec64	__i_mtime;
	struct timespec64	__i_ctime; /* use inode_*_ctime accessors! */
	spinlock_t		i_lock; /* i_blocks, i_bytes, maybe i_size */
	unsigned short		i_bytes;
	u8			i_blkbits;
	u8			i_write_hint;
	blkcnt_t		i_blocks;
	seqcount_t		i_size_seqcount;
	unsigned long		i_state;
	struct rw_semaphore	i_rwsem;
	unsigned long		dirtied_when;	/* jiffies of first dirtying */
	unsigned long		dirtied_time_when;
	struct hlist_node	i_hash;
	struct list_head	i_io_list;	/* backing dev IO list */
	struct bdi_writeback	*i_wb;		/* the associated cgroup wb */
	int			i_wb_frn_winner;
	u16			i_wb_frn_avg_time;
	u16			i_wb_frn_history;
	struct list_head	i_lru;		/* inode LRU list */
	struct list_head	i_sb_list;
	struct list_head	i_wb_list;	/* backing dev writeback list */
	union {
		struct hlist_head	i_dentry;
		/* struct rcu_head	   i_rcu; */
	};
	atomic64_t		i_version;
	atomic64_t		i_sequence; /* see futex */
	atomic_t		i_count;
	atomic_t		i_dio_count;
	atomic_t		i_writecount;
	atomic_t		i_readcount; /* struct files open RO */
	union {
		const struct file_operations	*i_fop; /* former ->i_op->default_file_ops */
		void (*free_inode)(struct inode *);
	};
	struct file_lock_context	*i_flctx;
	struct address_space	i_data;
	struct list_head	i_devices;
	union {
		struct pipe_inode_info	*i_pipe;
		struct cdev		*i_cdev;
		char			*i_link;
		unsigned		i_dir_seq;
	};

	__u32			i_generation;
	__u32			i_fsnotify_mask; /* all events this inode cares about */
	struct fsnotify_mark_connector *i_fsnotify_marks;
	struct fscrypt_info	*i_crypt_info;
	struct fsverity_info	*i_verity_info;
	void			*i_private; /* fs or device private pointer */
};

/*
 * kernel 6.11: 3aa63a569c64e708df547a8913c84e64a06e7853
 * Time structures changed once again, they're now split.
 */
struct inode___6_11 {
	umode_t			i_mode;
	unsigned short		i_opflags;
	kuid_t			i_uid;
	kgid_t			i_gid;
	unsigned int		i_flags;
	struct posix_acl	*i_acl;
	struct posix_acl	*i_default_acl;
	const struct inode_operations	*i_op;
	struct super_block	*i_sb;
	struct address_space	*i_mapping;
	void			*i_security;
	unsigned long		i_ino;
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t			i_rdev;
	loff_t			i_size;
	time64_t		i_atime_sec;
	time64_t		i_mtime_sec;
	time64_t		i_ctime_sec;
	u32			i_atime_nsec;
	u32			i_mtime_nsec;
	u32			i_ctime_nsec;
	u32			i_generation;
	spinlock_t		i_lock;	/* i_blocks, i_bytes, maybe i_size */
	unsigned short          i_bytes;
	u8			i_blkbits;
	enum rw_hint		i_write_hint;
	blkcnt_t		i_blocks;
	seqcount_t		i_size_seqcount;
	/* Misc */
	unsigned long		i_state;
	struct rw_semaphore	i_rwsem;
	unsigned long		dirtied_when;	/* jiffies of first dirtying */
	unsigned long		dirtied_time_when;
	struct hlist_node	i_hash;
	struct list_head	i_io_list;	/* backing dev IO list */
	struct bdi_writeback	*i_wb;		/* the associated cgroup wb */

	/* foreign inode detection, see wbc_detach_inode() */
	int			i_wb_frn_winner;
	u16			i_wb_frn_avg_time;
	u16			i_wb_frn_history;
	struct list_head	i_lru;		/* inode LRU list */
	struct list_head	i_sb_list;
	struct list_head	i_wb_list;	/* backing dev writeback list */
	union {
		struct hlist_head	i_dentry;
		/* struct rcu_head		i_rcu; */
	};
	atomic64_t		i_version;
	atomic64_t		i_sequence; /* see futex */
	atomic_t		i_count;
	atomic_t		i_dio_count;
	atomic_t		i_writecount;
	atomic_t		i_readcount; /* struct files open RO */
	union {
		const struct file_operations	*i_fop;	/* former ->i_op->default_file_ops */
		void (*free_inode)(struct inode *);
	};
	struct file_lock_context	*i_flctx;
	struct address_space	i_data;
	struct list_head	i_devices;
	union {
		struct pipe_inode_info	*i_pipe;
		struct cdev		*i_cdev;
		char			*i_link;
		unsigned		i_dir_seq;
	};
	__u32			i_fsnotify_mask; /* all events this inode cares about */
	struct fsnotify_mark_connector	*i_fsnotify_marks;
	struct fscrypt_inode_info	*i_crypt_info;
	struct fsverity_info	*i_verity_info;
	void			*i_private; /* fs or device private pointer */
};

#endif	/* _VMLINUX_EXTRA_H_ */
