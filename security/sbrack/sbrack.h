#ifndef _SBRACK_H_
#define _SBRACK_H_

#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/security.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/stat.h>		/* get permission define like S_IRWXG */
#include <linux/uidgid.h>
#include <linux/cred.h>
#include <linux/sched.h>	/* make get_current_groups() compile */
#include <linux/rwsem.h>
#include <linux/fs.h>

#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

#undef XDEBUG
// #define XDEBUG
#ifdef XDEBUG
#define INFO(fmt, ...) \
	pr_info("[%s:%s:%d] " fmt "\n", __FILE__, __func__, __LINE__,\
		##__VA_ARGS__)
#else
#define INFO(fmt, ...) \
	pr_info(fmt "\n", ##__VA_ARGS__)
#endif

/*
 * S_IRWXG
 * Group has read, write, and execute permission.
 * S_IRGRP
 * Group has read permission.
 * S_IWGRP
 * Group has write permission.
 * S_IXGRP
 * Group has execute permission.
 */

#define NEED_ALL	S_IRWXG
#define NEED_WRITE	S_IWGRP
#define NEED_READ	S_IRGRP
#define NEED_EXEC	S_IXGRP

/* we will check access permisson of the users who belong to this gid only */
#define SBRACK_GID	20000

struct role {
	int rid;
	int permission;
	struct list_head list;
};

/* each user's role list */ 
struct u_role {
	struct role *role;
	struct list_head list;
};

extern struct rw_semaphore sbrack_lock;
extern struct list_head role_list;
extern struct idr uid_map;

extern int api_init(void);
extern void api_exit(void);
extern void dump_role_list(struct list_head *head, int global);
extern int role_add_or_modify(int rid, int permission);
extern void role_del_all(int cascade);
extern int user_add(int uid);
extern int user_add_role(int uid, int rid);
extern void user_del_all(void);

#endif	/* not _SBRACK_H_ */

