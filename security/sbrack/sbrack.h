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

//#undef XDEBUG
#define XDEBUG
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

#define NEED_WRITE	S_IWGRP
#define NEED_READ	S_IRGRP
#define NEED_EXEC	S_IXGRP

/* we will check access permisson of the users who belong to this gid only */
#define SBRACK_GID	20000

static DECLARE_RWSEM(sbrack_lock);	/* protect data structure */
struct role {
	int rid;
	int permission;
	struct list_head list;
};
static LIST_HEAD(role_list);

/* each user's role list */ 
struct u_role {
	int rid;
	struct role *role;
	struct list_head list;
};

/* UID to its role list */
static struct idr uid_map;

int api_init(void);
void api_exit(void);

#endif	/* not _SBRACK_H_ */

