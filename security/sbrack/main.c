#include "sbrack.h"

/* UID to its role list */
struct idr uid_map;

/* protect data structure */
struct rw_semaphore sbrack_lock;

/* global role list */
struct list_head role_list;

/* ASSUMPTION:
 * SBRACK only checks permission for the users who belong to
 * STONYBROOK group (SBRACK_GID).
 */
static int should_check_permission(void)
{
	struct group_info *group_info = get_current_groups();
	int count = group_info->ngroups;
	int i, j, should = 0;

	/* borrowed from net/ipv4/ping.c */
	for (i = 0; i < group_info->nblocks; i++) {
		int cp_count = min_t(int, NGROUPS_PER_BLOCK, count);
		for (j = 0; j < cp_count; j++) {
			kgid_t gid = group_info->blocks[i][j];
			if (gid_eq(gid, KGIDT_INIT(SBRACK_GID))) {
				should = 1;
				goto out_release_group;
			}
		}

		count -= cp_count;
	}

out_release_group:
	put_group_info(group_info);
	return should;
}

/* return 0 if pass */
static int check_role_permission(int mask)
{
	struct list_head *current_head;
	kuid_t euid;	/* effective uid */
	int ret;

	if (mask && should_check_permission())
		INFO("checking permission...");
	else
		return 0;
	// XXX check inode gid to limit the domain?

	euid = current_euid();
	ret = -EACCES;
	down_read(&sbrack_lock);
	current_head = idr_find(&uid_map, (int)euid.val);
	if (current_head) {
		struct u_role *u_role;
		list_for_each_entry(u_role, current_head, list) {
			if (u_role->role->permission & mask) {
				ret = 0;
				goto out_lock;
			}
		}
	} // else doesn't have a role, deny

out_lock:
	up_read(&sbrack_lock);
	INFO("euid: %d, mask: %x, result: %d", (int)euid.val, mask, ret);
	return ret;
}

static int fs_mask_to_sbrack_mask(struct inode *inode, int mask)
{
	int sm = 0;
	if (mask & MAY_READ)
		sm |= NEED_READ;
	if (mask & MAY_WRITE || mask & MAY_APPEND)
		sm |= NEED_WRITE;

	/* XXX In order to test read/write permission with system 
	 * program (e.g., cat), we do not limit execution permission
	 * at this stage. */
	/*
	if (mask & MAY_EXEC)
		sm |= NEED_EXEC;
	*/

	return sm;
}

static int sbrack_inode_create(struct inode *dir,
	           	       struct dentry *dentry, umode_t mode)
{
	// INFO("checking sbrack_inode_create");
	return check_role_permission(NEED_WRITE);
}

static int sbrack_inode_link(struct dentry *old_dentry,
	         	     struct inode *dir, struct dentry *new_dentry)
{
	// INFO("checking sbrack_inode_link");
	return check_role_permission(NEED_WRITE);
}

static int sbrack_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	// INFO("checking sbrack_inode_unlink");
	return check_role_permission(NEED_WRITE);
}

static int sbrack_inode_symlink(struct inode *dir,
	            	        struct dentry *dentry, const char *old_name)
{
	// INFO("checking sbrack_inode_symlink");
	return check_role_permission(NEED_WRITE);
}

static int sbrack_inode_mkdir(struct inode *dir, struct dentry *dentry,
			      umode_t mode)
{
	// INFO("checking sbrack_inode_mkdir");
	return check_role_permission(NEED_WRITE);
}

static int sbrack_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	// INFO("checking sbrack_inode_rmdir");
	return check_role_permission(NEED_WRITE);
}

static int sbrack_inode_mknod(struct inode *dir, struct dentry *dentry,
	          umode_t mode, dev_t dev)
{
	// INFO("checking sbrack_inode_mknod");
	return check_role_permission(NEED_WRITE);
}

static int sbrack_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
	           struct inode *new_dir, struct dentry *new_dentry)
{
	// INFO("checking sbrack_inode_rename");
	return check_role_permission(NEED_WRITE);
}

static int sbrack_inode_readlink(struct dentry *dentry)
{
	// INFO("checking sbrack_inode_readlink");
	return check_role_permission(NEED_READ);
}

static int sbrack_inode_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	// INFO("checking sbrack_inode_follow_link");
	return check_role_permission(NEED_READ);
}

static int sbrack_inode_permission(struct inode *inode, int mask)
{
	int sbrack_mask = fs_mask_to_sbrack_mask(inode, mask);
	// INFO("checking sbrack_inode_permission");
	return check_role_permission(sbrack_mask);
}

static int sbrack_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	// INFO("checking sbrack_inode_setattr");
	return check_role_permission(NEED_WRITE);
}

static int sbrack_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
	// INFO("checking sbrack_inode_getattr");
	return check_role_permission(NEED_READ);
}

static int sbrack_inode_setxattr(struct dentry *dentry, const char *name,
	             	         const void *value, size_t size, int flags)
{
	// INFO("checking sbrack_inode_setxattr");
	return check_role_permission(NEED_WRITE);
}

static int sbrack_inode_getxattr(struct dentry *dentry, const char *name)
{
	// INFO("checking sbrack_inode_getxattr");
	return check_role_permission(NEED_READ);
}

static int sbrack_inode_listxattr(struct dentry *dentry)
{
	// INFO("checking sbrack_inode_listxattr");
	return check_role_permission(NEED_READ);
}

static int sbrack_inode_removexattr(struct dentry *dentry, const char *name)
{
	// INFO("checking sbrack_inode_removexattr");
	return check_role_permission(NEED_WRITE);
}

/* unused inode hooks
	void (*inode_post_setxattr) (struct dentry *dentry, const char *name,
	int (*inode_need_killpriv) (struct dentry *dentry);
	int (*inode_killpriv) (struct dentry *dentry);
	int (*inode_getsecurity) (const struct inode *inode, const char *name, void **buffer, bool alloc);
	int (*inode_setsecurity) (struct inode *inode, const char *name, const void *value, size_t size, int flags);
	int (*inode_listsecurity) (struct inode *inode, char *buffer, size_t buffer_size);
	void (*inode_getsecid) (const struct inode *inode, u32 *secid);
*/

static int data_init(void)
{
	struct list_head *head;

	init_rwsem(&sbrack_lock);
	idr_init(&uid_map); 
	INIT_LIST_HEAD(&role_list);

	// TODO remove sample data
	role_add_or_modify(1, NEED_ALL);
	role_add_or_modify(2, NEED_READ);

	user_add(1001);
	user_add_role(1001, 2);
	user_add_role(1001, 1);

	down_read(&sbrack_lock);
	head = idr_find(&uid_map, 1001);
	WARN_ON(!head);
	dump_role_list(head, 0);
	up_read(&sbrack_lock);

	return 0;
}

static void data_exit(void)
{
	down_write(&sbrack_lock);
	role_del_all(0);
	user_del_all();
	idr_destroy(&uid_map);
	up_write(&sbrack_lock);
}

static struct security_operations sbrack_ops = {
	.name			=	"sbrack",

	.inode_create		=	sbrack_inode_create,
	.inode_link		=	sbrack_inode_link,
	.inode_unlink		=	sbrack_inode_unlink,
	.inode_symlink		=	sbrack_inode_symlink,
	.inode_mkdir		=	sbrack_inode_mkdir,
	.inode_rmdir		=	sbrack_inode_rmdir,
	.inode_mknod		=	sbrack_inode_mknod,
	.inode_rename		=	sbrack_inode_rename,
	.inode_readlink		=	sbrack_inode_readlink,
	.inode_follow_link	=	sbrack_inode_follow_link,
	.inode_permission	=	sbrack_inode_permission,
	.inode_setattr		=	sbrack_inode_setattr,
	.inode_getattr		=	sbrack_inode_getattr,
	.inode_setxattr		=	sbrack_inode_setxattr,
	.inode_getxattr		=	sbrack_inode_getxattr,
	.inode_listxattr	=	sbrack_inode_listxattr,
	.inode_removexattr	=	sbrack_inode_removexattr,
};

static int __init init_sbrack(void)
{
        api_init();

        if (data_init()) {
                INFO("sbrack registration failed.");
                goto out_api;
        }

        if (register_security(&sbrack_ops)) {
                INFO("sbrack registration failed.");
                goto out_data;
        }

        INFO("installed sbrack module");
        return 0;

out_data:
        data_exit();
out_api:
        api_exit();

        return 1;
}

static void  __exit exit_sbrack(void)
{
	reset_security_ops();
	api_exit();
	data_exit();
	INFO("sbrack module removed");
}

security_initcall(init_sbrack);
module_exit(exit_sbrack);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kelong Wang");
MODULE_DESCRIPTION("CSE-509-F14 Proj.1");

