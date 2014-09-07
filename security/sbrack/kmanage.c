/*
 * role, user management with sysfs kobject
 */
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/init.h>
#include "sbrack.h"

static int role;
static int user;

/* caller should make sure sbrack_lock is held */
void dump_role_list(struct list_head *head, int global)
{
	struct role *role;
	struct u_role *u_role;

	if (!head) {
		INFO("uninitialized role list");
		return;
	}
	if (list_empty(head)) {
		INFO("empty role list");
		return;
	}

	if (global)
		list_for_each_entry(role, head, list)
			INFO("%d: %d", role->rid, role->permission);
	else	// print user's role list
		list_for_each_entry(u_role, head, list)
			INFO("%d: %d", u_role->role->rid,
			     u_role->role->permission);
}

int role_add_or_modify(int rid, int permission)
{
	struct role *role;
	int modified = 0;

	down_write(&sbrack_lock);
	list_for_each_entry(role, &role_list, list) {
		if (role->rid == rid) {
			role->permission = permission;
			modified = 1;
			break;
		}
	}
	if (!modified) {
		role = kmalloc(sizeof(*role), GFP_KERNEL);
		role->rid = rid;
		role->permission = permission;
		list_add_tail(&role->list, &role_list);
	}
#ifdef XDEBUG
	dump_role_list(&role_list, 1);
#endif
	up_write(&sbrack_lock);

	return 0;
}

/* caller should make sure sbrack_lock is held */
static int __role_del_for_one_user(int uid, void *p, void *data)
{
	struct u_role *u_role, *next;
	struct list_head *u_role_list = p;
	int *rid = data;

	list_for_each_entry_safe(u_role, next, u_role_list, list) {
		if (u_role->role->rid == *rid) {
			list_del(&u_role->list);
			kfree(u_role);
			INFO("user[%d]'s role[%d] revoked", uid, *rid);
			break;
		}
	}
#ifdef XDEBUG
	dump_role_list(u_role_list, 0);
#endif
	return 0;
}

/* caller should make sure sbrack_lock is held */
static void role_del_for_each_user(int rid)
{
	idr_for_each(&uid_map, __role_del_for_one_user, &rid);
}

/* delete all roles and corresponding entries in users' role lists.
 * caller should make sure sbrack_lock is held.
 * @cascade: if true, also delete role in user's role list; useful
 * 	     (set to false) during module exit to avoid duplicate loop
 * 	     by user_del_all(). */
void role_del_all(int cascade)
{
	struct role *role, *next;

	list_for_each_entry_safe(role, next, &role_list, list) {
		list_del(&role->list);
		if (cascade)
			role_del_for_each_user(role->rid);
		kfree(role);
	}

	WARN_ON(!list_empty(&role_list));
}

static int role_del_one(int rid)
{
	struct role *role, *next;
	int err = -EINVAL;	/* not found */

	down_write(&sbrack_lock);
	list_for_each_entry_safe(role, next, &role_list, list) {
		if (role->rid == rid) {
			list_del(&role->list);
			role_del_for_each_user(rid);
			kfree(role);
			err = 0;
			break;
		}
	}
#ifdef XDEBUG
	dump_role_list(&role_list, 1);
#endif
	up_write(&sbrack_lock);

	return err;
}

static ssize_t role_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	return sprintf(buf, "%d\n", role);
}

static ssize_t role_store(struct kobject *kobj, struct kobj_attribute *attr,
			  const char *buf, size_t count)
{
	char op[20];
	int rid, permission;
	int n;
	int err = 0;

	INFO("%.*s", (int)count, buf);
	if (count > 20)
		return -EINVAL;
	if ((n = sscanf(buf, "%s %d %d", op, &rid, &permission)) < 2)
		return -EINVAL;

	if (strcmp(op, "add") == 0) {
		if (n != 3 || permission < 0)
			return -EINVAL;
		err = role_add_or_modify(rid, permission);
	} else if (strcmp(op, "del") == 0) {
		if (n != 2)
			return -EINVAL;
		err = role_del_one(rid);
	} else {
		err = -EINVAL;
	}
	INFO("processed %s %d; result: %d", op, rid, err);

	if (!err)
		err = count;

	return err;
}

/* caller should make sure sbrack_lock is held */
static int __user_del_one(int uid, void *p, void *unused)
{
	struct list_head *u_role_list = p;
	struct u_role *u_role, *next;

	/* remove its role list */
	list_for_each_entry_safe(u_role, next, u_role_list, list) {
		list_del(&u_role->list);
		kfree(u_role);
	}

	kfree(u_role_list);
	idr_remove(&uid_map, uid);
	INFO("user[%d] deleted", uid);

	return 0;
}

/* caller should make sure sbrack_lock is held */
void user_del_all(void)
{
	idr_for_each(&uid_map, __user_del_one, NULL);
}

static int user_del_one(int uid)
{
	struct list_head *u_role_list;
	int err = 0;

	down_write(&sbrack_lock);
	u_role_list = idr_find(&uid_map, uid);
	if (u_role_list)
		__user_del_one(uid, u_role_list, NULL);
	else
		err = -EINVAL;	/* user not found */
	up_write(&sbrack_lock);

	return err;
}

int user_add(int uid)
{
	struct list_head *u_role_list;
	int err = 0;
	int id;

	down_write(&sbrack_lock);
	u_role_list = idr_find(&uid_map, uid);
	if (!u_role_list) {
		u_role_list = kmalloc(sizeof(*u_role_list), GFP_KERNEL);
		INIT_LIST_HEAD(u_role_list);
		idr_preload(GFP_KERNEL);
		id = idr_alloc(&uid_map, u_role_list, uid, uid + 1, GFP_KERNEL);
		idr_preload_end();
		WARN_ON(id != uid);
		INFO("user[%d] created", id);
	} else {
		err = -EINVAL;	/* user with same uid already exists */
	}
	up_write(&sbrack_lock);

	return err;
}

/* caller should make sure sbrack_lock is held and returned role should
 * be used under the same lock for consistency. */
static struct role * role_get_by_rid(int rid)
{
	struct role *role;
	list_for_each_entry(role, &role_list, list) {
		if (role->rid == rid)
			return role;
	}

	return NULL;
}

static int user_del_role(int uid, int rid)
{
	struct list_head *u_role_list;
	int err = 0;

	down_write(&sbrack_lock);
	u_role_list = idr_find(&uid_map, uid);
	if (u_role_list)
		err = __role_del_for_one_user(uid, u_role_list, &rid);
	else
		err = -EINVAL;	/* user not found */
	up_write(&sbrack_lock);

	return err;
}

int user_add_role(int uid, int rid)
{
	int err = 0;
	struct role *role;
	struct u_role *u_role;
	struct list_head *u_role_list;

	down_write(&sbrack_lock);
	u_role_list = idr_find(&uid_map, uid);
	if (!u_role_list) {
		err = -EINVAL;	/* user not found */
		goto out_lock;
	}
	role = role_get_by_rid(rid);
	if (!role) {
		err = -EINVAL;	/* role not found */
		goto out_lock;
	}

	list_for_each_entry(u_role, u_role_list, list) {
		if (u_role->role->rid == rid)
			goto out_lock;	/* already assigned */
	}

	u_role = kmalloc(sizeof(*u_role), GFP_KERNEL);
	u_role->role = role;
	list_add_tail(&u_role->list, u_role_list);
	INFO("assigned user[%d] to role[%d]", uid, rid);

out_lock:
	up_write(&sbrack_lock);

	return err;
}

static ssize_t user_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	return sprintf(buf, "%d\n", user);
}

static ssize_t user_store(struct kobject *kobj, struct kobj_attribute *attr,
			  const char *buf, size_t count)
{
	char op[20];
	int uid, rid;
	int n;
	int err = 0;

	INFO("%.*s", (int)count, buf);
	if (count > 20)
		return -EINVAL;
	if ((n = sscanf(buf, "%s %d %d", op, &uid, &rid)) < 2 || uid < 0)
		return -EINVAL;

	if (strcmp(op, "add") == 0) {
		if (n != 2)
			return -EINVAL;
		err = user_add(uid);
	} else if (strcmp(op, "del") == 0) {
		if (n != 2)
			return -EINVAL;
		err = user_del_one(uid);
	} else if (strcmp(op, "add_role") == 0) {
		if (n != 3 || rid < 0) {
			return -EINVAL;
		}
		err = user_add_role(uid, rid);
	} else if (strcmp(op, "del_role") == 0) {
		if (n != 3 || rid < 0)
			return -EINVAL;
		err = user_del_role(uid, rid);
	} else {
		err = -EINVAL;
	}
	INFO("processed %s %d; result: %d", op, uid, err);

	if (!err)
		err = count;

	return err;
}

static struct kobj_attribute role_attribute =
	__ATTR(role, 0666, role_show, role_store);
static struct kobj_attribute user_attribute =
	__ATTR(user, 0666, user_show, user_store);

/*
 * Create a group of attributes so that we can create and destroy them all
 * at once.
 */
static struct attribute *attrs[] = {
	&role_attribute.attr,
	&user_attribute.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

/*
 * An unnamed attribute group will put all of the attributes directly in
 * the kobject directory.  If we specify a name, a subdirectory will be
 * created for the attributes with the directory being the name of the
 * attribute group.
 */
static struct attribute_group attr_group = {
	.attrs = attrs,
};

static struct kobject *api_kobj;

int api_init(void)
{
	int retval;

	/*
	 * Create a simple kobject with the name of "sbrack",
	 * located under /sys/kernel/
	 *
	 * As this is a simple directory, no uevent will be sent to
	 * userspace.  That is why this function should not be used for
	 * any type of dynamic kobjects, where the name and number are
	 * not known ahead of time.
	 */
	api_kobj = kobject_create_and_add("sbrack", kernel_kobj);
	if (!api_kobj)
		return -ENOMEM;

	/* Create the files associated with this kobject */
	retval = sysfs_create_group(api_kobj, &attr_group);
	if (retval)
		kobject_put(api_kobj);

	return retval;
}

void api_exit(void)
{
	kobject_put(api_kobj);
}

