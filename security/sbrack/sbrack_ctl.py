#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Utils to manage role and user with persistant storage

import pickle
import getopt
import pwd, grp
import os
import sys

R = CAN_READ = 00040
W = CAN_WRITE = 00020
X = CAN_EXEC = 00010

class Role:
    def __init__(self, name, rid, permission):
        self.name = name
        self.rid = rid
        self.permission = permission
    
class User:
    def __init__(self, name, uid):
        self.name = name
        self.uid = uid
        self.roles = []

class SBrack:
    DB_PATH = "sbrack.db"
    SBRACK_GROUP = 'stonybrook'

    def __init__(self):
        self.data = {}
        self.data['users'] = {}
        self.data['roles'] = {}
        self.data['next_rid'] = 1
        try:
            if os.stat(self.DB_PATH).st_size > 0:
                with open(self.DB_PATH, "rb") as f:
                    self.data = pickle.load(f)
        except:
            pass

    @property
    def users(self):
        return self.data['users']

    @property
    def roles(self):
        return self.data['roles']

    def dump(self):
        # print self.data
        with open(self.DB_PATH, "wb") as f:
            pickle.dump(self.data, f)

    def reset(self):
        self.data['users'] = {}
        self.data['roles'] = {}
        self.data['next_rid'] = 1

    def user_in_sb_group(self, name):
        for g in grp.getgrall():
            if g.gr_name == self.SBRACK_GROUP:
                return name in g.gr_mem

    def validate_user(self, name, should_exist=True):
        try:
            pwd_u = pwd.getpwnam(name)
        except:
            raise Exception("username not exist on Linux")

        if not self.user_in_sb_group(name):
            raise Exception("user not in '%s' group" % self.SBRACK_GROUP)

        if not should_exist and self.users.has_key(name):
            raise Exception("user already exist in SBRACK")
        elif should_exist and not self.users.has_key(name):
            raise Exception("user not exist in SBRACK")

        return pwd_u

    def add_user(self, name):
        try:
            pwd_u = self.validate_user(name, should_exist=False)
            user = User(name, pwd_u.pw_uid)
            Kernel.add_user(user)
            self.users[name] = user
        except Exception as ex:
            print "user[%s]: %s" % (name, ex.message)

    def del_user(self, name):
        try:
            self.validate_user(name, should_exist=True)
            Kernel.del_user(self.users[name])
            self.users.pop(name)
        except Exception as ex:
            print "user[%s]: %s" % (name, ex.message)

    def validate_role(self, name, should_exist=True):
        if not should_exist and self.roles.has_key(name):
            raise Exception("role already exist in SBRACK")
        elif should_exist and not self.roles.has_key(name):
            raise Exception("role not exist in SBRACK")

    def build_perm(self, perm):
        if perm == "NONE":
            return 0

        p = 0
        if perm.find('W') >= 0:
            p |= W
        if perm.find('R') >= 0:
            p |= R
        if perm.find('X') >= 0:
            p |= X

        return p

    def add_role(self, name, perm):
        try:
            self.validate_role(name, should_exist=False)
            role = Role(name, self.data['next_rid'], self.build_perm(perm))
            Kernel.add_role(role)
            self.roles[name] = role
            self.data['next_rid'] += 1  # TODO check overflow
        except Exception as ex:
            print "role[%s]: %s" % (name, ex.message)

    def del_role(self, name):
        try:
            self.validate_role(name, should_exist=True)
            Kernel.del_role(self.roles[name])
            self.roles.pop(name)
        except Exception as ex:
            print "role[%s]: %s" % (name, ex.message)

    def list_role(self):
        for role in self.roles.values():
            if role.permission == 0:
                print "[%d]%s \tNONE" % (role.rid, role.name)
            else:
                print "[%d]%s \t%s%s%s" % (
                        role.rid,
                        role.name,
                        "R" if role.permission & R else " ",
                        "W" if role.permission & W else " ",
                        "X" if role.permission & X else " ")

    def validate_user_has_role(self, username, rolename, should_has=True):
        has = self.roles[rolename] in self.users[username].roles
        if should_has != has:
            if should_has:
                raise Exception("user does not have this role")
            else:
                raise Exception("user already has this role")

    def assign(self, username, rolename):
        try:
            self.validate_user(username, should_exist=True)
            self.validate_role(rolename, should_exist=True)
            self.validate_user_has_role(username, rolename, should_has=False)
            Kernel.assign(self.users[username], self.roles[rolename])
            self.users[username].roles.append(self.roles[rolename])
        except Exception as ex:
            print "assign[%s->%s]: %s" % (rolename, username, ex.message)

    def revoke(self, username, rolename):
        try:
            self.validate_user(username, should_exist=True)
            self.validate_role(rolename, should_exist=True)
            self.validate_user_has_role(username, rolename, should_has=True)
            Kernel.revoke(self.users[username], self.roles[rolename])
            self.users[username].roles.remove(self.roles[rolename])
        except Exception as ex:
            print "assign[%s->%s]: %s" % (rolename, username, ex.message)

    def list_user(self):
        for user in self.users.values():
            print "[%d]%s\troles:%s" % (user.uid, user.name,
                                        ",".join([r.name for r in user.roles]))

    def db_to_kernel(self):
        try:
            for role in self.roles.values():
                Kernel.add_role(role)

            for user in self.users.values():
                Kernel.add_user(user)
                for role in user.roles:
                    Kernel.assign(user, role)
        except Exception as ex:
            print "init_kernel_from_db: %s" % ex.message


class Kernel:
    SYSFS_USER_PATH = "/sys/kernel/sbrack/user"
    SYSFS_ROLE_PATH = "/sys/kernel/sbrack/role"

    def __init__(self):
        try:
            os.stat(SYSFS_USER_PATH)
            os.stat(SYSFS_USER_PATH)
        except:
            print "SBRACK kernel module uninitialized"
            sys.exit()

    @classmethod
    def add_user(self, user):
        return self.sbrack_write("add %d" % user.uid, self.SYSFS_USER_PATH)

    @classmethod
    def del_user(self, user):
        return self.sbrack_write("del %d" % user.uid, self.SYSFS_USER_PATH)

    @classmethod
    def add_role(self, role):
        return self.sbrack_write("add %d %d" % (role.rid, role.permission),
                                 self.SYSFS_ROLE_PATH)
    @classmethod
    def del_role(self, role):
        return self.sbrack_write("del %d" % role.rid, self.SYSFS_ROLE_PATH)

    @classmethod
    def assign(self, user, role):
        return self.sbrack_write("add_role %d %d" % (user.uid, role.rid),
                                 self.SYSFS_USER_PATH)

    @classmethod
    def revoke(self, user, role):
        return self.sbrack_write("del_role %d %d" % (user.uid, role.rid),
                                 self.SYSFS_USER_PATH)

    @classmethod
    def sbrack_write(self, cmd, where):
        fd = os.open(where, os.O_WRONLY)
        if os.write(fd, cmd) < 0:
            os.close(fd)
            raise Exception("failed to commit to kernel")
        os.close(fd)

def usage():
    print "Usage:"
    print "\tadd_role name RWX\t(example: R, RW, NONE)"
    print "\tdel_role name"
    print "\tlist_role"
    print "\t-------------"
    print "\tadd_user name"
    print "\tdel_user name"
    print "\tlist_user"
    print "\t-------------"
    print "\tassign user_name role_name"
    print "\trevoke user_name role_name"
    print "\t-------------"
    print "\treset_db\t(reset local policy data, not kernel)"
    print "\tinit_kernel_from_db\t(load previous data to newly initialized kernel)"
    print "\thelp"
    sys.exit()

def main():
    # TODO check stonybrook group; check sudo

    if len(sys.argv) < 2:
        usage()
    op = sys.argv[1]

    sb = SBrack()

    if op == "add_user":
        if len(sys.argv) != 3:
            usage()
        sb.add_user(sys.argv[2])
    elif op == "del_user":
        if len(sys.argv) != 3:
            usage()
        sb.del_user(sys.argv[2])
    elif op == "list_user":
        if len(sys.argv) != 2:
            usage()
        sb.list_user()
    elif op == "add_role":
        if len(sys.argv) != 4:
            usage()
        sb.add_role(sys.argv[2], sys.argv[3])
    elif op == "del_role":
        if len(sys.argv) != 3:
            usage()
        sb.del_role(sys.argv[2])
    elif op == "list_role":
        if len(sys.argv) != 2:
            usage()
        sb.list_role()
    elif op == "assign":
        if len(sys.argv) != 4:
            usage()
        sb.assign(sys.argv[2], sys.argv[3])
    elif op == "revoke":
        if len(sys.argv) != 4:
            usage()
        sb.revoke(sys.argv[2], sys.argv[3])
    elif op == "reset_db":
        if len(sys.argv) != 2:
            usage()
        sb.reset()
    elif op == "init_kernel_from_db":
        if len(sys.argv) != 2:
            usage()
        sb.db_to_kernel()
    else:
        usage()

    sb.dump()

if __name__ == '__main__':
    main()
