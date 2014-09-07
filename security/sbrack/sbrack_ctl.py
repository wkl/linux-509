#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Utils to manage role and user (talking to kernel) with persistant storage

import pickle
import getopt
import pwd, grp
import os
import sys

R = CAN_READ = 00040
W = CAN_WRITE = 00020
X = CAN_EXEC = 00010

class Role:
    total = 0
    def __init__(self, name, rid, permission):
        self.name = name
        self.rid = total + 1;
        self.permission = permission
    
class User:
    def __init__(self, name, uid):
        self.name = name
        self.uid = uid
        self.roles = {}

#import pdb; pdb.set_trace()
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

    def __del__(self):
        self.dump()

    @property
    def users(self):
        return self.data['users']

    @property
    def roles(self):
        return self.data['roles']

    def dump(self):
        with open(self.DB_PATH, "wb") as f:
            pickle.dump(self.data, f)

    def user_in_sb_group(self, name):
        for g in grp.getgrall():
            if g.gr_name == self.SBRACK_GROUP:
                return name in g.gr_mem

    def validate_user(self, name, should_exist=True):
        try:
            pwd_u = pwd.getpwnam(name)
        except:
            raise Exception("not exist on Linux")

        if not self.user_in_sb_group(name):
            raise Exception("not in '%s' group" % self.SBRACK_GROUP)

        if not should_exist and self.users.has_key(name):
            raise Exception("already exist in SBRACK")
        elif should_exist and not self.users.has_key(name):
            raise Exception("not exist in SBRACK")

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

    def add_role(self, name):
        try:
            pwd_u = self.validate_user(name, should_exist=False)
            user = User(name, pwd_u.pw_uid)
            Kernel.add_user(user)
            self.users[name] = user
        except Exception as ex:
            print "user[%s]: %s" % (name, ex.message)

class Kernel:
    SYSFS_USER_PATH = "/sys/kernel/sbrack/user"
    SYSFS_ROLE_PATH = "/sys/kernel/sbrack/role"

    def __init__(self):
        # TODO assert initialization of /sys/kernel/sbrack
        pass

    @classmethod
    def add_user(self, User):
        return self.sbrack_write("add %d" % User.uid, self.SYSFS_USER_PATH)

    @classmethod
    def del_user(self, User):
        return self.sbrack_write("del %d" % User.uid, self.SYSFS_USER_PATH)

    @classmethod
    def sbrack_write(self, cmd, where):
        fd = os.open(where, os.O_WRONLY)
        if os.write(fd, cmd) < 0:
            os.close(fd)
            raise Exception("failed to commit to kernel")
        os.close(fd)

def usage():
    print "Usage:"
    print "\tadd_user name"
    print "\tdel_user name"
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
    else:
        usage()

    sb.dump()

if __name__ == '__main__':
    main()
