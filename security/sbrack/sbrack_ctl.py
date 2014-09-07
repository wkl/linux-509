#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Utils to manage role and user (talking to kernel) with persistant storage

import pickle
import getopt
import pwd
import os

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
    def __init__(self):
        self.users = {}
        self.role = {}

    def dump(self, db="sbrack.db"):
        pass

    def user_in_sb_group(self, name):
        for grp in grp.getgrall():
            if grp.gr_name == 'stonybrook':
                return name in grp.gr_mem

    def add_user(self, name):
        try:
            u = pwd.getpwnam(name)
            if self.users.has_key(name):
                raise
            user = User(name, u.pw_uid)
            if Kernel.add_user(user):
                self.users[name] = user
            else:
                raise
        except:
            print "User not found on Linux or already exist in SBRACK"

    def del_user(self, name):
        try:
            pwd.getpwnam(name)
            if Kernel.del_user(self.users[name]):
                self.users.pop(name)
            else:
                raise
        except:
            print "User not found on Linux or not exist in SBRACK"

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
            return False
        os.close(fd)
        return True

def main():
    # TODO check stonybrook group
    sb = SBrack()
    sb.add_user('david')
    sb.del_user('david')

if __name__ == '__main__':
    main()
