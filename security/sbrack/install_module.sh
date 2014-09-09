#!/bin/sh
set -x
lsmod
rmmod sbrack
insmod sbrack.ko && python sbrack_ctl.py init_kernel_from_db
lsmod
