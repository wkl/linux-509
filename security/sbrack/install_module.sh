#!/bin/sh
set -x
lsmod
rmmod sbrack
insmod sbrack.ko
lsmod
