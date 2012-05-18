# Copyright (c) 2012 Sudhir Kasanavesi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This file consists of commands to create the output files. Once this 
# file is executed, it creates sys_xcrypt.ko file and xcipher files.
# It cleans up all the output files and temporary files when a make clean
# is executed.

obj-y := xcrypt.o
obj-m := sys_xcrypt.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
LIBS=-lcrypto
EXTRA_CFLAGS=-g
all:
	make -C $(KDIR) SUBDIRS=$(PWD) modules
	gcc -Wall -Werror xcipher.c -o xcipher -lssl -Iusr/src/linux-headers/include
default: 
	make -C $(KDIR) SUBDIRS=$(PWD) modules
	gcc -Wall -Werror xcipher.c -o xcipher -lssl -Iusr/src/linux-headers/include
clean: 
	make -C $(KDIR) SUBDIRS=$(PWD) clean
	rm xcipher
