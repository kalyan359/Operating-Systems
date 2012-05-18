/* Copyright (c) 2012 Sudhir Kasanavesi
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This file consists of the function pointer declaration which is used 
 * to hook the system call. The address pointed by this function pointer 
 * is changed in the loadable kernel module.
 */
 
#include <linux/syscalls.h>
#include <linux/module.h>

/* Function pointer that is used to hook to the system call */
long (*my_fxn_ptr)(void *args) = NULL;

EXPORT_SYMBOL(my_fxn_ptr);

/* Actual system call */
asmlinkage long sys_xcrypt(void *args)
{
	if (my_fxn_ptr == NULL)
		return -ENOSYS;
	else
		return my_fxn_ptr(args);
}
