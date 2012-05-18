/* Copyright (c) 2012 Sudhir Kasanavesi
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This file consists of the structure definition of required by the system
 * call. The user application must include this header file pass the 
 * structure as argument to the system call.
 */
#define __NR_xcrypt 349

typedef struct mysyscallargs {
	char *in_file;		/* input file name */
	char *out_file;		/* output file name */
	char *keybuf;		/* buffer to hold the key */
	char *cipherMethod;	/* cipher method */
	int flags;		/* Flag indicating encrypt/decrypt */
				/* if LSB is 0 - encrypt, else decrypt */
	int keylen; 		/* indicates length of the key buffer */
} myhw1args;

