/* Copyright (c) 2012 Sudhir Kasanavesi
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This file demonstrates the usage of system call. It fills up the necessary 
 * structure needed by the system call and calls it indirectly using syscall()
 */

#include <unistd.h>
#include <syscall.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <openssl/md5.h>
#include "sys_xcrypt.h"

/* To track the error number returned by the system call.*/
extern int errno;

/* structure declaration for parsing the options */
typedef struct options_struct{
	int  encryptFlag, decryptFlag, cipherFlag, pwdFlag;
	char *cipherMethod, *pwd, *inputFile, *outputFile;
} options;

/* This function uses getopt() and parses the given options
 * it fills up the options structure which is then used to 
 * invoke the system call.
 */
int parse_options(options *opts, int argc, char **argv)
{
	int opt_char, errFlag;
	errFlag = 0;

	opts->cipherMethod = "AES"; /* Default cipher method is AES */

	while ((opt_char = getopt(argc, argv, "edc::p:h")) != -1){
		switch(opt_char){
		case 'e':
			opts->encryptFlag = 1;
			break;
		case 'd':
			opts->decryptFlag = 1;
			break;
		case 'c':
			opts->cipherFlag = 1;
			opts->cipherMethod = "AES"; /* optarg; */
			break;
		case 'p':
			opts->pwdFlag = 1;
			opts->pwd = optarg;
			break;
		case 'h':
			fprintf(stdout, "Usage: %s {-e|-d} [-c ARG] {-p PASSWORD} [-h HELP] infile outfile\n", argv[0]);
			fprintf(stdout, "{-e|-d} : Use either -e to encrypt OR -d to decrypt.\n");
			fprintf(stdout, "-c : Use to specify encryption type, AES is used by default.\n" );
                	fprintf(stdout, "-p : Use to give password. Ex: -p \"this is my password\"\n");
			fprintf(stdout, "-h : Use to display this help message\n");
			fprintf(stdout, "infile : Use to specify input file name (along with path)\n");
			fprintf(stdout, "outfile : Use to specify output file name (along with path)\n"); 
			return -1;
		default: 
			errFlag = 1;
		}
	}
	
	if ((opts->encryptFlag == opts->decryptFlag) || (1 == errFlag) || 
	(0 == opts->pwdFlag) || (optind + 2 != argc)){
		fprintf(stderr, "Usage: %s {-e|-d} [-c ARG] {-p PASSWORD} [-h] infile outfile\n", argv[0]);
		return -1;
	}else{
		opts->inputFile = argv[optind];
		opts->outputFile = argv[optind + 1];
		return 0;
	}
}

/* This function is the entry point for the application. It accepts the 
 * options, parses them, fills data in the structure needed by the system
 * call and invokes the system call indirectly using syscall()
 */
int main(int argc, char *argv[])      
{
	options opts;
	unsigned char password[MD5_DIGEST_LENGTH];
	int pwdLen, validOptions;
	long syscallRetValue = 0;
	myhw1args arg1;	

	memset(&arg1, 0, sizeof arg1);
	validOptions = -1;
	memset(&opts, 0, sizeof opts);
	validOptions = parse_options(&opts,argc,argv);
       	pwdLen = strlen(opts.pwd);
       	
       	/* Compute the MD5 hash of the user pass-phrase */
       	MD5((const unsigned char *)opts.pwd, pwdLen, password);

       	/* fill the structure to be passed to the kernel */
	arg1.flags = (opts.encryptFlag == 1) ? 1 : 0;
	arg1.in_file = opts.inputFile;
	arg1.out_file = opts.outputFile;
	arg1.cipherMethod = opts.cipherMethod;
	arg1.keybuf = (char *) password;
	arg1.keylen = MD5_DIGEST_LENGTH;        

	/* System Call */
	syscallRetValue = syscall(__NR_xcrypt, &arg1);
	if (syscallRetValue != 0){
		switch (errno){
		case 1:
			printf("infile and outfile are same (or) wrong key specified\n");
			break;
		case 2:
			printf("Input file doesnot exist or not accessible\n");
			break;
		case 14:
			printf("Parameters are not accesible or NULL (or) Encrypt/Decrypt failed\n");
			break;
		case 22:
			printf("Unable to store key while encrypting\n");
			break;
		case 36:
			printf("Input file name (path) or Output file name (path) too long");
			break;
		case 90:
			printf("Pass-phrase should be within 6-4096 characters\n");
			break;
		}
		perror("Failed! ");
	}
	
	
	return 0;
}
