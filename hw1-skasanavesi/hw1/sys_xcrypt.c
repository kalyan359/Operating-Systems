/* Copyright (c) 2012 Sudhir Kasanavesi
 * File consists of source-code copied from CEPH File System source in
 * linux/net/ceph/crypto.c I have copied functions ceph_aes_encrypt() and
 * ceph_aes_decrypt() functions from the file and made some modifications.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This file consists of the loadable kernel module. The function pointer 
 * which is hooked up to the system call is made to point to a function
 * which consists of the implementation of the system call. This loadable 
 * kernel module must be loaded using "insmod" before any user-application 
 * which invokes the system call is run.
 * 
 * NOTE:
 * This file consists of source code copied from linux/net/ceph/crypto.c
 * I have copied the functions ceph_aes_encrypt() and ceph_aes_decrypt() 
 * functions and renamed them to aes_encrypt() and aes_decrypt(). I have
 * modified little code in those functions
 */

#include <asm/uaccess.h>     
#include <asm/string.h>
#include <crypto/hash.h>
#include <linux/module.h>     
#include <linux/init.h>     
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include "sys_xcrypt.h"

#define FILE_PATH_MAX 254
#define AES_BLOCK_SIZE 16
#define KEYBUF_MIN 6
#define KEYBUF_MAX 4095

/* Initial IV value needed for CBC - AES encryption */
#define IV "xcrypskasanavesi"

const u8 *aes_iv = (u8 *) IV;

// Function pointer which hooks the system call and loadable kernel module
extern long (*my_fxn_ptr)(void *args);

/* 
 * This function does basic checks to see whether the parameters passed
 * to the system call are accessible or not. It does these checks before 
 * copying from user area to kernel area. It does following checks:
 * check if the arguments are NULL
 * check if keybuf is between 6-4096
 * check if input file name (path included) is too long
 * check if output file name (path included) is too long
 *
 * Input: Pointer to structure myhw1args (defined in sys_xcrypt.c) 
 * Output: If all parameters are valid, returns 0; else returns
 * respective ERRNO.
 */
long checkArguments(void *args)
{
	myhw1args *ptr = (myhw1args *) args;
	
	/* check if the pointer could be accessed */
	if (ptr == NULL || 
	    unlikely(!access_ok(VERIFY_READ, ptr, sizeof(myhw1args))))
		return -EFAULT;
	/* check if the pointer to input file name is accesible */
	if (ptr->in_file == NULL || 
	    unlikely(!access_ok(VERIFY_READ, 
	    			ptr->in_file, sizeof(ptr->in_file))))
		return -EFAULT;
	/* check if the pointer to the output file name is accessible */
	if (ptr->out_file == NULL || 
	    unlikely(!access_ok(VERIFY_READ, 
	    			ptr->out_file, sizeof(ptr->out_file))))
		return -EFAULT;
	/* check if the pointer to the key buffer is accessible */
	if (ptr->keybuf == NULL ||
	    unlikely(!access_ok(VERIFY_READ, ptr->keybuf, ptr->keylen)))
		return -EFAULT;	/* check keybuf and keylen are same length */
	/* check if the pointer to the cipher method is accesible */
	if (ptr->cipherMethod == NULL || 
	    unlikely(!access_ok(VERIFY_READ, 
	    			ptr->cipherMethod, 
	    			sizeof(ptr->cipherMethod))))
		return -EFAULT;
	/* check if file name is too long */
	if ((strlen(ptr->in_file) > FILE_PATH_MAX) || 
	    (strlen(ptr->out_file) > FILE_PATH_MAX))
		return -ENAMETOOLONG;
	/* check if keybuf is within KEYBUF_MIN and KEYBUF_MAX */
	if ((strlen(ptr->keybuf) + 1 < KEYBUF_MIN) && 
	    (strlen(ptr->keybuf) + 1 > KEYBUF_MAX))
		return -EMSGSIZE;
	return 0;
}

/*
 * This function copies the arguments passed from the user area to
 * kernel area for subsequent usage and processing.
 *
 * Input: structure to be copied from, structure to be copied to
 * Output: Returns 0 if succesful, else returns respective ERRNO.
 */
long copyUserData(myhw1args *src,myhw1args *dest)
{
	long err = 0;
    
	if((err = copy_from_user(&dest->flags, 
				 &src->flags, sizeof(int))) != 0)
		return err;
	if((err = copy_from_user(&dest->keylen, 
				 &src->keylen, sizeof(int))) != 0 )
		return err;
	/* allocate memory to store input file name and copy. */
	dest->in_file = kmalloc(strlen(src->in_file) + 1, GFP_KERNEL);
	if (!dest->in_file) {
		err = -ENOMEM;
		goto dest_in_file_fail;
	}
	if ((err = copy_from_user(dest->in_file, 
				  src->in_file, 
				  strlen(src->in_file))) != 0)
		goto dest_in_file_fail;
	/* allocate memory to store output file name and copy */
	dest->out_file = kmalloc(strlen(src->out_file) + 1, GFP_KERNEL);
	if (!dest->out_file) {
		err = -ENOMEM;
		goto dest_out_file_fail;
	}
	if ((err = copy_from_user(dest->out_file, 
				  src->out_file, 
				  strlen(src->out_file))) != 0)
		goto dest_out_file_fail;
	/* allocate memory to store cipher method and copy */
	dest->cipherMethod = kmalloc(strlen(src->cipherMethod) + 1,
				     GFP_KERNEL);
	if (!dest->cipherMethod) {
		err = -ENOMEM;
		goto dest_cipher_method_fail;
	}
	if ((err = copy_from_user(dest->cipherMethod, 
				  src->cipherMethod, 
				  strlen(src->cipherMethod))) != 0)
		goto dest_cipher_method_fail;
	/* allocate memory to store key buffer and copy */
	dest->keybuf = kmalloc(strlen(src->keybuf) + 1, GFP_KERNEL);
	if (!dest->keybuf) {
		err = -ENOMEM;
		goto dest_key_buff_fail;
	}
	if ((err = copy_from_user(dest->keybuf, 
				  src->keybuf, 
				  strlen(src->keybuf))) != 0)
		 goto dest_key_buff_fail;

	/* Null-terminate all the buffers */
	dest->keybuf[strlen(src->keybuf)] = '\0';
	dest->in_file[strlen(src->in_file)] = '\0';
	dest->out_file[strlen(src->out_file)] = '\0';
	dest->cipherMethod[strlen(src->cipherMethod)] = '\0';
	
	return err;

dest_key_buff_fail:
	kfree(dest->keybuf);
dest_cipher_method_fail:
	kfree(dest->cipherMethod);
dest_out_file_fail:
	kfree(dest->out_file);
dest_in_file_fail:
	kfree(dest->in_file);
	return err;
}

void freeUserData(myhw1args *dest)
{
	if(dest != NULL) {
		if (dest->keybuf != NULL)
			kfree(dest->keybuf);
		if (dest->cipherMethod != NULL)
			kfree(dest->cipherMethod);
		if (dest->out_file != NULL)
			kfree(dest->out_file);
		if (dest->in_file != NULL)
			kfree(dest->in_file);	
	}
}

/*
 * The source-code of this function is copied from CEPH File System source
 * in linux/net/ceph/crypto.c I have renamed it to aes_encrypt() and did some
 * modifications.
 */ 
int aes_encrypt(const void *key, int key_len,
                            void *dst, size_t *dst_len,
                            const void *src, size_t src_len)
{
	struct scatterlist sg_in[2], sg_out[1];
	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("cbc(aes)",
							      0,
							      CRYPTO_ALG_ASYNC);
	struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };
	int ret;
	void *iv;
	int ivsize;
	size_t zero_padding = (0x10 - (src_len & 0x0f));
	char pad[AES_BLOCK_SIZE];

	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	memset(pad, zero_padding, zero_padding);
        
	*dst_len = src_len + zero_padding;

	crypto_blkcipher_setkey((void *)tfm, key, key_len);
	sg_init_table(sg_in, 2);
	sg_set_buf(&sg_in[0], src, src_len);
	sg_set_buf(&sg_in[1], pad, zero_padding);
	sg_init_table(sg_out, 1);
	sg_set_buf(sg_out, dst, *dst_len);
	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	
	memcpy(iv, aes_iv, ivsize);
	/*
	print_hex_dump(KERN_ERR, "enc key: ", DUMP_PREFIX_NONE, AES_BLOCK_SIZE, 1,
			key, key_len, 1);
	print_hex_dump(KERN_ERR, "enc src: ", DUMP_PREFIX_NONE, AES_BLOCK_SIZE, 1,
			src, src_len, 1);
	print_hex_dump(KERN_ERR, "enc pad: ", DUMP_PREFIX_NONE, AES_BLOCK_SIZE, 1,
			pad, zero_padding, 1);
	*/
	ret = crypto_blkcipher_encrypt(&desc, sg_out, sg_in,
				       src_len + zero_padding);
	crypto_free_blkcipher(tfm);
	if (ret < 0){
		 /* 
		 printk(KERN_ALERT "aes_crypt failed %d\n", ret); 
		 */
		return ret;
	}
	/*
	print_hex_dump(KERN_ERR, "enc out: ", DUMP_PREFIX_NONE, AES_BLOCK_SIZE, 1,
			dst, *dst_len, 1);
        */
        return 0;
}

/*
 * The source-code of this function is copied from CEPH File System source
 * in linux/net/ceph/crypto.c I have renamed it to aes_decrypt() and did some
 * modifications.
 */ 
int aes_decrypt(const void *key, int key_len,
                            void *dst, size_t *dst_len,
                            const void *src, size_t src_len)
{
	struct scatterlist sg_in[1], sg_out[2];
	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("cbc(aes)", 
							      0,
							      CRYPTO_ALG_ASYNC);
	struct blkcipher_desc desc = { .tfm = tfm };
	char pad[AES_BLOCK_SIZE];
	void *iv;
	int ivsize;
	int ret;
	int last_byte;

	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	crypto_blkcipher_setkey((void *)tfm, key, key_len);
	sg_init_table(sg_in, 1);
	sg_init_table(sg_out, 2);
	sg_set_buf(sg_in, src, src_len);
	sg_set_buf(&sg_out[0], dst, *dst_len);
	sg_set_buf(&sg_out[1], pad, sizeof(pad));

	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);

	memcpy(iv, aes_iv, ivsize);

	/*
	print_hex_dump(KERN_ERR, "dec key: ", DUMP_PREFIX_NONE, AES_BLOCK_SIZE, 1,
			key, key_len, 1);
	print_hex_dump(KERN_ERR, "dec  in: ", DUMP_PREFIX_NONE, AES_BLOCK_SIZE, 1,
			src, src_len, 1);
	*/

	ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, src_len);
	crypto_free_blkcipher(tfm);
	if (ret < 0) {
		/*
		printk(KERN_ALERT "aes_decrypt failed %d\n", ret);
		*/
		return ret;
	}

	if (src_len <= *dst_len)
		last_byte = ((char *)dst)[src_len - 1];
	else
		last_byte = pad[src_len - *dst_len - 1];
	if (last_byte <= AES_BLOCK_SIZE && src_len >= last_byte) 
		*dst_len = src_len - last_byte;
	/*
	} else {
		
		printk(KERN_ALERT 
			"aes_decrypt got bad padding %d on src len %d\n", 
			last_byte, 
			(int)src_len);
		return -EPERM;  // bad padding 
	}
	*/

	/*
	print_hex_dump(KERN_ERR, "dec out: ", DUMP_PREFIX_NONE, AES_BLOCK_SIZE, 1,
			dst, *dst_len, 1);
	*/

	return 0;
}

/*
 * This function opens the input file and returns the pointer.
 * It also does basic error checking and checks if it has permissions
 *
 * Input: filename (path)
 * Output: Returns pointer to file if succesful, else returns NULL.
 */
struct file* openInputFile(char *in_file)
{
	struct file *filp = NULL;
	if (in_file != NULL){
		filp = filp_open(in_file, O_EXCL, 0);
		if (filp == NULL || IS_ERR(filp)){
			printk(KERN_ALERT "File open error\n");
			filp = NULL;
        	} else {

		    filp_close(filp, NULL);
		    filp = filp_open(in_file, O_RDONLY, 0);
		    if (!(filp->f_op)){
			printk(KERN_ALERT "File has no file operations\n");
			filp_close(filp, NULL);
			filp = NULL;
		    }
		    if (!filp->f_op->read){
			printk(KERN_ALERT "File has no read operations\n");
			filp_close(filp, NULL);
			filp = NULL;
		    }
		}
    	}
	return filp;
}

/*
 * This function opens/creates the output file with the same permissions as 
 * of the input file and returns the pointer.
 * It also does basic error checking and checks if it has permissions
 *
 * Input: filename (path) and mode - user permissions
 * Output: Returns pointer to file if succesful, else returns NULL.
 */
struct file* openOutputFile(char *out_file, umode_t mode)
{
	struct file *filp = NULL;
	if (out_file != NULL){
		filp = filp_open(out_file, O_WRONLY|O_CREAT, mode);
		if (IS_ERR(filp)){
			printk(KERN_ALERT "File open error\n");
			filp = NULL;
		}
		if (!(filp->f_op)){
			printk(KERN_ALERT "File has no file operations\n");
			filp_close(filp, NULL);
			filp = NULL;
		}
		if (!filp->f_op->write){
			printk(KERN_ALERT "File has no write operations\n");
			filp_close(filp, NULL);
			filp = NULL;
		}  
	}
	return filp;
}

long do_xcrypt(myhw1args *k_args, int flags)
{
	struct file *in_file, *out_file;
	mm_segment_t fs;
	size_t ret;
	char *read_buffer, *decrypt_buff;
	char *buffer, *pad_buffer, *decrypt_pad, *hashed_key; 
	umode_t in_file_mode;
	size_t in_file_size;
	int toPad, counter, buffer_len, crypt_size, rc, decrypt_len, pad_len;
	struct shash_desc *sdescmd5;
	struct crypto_shash *md5;
	u8 *md5_hash = NULL;
	char extra_pad[3];
	long toRemove = 0;
	long retCode = 0;
	int xcryptFlag = 0;	
	struct inode *outfile_inode = NULL;
	struct dentry *outfile_dentry = NULL;

	counter = 0;
	if (k_args->in_file != NULL){
		in_file = openInputFile(k_args->in_file);

		if (in_file == NULL){
			retCode = -ENOENT;
			goto end_out;
		}

		/* Get the input file size and permissions */
		in_file_size = in_file->f_path.dentry->d_inode->i_size;
		in_file_mode = in_file->f_path.dentry->d_inode->i_mode;

		/* Compute MD5 hash of the key */
		md5 = crypto_alloc_shash("md5", 0, 0);
		if (md5 == NULL) {
			retCode = -ENOMEM;
			goto in_file_fail;
		}
		crypt_size = sizeof(struct shash_desc) + crypto_shash_descsize(md5);
		sdescmd5 = kmalloc(crypt_size, GFP_KERNEL);
		if (!sdescmd5) {
			retCode = -ENOMEM;
			goto in_file_fail;
		}
		md5_hash = kmalloc(AES_BLOCK_SIZE, GFP_KERNEL);
		if (!md5_hash) {
			retCode = -ENOMEM;
			goto sdescmd5_fail;
		}

		memset(sdescmd5, 0, crypt_size);
		memset(md5_hash, 0, AES_BLOCK_SIZE);
		
		/* check memory error */
		sdescmd5->tfm = md5;
		sdescmd5->flags = 0x0;
		
		rc = crypto_shash_init(sdescmd5);
		/* check rc */
		if (rc){
			retCode = -EINVAL;
			goto md5_hash_fail;
		}
		rc = crypto_shash_update(sdescmd5,(const char *) k_args->keybuf, k_args->keylen);
		if (rc){
			retCode = -EINVAL;
			goto md5_hash_fail;
		}		
		rc = crypto_shash_final(sdescmd5, md5_hash);
		if (rc){
			retCode = -EINVAL;
			goto md5_hash_fail;
		}
		
		crypto_free_shash(md5);

		/* Calculate the number of bits to be padded */
		if (in_file_size % AES_BLOCK_SIZE == 0)
			toPad = 0;
		else
			toPad = AES_BLOCK_SIZE - (in_file_size % AES_BLOCK_SIZE);

		if (in_file != NULL) {
			out_file = openOutputFile(k_args->out_file, 
						  in_file_mode);
			if (out_file != NULL) {
			    
			    outfile_inode = out_file->f_path.dentry->d_parent->d_inode;
			    outfile_dentry = out_file->f_path.dentry;
			    if(in_file->f_path.dentry->d_inode->i_ino ==
			       out_file->f_path.dentry->d_inode->i_ino){
				retCode = -EPERM;
				goto out_file_fail;
			    }
			    
			    read_buffer = (char *) kmalloc(PAGE_SIZE, GFP_KERNEL);
			    if (!read_buffer) {
			    	retCode = -ENOMEM;
			    	goto out_file_fail;
			    }
			    buffer = (char *) kmalloc(PAGE_SIZE + AES_BLOCK_SIZE, GFP_KERNEL);
			    if (!buffer) {
			    	retCode = -ENOMEM;
			    	goto read_buffer_fail;
			    }			    
			    pad_buffer = (char *) kmalloc(2 * AES_BLOCK_SIZE, GFP_KERNEL);
			    if (!pad_buffer) {
			    	retCode = -ENOMEM;
			    	goto buffer_fail;
			    }			    
			    decrypt_pad = (char *) kmalloc(2 * AES_BLOCK_SIZE, GFP_KERNEL);
			    if (!decrypt_pad) {
			    	retCode = -ENOMEM;
			    	goto pad_buffer_fail;
			    }			    
			    decrypt_buff = (char *) kmalloc(2 * AES_BLOCK_SIZE, GFP_KERNEL);
			    if (!decrypt_buff) {
			    	retCode = -ENOMEM;
			    	goto decrypt_pad_fail;
			    }			    
			    hashed_key = (char *) kmalloc(AES_BLOCK_SIZE, GFP_KERNEL);
			    if (!hashed_key) {
			    	retCode = -ENOMEM;
			    	goto decrypt_buff_fail;
			    }			    

			    memset(read_buffer, 0, PAGE_SIZE);
			    memset(buffer, 0, PAGE_SIZE + AES_BLOCK_SIZE );
			    memset(decrypt_pad, 0, 2 * AES_BLOCK_SIZE);
			    memset(decrypt_buff, 0, 2 * AES_BLOCK_SIZE);
			    memset(hashed_key, 0, AES_BLOCK_SIZE);
			    memset(pad_buffer, 0, 2 * AES_BLOCK_SIZE);
			    pad_len = 2 * AES_BLOCK_SIZE;

			    fs = get_fs();
			    set_fs(get_ds());
			    
			    if(flags == 1) {
				sprintf(extra_pad, "%d",toPad);
				extra_pad[2] = '\0';
				memcpy(pad_buffer, extra_pad, 2);
			        out_file->f_op->write(out_file,
						      md5_hash,
						      AES_BLOCK_SIZE,
						      &out_file->f_pos);
			         xcryptFlag = aes_encrypt(md5_hash,
					    AES_BLOCK_SIZE,
					    decrypt_buff,
					    &buffer_len,
					    pad_buffer,
					    2 * AES_BLOCK_SIZE);
				if (xcryptFlag < 0 ) {
					retCode = -EFAULT;
					goto hashed_key_fail;
				}
					
			        out_file->f_op->write(out_file, 
						      pad_buffer,
						      2 * AES_BLOCK_SIZE,
						      &out_file->f_pos);
			    } else {
				in_file->f_op->read(in_file,
						    hashed_key,
						    AES_BLOCK_SIZE,
						    &in_file->f_pos);
				if(0 != memcmp(md5_hash, hashed_key, AES_BLOCK_SIZE)){
					retCode = -EPERM;
					goto hashed_key_fail;
				}
				else {
					in_file->f_op->read(in_file,
							   decrypt_pad,
							   2 * AES_BLOCK_SIZE,
							   &in_file->f_pos);
					xcryptFlag = aes_decrypt(md5_hash,
						    AES_BLOCK_SIZE,
						    decrypt_buff,
						    &decrypt_len,
						    decrypt_pad,
						    pad_len);
					if (xcryptFlag < 0 ) {
						retCode = -EFAULT;
						goto hashed_key_fail;
					}					
					memcpy(extra_pad, decrypt_pad, 2);
					extra_pad[2] = '\0';
					toRemove = simple_strtol(extra_pad, 
								 (char **)&extra_pad,
								 0);		    
				}
					
			    }
			    while ((ret = in_file->f_op->read(in_file, 
							  read_buffer, 
							  PAGE_SIZE, 
							  &in_file->f_pos))
				    > 0) {
			        if (flags == 1) { /* encrypt */
				    if (ret < PAGE_SIZE) {
				        for (counter = 0; counter < toPad; counter++)
					    memcpy(buffer+ret+counter, &toPad, 1);
					xcryptFlag = aes_encrypt(md5_hash, 
						    AES_BLOCK_SIZE, 
						    buffer,
						    &buffer_len,
						    read_buffer,
						    ret + toPad);
					if (xcryptFlag < 0 ) {
						retCode = -EFAULT;
						goto hashed_key_fail;
					}						    
					out_file->f_op->write(out_file,
							      buffer,
							      ret+toPad,
							      &out_file->f_pos);
				    } else {
					xcryptFlag = aes_encrypt(md5_hash,
						    AES_BLOCK_SIZE,
						    buffer,
						    &buffer_len,
						    read_buffer,
						    PAGE_SIZE);
					if (xcryptFlag < 0 ) {
						retCode = -EFAULT;
						goto hashed_key_fail;
					}						    
					out_file->f_op->write(out_file,
							      buffer,
							      ret,
							      &out_file->f_pos);
				    }
				} else { /* decrypt */
				    memset(buffer, 0, PAGE_SIZE);
				    buffer_len = PAGE_SIZE;
				    xcryptFlag = aes_decrypt(md5_hash, 
				    		AES_BLOCK_SIZE,
				    		buffer,
				    		&buffer_len,
				    		read_buffer,
				    		ret);
				    if (xcryptFlag < 0 ) {
					retCode = -EFAULT;
					goto hashed_key_fail;
				    }				    		
				    if (ret < PAGE_SIZE)
					ret = ret - toRemove;
				    out_file->f_op->write(out_file,
				    			  buffer,
				    			  ret,
				    			  &out_file->f_pos);
				    
				}
	            	    }   
			    set_fs(fs);
			} else { /* out_file == NULL */
			    retCode = -EFAULT;
			    goto out_file_fail;
			}
	        }
		else  {/* in_file == NULL */
			retCode = -EFAULT;
			goto md5_hash_fail;
		}
	}
	else {
		/* k_args->in_file == NULL */
		retCode = -EFAULT;
		goto end_out;
	}
hashed_key_fail:
	kfree(hashed_key);
decrypt_buff_fail:
	kfree(decrypt_buff);
decrypt_pad_fail:
	kfree(decrypt_pad);
pad_buffer_fail:
	kfree(pad_buffer);
buffer_fail:
	kfree(buffer);
read_buffer_fail:
	kfree(read_buffer);
out_file_fail:
	filp_close(out_file, NULL);
md5_hash_fail:
	kfree(md5_hash);
sdescmd5_fail:
	kfree(sdescmd5);
in_file_fail:
	filp_close(in_file, NULL);
end_out:
	if (retCode < 0){
		// Delete partial output file
		if (outfile_dentry != NULL && outfile_inode != NULL)
			vfs_unlink(outfile_inode, outfile_dentry);
	}
	return retCode;
}
 

/* Implementation of xcrypt() system call 
 * This function is called when the user-application invokes the system call.
 * 
 * Input: struct defined in the header
 * Output: Returns 0 if successful, else returns ERRNO
 */
long my_sys_xcrypt(void *args)
{    
	myhw1args *k_sys_args = NULL;
	long rc = 0;   
	int flags;
	long valid = checkArguments(args);
	
	if (0 == valid) {
		k_sys_args = kmalloc(sizeof(myhw1args), GFP_KERNEL);
		if (!k_sys_args) {
			rc = -ENOMEM;
			goto k_sys_args_fail;
		}
		memset(k_sys_args, 0, sizeof(myhw1args));
		rc = copyUserData(args, k_sys_args);
		if (rc != 0) {
			rc = -ENOMEM;
			goto k_sys_args_fail;
		}
			 
		flags = k_sys_args->flags & 1; /* Get the LSB of flags*/
		rc = do_xcrypt(k_sys_args, flags);
		//freeUserData(k_sys_args);
	} else {
		rc =  valid;
		goto out_no_dealloc;
	}
k_sys_args_fail:
	kfree(k_sys_args);
out_no_dealloc:
	return rc;
}

/* Module entry */
static int __init init_xcrypt(void)
{
	printk(KERN_ALERT "sys_xcrypt module loaded.\n");
	if (my_fxn_ptr == NULL)
		my_fxn_ptr = my_sys_xcrypt;
	else {
		printk(KERN_ALERT "sys_xcrypt module failed to load.\n");
		return -1;
	}
	return 0;         
}

/* Module exit */
static void __exit  exit_xcrypt(void)
{
	printk(KERN_ALERT "sys_xcrypt module unloaded.\n");
	if (my_fxn_ptr == my_sys_xcrypt)
		my_fxn_ptr = NULL;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SUDHIR");
MODULE_DESCRIPTION("xcrypt() System Call Implementation. "
                   "Used for encrypting and decrypting files.");

module_init(init_xcrypt);
module_exit(exit_xcrypt);

