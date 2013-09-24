/*
 * Copyright (c) 2003-2011 Erez Zadok
 * Copyright (c) 2003-2006 Charles P. Wright
 * Copyright (c) 2005-2007 Josef 'Jeff' Sipek
 * Copyright (c) 2005-2006 Junjiro Okajima
 * Copyright (c) 2005      Arun M. Krishnakumar
 * Copyright (c) 2004-2006 David P. Quigley
 * Copyright (c) 2003-2004 Mohammad Nayyer Zubair
 * Copyright (c) 2003      Puja Gupta
 * Copyright (c) 2003      Harikesavan Krishnan
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "wrapfs.h"
int wrapfs_removexattr(struct dentry *dentry, const char *name);

/* This is lifted from fs/xattr.c */
void *wrapfs_xattr_alloc(size_t size, size_t limit)
{
	void *ptr;

	if (size > limit)
		return ERR_PTR(-E2BIG);

	if (!size)		/* size request, no buffer is needed */
		return NULL;

	ptr = kmalloc(size, GFP_KERNEL);
	if (unlikely(!ptr))
		return ERR_PTR(-ENOMEM);
	return ptr;
}

/*
 * BKL held by caller.
 * dentry->d_inode->i_mutex locked
 */
ssize_t wrapfs_getxattr(struct dentry *dentry, const char *name, void *value,
			 size_t size)
{
	struct dentry *lower_dentry = NULL;
	//struct dentry *parent;
	struct path lower_path;
	int err = -EOPNOTSUPP;
	//bool valid;

	//wrapfs_read_lock(dentry->d_sb, wrapfs_SMUTEX_CHILD);
//	parent = wrapfs_lock_parent(dentry, wrapfs_DMUTEX_PARENT);
	//wrapfs_lock_dentry(dentry, wrapfs_DMUTEX_CHILD);

	// valid = __wrapfs_d_revalidate(dentry, parent, false);
	// if (unlikely(!valid)) {
		// err = -ESTALE;
		// goto out;
	// }

	lower_dentry = wrapfs_lower_dentry(dentry,&lower_path);

	err = vfs_getxattr(lower_dentry, (char *) name, value, size);

//out:
//	wrapfs_check_dentry(dentry);
//	wrapfs_unlock_dentry(dentry);
//	wrapfs_unlock_parent(dentry, parent);
//	wrapfs_read_unlock(dentry->d_sb);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * BKL held by caller.
 * dentry->d_inode->i_mutex locked
 */
int wrapfs_setxattr(struct dentry *dentry, const char *name,
		     const void *value, size_t size, int flags)
{


	struct dentry *lower_dentry = NULL;
	//struct dentry *parent;
	struct path lower_path;
	int err = -EOPNOTSUPP;
	struct file *lower_file;
	struct hash_desc desc;
	mm_segment_t oldfs;
	struct scatterlist sg[1];
	unsigned char *digest=NULL;
	struct inode *ip = NULL;
	 loff_t i_size;
	     int rc=0;
	         int nbytes;
	         int retval,retval1;
	         unsigned char *buff;
	         char *rbuf;
	         int i;
	         char *intgval="user.integrity_val";
	
	if (current_cred()->uid != 0)
     return -EACCES;

	if(!strcmp("user.integrity_val",name))
	{
		printk("user.integrity_val cannot be set by user \n");
		return -EACCES;
	}	
	ip=dentry->d_inode;

	//printk("hello  %d \n %s %d \n", strcmp("user.has_integrity",name), (char *)value,current_cred()->uid);


	if(!strcmp("user.has_integrity",name) && !memcmp((char *)value,"1",1))
	{
		lower_dentry = wrapfs_lower_dentry(dentry, &lower_path);
		err = vfs_setxattr(lower_dentry, (char *) name, (void *) value,size, flags);

		if(S_ISREG(ip->i_mode))
		{	
		
		lower_file = dentry_open(lower_dentry, lower_path.mnt,0, current_cred());

		if (!lower_file || IS_ERR(lower_file))
        {
        	printk("error in FP \n");
        	goto out;
        }

        if(!lower_file->f_op->write)
         {

            printk("the user doesn't have permission to read/write on the file system doesn't allow reads \n");
            goto out;
         }  

        lower_file->f_pos= 0;
        oldfs = get_fs();
        set_fs(KERNEL_DS);


                desc.tfm = crypto_alloc_hash("md5",0,0x00000080);

                if(IS_ERR(desc.tfm))
                {
                    err=PTR_ERR(desc.tfm);
                    printk("Error attempting to allocate crypto context l err = %d \n",err);
                    goto out;
                }

                desc.flags=0;  

                rc=crypto_hash_init(&desc);
				
				if(rc)
           		{	
                	printk("Error initializing crypto hash ; rc= %d \n",rc);
                	crypto_free_hash(desc.tfm);
   	                //filp_close(lower_file, NULL);
					goto out;
				}


		rbuf=kzalloc(PAGE_SIZE,GFP_KERNEL);

        if(!rbuf)
        {
            
            //filp_close(lower_file, NULL);
            err=-ENOMEM;
        	goto out;
        }

        memset(rbuf,0,PAGE_SIZE);

		i_size = i_size_read(lower_file->f_dentry->d_inode);


		 while(lower_file->f_pos<i_size)
        {

           nbytes=lower_file->f_op->read(lower_file,rbuf,PAGE_SIZE,&lower_file->f_pos);
           
           if(nbytes<0)
           {
               rc= nbytes;
               break;
           }

           if(nbytes==0)
                break;
        
           //fp->f_pos+=nbytes;
           printk("nbytes : %d\n",nbytes);
           sg_init_one(sg,rbuf,nbytes);
           rc= crypto_hash_update(&desc,sg,nbytes);

           if(rc)
           {
                printk("Error updating crypto hash ; rc= %d \n",rc);
                crypto_free_hash(desc.tfm);
                kfree(rbuf);
               // filp_close(lower_file, NULL);
                err=rc;
                goto out;
           }

       }

 	  	kfree(rbuf);
    
        digest=kmalloc(16,GFP_KERNEL);

        if(digest==NULL)
        {
            printk("Memory not allocated to digest  \n");
            //filp_close(lower_file, NULL);
            err=-ENOMEM;
        	goto out;
        }

           rc=crypto_hash_final(&desc,digest);
       
        if(rc)
        {
            printk("Error finalizing crypto hash ; rc= %d \n",rc);
            kfree(digest);
           // filp_close(lower_file, NULL);
            err=rc;
            goto out;
        }
			for(i=0;i<16;i++)
				printk("%.2x ",digest[i]);

        retval= vfs_setxattr(lower_file->f_path.dentry,"user.integrity_val",digest,16,0);

        if(retval<0)
        {
            printk("Error in setting attributes \n");
            kfree(digest);
           // filp_close(lower_file, NULL);
            err=retval;
        	goto out;
        }
    	 kfree(digest);
    	 err=retval;
    }
    	 goto out;
	}

	else if(!strcmp("user.has_integrity",name) && !memcmp((char *)value,"0",1))
	{
		lower_dentry = wrapfs_lower_dentry(dentry, &lower_path);
		err = vfs_setxattr(lower_dentry, (char *) name, (void *) value,size, flags);

		//vfs_getxattr(fp->f_path.dentry,"user.md5sumcheck",args2->ibuf,((struct mode2args *)arg)->ilen);
		buff=kmalloc(16,GFP_KERNEL);
		retval1=vfs_getxattr(lower_dentry,"user.integrity_val",buff,16);
		
		
		if(retval1<=0)
        {
            printk(" Error getting attribute / the attribute doesn't exist \n");
            kfree(buff);
            //err= -EFAULT;
        	goto out;
        }

        else
        {	
        	//strcpy(name,"user.integrity_val");
        	printk("integrity_val being removed is :");
        	for(i=0;i<16;i++)
			printk(" %x ",buff[i]);
			return wrapfs_removexattr(dentry,intgval);
		}
        
	}

	else
	{
		printk("in final loop \n");
		lower_dentry = wrapfs_lower_dentry(dentry, &lower_path);
		err = vfs_setxattr(lower_dentry, (char *) name, (void *) value,size, flags);
		goto out;
	}
	

	//bool valid;

	//wrapfs_read_lock(dentry->d_sb, wrapfs_SMUTEX_CHILD);
	//parent = wrapfs_lock_parent(dentry, wrapfs_DMUTEX_PARENT);
	//wrapfs_lock_dentry(dentry, wrapfs_DMUTEX_CHILD);

	// valid = __wrapfs_d_revalidate(dentry, parent, false);
	// if (unlikely(!valid)) {
		// err = -ESTALE;
		// goto out;
	// }

		


out:
	//wrapfs_check_dentry(dentry);
	//wrapfs_unlock_dentry(dentry);
	//wrapfs_unlock_parent(dentry, parent);
	//wrapfs_read_unlock(dentry->d_sb);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * BKL held by caller.
 * dentry->d_inode->i_mutex locked
 */
int wrapfs_removexattr(struct dentry *dentry, const char *name)
{
	struct dentry *lower_dentry = NULL;
	//struct dentry *parent;
	struct path lower_path;
	int err = -EOPNOTSUPP;
	struct inode *i = NULL;
	char *intgval="user.integrity_val";
	/*uid_t uid,euid;

	uid=getuid();
	euid=geteuid();


	if (uid<0 || uid!=euid || uid==0)
		return -EACCES;*/

	if (current_cred()->uid != 0)
     return -EACCES;

	printk("in wrapfs_removexattr\n");
	//bool valid;
	/*if(!strcmp("user.integrity_val",name))
	{
		printk("user.integrity_val removed be set by user \n");
		return -EACCES;
	}*/
	// wrapfs_read_lock(dentry->d_sb, wrapfs_SMUTEX_CHILD);
	// parent = wrapfs_lock_parent(dentry, wrapfs_DMUTEX_PARENT);
	// wrapfs_lock_dentry(dentry, wrapfs_DMUTEX_CHILD);

	// valid = __wrapfs_d_revalidate(dentry, parent, false);
	// if (unlikely(!valid)) {
		// err = -ESTALE;
		// goto out;
	// }
	i=dentry->d_inode;

	if(!strcmp("user.has_integrity",name) && (S_ISREG(i->i_mode)))
	{
		wrapfs_removexattr(dentry,intgval);
	}

	lower_dentry = wrapfs_lower_dentry(dentry,&lower_path);

	err = vfs_removexattr(lower_dentry, (char *) name);

//out:
//	wrapfs_check_dentry(dentry);
//	wrapfs_unlock_dentry(dentry);
//	wrapfs_unlock_parent(dentry, parent);
//	wrapfs_read_unlock(dentry->d_sb);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * BKL held by caller.
 * dentry->d_inode->i_mutex locked
 */
ssize_t wrapfs_listxattr(struct dentry *dentry, char *list, size_t size)
{
	struct dentry *lower_dentry = NULL;
	//struct dentry *parent;
	struct path lower_path;
	int err = -EOPNOTSUPP;
	char *encoded_list = NULL;
	//bool valid;

	// wrapfs_read_lock(dentry->d_sb, wrapfs_SMUTEX_CHILD);
	// parent = wrapfs_lock_parent(dentry, wrapfs_DMUTEX_PARENT);
	// wrapfs_lock_dentry(dentry, wrapfs_DMUTEX_CHILD);

	// valid = __wrapfs_d_revalidate(dentry, parent, false);
	// if (unlikely(!valid)) {
		// err = -ESTALE;
		// goto out;
	// }

	lower_dentry = wrapfs_lower_dentry(dentry,&lower_path);

	encoded_list = list;
	err = vfs_listxattr(lower_dentry, encoded_list, size);

//out:
	//wrapfs_check_dentry(dentry);
	//wrapfs_unlock_dentry(dentry);
	//wrapfs_unlock_parent(dentry, parent);
	//wrapfs_read_unlock(dentry->d_sb);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
}
