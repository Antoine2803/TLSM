#include <linux/security.h>
#include <linux/types.h>
#include <linux/dcache.h>

#include "tlsm.h"

static ssize_t tlsm_read(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	const int plen = 256;
	char fpath[plen];
	char *res = d_path(&file->f_path, fpath, plen);
	printk(KERN_DEBUG "[TLSM] read to file %s, out buff size %lu", res, count);
	
	// change with actual value and length 
	const char* r = "test read operations";
	const int rlen=21;
	
	
	if (*ppos >= rlen || !count) {
		return 0;
	} 

	if (copy_to_user(buf, r, rlen)) {
		return -EFAULT;
	}
	*ppos+=rlen;
	return rlen;
}

static ssize_t tlsm_write(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{

	const int plen = 256;
	char fpath[plen];
	char *res = d_path(&file->f_path, fpath, plen);
	printk(KERN_DEBUG "[TLSM] write to file %s", res);
	return count;
}

static const struct file_operations tlsm_ops = {
	.read  = tlsm_read,
	.write = tlsm_write,
};

/**
 * tlsm_interface_init - Initialize /sys/kernel/security/tlsm/ interface.
 *
 * Returns 0.
 */
static int tlsm_interface_init(void)
{
	struct dentry* tlsm_fs_root = securityfs_create_dir("tlsm", NULL);
	printk(KERN_DEBUG "[TLSM] fs created");
	securityfs_create_file("testfile", 0666, tlsm_fs_root, NULL, &tlsm_ops);
	return 0;
}

fs_initcall(tlsm_interface_init);