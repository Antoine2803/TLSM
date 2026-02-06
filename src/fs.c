#include <linux/security.h>
#include <linux/types.h>
#include <linux/dcache.h>
#include <linux/string.h>

#include "tlsm.h"
#include "utils.h"
#include "common.h"

static ssize_t tlsm_read(struct file *file, char __user *buf,
						 size_t count, loff_t *ppos)
{
	const int plen = 256;
	char fpath[256];
	char *res = d_path(&file->f_path, fpath, plen);
	printk(KERN_DEBUG "[TLSM] read to file %s, out buff size %lu", res, count);

	int rlen = 0;
	long pos = *ppos;

	char *kbuf;
	kbuf = memdup_user_nul(buf, count);

	if (strncmp((const char *)&file->f_path.dentry->d_iname, "list_policies", 13) == 0 && strlen((const char *)&file->f_path.dentry->d_iname) == 13)
	{
		printk(KERN_DEBUG "[TLSM][FS-REEAD] list_policies request (count=%zd, pos=%ld)", count, pos);
		struct policy_node *curr = tlsm_policies->head;
		int i = 0;
		while (curr && count - pos)
		{
			struct policy *p = curr->policy;
			int j = scnprintf(&kbuf[pos], count - pos, "rule #%d : %s %s %s\n", i, tlsm_ops2str(p->op), p->subject, p->object);
			rlen += j;
			pos += j;
			i++;
			curr = curr->next;
		}
	}
	else
	{
		printk(KERN_DEBUG "[TLSM] fs error");
	}

	printk(KERN_DEBUG "[TLSM] read request output %s", kbuf);

	if (*ppos >= rlen || !count)
	{
		return 0;
	}

	if (copy_to_user(buf, kbuf, rlen))
	{
		return -EFAULT;
	}
	*ppos += rlen;
	return rlen;
}

static ssize_t tlsm_write(struct file *file, const char __user *buf,
						  size_t count, loff_t *ppos)
{

	const int plen = 256;
	char fpath[256];
	char *res = d_path(&file->f_path, fpath, plen);
	printk(KERN_DEBUG "[TLSM] write to file %s", res);

	char *state;

	state = memdup_user_nul(buf, count);
	if (IS_ERR(state))
		return PTR_ERR(state);

	if (strncmp((const char *)&file->f_path.dentry->d_iname, "add_policy", 10) == 0 && strlen((const char *)&file->f_path.dentry->d_iname) == 10)
	{
		printk(KERN_DEBUG "[TLSM][ADD_RULE] %s.", state);

		struct policy *p = parse_policy(state);

		if (p == NULL)
		{
			printk(KERN_ERR "[TLSM][ERROR] cannot create policy");
		}
		else
		{
			int res = tlsm_plist_add(tlsm_policies, p);

			if (res != 0)
				printk(KERN_ERR "[TLSM][ERROR] cannot add new rule");
		}
	}

	kfree(state);
	return count;
}

static const struct file_operations tlsm_ops = {
	.read = tlsm_read,
	.write = tlsm_write,
};

/**
 * tlsm_interface_init - Initialize /sys/kernel/security/tlsm/ interface.
 *
 * Returns 0.
 */
static int tlsm_interface_init(void)
{
	struct dentry *tlsm_fs_root = securityfs_create_dir("tlsm", NULL);
	printk(KERN_DEBUG "[TLSM] fs created");
	securityfs_create_file("add_policy", 0666, tlsm_fs_root, NULL, &tlsm_ops);
	securityfs_create_file("list_policies", 0666, tlsm_fs_root, NULL, &tlsm_ops);
	return 0;
}

fs_initcall(tlsm_interface_init);