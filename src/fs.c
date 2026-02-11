#include <linux/security.h>
#include <linux/types.h>
#include <linux/dcache.h>
#include <linux/string.h>

#include "fs.h"
#include "tlsm.h"
#include "utils.h"
#include "common.h"

struct dentry *tlsm_fs_root = NULL;
struct fs_request tlsm_request;

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
		printk(KERN_DEBUG "[TLSM][FS] read list_policies request (count=%zd, pos=%ld)", count, pos);
		struct policy_node *curr = tlsm_policies->head;
		int i = 0;
		while (curr && count - pos)
		{
			struct policy *p = curr->policy;
			int j = scnprintf(&kbuf[pos], count - pos, "rule #%d : %s %s %s %s (hit count %lld)\n", i, tlsm_ops2str(p->op), tlsm_cat2str(p->category), p->subject, p->object, p->hit_count);
			rlen += j;
			pos += j;
			i++;
			curr = curr->next;
		}
	}
	else
	{
		printk(KERN_DEBUG "[TLSM][FS] fs error");
	}

	printk(KERN_DEBUG "[TLSM][FS] read request output %s", kbuf);

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
	printk(KERN_DEBUG "[TLSM][FS] write to file %s", res);

	char *state;

	state = memdup_user_nul(buf, count);
	if (IS_ERR(state))
		return PTR_ERR(state);

	if (strncmp((const char *)&file->f_path.dentry->d_iname, "add_policy", 10) == 0 && strlen((const char *)&file->f_path.dentry->d_iname) == 10)
	{
		printk(KERN_DEBUG "[TLSM][FS][ADD_RULE] %s.", state);

		struct policy *p = parse_policy(state);

		if (p == NULL)
		{
			printk(KERN_ERR "[TLSM][FS] cannot create policy");
		}
		else
		{
			int res = tlsm_plist_add(tlsm_policies, p);

			if (res != 0)
				printk(KERN_ERR "[TLSM][FS] cannot add new rule");
		}
	}
	else if (strncmp((const char *)&file->f_path.dentry->d_iname, "del_policy", 10) == 0 && strlen((const char *)&file->f_path.dentry->d_iname) == 10)
	{
		int target;

		// Remove trailing '\n'
		int len = strlen(state);
		if (*(state + len - 1) == '\n')
			*(state + len - 1) = '\0';

		int ret = kstrtoint(state, 10, &target);
		if (ret == 0)
		{
			if (tlsm_plist_del(tlsm_policies, target) != 0)
			{
				printk(KERN_ERR "[TLSM][FS] no existing rule at index %d", target);
			}
		}
		else
		{
			printk(KERN_ERR "[TLSM][FS] failed to parse policy index, error %d", ret);
		}
	}
	else
	{
		printk(KERN_ERR "[TLSM][FS] error, unsupported write op %s", res);
	}

	kfree(state);
	return count;
}

static const struct file_operations tlsm_ops = {
	.read = tlsm_read,
	.write = tlsm_write,
};

static ssize_t tlsm_req_read(struct file *file, char __user *buf,
							 size_t count, loff_t *ppos)
{
	// TODO : serialize request
	return 0;
}

static ssize_t tlsm_req_write(struct file *file, const char __user *buf,
							  size_t count, loff_t *ppos)
{

	char *state;
	state = memdup_user_nul(buf, count);

	const int plen = 256;
	char fpath[256];
	char *res = d_path(&file->f_path, fpath, plen);
	printk(KERN_DEBUG "[TLSM] write to request file %s", res);

	switch (*state)
	{
	case '0':
		tlsm_request.answer = TLSM_ALLOW;
		break;

	case '1':
		tlsm_request.answer = TLSM_DENY;
		break;

	default:
		printk(KERN_ERR "[TLSM][ERROR] Cannot parse anwser %s assuming deny", state);
		tlsm_request.answer = TLSM_DENY;
		break;
	}

	// wake up lsm hook pending on user response
	printk(KERN_DEBUG "[TLSM] increasing semaphore");
	up(&(tlsm_request.sem));

	*ppos += count;
	return count;
}

static const struct file_operations tlsm_reqfile_ops = {
	.read = tlsm_req_read,
	.write = tlsm_req_write,
};

/**
 * tlsm_interface_init - Initialize /sys/kernel/security/tlsm/ interface.
 *
 * Returns 0.
 */
static int tlsm_interface_init(void)
{
	tlsm_fs_root = securityfs_create_dir("tlsm", NULL);
	printk(KERN_DEBUG "[TLSM] fs created");
	securityfs_create_file("add_policy", 0666, tlsm_fs_root, NULL, &tlsm_ops);
	securityfs_create_file("del_policy", 0666, tlsm_fs_root, NULL, &tlsm_ops);
	securityfs_create_file("list_policies", 0666, tlsm_fs_root, NULL, &tlsm_ops);
	return 0;
}

fs_initcall(tlsm_interface_init);

struct fs_request *create_fs_request(int uid, int request_number)
{
	if (!tlsm_fs_root) {
		printk(KERN_ERR "[TLSM][FS][ERROR] attemped to create user request file but fs not initialized");
		return NULL;
	}

	printk(KERN_DEBUG "[TLSM][FS] creating request file for uid %d, request %d", uid, request_number);
	
	sema_init(&tlsm_request.sem, 0); // init caller wake-up semaphore

	// convert numbers to string
	char buf[16], buf2[16];
	snprintf(buf, sizeof(buf), "user_%d", uid);
	snprintf(buf2, sizeof(buf2), "request_%d", request_number);

	// create request file
	// TODO : check if already exists
	struct dentry *user_fsdir = securityfs_create_dir(buf, tlsm_fs_root);
	
	// TODO check if already exist
	securityfs_create_file(buf2, 0666, user_fsdir, NULL, &tlsm_reqfile_ops);

	// TODO: set user as owner of dir & files
	return &tlsm_request;
}
