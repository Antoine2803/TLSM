#include <linux/security.h>
#include <linux/cred.h>
#include <linux/types.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <linux/limits.h>

#include "fs.h"
#include "tlsm.h"
#include "utils.h"
#include "access.h"
#include "common.h"

struct dentry *tlsm_fs_root = NULL;

unsigned long long last_read = 0;

static ssize_t tlsm_read(struct file *file, char __user *buf,
						 size_t count, loff_t *ppos)
{
	char *fpath = kzalloc(sizeof(char) * PATH_MAX, GFP_KERNEL);
	if (unlikely(!fpath))
		return 0;

	char *res = d_path(&file->f_path, fpath, PATH_MAX);
	printk(KERN_DEBUG "[TLSM][FS] read to file %s, out buff size %lu", res, count);

	int rlen = 0;
	long pos = *ppos;

	char *kbuf;
	kbuf = memdup_user_nul(buf, count);
	if (IS_ERR(kbuf))
	{
		kfree(fpath);
		return PTR_ERR(kbuf);
	}

	if (strncmp((const char *)&file->f_path.dentry->d_iname, "list_policies", 13) == 0 && strlen((const char *)&file->f_path.dentry->d_iname) == 13)
	{
		printk(KERN_DEBUG "[TLSM][FS] read list_policies request (count=%zd, pos=%ld)", count, pos);
		struct policy_node *curr = tlsm_policies->head;

		// select if this is a new read from the beginning
		// or the continuation of a previous read
		unsigned long long i = 0;
		if (pos > 0)
		{
			i = last_read;
		}
		else
		{
			last_read = 0;
		}

		// seek to last read policy
		for (unsigned long long j = 0; j < i; j++)
		{
			if (curr)
				curr = curr->next;
		}

		while (curr && count - rlen > 512)
		{
			struct policy *p = curr->policy;
			int j = scnprintf(&kbuf[rlen], count - rlen, "rule #%lld : %s %s %s %s (hit count %lld)\n", i, p->subject, tlsm_cat2str(p->category), tlsm_ops2str(p->op), p->object, p->hit_count);
			rlen += j;
			i++;
			curr = curr->next;
		}
		last_read = i;
	}
	else
	{
		printk(KERN_DEBUG "[TLSM][ERROR] fs error - cannot read this file");
	}

	kfree(fpath);

	if (rlen == 0 || !count)
	{
		kfree(kbuf);
		return 0;
	}
	else if (copy_to_user(buf, kbuf, rlen))
	{
		kfree(kbuf);
		return -EFAULT;
	}

	if (kbuf)
		kfree(kbuf);

	*ppos += rlen;
	return rlen;
}

static ssize_t tlsm_write(struct file *file, const char __user *buf,
						  size_t count, loff_t *ppos)
{
	char *fpath = kzalloc(sizeof(char) * PATH_MAX, GFP_KERNEL);
	if (unlikely(!fpath))
		return count;

	char *state;
	state = memdup_user_nul(buf, count);

	if (IS_ERR(state))
	{
		kfree(fpath);
		return PTR_ERR(state);
	}

	if (strncmp((const char *)&file->f_path.dentry->d_iname, "add_policy", 10) == 0 && strlen((const char *)&file->f_path.dentry->d_iname) == 10)
	{
		struct policy *p = parse_policy(state);

		if (p == NULL)
		{
			printk(KERN_ERR "[TLSM][FS] cannot create policy");
			kfree(fpath);
			kfree(state);
			return -EINVAL;
		}
		else
		{
			int res = tlsm_plist_add(tlsm_policies, p);

			if (res != 0)
			{
				printk(KERN_ERR "[TLSM][FS] cannot add new rule");
				tlsm_policy_free(p);
			}
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
				printk(KERN_ERR "[TLSM][FS][ERROR] no existing rule at index %d", target);
				kfree(fpath);
				kfree(state);
				return -EINVAL;
			}
		}
		else
		{
			printk(KERN_ERR "[TLSM][FS] failed to parse policy index, error %d", ret);
			kfree(fpath);
			kfree(state);
			return -EINVAL;
		}
	}
	else if (strncmp((const char *)&file->f_path.dentry->d_iname, "add_watchdog", 12) == 0 && strlen((const char *)&file->f_path.dentry->d_iname) == 12)
	{
		struct tlsm_watchdog *nw = parse_watchdog(state);
		if (nw != NULL)
		{
			size_t bef = list_count_nodes(&tlsm_watchdogs);
			list_add_tail(&nw->node, &tlsm_watchdogs);
			size_t after = list_count_nodes(&tlsm_watchdogs);
			printk(KERN_DEBUG "[TLSM][FS] Adding watchdog, %zu->%zu", bef, after);
		}
		else
		{
			printk(KERN_ERR "[TLSM][FS][ERROR] Cannot create new watchdog");
		}
	}
	else
	{
		char *res = d_path(&file->f_path, fpath, PATH_MAX);
		printk(KERN_ERR "[TLSM][FS] error, unsupported write op %s", res);
	}

	kfree(fpath);
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
	if (allow_req_fs_op(get_current()))
		return 0;

	char *fpath = kzalloc(sizeof(char) * PATH_MAX, GFP_KERNEL);
	if (unlikely(!fpath))
		return 0;

	char *res = d_path(&file->f_path, fpath, PATH_MAX);
	printk(KERN_DEBUG "[TLSM][FS] read to file %s, out buff size %lu", res, count);

	int rlen = 0;
	long pos = *ppos;

	char *kbuf;
	kbuf = memdup_user_nul(buf, count);
	if (IS_ERR(kbuf))
	{
		kfree(fpath);
		return PTR_ERR(kbuf);
	}

	struct fs_request *req = (struct fs_request *)file->f_inode->i_private;

	if (strncmp((const char *)&file->f_path.dentry->d_iname, "request_", 8) == 0)
	{
		// serialize supervised or not
		int k = scnprintf(&kbuf[pos], count - pos, "%hd %d\n", req->access_request.supervised, req->access_request.score);
		rlen += k;
		pos += k;

		// serialize access_request, human-readable format
		k = scnprintf(&kbuf[pos], count - pos, "%s trying to %s %s\n", req->access_request.subject, tlsm_ops2str(req->access_request.op), req->access_request.object);
		rlen += k;
		pos += k;
		printk(KERN_DEBUG "[TLSM][FS] read buffer content %d out of %zd", rlen, count);

		// serialize op_stat
		for (int i = 0; i < TLSM_OPS_LEN; i++)
		{
			k = scnprintf(&kbuf[pos], count - pos, "%lld %lld\n", req->stats[i].deny, req->stats[i].total);
			rlen += k;
			pos += k;
		}
	}
	else
	{
		printk(KERN_DEBUG "[TLSM][ERROR] fs error");
	}

	kfree(fpath);

	if (*ppos >= rlen || !count)
	{
		kfree(kbuf);
		return 0;
	}

	if (copy_to_user(buf, kbuf, rlen))
	{
		kfree(kbuf);
		return -EFAULT;
	}

	if (kbuf)
		kfree(kbuf);

	*ppos += rlen;
	return rlen;
}

static ssize_t tlsm_req_write(struct file *file, const char __user *buf,
							  size_t count, loff_t *ppos)
{
	if (allow_req_fs_op(get_current()))
	{
		*ppos += count;
		return count;
	}

	char *state;
	state = memdup_user_nul(buf, count);
	if (IS_ERR(state))
	{
		return PTR_ERR(state);
	}

	struct fs_request *req = (struct fs_request *)file->f_inode->i_private;

	char *fpath = kzalloc(sizeof(char) * PATH_MAX, GFP_KERNEL);
	if (unlikely(!fpath))
	{
		kfree(state);
		return count;
	}

	char *res = d_path(&file->f_path, fpath, PATH_MAX);
	printk(KERN_DEBUG "[TLSM] write to request file %s", res);

	req->answer = parse_answer(state);

	// wake up lsm hook pending on user response
	up(&(req->sem));

	if (state)
		kfree(state);

	kfree(fpath);

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
	securityfs_create_file("add_watchdog", 0666, tlsm_fs_root, NULL, &tlsm_ops);
	securityfs_create_file("add_policy", 0600, tlsm_fs_root, NULL, &tlsm_ops);
	securityfs_create_file("del_policy", 0600, tlsm_fs_root, NULL, &tlsm_ops);
	securityfs_create_file("list_policies", 0600, tlsm_fs_root, NULL, &tlsm_ops);
	return 0;
}

fs_initcall(tlsm_interface_init);

/**
 * create_fs_request - create a new file associated with a access request
 *
 * Returns the fs_request associated with the created file. Can return NULL
 */
struct fs_request *create_fs_request(int uid, struct access access_request, struct op_stat *stats, int request_number)
{
	if (!tlsm_fs_root)
	{
		printk(KERN_ERR "[TLSM][FS][ERROR] attemped to create user request file but fs not initialized");
		return NULL;
	}

	struct fs_request *req;
	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return NULL;

	printk(KERN_DEBUG "[TLSM][FS] creating request file for uid %d, request %d", uid, request_number);

	req->number = request_number;
	memcpy(&req->access_request, &access_request, sizeof(struct access));
	req->stats = stats;
	sema_init(&req->sem, 0); // init caller wake-up semaphore

	// convert numbers to string
	char buf[16];
	char buf2[16];
	snprintf(buf, sizeof(buf), "user_%d", uid);
	snprintf(buf2, sizeof(buf2), "request_%d", request_number);

	// create user request folder
	struct dentry *user_fsdir;

	user_fsdir = securityfs_create_dir(buf, tlsm_fs_root);
	int lookedup = 0;
	if (IS_ERR(user_fsdir))
	{
		if (PTR_ERR(user_fsdir) == -EEXIST)
		{
			printk(KERN_DEBUG "[TLSM][FS] dir already exists, looking up for dentry");
			struct qstr name = QSTR(buf);
			lookedup = 1;
			user_fsdir = lookup_noperm(&name, tlsm_fs_root);

			if (IS_ERR(user_fsdir))
			{
				printk(KERN_ERR "[TLSM][FS][ERROR] lookup failed");
				kfree(req);
				return NULL;
			}
		}
		else
		{
			printk(KERN_ERR "[TLSM][FS][ERROR] create_dir failed");
			goto fs_request_fail;
		}
	}
	else
	{
		// folder _created_ successfully
		// setting perms
		user_fsdir->d_inode->i_gid = current_gid();
		user_fsdir->d_inode->i_uid = current_uid();
		user_fsdir->d_inode->i_mode = S_IFDIR | 0700;
	}

	req->request_file = securityfs_create_file(buf2, 0600, user_fsdir, req, &tlsm_reqfile_ops);
	if (IS_ERR(req->request_file))
	{
		printk(KERN_ERR "[TLSM][FS] tried to overwrite existing request file request_%d", request_number);
		goto fs_request_fail;
	}
	printk(KERN_DEBUG "[TLSM][FS] secufs request file request_%d created", request_number);
	req->request_file->d_inode->i_gid = current_gid();
	req->request_file->d_inode->i_uid = current_uid();

	signal_watchdog(uid, request_number);

	if (lookedup)
		dput(user_fsdir);

	return req;

fs_request_fail:
	if (lookedup)
		dput(user_fsdir);
	kfree(req);
	return NULL;
}

void remove_fs_file(struct fs_request *req)
{
	printk(KERN_DEBUG "[TLSM][FS] removing file %s", req->request_file->d_iname);
	securityfs_remove(req->request_file);
	kfree(req->answer);
	kfree(req);
}
