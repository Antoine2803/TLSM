#include <linux/security.h>
#include <linux/export.h>
#include <linux/lsm_hooks.h>
#include <uapi/linux/lsm.h>
#include <linux/module.h>
#include <linux/dcache.h>
#include <linux/delay.h>

#include "tlsm.h"

static int mode = 0;
module_param(mode, int, S_IRUGO);
MODULE_PARM_DESC(mode, "TLSM mode");

static int count = 0;

static int log_open(struct file *f)
{
	kuid_t uid;
	const int buflen = 256;
	char buf[buflen];
	char comm[TASK_COMM_LEN];
	char exe_buf[256];
	char *exe_path = "unknown";

	struct task_struct *curr = get_current();

	uid = current_uid();
	struct inode *inode = file_inode(f);
	char *res = d_path(&f->f_path, buf, buflen);

	get_task_comm(comm, curr);

	struct file *exe_file = get_task_exe_file(curr);
	if (exe_file)
	{
		char *tmp = d_path(&exe_file->f_path, exe_buf, sizeof(exe_buf));
		if (!IS_ERR(tmp))
			exe_path = tmp;
		fput(exe_file);
	}

	if (IS_ERR(res))
		res = "unknown";

	if (strstr(res, "/home/") != NULL)
	{
		count++;
		printk(KERN_DEBUG
			   "[TLSM] (%d) pid=%d uid=%d comm=%s exe=%s accessing %s (inode=%ld)\n",
			   count,
			   task_tgid_nr(current),
			   __kuid_val(uid),
			   comm,
			   exe_path,
			   res,
			   inode->i_ino);

		if ((strstr(comm, "cat") != NULL) && (strstr(res, "test.txt") != NULL))
		{
			ssleep(5);
			return 0;
		}
		if ((strstr(comm, "ls") != NULL) && (strstr(res, "image") != NULL))
		{
			return 1;
		}
	}

	return 0;
}

static struct security_hook_list hooks[] __ro_after_init = {
	LSM_HOOK_INIT(file_open, log_open),
};

static const struct lsm_id tlsm_lsmid = {
	.name = "tlsm",
	.id = 114,
};

static int __init tlsm_init(void)
{
	security_add_hooks(hooks, ARRAY_SIZE(hooks), &tlsm_lsmid);
	printk(KERN_INFO "TLSM: loaded with mode %d", mode);
	return 0;
}

DEFINE_LSM(tlsm) = {
	.name = "tlsm",
	.init = tlsm_init,
};
