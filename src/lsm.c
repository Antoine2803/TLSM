#include <linux/security.h>
#include <linux/export.h>
#include <linux/lsm_hooks.h>
#include <uapi/linux/lsm.h>
#include <linux/module.h>
#include <linux/dcache.h>
#include <linux/delay.h>

#include "tlsm.h"
#include "utils.h"

static int mode = 0;
module_param(mode, int, S_IRUGO);
MODULE_PARM_DESC(mode, "TLSM mode");

struct plist *tlsm_policies;

static int tlsm_hook_open(struct file *f)
{
	kuid_t uid;
	const int buflen = 256;
	char buf[256];
	char comm[TASK_COMM_LEN];
	char exe_buf[256];
	char *exe_path = "unknown";

	struct task_struct *curr = get_current();

	uid = current_uid();
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

	struct policy_node *tmp = tlsm_policies->head;

	while (tmp)
	{
		if (tmp->policy->op == TLSM_FILE_OPEN)
		{
			if (strncmp(comm, tmp->policy->subject, strlen(tmp->policy->subject)) == 0)
			{
				if (strncmp(res, tmp->policy->object, strlen(tmp->policy->object)) == 0)
				{
					printk(KERN_DEBUG "[TLSM][FS][BLOCK] blocking %s access to %s", exe_path, res);
					return 1;
				}
			}
		}
		tmp = tmp->next;
	}

	return 0;
}

static struct security_hook_list hooks[] __ro_after_init = {
	LSM_HOOK_INIT(file_open, tlsm_hook_open),
};

static const struct lsm_id tlsm_lsmid = {
	.name = "tlsm",
	.id = 114,
};

static int __init tlsm_init(void)
{
	security_add_hooks(hooks, ARRAY_SIZE(hooks), &tlsm_lsmid);
	printk(KERN_INFO "[TLSM] loaded with mode %d", mode);
	tlsm_policies = tlsm_plist_new();
	if (!tlsm_policies)
	{
		printk(KERN_ERR "[TLSM] failed to init policies ! TODO: remove hooks on init failure");
	}
	return 0;
}

DEFINE_LSM(tlsm) = {
	.name = "tlsm",
	.init = tlsm_init,
};
