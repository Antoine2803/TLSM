#include <linux/security.h>
#include <linux/export.h>
#include <linux/lsm_hooks.h>
#include <uapi/linux/lsm.h>
#include <linux/module.h>
#include <linux/dcache.h>

static int mode = 0;
module_param(mode, int, S_IRUGO);
MODULE_PARM_DESC(mode, "TLSM mode");

static int count = 0;

static int log_open(struct file *f)
{
	kuid_t uid;
	int buflen = 256;
	char buf[buflen];
	count++;

	uid = current_uid();
	struct inode *inode = file_inode(f);
	char *res = d_path(&f->f_path, buf, buflen);

	if (IS_ERR(res))
		res = "unknown";

	printk(KERN_DEBUG "[TLSM] (%d) - %d is trying to access to file=%s (inode=%ld)", count, __kuid_val(uid), res, inode->i_ino);

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
