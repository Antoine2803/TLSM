#include <linux/security.h>
#include <linux/export.h>
#include <linux/lsm_hooks.h>
#include <uapi/linux/lsm.h>
#include <linux/module.h>

static int mode = 0;
module_param(mode, int, S_IRUGO);
MODULE_PARM_DESC(mode, "TLSM mode");



static int __init tlsm_init(void)
{
	printk(KERN_INFO "TLSM: loaded with mode %d", mode);
	return 0;
}

DEFINE_LSM(tlsm) = {
	.name = "tlsm",
	.init = tlsm_init,
};
