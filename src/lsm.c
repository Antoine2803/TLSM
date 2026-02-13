#include <linux/security.h>
#include <linux/export.h>
#include <linux/lsm_hooks.h>
#include <uapi/linux/lsm.h>
#include <linux/module.h>
#include <linux/dcache.h>
#include <linux/delay.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/in6.h>
#include <linux/un.h>

#include "tlsm.h"
#include "utils.h"
#include "access.h"

static int mode = 0;
module_param(mode, int, S_IRUGO);
MODULE_PARM_DESC(mode, "TLSM mode");

struct lsm_blob_sizes tlsm_blob_sizes __ro_after_init = {
	.lbs_task = sizeof(struct tlsm_task_security),
};

inline struct tlsm_task_security *get_task_security(struct task_struct *ts)
{
	return ts->security + tlsm_blob_sizes.lbs_task;
};

struct plist *tlsm_policies;
struct list_head tlsm_watchdogs;


/* TLSM Operation hooks */
/* these hooks are called on operations */
static int tlsm_hook_open(struct file *f)
{
	const int buflen = 256;
	char buf[256];

	char *res = d_path(&f->f_path, buf, buflen);

	struct access_t access_request;
	access_request.op = TLSM_FILE_OPEN;
	access_request.object = res;

	return autorize_access(access_request);
}

static int __tlsm_hook_socket(struct socket *sock, struct sockaddr *address, int addrlen, tlsm_ops_t sock_op)
{
	char ip[48];
	struct access_t access_request;
	access_request.op = sock_op;

	switch (address->sa_family)
	{
	case AF_UNIX:
		struct sockaddr_un *addr_un = (struct sockaddr_un *)address;
		access_request.object = addr_un->sun_path;
		break;

	case AF_INET:
		struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
		snprintf(ip, sizeof(ip), "%pI4", &addr4->sin_addr);
		access_request.object = ip;
		break;

	case AF_INET6:
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)address;
		snprintf(ip, sizeof(ip), "%pI6", &addr6->sin6_addr);
		access_request.object = ip;
		break;

	default:
		break;
	}

	return autorize_access(access_request);
}

static int tlsm_hook_sbind(struct socket *sock, struct sockaddr *address, int addrlen)
{
	return __tlsm_hook_socket(sock, address, addrlen, TLSM_SOCKET_BIND);
}

static int tlsm_hook_sconnect(struct socket *sock, struct sockaddr *address, int addrlen)
{
	return __tlsm_hook_socket(sock, address, addrlen, TLSM_SOCKET_CONNECT);
}

/* TLSM security hooks */
/* these hooks handle the allocation and destruction
 *of the opaque security struct */

static int tlsm_task_allocate(struct task_struct *task, u64 clone_flags)
{
	return 0;
}

static void tlsm_task_free(struct task_struct *task)
{
}

static struct security_hook_list hooks[] __ro_after_init = {
	// syscall hooks
	LSM_HOOK_INIT(file_open, tlsm_hook_open),
	LSM_HOOK_INIT(socket_bind, tlsm_hook_sbind),
	LSM_HOOK_INIT(socket_connect, tlsm_hook_sconnect),

	// tlsm memory management hooks
	LSM_HOOK_INIT(task_alloc, tlsm_task_allocate),
	LSM_HOOK_INIT(task_free, tlsm_task_free),
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
		printk(KERN_ERR "[TLSM] failed to init policies !");
	}
	INIT_LIST_HEAD(&tlsm_watchdogs);
	
	return 0;
}

DEFINE_LSM(tlsm) = {
	.name = "tlsm",
	.init = tlsm_init,
	.blobs = &tlsm_blob_sizes,
};
