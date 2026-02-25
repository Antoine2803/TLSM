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
#include <linux/limits.h>
#include <linux/binfmts.h>

#include "tlsm.h"
#include "utils.h"
#include "access.h"

int request_timeout = 20;
module_param(request_timeout, int, S_IRUGO);
MODULE_PARM_DESC(request_timeout, "TLSM interactive request timeout");

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
	char *buf = kzalloc(sizeof(char) * PATH_MAX, GFP_KERNEL);
	char *res = d_path(&f->f_path, buf, PATH_MAX);

	struct access access_request;
	access_request.op = TLSM_FILE_OPEN;
	access_request.object = res;

	int code = autorize_access(access_request);
	kfree(buf);

	return code;
}

static int __tlsm_hook_socket(struct socket *sock, struct sockaddr *address, int addrlen, tlsm_ops_t sock_op)
{
	char ip[48];
	struct access access_request;
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

/**
 * Dangereux
 */
static int tlsm_hook_task_kill(struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred)
{
	if (!sig) // SIG_NULL
		return 0;
	if (cred) // USB IO Comment
		return 0;

	// Ignorer les threads kernel
	if (!(current->mm))
		return 0;

	if (info && info->si_pid == 0 && info->si_uid == 0)
	{ // if info avaliable and signal has been sent by kernel / admin / init -> allow by default
		return 0;
	}

	struct access access_request;
	access_request.op = TLSM_SIGNAL;
	access_request.object = get_exe_path_for_task(p);

	return autorize_access(access_request);
}

static int tlsm_hook_bprm_check_security(struct linux_binprm *bprm)
{

	char *exe_path = kzalloc(sizeof(char) * PATH_MAX, GFP_KERNEL);
	char *res = d_path(&bprm->file->f_path, exe_path, PATH_MAX);

	struct access access_request;
	access_request.op = TLSM_EXECVE;
	access_request.object = res;

	int code = autorize_access(access_request);
	kfree(exe_path);

	return code;
}

/* TLSM security hooks */
/* these hooks handle the allocation and destruction
 *of the opaque security struct */

static int tlsm_task_allocate(struct task_struct *task, u64 clone_flags)
{
	struct tlsm_task_security *ts = get_task_security(task);
	ts->score = 100;
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
	LSM_HOOK_INIT(task_kill, tlsm_hook_task_kill),
	LSM_HOOK_INIT(bprm_check_security, tlsm_hook_bprm_check_security),

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
	printk(KERN_INFO "[TLSM] loaded with interactive timeout=%d", request_timeout);
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
