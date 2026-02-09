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

static int tlsm_hook_sbind(struct socket *sock, struct sockaddr *address, int addrlen)
{
	kuid_t uid;
	char comm[TASK_COMM_LEN];
	char exe_buf[256];
	char *exe_path = "unknown";

	struct task_struct *curr = get_current();

	uid = current_uid();

	get_task_comm(comm, curr);

	struct file *exe_file = get_task_exe_file(curr);
	if (exe_file)
	{
		char *tmp = d_path(&exe_file->f_path, exe_buf, sizeof(exe_buf));
		if (!IS_ERR(tmp))
			exe_path = tmp;
	}

	struct policy_node *tmp = tlsm_policies->head;

	while (tmp)
	{
		if (tmp->policy->op == TLSM_SOCKET_BIND)
		{
			if (strncmp(comm, tmp->policy->subject, strlen(tmp->policy->subject)) == 0)
			{
				if (tmp->policy->object_type == AF_INET)
				{
					struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
					char ip[16];
					snprintf(ip, sizeof(ip), "%pI4", &addr4->sin_addr);

					if (strcmp(ip, tmp->policy->object) == 0)
					{
						printk(KERN_DEBUG "[TLSM][SOCK][BLOCK] blocking %s bind to %s", exe_path, ip);
						return 1;
					}
				}
				if (tmp->policy->object_type == AF_INET6)
				{
					struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)address;
					char ip[48];
					snprintf(ip, sizeof(ip), "%pI6", &addr6->sin6_addr);

					if (strcmp(ip, tmp->policy->object) == 0)
					{
						printk(KERN_DEBUG "[TLSM][SOCK][BLOCK] blocking %s bind to %s", exe_path, ip);
						return 1;
					}
				}
				if (address->sa_family == AF_UNIX)
				{
					struct sockaddr_un *addr_un = (struct sockaddr_un *)address;

					if (strcmp(addr_un->sun_path, tmp->policy->object) == 0)
					{
						printk(KERN_DEBUG "[TLSM][SOCK][BLOCK] blocking %s bind to %s", exe_path, addr_un->sun_path);
						return 1;
					}
				}
			}
		}
		tmp = tmp->next;
	}

	return 0;
}

static int tlsm_hook_sconnect(struct socket *sock, struct sockaddr *address, int addrlen)
{
	kuid_t uid;
	char comm[TASK_COMM_LEN];
	char exe_buf[256];
	char *exe_path = "unknown";

	struct task_struct *curr = get_current();

	uid = current_uid();

	get_task_comm(comm, curr);

	struct file *exe_file = get_task_exe_file(curr);
	if (exe_file)
	{
		char *tmp = d_path(&exe_file->f_path, exe_buf, sizeof(exe_buf));
		if (!IS_ERR(tmp))
			exe_path = tmp;
	}

	struct policy_node *tmp = tlsm_policies->head;

	while (tmp)
	{
		if (tmp->policy->op == TLSM_SOCKET_CONNECT)
		{
			if (strncmp(comm, tmp->policy->subject, strlen(tmp->policy->subject)) == 0)
			{
				if (tmp->policy->object_type == AF_INET)
				{
					struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
					char ip[16];
					snprintf(ip, sizeof(ip), "%pI4", &addr4->sin_addr);

					if (strcmp(ip, tmp->policy->object) == 0)
					{
						printk(KERN_DEBUG "[TLSM][SOCK][BLOCK] blocking %s connect to %s", exe_path, ip);
						return 1;
					}
				}
				if (tmp->policy->object_type == AF_INET6)
				{
					struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)address;
					char ip[48];
					snprintf(ip, sizeof(ip), "%pI6", &addr6->sin6_addr);

					if (strcmp(ip, tmp->policy->object) == 0)
					{
						printk(KERN_DEBUG "[TLSM][SOCK][BLOCK] blocking %s connect to %s", exe_path, ip);
						return 1;
					}
				}
				if (address->sa_family == AF_UNIX)
				{
					struct sockaddr_un *addr_un = (struct sockaddr_un *)address;

					if (strcmp(addr_un->sun_path, tmp->policy->object) == 0)
					{
						printk(KERN_DEBUG "[TLSM][SOCK][BLOCK] blocking %s connect to %s", exe_path, addr_un->sun_path);
						return 1;
					}
				}
			}
		}
		tmp = tmp->next;
	}

	return 0;
}

static struct security_hook_list hooks[] __ro_after_init = {
	LSM_HOOK_INIT(file_open, tlsm_hook_open),
	LSM_HOOK_INIT(socket_bind, tlsm_hook_sbind),
	LSM_HOOK_INIT(socket_connect, tlsm_hook_sconnect),
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
