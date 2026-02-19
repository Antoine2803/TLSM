#include <linux/semaphore.h>

#include "tlsm.h"
#include "access.h"
#include "utils.h"
#include "fs.h"

static unsigned long long request_count = 0;

/**
 * process_policy - process a policy depending on its category (allow, deny, ask)
 *
 * Return 0 if the operation is allowed or -EPERM is not allowed.
 * For "ask" policies, ask the user via security fs. If answer times out or error, default to -EPERM.
 */
int process_policy(struct policy *pol, struct access access_request)
{
    switch (pol->category)
    {
    case TLSM_ASK:
        // ask user
        kuid_t uid;
        uid = current_uid();

        access_request.subject = get_exe_path_for_task(get_current());

        if (__kuid_val(uid) == 0) // Don't block root actions for now
            return 0;

        struct fs_request *fs_req = create_fs_request(__kuid_val(uid), access_request, request_count++);
        if (!fs_req)
            return -EPERM;

        int ret = down_timeout(&(fs_req->sem), msecs_to_jiffies(request_timeout * 1000));
        if (ret == 0)
        {
            // acquire was successfull
            printk(KERN_DEBUG "[TLSM][ACCESS] semaphore OK, got answer %s", tlsm_cat2str(fs_req->answer));
            remove_fs_file(fs_req);
            kfree(access_request.subject);
            return -(int)fs_req->answer;
        }
        else
        {
            // timeout or other issue
            printk(KERN_DEBUG "[TLSM][ACCESS] semaphore timeout");

            kfree(access_request.subject);
            remove_fs_file(fs_req);
            return -EPERM;
        }
        break;

    case TLSM_ALLOW:
        return 0;
        break;
    case TLSM_DENY:
    default:
        return -EPERM;
        break;
    }
}

int autorize_access(struct access access_request)
{
    struct policy_node *pointer = tlsm_policies->head;

    struct task_struct *task = get_current();
    struct tlsm_task_security *ts = get_task_security(task);

    char *exe_path = get_exe_path_for_task(task);

    struct policy *p;
    while (pointer)
    {
        p = pointer->policy;
        if (p->op == access_request.op)
        {
            if (strncmp(exe_path, p->subject, strlen(p->subject)) == 0)
            {
                switch (access_request.op)
                {
                case TLSM_FILE_OPEN:
                    if (strstr(access_request.object, p->object) != NULL)
                        goto apply;
                    break;

                case TLSM_SOCKET_BIND:
                case TLSM_SOCKET_CONNECT:
                    if (strncmp(access_request.object, p->object, strlen(p->object)) == 0 || strncmp(p->object, "any", strlen(p->object)) == 0)
                        goto apply;
                    break;
                case TLSM_SIGNAL:
                    goto apply;
                    break;
                case TLSM_EXECVE:
                    if (strncmp(access_request.object, p->object, strlen(p->object)) == 0 || strncmp(p->object, "any", strlen(p->object)) == 0)
                        goto apply;
                    break;
                default:
                    break;
                }
            }
        }
        pointer = pointer->next;
    }

    // allowing operation
    return 0;

apply:
    int answer = process_policy(p, access_request);
    kfree(exe_path);

    if (answer == 0)
    {
        return 0;
    }
    else
    {
        goto rejected;
    }

rejected:
    ts->hit_count++;
    score_update(&ts->score, -1);
    p->hit_count++;
    printk(KERN_DEBUG "[TLSM][ACCESS][BLOCK] %s %s %s (%llu time, %u score)", exe_path, tlsm_ops2str(access_request.op), access_request.object, ts->hit_count, ts->score);
    // rejecting operation
    return 1;
}

int allow_req_fs_op(struct task_struct *t)
{
    char *exe_path = get_exe_path_for_task(t);

    if (strcmp(exe_path, CONFIG_SECURITY_TLSM_WATCHDOG) != 0)
    {
        printk(KERN_DEBUG "[TLSM][ERROR] %s is trying to do an unauthorized operation on the fs request", exe_path);
        kfree(exe_path);
        return 1;
    }

    kfree(exe_path);
    return 0;
}