#include <linux/semaphore.h>

#include "tlsm.h"
#include "access.h"
#include "utils.h"
#include "fs.h"

static unsigned long long request_count = 0;

int tlsmd_request(tlsm_category_t cat, struct access *access_request)
{
    // ask user
    kuid_t uid;
    uid = current_uid();

    if (__kuid_val(uid) == 0) // Don't block root actions for now
        return 0;

    if (cat == TLSM_ASK)
    {
        access_request->supervised = 1;
    }
    else
    {
        access_request->supervised = 0;
    }

    struct task_struct *curr = get_current();
    struct tlsm_task_security *ts = get_task_security(curr);
    struct op_stat *stats;
    stats = kzalloc(sizeof(*stats) * TLSM_OPS_LEN, GFP_KERNEL);
    memcpy(stats, ts->stats, sizeof(struct op_stat) * TLSM_OPS_LEN);

    access_request->subject = get_exe_path_for_task(curr);
    access_request->score = ts->score;
    access_request->score_delta = DEFAULT_SCORE_UPDATE;

    struct fs_request *fs_req = create_fs_request(__kuid_val(uid), *access_request, stats, request_count++);
    if (!fs_req)
    {
        kfree(stats);
        kfree(access_request->subject);
        return -EPERM;
    }

    int ret = down_timeout(&(fs_req->sem), msecs_to_jiffies(request_timeout * 1000));
    if (ret == 0 && fs_req->answer != NULL)
    {
        // acquire was successfull
        int res = fs_req->answer->allow;
        printk(KERN_DEBUG "[TLSM][ACCESS] semaphore OK, got answer %d", res);
        access_request->score_delta = fs_req->answer->score_delta;
        kfree(stats);
        kfree(access_request->subject);
        remove_fs_file(fs_req);
        return -res;
    }
    else
    {
        // timeout or other issue
        printk(KERN_DEBUG "[TLSM][ACCESS] semaphore timeout or answer parsing failure (or another, unspecified issue)");
        kfree(stats);
        kfree(access_request->subject);
        remove_fs_file(fs_req);
        return -EPERM;
    }
}

/**
 * process_policy - process a policy depending on its category (allow, deny, ask)
 *
 * Return 0 if the operation is allowed or -EPERM is not allowed.
 * For "ask" policies, ask the user via security fs. If answer times out or error, default to -EPERM.
 */
int process_policy(struct policy *pol, struct access* access_request)
{
    switch (pol->category)
    {
    case TLSM_ANALYZE:
        return tlsmd_request(TLSM_ANALYZE, access_request);
        break;
    case TLSM_ASK:
        return tlsmd_request(TLSM_ASK, access_request);
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
        if (p->category == TLSM_ANALYZE)
        {
            if (strcmp(exe_path, p->subject) == 0)
                goto apply;
        }
        else if (p->op == access_request.op)
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

    // allowing operation if not handled
    return 0;

apply:
    int answer = process_policy(p, &access_request);
    ts->stats[access_request.op].total++;

    score_update(&ts->score, access_request.score_delta);

    if (answer == 0)
    {
        kfree(exe_path);
        return 0;
    }
    else
    {
        ts->stats[access_request.op].deny++;
        p->hit_count++;
        printk(KERN_DEBUG "[TLSM][ACCESS][BLOCK] %s %s %s (%llu time, %u score)", exe_path, tlsm_ops2str(access_request.op), access_request.object, ts->stats[access_request.op].deny, ts->score);
        // rejecting operation
        kfree(exe_path);

        return -EPERM;
    }
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