
#include "tlsm.h"
#include "access.h"
#include "utils.h"

extern struct plist *tlsm_policies;

int autorize_access(struct access_t access_request)
{
    char comm[TASK_COMM_LEN];
    struct policy_node *pointer = tlsm_policies->head;
    
    struct task_struct* task = get_current();
    struct tlsm_task_security *ts = get_task_security(task);
    
    get_task_comm(comm, task);
    
    // char *exe_path = "unknown";
    // struct file *exe_file = get_task_exe_file(curr);
    // if (exe_file)
    // {
    //     char *tmp = d_path(&exe_file->f_path, exe_buf, sizeof(exe_buf));
    //     if (!IS_ERR(tmp))
    //         exe_path = tmp;
    // }

    while (pointer)
    {
        struct policy *p = pointer->policy;
        if (p->op == access_request.op)
        {
            if (strncmp(comm, p->subject, strlen(p->subject)) == 0)
            {
                if (strncmp(access_request.object, p->object, strlen(p->object)) == 0)
                {
                    ts->hit_count++;
                    p->hit_count++;
                    printk(KERN_DEBUG "[TLSM][ACCESS][BLOCK] %s %s %s (%llu time)", comm, tlsm_ops2str(access_request.op), access_request.object, ts->hit_count);
                    return 1;
                }
            }
        }
        pointer = pointer->next;
    }

    // allowing operation
    return 0;
}