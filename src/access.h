#ifndef ACCESS_H
#define ACCESS_H

#include "common.h"
#include "tlsm.h"

struct access
{
    tlsm_ops_t op;
    char *subject;
    char *object;
    void *meta;
};

int process_policy(struct policy *pol, struct access access_request);
int autorize_access(struct access access_request);
int allow_req_fs_op(struct task_struct *t);

#endif // ACCESS_H