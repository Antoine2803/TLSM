#ifndef ACCESS_H
#define ACCESS_H

#include "common.h"
#include "tlsm.h"

#define DEFAULT_SCORE_UPDATE 0 // use a negative value to decrease score

struct access
{
    short supervised;
    unsigned int score;
    unsigned int score_delta;

    tlsm_ops_t op;
    char *subject;
    char *object;
    void *meta;
};

int process_policy(struct policy *pol, struct access *access_request);
int autorize_access(struct access access_request);
int allow_req_fs_op(struct task_struct *t);
int tlsmd_request(tlsm_category_t cat, struct access *access_request);

#endif // ACCESS_H