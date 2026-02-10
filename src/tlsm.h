#ifndef _TLSM_H
#define _TLSM_H

#include <linux/errno.h>
#include <linux/mm.h>

#include "common.h"

struct policy
{
    tlsm_ops_t op;
    char *subject;
    char *object;

    unsigned long long hit_count;
};

struct plist
{
    struct policy_node *head;
    struct policy_node *tail;
};

struct policy_node
{
    struct policy_node *next;
    struct policy *policy;
};

struct tlsm_request
{
    tlsm_ops_t op;
    char *object;
    char *subject;
};

extern struct lsm_blob_sizes tlsm_blob_sizes;
inline struct tlsm_task_security *get_task_security(struct task_struct *ts);

struct tlsm_task_security
{
    /* when changing this struct, adjust tlsm_task_alloc et tlsm_task_free accordingly */
    unsigned long long hit_count;
};

extern struct plist *tlsm_policies; // linked list of active policies

#endif /* _TLSM_H */