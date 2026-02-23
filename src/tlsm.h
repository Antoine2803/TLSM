#ifndef _TLSM_H
#define _TLSM_H

#include <linux/errno.h>
#include <linux/mm.h>

#include "common.h"

struct policy
{
    tlsm_category_t category;
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

struct tlsm_watchdog
{
    int uid; // watchdog's owern user id
    int pid; // pid of wathdog process
    struct list_head node;
};

extern struct lsm_blob_sizes tlsm_blob_sizes;
inline struct tlsm_task_security *get_task_security(struct task_struct *ts);

struct op_stat
{
    unsigned long long total;
    unsigned long long deny;
};

struct tlsm_task_security
{
    /* when changing this struct, adjust tlsm_task_alloc et tlsm_task_free accordingly
       if using pointers to allocated data structures
    */

    unsigned int score;

    struct op_stat stats[TLSM_OPS_LEN];
};

extern struct plist *tlsm_policies; // linked list of active policies
extern struct list_head tlsm_watchdogs;
extern int request_timeout; // timeout for interactive mode

#endif /* _TLSM_H */