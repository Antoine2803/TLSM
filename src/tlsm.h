#ifndef _TLSM_H
#define _TLSM_H

#include <linux/errno.h>
#include <linux/mm.h>

#include "common.h"

struct policy {
    tlsm_category_t category;
    tlsm_ops_t op;
    char* subject;
    char* object;
};

struct plist {
    struct policy_node* head;
    struct policy_node* tail;
};

struct policy_node {
    struct policy_node* next;
    struct policy* policy;
};

struct tlsm_request {
    tlsm_category_t category; // indicates the general cate
    tlsm_ops_t op;
    char* object;
    char* subject;
};

extern struct plist* tlsm_policies; // linked list of active policies



#endif /* _TLSM_H */