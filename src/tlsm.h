#ifndef _TLSM_H
#define _TLSM_H

#include <linux/errno.h>
#include <linux/mm.h>


struct policy {
    short int type;
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

extern struct plist* tlsm_policies;

#endif /* _TLSM_H */