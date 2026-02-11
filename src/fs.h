#ifndef TLSM_FS_H
#define TLSM_FS_H

#include <linux/semaphore.h>

#include "common.h"

struct fs_request {
    struct semaphore sem;
    tlsm_category_t answer;
};

extern struct fs_request tlsm_request;

struct fs_request* create_fs_request(int uid, int request_number);

#endif // TLSM_FS_H