#ifndef TLSM_FS_H
#define TLSM_FS_H

#include <linux/semaphore.h>

#include "common.h"

struct fs_request {
    unsigned long long number;
    struct semaphore sem;
    tlsm_category_t answer;
    struct dentry* request_file;
};

struct fs_request* create_fs_request(int uid, int request_number);
void remove_fs_file(struct fs_request *req);

#endif // TLSM_FS_H