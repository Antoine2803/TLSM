#ifndef TLSM_FS_H
#define TLSM_FS_H

#include <linux/semaphore.h>

#include "access.h"
#include "common.h"

struct fs_request
{
    unsigned long long number;
    struct access access_request;
    struct semaphore sem;
    tlsm_category_t answer;
    struct dentry *request_file;
};

struct fs_request *create_fs_request(int uid, struct access access_request, int request_number);
void remove_fs_file(struct fs_request *req);

#endif // TLSM_FS_H