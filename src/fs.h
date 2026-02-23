#ifndef TLSM_FS_H
#define TLSM_FS_H

#include <linux/semaphore.h>

#include "access.h"
#include "common.h"
#include "tlsm.h"

#define TLSM_REQ_ALLOW 0
#define TLSM_REQ_DENY 1

struct fs_answer
{
    int allow;
    int score_delta;
};

struct fs_request
{
    unsigned long long number;
    struct access access_request;
    struct semaphore sem;
    struct fs_answer *answer;
    struct dentry *request_file;
    struct op_stat *stats;
};

struct fs_request *
create_fs_request(int uid, struct access access_request, struct op_stat *stats, int request_number);
void remove_fs_file(struct fs_request *req);

#endif // TLSM_FS_H