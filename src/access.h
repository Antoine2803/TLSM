#ifndef ACCESS_H
#define ACCESS_H

struct access_t
{
    tlsm_ops_t op;
    char *object;
};

int process_policy(struct policy *pol, struct access_t access_request);
int autorize_access(struct access_t access_request);

#endif // ACCESS_H