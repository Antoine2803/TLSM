#ifndef TLSM_COMMON_H
#define TLSM_COMMON_H

typedef enum tlsm_category
{
    TLSM_FILE,
    TLSM_NETWORK,
} tlsm_category_t;

/* TLSM OPERATIONS */
/* to add a new operation, one must *at least* add the operation in the enum and in the op2str table */

typedef enum tlsm_ops
{
    TLSM_OP_UNDEFINED,
    TLSM_FILE_OPEN,
    TLSM_SOCKET_BIND,
    TLSM_SOCKET_CONNECT
} tlsm_ops_t;

static const struct {
    tlsm_ops_t    val;
    const char *str;
} op2str [] = {
    {TLSM_OP_UNDEFINED, "undefined"},
    {TLSM_FILE_OPEN, "open"},
    {TLSM_SOCKET_BIND, "bind"},
    {TLSM_SOCKET_CONNECT, "connect"},
};

const char* tlsm_ops2str(tlsm_ops_t op);
tlsm_ops_t str2tlsm_ops(const char *str);

#endif /* TLSM_COMMON_H */