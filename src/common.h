#ifndef TLSM_COMMON_H
#define TLSM_COMMON_H

typedef enum tlsm_category
{
    TLSM_ALLOW, // must be first so TLSM_ALLOW equals 0 !!
    TLSM_DENY,
    TLSM_ASK,
} tlsm_category_t;

static const struct
{
    tlsm_category_t val;
    const char *str;
} category2str[] = {
    {TLSM_ALLOW, "allow"},
    {TLSM_DENY, "deny"},
    {TLSM_ASK, "ask"},
};

const char *tlsm_cat2str(tlsm_category_t op);
tlsm_category_t str2tlsm_cat(const char *str);


/* TLSM OPERATIONS */
/* to add a new operation, one must *at least* add the operation in the enum and in the op2str table */

typedef enum tlsm_ops
{
    TLSM_OP_UNDEFINED,
    TLSM_FILE_OPEN,
    TLSM_SOCKET_BIND,
    TLSM_SOCKET_CONNECT,
    TLSM_SIGNAL,
    TLSM_EXECVE,
} tlsm_ops_t;

static const struct
{
    tlsm_ops_t val;
    const char *str;
    const int argc;
} op2data[] = {
    {TLSM_OP_UNDEFINED, "undefined", 0},
    {TLSM_FILE_OPEN, "open", 1},
    {TLSM_SOCKET_BIND, "bind", 1},
    {TLSM_SOCKET_CONNECT, "connect", 1},
    {TLSM_SIGNAL, "signal", 0},
    {TLSM_EXECVE, "execve", 1},
};

const char *tlsm_ops2str(tlsm_ops_t op);
tlsm_ops_t str2tlsm_ops(const char *str);
int tlsm_op2argc(tlsm_ops_t op);

#endif /* TLSM_COMMON_H */