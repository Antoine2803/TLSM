#include <linux/string.h>
#include "common.h"

const char* tlsm_ops2str(tlsm_ops_t op) {
    return op2str[(int)op].str;
}

tlsm_ops_t str2tlsm_ops(const char *str)
{
    int j;
    for (j = 0;  j < sizeof (op2str) / sizeof (op2str[0]);  ++j)
        if (!strncmp(str, op2str[j].str, strlen(str)))
            return op2str[j].val;    
    return TLSM_OP_UNDEFINED;
}