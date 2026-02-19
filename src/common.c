#include <linux/string.h>
#include "common.h"

const char *tlsm_cat2str(tlsm_category_t category)
{
    return category2str[(int)category].str;
}

tlsm_category_t str2tlsm_cat(const char *str)
{
    int j;
    for (j = 0; j < sizeof(category2str) / sizeof(category2str[0]); ++j) {
        if (!strncmp(str, category2str[j].str, strlen(str)))
            return category2str[j].val;
    }
    printk(KERN_ERR "[TLSM][ERROR] Couldn't parse category %s, assuming TLSM_DENY", str);
    return TLSM_DENY;
}

const char *tlsm_ops2str(tlsm_ops_t op)
{
    return op2data[(int)op].str;
}

tlsm_ops_t str2tlsm_ops(const char *str)
{
    int j;
    for (j = 0; j < sizeof(op2data) / sizeof(op2data[0]); ++j)
        if (!strncmp(str, op2data[j].str, strlen(str)))
            return op2data[j].val;
    return TLSM_OP_UNDEFINED;
}

int tlsm_op2argc(tlsm_ops_t op) {
    return op2data[(int)op].argc;
}
