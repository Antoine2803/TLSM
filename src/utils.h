#ifndef _TLSM_UTILS_H
#define _TLSM_UTILS_H

char **str_split(char *string, const char delimiter, int *out_count);
struct policy *parse_policy(char *rule);
struct plist *tlsm_plist_new(void);
int tlsm_plist_add(struct plist *plist, struct policy *policy);
void tlsm_plist_free(struct plist *plist);
struct policy *tlsm_policy_dup(struct policy *policy);
void tlsm_policy_free(struct policy *policy);
void plist_debug(struct plist *l);

#endif // _TLSM_UTILS_H
