#ifndef _TLSM_UTILS_H
#define _TLSM_UTILS_H

char **str_split(char *string, const char delimiter, int *out_count);
struct policy *parse_policy(char *rule);
void free_karray_from(char **array, int start, int len);

struct plist *tlsm_plist_new(void);
int tlsm_plist_add(struct plist *plist, struct policy *policy);
int tlsm_plist_del(struct plist *plist, int index);
void tlsm_plist_free(struct plist *plist);

struct policy *tlsm_policy_dup(struct policy *policy);
void tlsm_policy_free(struct policy *policy);

struct tlsm_watchdog *parse_watchdog(char *str);
void signal_watchdog(int uid, int request_number);

void plist_debug(struct plist *l);
char *get_current_exe_path(struct task_struct *t);

#endif // _TLSM_UTILS_H
