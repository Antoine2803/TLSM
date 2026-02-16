#include <linux/string.h>
#include <linux/signal.h>
#include <linux/signal_types.h>

#include "utils.h"
#include "common.h"
#include "tlsm.h"

/**
 * strip - get a substring from string string[start, end]
 *
 * Return: the substring
 */
static char *str_strip(char *string, int start, int end)
{
    if (!string || start < 0 || start > end)
        return NULL;

    size_t string_size = strlen(string);
    if (start > string_size)
        return NULL;

    if (end > string_size)
        end = string_size;

    size_t len = (end - start);
    char *res = (char *)kmalloc(len + 1, GFP_KERNEL);

    if (!res)
        return NULL;

    memcpy(res, string + start, len);
    res[len] = '\0';

    return res;
}

/**
 * str_split - split a strint according to a token
 *
 * Return: a list of string
 */
char **str_split(char *string, const char delimiter, int *out_count)
{
    if (!string || !out_count)
        return NULL;

    // Remove trailing '\n'
    int len = strlen(string);
    if (*(string + len - 1) == '\n')
        *(string + len - 1) = '\0';

    char **res = 0;
    size_t i = 0;
    int count = 0;
    ssize_t last_delim = -1;
    char *tmp = string;

    while (*tmp)
    {
        if (*tmp == delimiter)
        {
            if (last_delim != i - 1)
            {
                count++;
            }
            last_delim = i;
        }
        tmp++;
        i++;
    }

    if (last_delim != i - 1)
    {
        count++;
    }

    *out_count = count;

    if (count == 0)
        return NULL;

    res = kmalloc_array(count, sizeof(char *), GFP_KERNEL);

    if (!res)
        return NULL;

    char **res_cpy = res;
    char *word = NULL;
    i = 0;
    tmp = string;
    last_delim = -1;
    while (*tmp)
    {
        if (*tmp == delimiter)
        {
            if (last_delim != i - 1)
            {
                word = str_strip(string, last_delim + 1, i);
                if (!word)
                    goto strip_fail;
                *res_cpy++ = word;
            }
            last_delim = i;
        }
        tmp++;
        i++;
    }
    if (last_delim != i - 1)
    {
        word = str_strip(string, last_delim + 1, i);
        if (!word)
            goto strip_fail;
        *res_cpy = word;
    }

    return res;

strip_fail:
    while (res_cpy > res)
    {
        kfree(*--res_cpy);
    }
    kfree(res);
    return NULL;
}

/**
 * free_karray_from - free an array from the element start, (if start=0 also free the array pointer)
 */
void free_karray_from(char **array, int start, int len)
{
    if (array)
    {
        int i;
        for (i = 0; i < len; i++)
        {
            if (i >= start)
            {
                if (*(array + i))
                {
                    kfree(*(array + i));
                }
            }
        }
    }
    if (start == 0)
    {
        kfree(array);
    }
}

/**
 * parse_policy - Parse a tlsm policy
 *
 * Return: the parsed policy in newly *allocated memory*
 *         NULL on failure
 */
struct policy *parse_policy(char *rule)
{
    int word_count;
    char **words = str_split(rule, ' ', &word_count);

    if (!words)
        return NULL;

    struct policy *new_policy;
    new_policy = kmalloc(sizeof(*new_policy), GFP_KERNEL);
    new_policy->hit_count = 0;

    if (!new_policy || word_count < 3)
        goto parse_policy_fail;

    tlsm_category_t category = str2tlsm_cat(words[1]);
    kfree(words[1]);

    tlsm_ops_t op = str2tlsm_ops(words[2]);
    if (op == TLSM_OP_UNDEFINED)
    {
        printk(KERN_ERR "[TLSM][ERREUR] cannot parse operation %s", words[2]);
        goto parse_policy_fail;
    }
    kfree(words[2]);

    new_policy->subject = words[0];
    new_policy->category = category;
    new_policy->op = op;
    new_policy->object = words[3];
    free_karray_from(words, 4, word_count);

    kfree(words);

    return new_policy;

parse_policy_fail:
    if (new_policy)
        kfree(new_policy);
    free_karray_from(words, 0, word_count);
    return NULL;
}

/**
 * parse_watchdog - Parse a tlsm watchdog
 *
 * Return: the parsed watchdog in newly *allocated memory*
 *         NULL on failure
 */
struct tlsm_watchdog *parse_watchdog(char *str)
{
    int word_count;
    char **words = str_split(str, ' ', &word_count);

    if (!words)
        return NULL;

    if (word_count < 2)
    {
        free_karray_from(words, 0, word_count);
        return NULL;
    }

    struct tlsm_watchdog *new_watchdog;
    new_watchdog = kmalloc(sizeof(*new_watchdog), GFP_KERNEL);

    int pid;
    int err_code1 = kstrtoint(words[0], 10, &pid);
    if (err_code1 == 0)
    {
        new_watchdog->pid = pid;
    }
    else
    {
        printk(KERN_ERR "[TLSM][ERROR] can't parse watchdog PID, error : %d", err_code1);
        goto parse_watchdog_fail;
    }

    char comm[TASK_COMM_LEN];
    struct task_struct *t = pid_task(find_vpid(pid), PIDTYPE_PID);
    get_task_comm(comm, t);
    if (strcmp(comm, "tlsmd") != 0)
    {
        printk(KERN_DEBUG "[TLSM][ERROR] trying to add an unknown watchdog");
        goto parse_watchdog_fail;
    }

    int uid;
    int err_code2 = kstrtoint(words[1], 10, &uid);
    if (err_code2 == 0)
    {
        new_watchdog->uid = uid;
    }
    else
    {
        printk(KERN_ERR "[TLSM][ERROR] can't parse watchdog UID, error : %d", err_code2);
        goto parse_watchdog_fail;
    }

    free_karray_from(words, 0, word_count);
    return new_watchdog;

parse_watchdog_fail:
    kfree(new_watchdog);
    free_karray_from(words, 0, word_count);
    return NULL;
}
/**
 * signal_watchdog - tries to signals userland watchdog that a new request is available
 * Remove old watchdog if process doens't exist
 */
void signal_watchdog(int uid, int request_number)
{
    // signal data
    struct kernel_siginfo info;
    struct task_struct *t;
    memset(&info, 0, sizeof(struct kernel_siginfo));
    info.si_signo = SIGUSR1;
    info.si_code = SI_QUEUE;
    info.si_int = request_number;

    // find watchdog to signal
    struct tlsm_watchdog *elem;
    struct tlsm_watchdog *found = NULL;
    list_for_each_entry(elem, &tlsm_watchdogs, node)
    {
        if (elem->uid == uid)
        {
            found = elem;
            break;
        }
    }

    if (found)
    {
        printk(KERN_DEBUG "[TLSM][WATCHDOG] found watchdog with mathcing uid %d (pid=%d)", uid, elem->pid);
        rcu_read_lock();
        t = pid_task(find_vpid(elem->pid), PIDTYPE_PID);
        if (t != NULL)
        {
            rcu_read_unlock();
            if (send_sig_info(SIGUSR1, &info, t) < 0)
                printk(KERN_ERR "[TLSM][WATCHDOG] failed to send signal");
        }
        else
        {
            // TODO: improve by making the removal inside the search function
            // see https://docs.kernel.org/core-api/list.html#traversing-whilst-removing-nodes

            // pid doesn't exist anymore
            list_del(&elem->node);
            signal_watchdog(uid, request_number); // call on the remeinder of the watchdog list
                                                  // in case an old wathchdog died and there is a
                                                  // new one
        }
    }
    else
    {
        printk(KERN_DEBUG "[TLSM][WATCHDOG] no registered watchdog found");
    }
}

/**
 * tlsm_policy_free - frees a tlsm policy
 */
void tlsm_policy_free(struct policy *policy)
{
    if (!policy)
        return;
    kfree(policy->object);
    kfree(policy->subject);
    kfree(policy);
}

/**
 * tlsm_policy_dup - allocate a new policy and copy from a existing one
 *
 * returns NULL on failure
 */
struct policy *tlsm_policy_dup(struct policy *policy)
{
    struct policy *p;
    p = kmalloc(sizeof(*p), GFP_KERNEL);
    if (!p)
        return NULL;

    p->subject = kstrdup(policy->subject, GFP_KERNEL);
    if (!p->subject)
    {
        kfree(p);
        return NULL;
    }
    p->object = kstrdup(policy->object, GFP_KERNEL);
    if (!p->object)
    {
        kfree(p->subject);
        kfree(p);
        return NULL;
    }

    return p;
}

/**
 * tlsm_new_plist - Creates a new policy list.
 *
 * Returns a pointer to the allocated list, NULL on failure.
 */
struct plist *tlsm_plist_new(void)
{
    struct plist *t;
    t = kmalloc(sizeof(*t), GFP_KERNEL);
    if (!t)
        return NULL;
    t->head = NULL;
    t->tail = NULL;
    return t;
}

/**
 * tlsm_plist_add - Appends a new policy to a policy list.
 */
int tlsm_plist_add(struct plist *plist, struct policy *policy)
{
    // allocate new node
    struct policy_node *node;
    node = kmalloc(sizeof(*node), GFP_KERNEL);
    if (!node)
        return -ENOMEM;

    node->next = NULL;

    node->policy = policy;
    if (!(plist->head))
    {
        plist->head = node;
        plist->tail = node;
    }
    else
    {
        plist->tail->next = node;
        plist->tail = node;
    }

    return 0;
}

/**
 * tlsm_plist_del - removes a policy from the policy list
 */
int tlsm_plist_del(struct plist *plist, int index)
{

    int curr_i = 0;
    struct policy_node *curr = plist->head;
    struct policy_node *prev = NULL;

    // iterate until the target node to remove
    while (curr && curr_i < index)
    {
        curr_i++;
        prev = curr;
        curr = curr->next;
    }

    if (curr_i == index)
    {
        if (curr) // if the node actually exists
        {
            if (prev) // if curr is node the firs node of the list
            {         // curr is not the head
                prev->next = curr->next;
                if (curr->next == NULL)
                    plist->tail = prev;
            }
            else
            { // curr is the head / first node of the list
                plist->head = curr->next;
                if (plist->tail == curr) // if curr was the only node
                    plist->tail = NULL;
            }
            kfree(curr);
            return 0;
        }
        // curr = tail->next, nothing to do
    }
    // else : failed to find target node
    return -1;
}

/**
 * tlsm_plist_free - Frees a policy list
 */
void tlsm_plist_free(struct plist *plist)
{
    // if plist is not null
    if (!plist)
        return;

    struct policy_node *curr = plist->head;
    while (curr)
    {
        struct policy_node *temp = curr->next;
        tlsm_policy_free(curr->policy);
        kfree(curr);
        curr = temp;
    }

    kfree(plist);
}

/**
 * plist_debug - print list to dmesg
 */
void plist_debug(struct plist *l)
{
    struct policy_node *tmp = l->head;
    while (tmp)
    {
        printk(KERN_DEBUG "[TLSM][LIST_DEBUG] type=%d, subject=%s, object=%s", tmp->policy->op, tmp->policy->subject, tmp->policy->object);
        tmp = tmp->next;
    }
}