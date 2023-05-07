#include <asm/current.h>
#include <linux/string.h>
#include <asm/errno.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/magic_syscall.h>
#include <linux/types.h>
#include <asm/uaccess.h>

#define TRUE 1
#define FALSE 0
#define SUCCESS 0

int IsSecretInList(struct list_head* secretsList, char secret[SECRET_MAXSIZE])
{
    list_t *currentStolenSecretPtr;
    struct stolenSecretListNode *currentStolenSecretNode;
    list_for_each(currentStolenSecretPtr, secretsList)
    {
        currentStolenSecretNode = list_entry(currentStolenSecretPtr, struct stolenSecretListNode, ptr);
        if(strncmp(currentStolenSecretNode->secret, secret, SECRET_MAXSIZE) == 0) 
            return TRUE;
    }
    return FALSE;
}

void PrintWandStatus(struct wand_struct *wand)
{
    printk("wand power: %d\n", wand->power);
    printk("wand health: %d\n", wand->health);
    printk("wand secret: %s\n", wand->secret);
    PrintStolenSecretList(&(wand->stolenSecretsListHead));
}

void PrintStolenSecretList(struct list_head *stolenSecretsListHead)
{
    if(list_empty(stolenSecretsListHead))
    {
        printk("stolen secrets list is empty\n");
        return;
    }
    list_t *currentStolenSecretPtr;
    struct stolenSecretListNode *currentStolenSecretNode;
    int i = 1;
    list_for_each(currentStolenSecretPtr, stolenSecretsListHead)
    {
        currentStolenSecretNode = list_entry(currentStolenSecretPtr, struct stolenSecretListNode, ptr);
        printk("stolen secret number %d: %s\n", i, currentStolenSecretNode->secret);
        i++;
    }
}

int magic_get_wand_syscall(int power, char secret[SECRET_MAXSIZE])
{
    if(strlen(secret) == 0)
    {
        return -EINVAL;
    }

    struct task_struct *currentProccess = current;
    if(currentProccess->wand != NULL)
    {
        return -EEXIST;
    }

    struct wand_struct *currentProccessWand = (struct wand_struct *)kmalloc(sizeof(struct wand_struct), GFP_KERNEL);
    if (currentProccessWand == NULL)
    {
        return -ENOMEM;
    }

    currentProccessWand->power = power;
    currentProccessWand->health = 100;
    if(copy_from_user(currentProccessWand->secret, secret, SECRET_MAXSIZE) != 0)
    {
        kfree(currentProccessWand);
        return -EFAULT;
    }

    INIT_LIST_HEAD(&(currentProccessWand->stolenSecretsListHead));

    currentProccess->wand = currentProccessWand;

    return SUCCESS;
}

int magic_attack_syscall(pid_t pid)
{
    struct task_struct *currentProccess = current;
    struct task_struct *proccessToAttack = find_task_by_pid(pid);
    if(proccessToAttack == NULL)
    {
        return -ESRCH;
    }
    struct wand_struct *currentProccessWand = currentProccess->wand;
    struct wand_struct *proccessToAttackWand = proccessToAttack->wand;
    if(proccessToAttackWand == NULL || currentProccessWand == NULL)
    {
        return -EPERM;
    }
    if(proccessToAttackWand->health == 0)
    {
        return -EHOSTDOWN;
    }
    if(pid == currentProccess->pid || IsSecretInList(&(proccessToAttackWand->stolenSecretsListHead), currentProccessWand->secret) == TRUE)
    {
        return -ECONNREFUSED;
    }
    proccessToAttackWand->health  = proccessToAttackWand->health - currentProccessWand->power > 0 ? proccessToAttackWand->health - currentProccessWand->power : 0;

    return SUCCESS;
}

int magic_legilimens_syscall(pid_t pid)
{
    struct task_struct *currentProccess = current;
    struct task_struct *proccessToStealFrom = find_task_by_pid(pid);
    if(proccessToStealFrom == NULL)
    {
        return -ESRCH;
    }
    struct wand_struct *currentProccessWand = currentProccess->wand;
    struct wand_struct *proccessToStealFromWand = proccessToStealFrom->wand;
    if(proccessToStealFromWand == NULL || currentProccessWand == NULL)
    {
        return -EPERM;
    }
    if(pid == currentProccess->pid)
    {
        return SUCCESS;
    }
    if(IsSecretInList(&(currentProccessWand->stolenSecretsListHead), proccessToStealFromWand->secret))
    {
        return -EEXIST;
    }
    struct stolenSecretListNode *newStolenSecretNode = (struct stolenSecretListNode*)kmalloc(sizeof(struct stolenSecretListNode), GFP_KERNEL);
    strncpy(newStolenSecretNode->secret, proccessToStealFromWand->secret, SECRET_MAXSIZE);
    list_add_tail(&(newStolenSecretNode->ptr), &(currentProccessWand->stolenSecretsListHead));
    
    return SUCCESS;
}

int magic_list_secrets_syscall(char secrets[][SECRET_MAXSIZE], size_t size)
{
    if (secrets == NULL)
    {
        return -EFAULT;
    }
    struct task_struct *currentProccess = current;
    struct wand_struct *currentProccessWand = currentProccess->wand;
    if(currentProccessWand == NULL)
    {
        return -EPERM;
    }
    int numberOfSecretsCopied = 0;
    int totalSecrets = 0;
    list_t *currentStolenSecretPtr;
    struct stolenSecretListNode *currentStolenSecretNode;
    list_for_each(currentStolenSecretPtr, &(currentProccessWand->stolenSecretsListHead))
    {
        totalSecrets++;
        if(numberOfSecretsCopied < size)
        {
            currentStolenSecretNode = list_entry(currentStolenSecretPtr, struct stolenSecretListNode, ptr);
            if(copy_to_user(secrets[numberOfSecretsCopied], currentStolenSecretNode->secret, SECRET_MAXSIZE) != 0)
            {
                return -EFAULT;
            }
            numberOfSecretsCopied++;
        }
        continue;
    }
    if(numberOfSecretsCopied < size)
    {
        int i;
        for (i = numberOfSecretsCopied; i < size; i++)
        {
            if(secrets[i] == NULL)
            {
                return -EFAULT;
            }
            secrets[i][0] = '\0';
        }
    }
    
    return totalSecrets-numberOfSecretsCopied;
}

