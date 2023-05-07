#include <asm/current.h>
#include <linux/string.h>
#include <asm/errno.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/magic_syscall.h>
#include <linux/types.h>
#include <asm/uaccess.h>
#include <linux/timer.h>

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

void myTimerCallback(struct timer_list *timer)
{
    struct task_struct *currentProccess = current;
    struct wand_struct *currentProccessWand = currentProccess->wand;
    // check if the current proccess is sleeping
    if(currentProccess->state == TASK_INTERRUPTIBLE)
    {
        //TODO - wait for the proccess to wake up

    }
    // check if the current proccess killed
    if(currentProccess->state == TASK_UNINTERRUPTIBLE)
    {
        // set the current proccess priority to the lowest priority
        currentProccess->prio = 0;
        // print the wand status
        printk("wand status:\n");
        PrintWandStatus(currentProccessWand);
        // delete the timer
        del_timer(timer);
        // free the timer memory
        kfree(timer);
        // free the wand memory
        kfree(currentProccessWand);
        // set the wand pointer to NULL
        currentProccess->wand = NULL;
    }
    // set the current proccess priority to the lowest priority
    currentProccess->prio = 0;
    // print the wand status
    printk("wand status:\n");
    PrintWandStatus(currentProccessWand);
    // delete the timer
    del_timer(timer);
    // free the timer memory
    kfree(timer);
    // free the wand memory
    kfree(currentProccessWand);
    // set the wand pointer to NULL
    currentProccess->wand = NULL;
    
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

int magic_clock(unsigned int seconds)
{
    struct task_struct *currentProccess = current;
    struct wand_struct *currentProccessWand = currentProccess->wand;
    if(currentProccessWand == NULL)
    {
        return -EPERM;
    }
    struct timer_list *myTimer = (struct timer_list*)kmalloc(sizeof(struct timer_list), GFP_KERNEL);
    if(myTimer == NULL)
    {
        return -ENOMEM;
    }
    init_timer(myTimer);
    myTimer->expires = jiffies + seconds * HZ;
    myTimer->function = myTimerCallback;
    // set the current proccess priority to the highest priority
    currentProccess->prio = MAX_PRIO - 1;
    // add the timer to the timer list
    add_timer(myTimer);
    return SUCCESS;
}
