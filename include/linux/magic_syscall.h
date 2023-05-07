#ifndef _MAGIC_SYSCALL_H
#define _MAGIC_SYSCALL_H

#include <linux/list.h>

#define SECRET_MAXSIZE 32

int magic_get_wand_syscall(int power, char secret[SECRET_MAXSIZE]);
int magic_attack_syscall(pid_t pid);
int magic_legilimens_syscall(pid_t pid);
int magic_list_secrets_syscall(char secrets[][SECRET_MAXSIZE], size_t size);
int magic_clock(unsigned int seconds);

struct wand_struct // how sched.h will know about this struct?
{
    int power;
    int health;
    char secret[SECRET_MAXSIZE];
    struct list_head stolenSecretsListHead;
};

struct stolenSecretListNode
{
    char secret[SECRET_MAXSIZE];
    list_t ptr;
};

#endif
