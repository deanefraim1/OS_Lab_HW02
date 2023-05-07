#include "magic_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define SECRET_MAXSIZE 32

int main()
{
    while(1)
    {
        printf("Please enter desired act: \n");
        printf("1. Get wand\n");
        printf("2. Attack\n");
        printf("3. Legilimens\n");
        printf("4. List secrets\n");
        printf("5. Exit\n");
        printf("6. Get PID\n");
        printf("7. Check if fork+Attack fails\n");
        int actNumber;
        scanf("%d", &actNumber);
        switch (actNumber)
        {
            case 1:
            {
                printf("Please enter power: ");
                int power;
                scanf("%d", &power);
                printf("Please enter secret: ");
                char secret[SECRET_MAXSIZE];
                scanf("%s", secret); 
                int ret = magic_get_wand(power, secret);
                printf("return value = %d\n", ret);
                if(ret < 0)
                    printf("errno = %d\n", errno);
                break;
            }
            case 2:
            {
                printf("Please enter pid: ");
                int pid;
                scanf("%d", &pid);
                int ret = magic_attack(pid);
                printf("return value = %d\n", ret);
                if(ret < 0)
                    printf("errno = %d\n", errno);
                break;
            }
            case 3:
            {
                printf("Please enter pid: ");
                int pid;
                scanf("%d", &pid);
                int ret = magic_legilimens(pid);
                printf("return value = %d\n", ret);
                if(ret < 0)
                    printf("errno = %d\n", errno);
                break;
            }
            case 4:
            {
                printf("Please enter size: ");
                size_t size;
                scanf("%zu", &size);
                char (*secrets)[SECRET_MAXSIZE] = malloc(size * SECRET_MAXSIZE * sizeof(char));
                int ret = magic_list_secrets(secrets, size);
                printf("return value = %d\n", ret);
                if(ret < 0)
                    printf("errno = %d\n", errno);
                int i;
                for (i = 0; i < size; i++)
                {
                    printf("stolen secret number %d: %s\n",i+1, secrets[i]);
                }
                free(secrets);
                break;
            }
            case 5:
            {
                return 0;
            }
            case 6:
            {
                printf("pid = %d\n", getpid());
                break;
            }
            case 7:
            {
                int pid = fork();
                if(pid == 0)
                {
                    printf("Please enter pid: ");
                    int pid;
                    scanf("%d", &pid);
                    int ret = magic_attack(pid);
                    printf("return value = %d\n", ret);
                    if(ret < 0)
                        printf("errno = %d\n", errno);
                    return 0;
                }
                else
                {
                    waitpid(pid, NULL, 0);
                }
                break;
            }
        }
    }
}
