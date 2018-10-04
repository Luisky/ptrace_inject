//
// Created by luisky on 27/09/18.
//

/*
 * This program was created to be used for testing
 * the ptrace() system call
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <string.h>
 
/*static void handler(int sig_no)
{
    printf("\n\n\tSignal %d caught\n\n\n", sig_no);

    return;
}*/

int add_int(int a, int b)
{
    usleep(100000); //100ms
    return a + b;
}

int opti_add_int(int a, int b)
{
    printf("YO LES POTES !\n");
    //usleep(50000);
    return a + b;
}

int main()
{
    printf("PID %d\n\n", getpid());
    int a = 5;
    int b = 10;

    /*struct sigaction sa;
    memset (&sa, '\0', sizeof(sa));
    sa.sa_handler = handler;
    sigaction(SIGTRAP, &sa, NULL);*/

    while(true) {

        if ( (a + b) == INT_MAX) {
            break;
        }

        printf("add_int(): %d\n", add_int(a, b));
        a+=5;
        b+=10;
    }

    return EXIT_SUCCESS;

}