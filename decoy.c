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


int add_int(int a, int b)
{
    sleep(1);
    return a + b;
}

int main()
{
    printf("PID %d\n\n", getpid());

    int a = 5;
    int b = 10;

    while(true) {

        if ( (a + b) > 100000) {
            a = 5;
            b = 10;
        }

        printf("add_int(): %d\n", add_int(a, b));
        a+=1;
        b+=2;
    }

    return EXIT_SUCCESS;
}