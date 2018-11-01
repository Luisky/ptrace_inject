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


int add_int(int a, int b)
{
    sleep(1);
    return a + b;
}

int mod_a_b(int *a, int *b)
{
    printf("mod_a_b\n");
    *a = 0;
    *b = 1;
    printf("a: %d, b: %d\n", *a, *b);
    printf("a_addr: %p, b_addr: %p\n", a, b);

    return 256;
}

int opti_add_int(int a, int b)
{
    printf("opti_add_int\n");
    return a + b;
}

int main()
{
    printf("PID %d\n\n", getpid());
    printf("address of posix_memalign: %p\n", posix_memalign);
    printf("address of aligned_alloc: %p\n", aligned_alloc);
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