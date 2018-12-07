/*
 * This program was created to be used for testing
 * the ptrace() system call
 *
 */
#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>
#include <sys/mman.h>


int add_int(int a, int b)
{
    sleep(1);
    return a + b;
}

int main()
{
    int a = 5;
    int b = 10;

    printf("func alligned_alloc %p\n", aligned_alloc);
    printf("func posix_memalign %p\n", posix_memalign);
    printf("func mprotect       %p\n", mprotect);

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