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

int add_int(int a, int b)
{
    usleep(100000); //100ms
    return a + b;
}

int main()
{
    int a = 5;
    int b = 10;

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