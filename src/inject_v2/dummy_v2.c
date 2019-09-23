/*
 * man 2 syscall
 * for syscall(SYS_gettid)
 *
 */
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <omp.h>

#define NB_THREAD 4

/*
 * 1 thread: 750000000
 * 2 thread: 1500000000
 * 3 thread: 2250000000
 * 4 thread: 3000000000
 */

uint64_t val = 0;
pthread_mutex_t mutex;

void increment()
{
    pthread_mutex_lock(&mutex);
    val++;
    pthread_mutex_unlock(&mutex);

    return;
}

void funky_cop()
{
    printf("tid %ld started\n", syscall(SYS_gettid));
    for (int i = 0; i < 750000000; ++i) increment();
    return;
}

int main()
{
    pthread_t threads[NB_THREAD];
    pthread_mutex_init(&mutex, NULL);
    printf("val addr 0x%p\n", (void *) &val);

    for (size_t i = 0; i < NB_THREAD; i++) pthread_create(&threads[i], NULL, (void * (*)(void *)) funky_cop, NULL);
    for (size_t i = 0; i < NB_THREAD; i++) pthread_join(threads[i], NULL);

    pthread_mutex_destroy(&mutex);
    printf("val : %ld\n", val);

    //__asm__("int3");

    return EXIT_SUCCESS;
}
