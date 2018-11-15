#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <wait.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

// not useful
#include <libelf.h>

#define BASE_10 10
#define STR_SIZE 64

/*
 * kill -l
 * or https://elixir.bootlin.com/linux/v4.4/source/arch/x86/include/uapi/asm/signal.h#L41
 * or https://elixir.bootlin.com/linux/v4.5/source/include/uapi/asm-generic/signal.h
 * for insights on the SIGNAL(s) values
 *
 */

typedef struct Arg Arg;

struct Arg {
    struct user_regs_struct user_regs;
    unsigned long long int func_addr;
    unsigned long long int opti_func_addr;
    char path_to_mem[STR_SIZE];
    uint8_t old_first_4_bytes[4];
    uint8_t old_12_remaining_bytes[12];
};


void init_hotpatchor(pid_t pid, char *func_name, char* path_mem, unsigned long long int *func_addr);
void init_ptrace_attach(pid_t pid);

void write_trap_and_jump(pid_t pid, Arg *arg);
void restore_mem(pid_t pid, Arg *arg);

void hotpatch(pid_t pid, Arg *arg);

pid_t get_pid_from_argv(char *argv_pid);
long get_maps_addr(pid_t pid);

unsigned long long int get_offset_func(char* proc_name,char* func_name);
unsigned long long int get_offset_libc_func(char *lib_path, char * func_name);
unsigned long long int get_start_addr_heap(pid_t pid);
unsigned long long int get_func_addr(pid_t pid, char* func_name);

char* get_proc_name(pid_t pid);

void continue_exec(pid_t pid, bool wait);
void path_and_start_addr_of_libc(pid_t pid, char *libc_path, unsigned long long int *libc_addr);

int challenge3_func(int a, int b);
void end_challeng3_func();

