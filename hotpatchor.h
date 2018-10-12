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

// not useful
#include <libelf.h>

#define BASE_10 10

/*
 * kill -l
 * or https://elixir.bootlin.com/linux/v4.4/source/arch/x86/include/uapi/asm/signal.h#L41
 * or https://elixir.bootlin.com/linux/v4.5/source/include/uapi/asm-generic/signal.h
 * for insights on the SIGNAL(s) values
 *
 */

pid_t get_pid_from_argv(char *argv_pid);
void init_hotpatchor(pid_t pid, char *func_name, char* path_mem, long long int *func_addr);
void init_ptrace_attach(pid_t pid);

void write_trap_at_addr(pid_t pid, char *path_mem, long long int func_addr, char* char_read_in_mem);
void get_regs(pid_t pid, struct user_regs_struct * user_regs, long long int func_addr, unsigned long long int *opti_func_addr, char * path_mem, char* char_read_in_mem);

long long int get_func_addr(pid_t pid, char* func_name);
long get_offset_func(char* proc_name,char* func_name);
long get_maps_addr(pid_t pid);
char* get_proc_name(pid_t pid);


