#ifndef SEL_TP_HOTPATCHOR_H
#define SEL_TP_HOTPATCHOR_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <wait.h>
#include <limits.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <dirent.h>
#include <err.h>
#include <stdint.h>

// not useful
//#include <libelf.h>

#define STR_SIZE 256

#define HEAP        "[heap]"
#define STACK       "[stack]"
#define VVAR        "[vvar]"
#define VDSO        "[vsdo]"
#define VSYSCALL    "[vsyscall]"

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
    uint64_t func_addr;
    uint64_t allocated_mem;
    uint8_t backup[16];
    uint8_t old_byte;
    char path_to_mem[STR_SIZE];
    char self_prog_path[STR_SIZE];
};

union endian64_u { // for endianess
    uint64_t val;
    uint8_t each[8];
};

union endian32_u { // for endianess
    uint32_t val;
    uint8_t each[4];
};


pid_t get_pid_from_argv(char *argv1);
void hotwait(pid_t pid);

void init_hotpatchor(pid_t pid, Arg *arg, char *argv1, char *argv2);
void init_ptrace_attach(pid_t pid);
void init_ptrace_seize(pid_t pid);

void write_trap_only(pid_t pid, Arg *arg);
void write_trap_and_syscall(pid_t pid, Arg *arg);

void hotpatch(pid_t pid, Arg *arg);
void restore_mem(pid_t pid, Arg *arg);

uint64_t get_addr_from_proc_maps(pid_t pid, char *str, char *lib_path);
uint64_t get_symbol_offset(char *exec_path, char * sym_name, bool dynamic);
uint64_t get_func_addr(pid_t pid, char* lib_or_exec, char* func_name, bool dyn);

void tid_buf_and_number(pid_t pid, pid_t **tid_buf, size_t *tid_nb);

int challenge3_func(int a, int b);
void end_challeng3_func();

#endif //SEL_TP_HOTPATCHOR_H