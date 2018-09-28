#include "hotpatchor.h"

/*
 * Could use AS2_TP5 (multithreaded matrix calculations) /home/luisky/CLionProjects/L3_CDA_C/AS2_TP5
 * or a small decoy program which calls a function (maybe better at first)
 *
 */


int main(int argc, char **argv) {

    pid_t pid;
    char* func_name;

    FILE *fp;
    char path_mem[64];
    long long int func_addr;

    if (argc != 3) exit(EXIT_FAILURE);

    pid = get_pid_from_argv(argv[1]);
    func_name = argv[2];

    init_hotpatchor(pid, func_name, path_mem, &func_addr);
    init_ptrace_attach(pid);
    write_trap_at_addr(pid, path_mem, func_addr);

    //__asm__("int3"); //0xCC

    return EXIT_SUCCESS;
}