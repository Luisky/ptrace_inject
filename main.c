#include "hotpatchor.h"

/*
 * Could use AS2_TP5 (multithreaded matrix calculations) /home/luisky/CLionProjects/L3_CDA_C/AS2_TP5
 * or a small decoy program which calls a function (maybe better at first)
 *
 */


int main(int argc, char **argv) {

    pid_t pid;
    char* func_name;
    struct user_regs_struct user_regs;

    FILE *fp;
    char path_mem[64];
    long long int func_addr;

    if (argc != 3) exit(EXIT_FAILURE);

    pid = get_pid_from_argv(argv[1]);
    func_name = argv[2];

    init_hotpatchor(pid, func_name, path_mem, &func_addr);
    init_ptrace_attach(pid);

    // BEGIN PROTO
    long long int opti_func_addr = get_func_addr(pid, "opti_add_int");
    printf("opti_func_addr 0x%llx\n", opti_func_addr);
    // END PROTO

    write_trap_at_addr(pid, path_mem, func_addr);
    get_regs(pid, &user_regs, func_addr, &opti_func_addr, path_mem);



    //__asm__("int3"); //0xCC

    return EXIT_SUCCESS;
}