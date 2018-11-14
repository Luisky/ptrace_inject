#include "hotpatchor.h"

/*
 * Could use AS2_TP5 (multithreaded matrix calculations) /home/luisky/CLionProjects/L3_CDA_C/AS2_TP5
 * or a small decoy program which calls a function (maybe better at first)
 * __asm__("int3"); //0xCC
 */


int main(int argc, char **argv) {

    if (argc != 3) {
        fprintf(stderr, "You didn't provide the right arguments: %s [pid] [func_name_to_replace]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    pid_t pid;
    char* func_name;

    Arg arg;

    pid = get_pid_from_argv(argv[1]);
    func_name = argv[2];

    init_hotpatchor(pid, func_name, arg.path_to_mem, &(arg.func_addr));
    init_ptrace_attach(pid);

    //arg.opti_func_addr = get_func_addr(pid, "opti_add_int");
    //printf("opti_func_addr 0x%llx\n", arg.opti_func_addr);

    write_trap_at_addr(pid, &arg); // WE SHOULD BE WAITING HERE
    //exec_func_with_val(pid, &arg);


    //arg.opti_func_addr = get_func_addr(pid, "mod_a_b");
    //printf("mod_a_b 0x%llx\n", arg.opti_func_addr);

    //exec_func_with_ptr(pid, &arg); // we follow up with another call
    //continue_exec(pid, false); // RESTART THE TRACEE
    // END CHALLENGE 1 AND 2

    exec_posix_melalign(pid, &arg);
    continue_exec(pid, false);

    printf("finished\n");

    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return EXIT_SUCCESS;
}