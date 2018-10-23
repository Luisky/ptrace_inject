#include "hotpatchor.h"

/*
 * Could use AS2_TP5 (multithreaded matrix calculations) /home/luisky/CLionProjects/L3_CDA_C/AS2_TP5
 * or a small decoy program which calls a function (maybe better at first)
 *
 */


int main(int argc, char **argv) {

    if (argc != 3) exit(EXIT_FAILURE);

    pid_t pid;
    char* func_name;

    Arg arg;

    pid = get_pid_from_argv(argv[1]);
    func_name = argv[2];

    init_hotpatchor(pid, func_name, arg.path_to_mem, &(arg.func_addr));
    init_ptrace_attach(pid);

    //TODO: create a debug state for messages on stdin, or write them on stderr (either way do something about it !)

    // CHALLENGE 1 AND 2
    arg.opti_func_addr = get_func_addr(pid, "opti_add_int");
    printf("opti_func_addr 0x%llx\n", arg.opti_func_addr);

    write_trap_at_addr(pid, &arg);
    exec_func_with_val(pid, &arg);

    arg.opti_func_addr = get_func_addr(pid, "mod_a_b");
    printf("mod_a_b 0x%llx\n", arg.opti_func_addr);

    exec_func_with_ptr(pid, &arg); // we follow up with another call
    continue_exec(pid, false); // RESTART THE TRACEE
    // END CHALLENGE 1 AND 2

    //TODO: CHALLENGE 3

    long pagesize = sysconf(_SC_PAGESIZE);





    //__asm__("int3"); //0xCC

    return EXIT_SUCCESS;
}