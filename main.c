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

    write_trap_and_jump(pid, &arg);

    hotpatch(pid, &arg);
    continue_exec(pid, false); //here there's no waiting because our process won't hit another 0xCC normally


    printf("finished\n");

    sleep(5);

    restore_mem(pid, &arg);
    continue_exec(pid, false);

    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return EXIT_SUCCESS;
}