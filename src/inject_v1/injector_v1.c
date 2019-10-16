#include "hotpatchor.h"
/*
 * Could use AS2_TP5 (multithreaded matrix calculations) /home/luisky/CLionProjects/L3_CDA_C/AS2_TP5
 * or a small decoy program which calls a function (maybe better at first)
 * __asm__("int3"); //0xCC
 */

int main(int argc, char **argv)
{
    if (argc != 3)
        errx(EXIT_FAILURE, "You didn't provide the right arguments: %s [prog_name] [func_name_to_replace]\n", argv[0]);

    Arg arg;
    pid_t pid;

    pid = get_pid_from_argv(argv[1]);
    init_hotpatchor(pid, &arg, argv[1], argv[2]);

    printf("\npid traced : %d\n\n", pid);

    init_ptrace_attach(pid);

    write_trap_and_syscall(pid, &arg);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    hotwait(pid);

    hotpatch(pid, &arg);
    ptrace(PTRACE_CONT, pid, NULL, NULL); // no wait because there is no trap left

    printf("finished\n");

    sleep(3);

    restore_mem(pid, &arg);
    ptrace(PTRACE_CONT, pid, NULL, NULL); // no wait because there is no trap left

    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return EXIT_SUCCESS;
}
