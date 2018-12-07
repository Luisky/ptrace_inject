#include "hotpatchor/hotpatchor.h"

/*
 * Could use AS2_TP5 (multithreaded matrix calculations) /home/luisky/CLionProjects/L3_CDA_C/AS2_TP5
 * or a small decoy program which calls a function (maybe better at first)
 * __asm__("int3"); //0xCC
 * asm("LOCK INCL 0x2e49(%rip)"); f0 ff 05 49 2e 00 00
 */


int main(int argc, char **argv) {

    if (argc != 3) errx(EXIT_FAILURE, "You didn't provide the right arguments: %s [prog_name] [func_name_to_replace]\n", argv[0]);

    Arg arg;
    pid_t pid;

    pid = get_pid_from_argv(argv[1]);
    init_hotpatchor(pid, &arg, argv[1], argv[2]);

    printf("\npid traced : %d\n\n", pid);

    /*
     * we have to open /proc/[pid]/task folder and list the entries, removing the one corresponding to the main thread
     * and then stop them one by one
     */
    pid_t tid = pid+1; // this isn't correct

    size_t tid_nb = 0;
    pid_t *tid_buf = NULL;

    tid_buf_and_number(pid, &tid_buf, &tid_nb);

    printf("tid(s) %ld:\n", tid_nb);
    for (int i = 0; i < tid_nb; ++i) printf("%d\n", tid_buf[i]);

    /*
     * Normally it's a group stop
     */
    //kill(pid, SIGSTOP);
    init_ptrace_attach(pid);
    for (int i = 0; i < tid_nb; ++i) init_ptrace_attach(tid_buf[i]);

    /*hotwait(pid);
    for (int i = 0; i < tid_nb; ++i) hotwait((pid_t) tid_buf[i]);

    init_ptrace_seize(pid);
    for (int i = 0; i < tid_nb; ++i) init_ptrace_seize((pid_t) tid_buf[i]);*/

    for (int i = 0; i < tid_nb; ++i) {
        struct user_regs_struct regs;

        ptrace(PTRACE_GETREGS, tid_buf[i], NULL, &regs);
        printf("rip value of %d : %llx\n", i, regs.rip);
    }

    write_trap_only(pid, &arg);

    //kill(pid, SIGCONT);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    for (int i = 0; i < tid_nb; ++i) ptrace(PTRACE_CONT, tid_buf[i], NULL, NULL);

    for (int i = 0; i < tid_nb; ++i) hotwait(tid_buf[i]);
     printf("DOES THIS WORK\n");

    uint64_t rip = 0;
    for (int i = 0; i < tid_nb; ++i) {
        struct user_regs_struct regs;

        ptrace(PTRACE_GETREGS, tid_buf[i], NULL, &regs);
        rip = regs.rip;
        printf("rip value of %d : %lx\n",i, rip);

        --regs.rip;
        ptrace(PTRACE_SETREGS, tid_buf[i], NULL, &regs);
    }

    uint64_t addr_val = get_func_addr(pid, argv[1], "val", false);
    printf("val is located at : 0x%lx\n", addr_val);

    ssize_t br = 0;
    int fd = open(arg.path_to_mem, O_RDWR);
    uint8_t replacement_code[8] = { 0xF0, 0xFF, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3 };
    uint32_t diff = addr_val - (rip + 7);

    /*union endian64_u addr;
    addr.val = (uint32_t) diff;
    for (int i = 0; i < 4; ++i) replacement_code[3+i] = addr.each[i];*/
    printf("val addr 0x%lx\n", diff);
    *((uint32_t *) (replacement_code+3)) = diff;

    if (lseek(fd, (off_t) arg.func_addr, SEEK_SET) < 0) perror("lseek");
    if ( (br = write(fd, replacement_code, 8)) < 0) perror("write");

    close(fd); // this seals the deal and should send SIGTRAP after we send SIGCONT
    printf("%ld byte(s) written at address 0x%lx\n", br, arg.func_addr);

    ptrace(PTRACE_CONT, pid, NULL, NULL); // no wait because there is no trap left
    for (int i = 0; i < tid_nb; ++i) {
        ptrace(PTRACE_CONT, tid_buf[i], NULL, NULL); // no wait because there is no trap left
        printf("last continue %d\n",i);
    }

    printf("finished\n");

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    for (int i = 0; i < tid_nb; ++i) {
        ptrace(PTRACE_DETACH, (pid_t) tid_buf[i], NULL, NULL);
    }


    return EXIT_SUCCESS;
}