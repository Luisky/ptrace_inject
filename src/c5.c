#include "hotpatchor/hotpatchor.h"

/*
 * Could use AS2_TP5 (multithreaded matrix calculations) /home/luisky/CLionProjects/L3_CDA_C/AS2_TP5
 * or a small decoy program which calls a function (maybe better at first)
 * __asm__("int3"); //0xCC
 * see test.s for info on lock inc 
 */


int main(int argc, char **argv) {

    if (argc != 3) errx(EXIT_FAILURE, "You didn't provide the right arguments: %s [prog_name] [func_name_to_replace]\n", argv[0]);

    //TODO: try using PTRACE_SEIZE and PTRACE_INTERUPT

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

    init_ptrace_attach(pid);
    for (int i = 0; i < tid_nb; ++i) init_ptrace_attach(tid_buf[i]);

    for (int i = 0; i < tid_nb; ++i) {
        struct user_regs_struct regs;

        ptrace(PTRACE_GETREGS, tid_buf[i], NULL, &regs);
        printf("rip value of %d : %llx\n", i, regs.rip);
    }

    write_trap_only(pid, &arg);

    ptrace(PTRACE_CONT, pid, NULL, NULL);
    for (int i = 0; i < tid_nb; ++i) ptrace(PTRACE_CONT, tid_buf[i], NULL, NULL);
    for (int i = 0; i < tid_nb; ++i) hotwait(tid_buf[i]);

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
    uint8_t replacment_code[16] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x48, 0xFF, 0x00, 0xC3, 0x90};

    /*union endian64_u addr;
    addr.val = (uint32_t) diff;
    for (int i = 0; i < 4; ++i) replacement_code[3+i] = addr.each[i];*/
    
    *((uint64_t *) (replacment_code+2)) = addr_val;

    if (lseek(fd, (off_t) arg.func_addr, SEEK_SET) < 0) err(EXIT_FAILURE,"lseek");
    if ( (br = write(fd, replacment_code, 16)) < 0) err(EXIT_FAILURE,"write");

    close(fd); // this seals the deal and should send SIGTRAP after we send SIGCONT
    printf("%ld byte(s) written at address 0x%lx\n", br, arg.func_addr);

    ptrace(PTRACE_CONT, pid, NULL, NULL); // no wait because there is no trap left
    for (int i = 0; i < tid_nb; ++i) ptrace(PTRACE_CONT, tid_buf[i], NULL, NULL); // no wait because there is no trap left

    printf("finished\n");

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    for (int i = 0; i < tid_nb; ++i) ptrace(PTRACE_DETACH, (pid_t) tid_buf[i], NULL, NULL);


    return EXIT_SUCCESS;
}