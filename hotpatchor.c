#include "hotpatchor.h"


void init_hotpatchor(pid_t pid, char *func_name, char *path_mem, unsigned long long int *func_addr)
{
    sprintf(path_mem, "/proc/%d/mem", (int)pid);
    *func_addr = get_func_addr((int)pid, func_name);

    return;
}

void init_ptrace_attach(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        fprintf(stderr, "Ptrace failed\n"); //TODO: check errno
        exit(EXIT_FAILURE);
    }

    int wstatus;
    waitpid(pid, &wstatus, 0); // PTRACE_ATTACH sends SIGSTOP to the tracee
    if (WIFSTOPPED(wstatus)) printf("process was stopped by signal number %d\n", WSTOPSIG(wstatus));


    return;
}


void write_trap_and_jump(pid_t pid, Arg *arg) {

    int fd;
    ssize_t br;
    uint8_t buf[4] = { (char)0xCC, (char)0xFF, (char)0xD0, (char)0xCC };

    //process must be stopped in order to be able to read mem so:

    fd = open(arg->path_to_mem, O_RDWR);

    if (lseek(fd, (off_t) arg->func_addr, SEEK_SET) < 0) perror("lseek");
    if (read(fd, arg->old_first_4_bytes, 4) < 0) perror("read");

    if (lseek(fd, (off_t) arg->func_addr, SEEK_SET) < 0) perror("lseek");
    if ( (br = write(fd, buf, 4)) < 0) perror("write");

    close(fd); // this seals the deal and should send SIGTRAP after we send SIGCONT
    printf("%ld byte(s) written at address 0x%llx\n", br, arg->func_addr);

    continue_exec(pid, true); // RESTART THE TRACEE

    return;
}


void restore_mem(pid_t pid, Arg *arg)
{
    int fd;
    int wstatus;
    ssize_t br;
    uint8_t int3 = (char) 0xCC;

    kill(pid, SIGSTOP);
    waitpid(pid, &wstatus, 0); // we need the process to stop
    if (WIFSTOPPED(wstatus)) printf("process was stopped by signal number %d\n", WSTOPSIG(wstatus));

    fd = open(arg->path_to_mem, O_WRONLY);
    lseek(fd, (off_t) arg->func_addr, SEEK_SET);
    write(fd, &int3, 1);
    close(fd);

    continue_exec(pid, true);

    //TODO: refactor this code with if() statements

    fd = open(arg->path_to_mem, O_RDWR);

    lseek(fd,(off_t) arg->func_addr, SEEK_SET);
    br = write(fd, arg->old_first_4_bytes, 4);
    printf("%ld byte(s) written\n", br);
    br = write(fd, arg->old_12_remaining_bytes, 12);
    printf("%ld byte(s) written\n", br);

    ptrace(PTRACE_SETREGS, pid, NULL, &(arg->user_regs));

    close(fd);

    return;
}

/*
 * Process must be stopped in order to use this
 *
 */
void hotpatch(pid_t pid, Arg *arg)
{
    //needed for the rest of the challenge
    unsigned long long int offset_func_c3 = get_offset_func(get_proc_name(getpid()), "challenge3_func");
    unsigned long long int offset_func_c3_end = get_offset_func(get_proc_name(getpid()), "end_challeng3_func");
    unsigned long long int func_size = offset_func_c3_end - offset_func_c3;

    size_t pagesize = (size_t) sysconf(_SC_PAGESIZE);
    unsigned long long int mem_size = pagesize * (1 + (func_size / pagesize));

    /*
     * we save the old registers values in order to restore them later on
     * and create another structure that we will modify
     */
    struct user_regs_struct registers;
    ptrace(PTRACE_GETREGS, pid, NULL, &(arg->user_regs));
    registers = arg->user_regs;

    /*
     * Getting the path and offset in mem of libc
     */
    char libc_path[256];
    unsigned long long int libc_addr = 0;

    path_and_start_addr_of_libc(pid, libc_path, &libc_addr);

    /*
     * Getting the offset in mem of alligend_alloc, posix_memalign and mprotect
     * both aligned_alloc and posix_memalign are correct, in this case we use posix_memalign as requested..
     * look at the README for more info
     */

    unsigned long long int aligned_alloc_address = get_offset_libc_func(libc_path, "aligned_alloc") + libc_addr;
    unsigned long long int posix_memalign_address= get_offset_libc_func(libc_path, "posix_memalign") + libc_addr;
    unsigned long long int mprotect_address = get_offset_libc_func(libc_path, "mprotect") + libc_addr;

    // here we save the previous value in the heap
    unsigned long long int addr_start_heap = get_start_addr_heap(pid);
    unsigned long long int old_data_heap = ptrace(PTRACE_PEEKDATA, pid, addr_start_heap, NULL);

    /*
     * we set the registers and write the indirect call
     */
    registers.rax = posix_memalign_address;
    registers.rdi = addr_start_heap;
    registers.rsi = pagesize;
    registers.rdx = mem_size;

    ptrace(PTRACE_SETREGS, pid, NULL, &registers);
    continue_exec(pid, true); // RESTART THE TRACEE

    ptrace(PTRACE_GETREGS, pid, NULL, &registers);
    // the value of rax should be the address of the memory allocated if aligned_alloc is used, 0 if posix_memalign is used
    //unsigned long long int addr_allocated = registers.rax;
    if ( registers.rax != 0 ) {
        fprintf(stderr, "error with posix_memalign\n");
    }
    unsigned long long int addr_allocated = ptrace(PTRACE_PEEKDATA, pid, addr_start_heap, NULL);
    printf("addr_allocated %llx\n", addr_allocated);

    if (ptrace(PTRACE_POKEDATA, pid, addr_start_heap, old_data_heap) == -1) perror("POKEDATA restore previous @stack value");

    /*
     * SECOND STEP: mprotect
     */

    // restoring all registers to their previous values (mostly to get rip back at 0xFF 0xD0)
    registers = arg->user_regs;
    registers.rax = mprotect_address;
    registers.rdi = addr_allocated;
    registers.rsi = mem_size-1;
    registers.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;

    // this will execute mprotect
    ptrace(PTRACE_SETREGS, pid, NULL, &registers);
    continue_exec(pid, true); // RESTART THE TRACEE

    ptrace(PTRACE_GETREGS, pid, NULL, &registers);
    if ( registers.rax != 0 ) {
        fprintf(stderr, "error with mprotect\n");
    }

    /*
     * THIRD STEP: copy the function code inside the allocated memory and write trampoline while we're at it
     */

    unsigned char *code = malloc(sizeof(unsigned char) * func_size);

    int fd = open(get_proc_name(getpid()), O_RDONLY);
    lseek(fd, (off_t) offset_func_c3, SEEK_SET);
    read(fd, code, func_size);
    close(fd);

    // we write the code in mem
    fd = open(arg->path_to_mem, O_RDWR);
    lseek(fd, (off_t) addr_allocated, SEEK_SET); //or addr_allocated with aligned_alloc
    write(fd, code, func_size);

    // we're going to write the trampoline at the start of the func to be replaced so we have to set rip to its value
    arg->user_regs.rip = arg->func_addr;
    ptrace(PTRACE_SETREGS, pid, NULL, &(arg->user_regs));

    union ulli_u { // for endianess
        unsigned long long int cont;
        unsigned char each[8];
    };

    union ulli_u test;
    test.cont = addr_allocated; //or addr_allocated

    unsigned char jump_at_addr_and_ret[16] = { (unsigned char) 0x48, (unsigned char) 0xB8};
    for (int i = 0; i < 8; ++i) jump_at_addr_and_ret[2+i] = test.each[i];
    jump_at_addr_and_ret[10] = (unsigned char)0xFF;
    jump_at_addr_and_ret[11] = (unsigned char)0xE0;
    jump_at_addr_and_ret[12] = (unsigned char)0xC3;
    jump_at_addr_and_ret[13] = (unsigned char)0x90;
    jump_at_addr_and_ret[14] = (unsigned char)0x90;
    jump_at_addr_and_ret[15] = (unsigned char)0x90;


    lseek(fd, (off_t) arg->func_addr+4, SEEK_SET);
    read(fd, arg->old_12_remaining_bytes, 12);

    // we write the trampoline here
    lseek(fd, (off_t) arg->func_addr, SEEK_SET);
    write(fd, jump_at_addr_and_ret, 16);

    close(fd);

    free(code);

    return;
}


pid_t get_pid_from_argv(char *argv_pid)
{
    pid_t pid;
    char *endptr;
    errno = 0; // to differentiate between success and failure after strtol() has been called

    pid = (pid_t)strtol(argv_pid, &endptr, BASE_10);

    if ( (errno == ERANGE && ((long)pid == LONG_MAX || (long)pid == LONG_MIN)) || (errno != 0 && pid == 0) ) {
        perror("strtol");
        exit(EXIT_FAILURE);
    }

    if (endptr == argv_pid) {
        fprintf(stderr, "Aucun chiffre trouvé\n");
        exit(EXIT_FAILURE);
    }

    return pid;
}


long get_maps_addr(pid_t pid)
{
    char path_maps[64];
    char buf[12];
    long addr;

    sprintf(path_maps,"/proc/%d/maps", (int)pid);

    int fd = open(path_maps,O_RDONLY);
    if ( fd < 0 ) {
        perror("open");
        return -1;
    }

    read(fd,buf,12);
    close(fd);

    addr = strtoll(buf,NULL,16);
    printf("addr in vm 0x%llx\n", (long long unsigned int)addr);

    return addr;
}


unsigned long long int get_offset_func(char* proc_name,char* func_name)
{
    FILE* fp;
    char exec[128];
    unsigned long long int offset;

    sprintf(exec, "/usr/bin/objdump -d %s | grep %s | cut -f 1 -d \" \"", proc_name, func_name);

    fp = popen(exec,"r");

    if (fp == NULL) {
        perror("popen");
        exit(EXIT_FAILURE);
    }

    fscanf(fp, "%llx", &offset);
    pclose(fp);

    fprintf(stderr, "\toffset of the function %s 0x%llx\n", func_name, offset);

    return offset;
}


unsigned long long int get_offset_libc_func(char *lib_path, char * func_name)
{
    FILE* fp;
    char exec[128];
    unsigned long long int offset;

    sprintf(exec, "/usr/bin/objdump -T %s | grep %s | grep w | cut -f 1 -d \" \"", lib_path, func_name);

    fp = popen(exec,"r");

    if (fp == NULL) {
        perror("popen");
        exit(EXIT_FAILURE);
    }

    fscanf(fp, "%llx", &offset);
    pclose(fp);

    printf("offset of the function %s 0x%llx\n", func_name, offset);

    return offset;
}

unsigned long long int get_start_addr_heap(pid_t pid) {

    char path[64];
    char *line = NULL;
    size_t len = 0;
    ssize_t nb_char_read;

    sprintf(path, "/proc/%d/maps", pid);

    unsigned long long int addr_start;
    unsigned long long int addr_end;
    char perms[5];
    unsigned long int offset;
    short dev_maj;
    short dev_min;
    int inode;
    char path_or_desc[256];

    unsigned long long int addr_start_heap = 0;

    FILE *fp_maps = fopen(path, "r");
    while (getline(&line, &len, fp_maps) != -1) {
        sscanf(line, "%llx-%llx %s %lx %x:%x %d %s", &addr_start, &addr_end, perms, &offset, (int *) &dev_maj, (int *) &dev_min, &inode, path_or_desc);
        if(strcmp(path_or_desc, "[heap]") == 0) addr_start_heap = addr_start;
    }

    printf("\taddr_start_heap: 0x%llx\n", addr_start_heap);

    return addr_start_heap;
}


char* get_proc_name(pid_t pid)
{
    int fd;
    char cmd [26];
    static char proc_name[128];

    sprintf(cmd, "/proc/%d/cmdline", pid);

    fd = open(cmd, O_RDONLY);
    read(fd, proc_name, 128);
    close(fd);
    memcpy(proc_name, proc_name+2, strlen(proc_name));

    return proc_name;
}


unsigned long long int get_func_addr(pid_t pid, char* func_name)
{
    return get_maps_addr(pid) + get_offset_func(get_proc_name(pid),func_name);
}


void continue_exec(pid_t pid, bool wait)
{

    int wstatus;

    ptrace(PTRACE_CONT, pid, NULL, NULL);

    if (wait) waitpid(pid, &wstatus, 0); // this stops the tracing program, can be replaced with: wait()
    else waitpid(pid, &wstatus, WNOHANG);
    if (WIFSTOPPED(wstatus)) {
        printf("process was stopped by signal number %d\n", WSTOPSIG(wstatus));
        if (WSTOPSIG(wstatus) == 11) {
            perror("SIGSEGV");
            exit(EXIT_FAILURE);
        }
    }

    return;

}

void path_and_start_addr_of_libc(pid_t pid, char *libc_path, unsigned long long int *libc_addr)
{

    char path[64];
    char *line = NULL;
    size_t len = 0;

    sprintf(path, "/proc/%d/maps", pid);

    unsigned long long int addr_start = 0;
    unsigned long long int addr_end = 0;
    char perms[5];
    unsigned long int offset;
    short dev_maj;
    short dev_min;
    int inode;
    char path_or_desc[256];


    FILE *fp_maps = fopen(path, "r");
    while (getline(&line, &len, fp_maps) != -1) {
        sscanf(line, "%llx-%llx %s %lx %x:%x %d %s", &addr_start, &addr_end, perms, &offset, (int *) &dev_maj, (int *) &dev_min, &inode, path_or_desc);
        if(path_or_desc[0] == '/') {
            char * cp = strrchr(path_or_desc, '/');
            cp++; // move to first char instead of '/'
            if ( (strcmp(cp, "libc-2.28.so") == 0) && (offset == 0) ) { //executable code //TODO: find a method with libc.so.6 to find the path (for portability)
                strcpy(libc_path, path_or_desc);
                *libc_addr = addr_start;
                return;
            }
        }
    }

    return;
}


int challenge3_func(int a, int b)
{
    //test with printf will fail it seems
    //printf("hey\n");

    return a + b;
}

void end_challeng3_func()
{
    return;
}
