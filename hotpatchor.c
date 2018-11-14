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

    //PTRACE_ATTACH should stop the process;
    //continue_exec(pid, true); // RESTART THE TRACEE

    int wstatus;

    waitpid(pid, &wstatus, 0); // this stops the tracing program, can be replaced with: wait()
    if (WIFSTOPPED(wstatus)) {
        printf("process was stopped by signal number %d\n", WSTOPSIG(wstatus));
        /*if (WSTOPSIG(wstatus) == 11) {
            perror("SIGSEGV");
            exit(EXIT_FAILURE);
        }*/
    }


    return;
}

void write_trap_at_addr(pid_t pid, Arg *arg)
{
    int fd;
    ssize_t br;
    uint8_t int3 = (char)0xCC;

    //process must be stopped in order to be able to read mem so:
    //kill((int)pid, SIGSTOP); // we send another SIGSTOP to be able to write in /proc/[pid]/mem

    fd = open(arg->path_to_mem, O_RDWR);

    if (lseek(fd, (off_t) arg->func_addr, SEEK_SET) < 0) perror("lseek");
    if (read(fd, &(arg->old_byte), 1) < 0) perror("read");

    if (lseek(fd, (off_t) arg->func_addr, SEEK_SET) < 0) perror("lseek");
    if ( (br = write(fd, &int3, 1)) < 0) perror("write");

    close(fd); // this seals the deal and should send SIGTRAP after we send SIGCONT
    printf("%ld byte(s) written at address 0x%llx\n", br, arg->func_addr);

    continue_exec(pid, true); // RESTART THE TRACEE

    return;
}


/*
 * In order to use this function the process must be stopped
 * If everything is working according to plan rip should be equal to func_addr+1
 * if not ... well ABORT !!!
 *
 */
void write_indirect_call_at_rip(pid_t pid, Arg *arg)
{
    int fd;
    ssize_t br;
    uint8_t buf[3] = { (char)0xFF, (char)0xD0, (char)0xCC};

    //TODO: refactor this code with if() statements

    fd = open(arg->path_to_mem, O_RDWR);

    lseek(fd, (long) arg->user_regs.rip, SEEK_SET); // SUPER IMPORTANT
    read(fd, arg->old_buf, 3);

    lseek(fd, (long) arg->user_regs.rip, SEEK_SET);
    br = write(fd, buf, 3);

    if (br <= 0) perror("write");
    close(fd);
    printf("%ld byte(s) written at address 0x%llx\n", br, arg->user_regs.rip);

    return;
}


void restore_mem(pid_t pid, Arg *arg)
{
    int fd;
    ssize_t br;

    //TODO: refactor this code with if() statements

    fd = open(arg->path_to_mem, O_RDWR);

    lseek(fd,(off_t) arg->func_addr, SEEK_SET);
    br = write(fd, &(arg->old_byte), 1);
    printf("%ld byte(s) written\n", br);
    printf("char: %x \n", arg->old_byte);

    lseek(fd, (long) arg->user_regs.rip, SEEK_SET);
    br = write(fd, arg->old_buf, 3);
    printf("%ld byte(s) written\n", br);
    printf("char: %x %x %x\n", arg->old_buf[0], arg->old_buf[1], arg->old_buf[2]);

    close(fd);

    return;
}

/*
 * This function is to be executed after a SIGTRAP occured (call to: write_trap_at_addr)
 * don't use this if you don't know whether the traced process has stopped or not
 *
 */
void exec_func_with_val(pid_t pid, Arg *arg)
{
    struct user_regs_struct registers;

    // GET and SET the registers
    ptrace(PTRACE_GETREGS, pid, NULL, &(arg->user_regs));
    registers = arg->user_regs; // same as memcopy

    //TODO: see if this works
    arg->old_rsi = arg->user_regs.rsi;
    arg->old_rdi = arg->user_regs.rdi;

    //TODO: should use a va_list for argument instead of hardcoding
    registers.rax = arg->opti_func_addr;
    registers.rsi = 0;
    registers.rdi = 1;

    ptrace(PTRACE_SETREGS, pid, NULL, &registers);
    write_indirect_call_at_rip(pid, arg);

    continue_exec(pid, true); // RESTART THE TRACEE

    // we check if rax has the right value
    ptrace(PTRACE_GETREGS, pid, NULL, &registers);
    printf("value of rax right now %llx\n", registers.rax);

    // restoring everything registers and code in memory arg->user_regs hasn't changed
    ptrace(PTRACE_SETREGS, pid, NULL, &(arg->user_regs));
    restore_mem(pid, arg);

    return;
}

void exec_func_with_ptr(pid_t pid, Arg *arg)
{
    struct user_regs_struct registers;

    ptrace(PTRACE_GETREGS, pid, NULL, &(arg->user_regs));
    registers = arg->user_regs;

    /*
     * TODO: PUT THIS IN A FUNCTION
     *
     * using FILE (stream) is actually more convenient for strings and stuff
     *
     */

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

    /*
     * TODO: END OF PUT THIS IN A FUNCTION
     */

    unsigned long long int addr_a = addr_start_heap;
    unsigned long long int addr_b = addr_start_heap+(sizeof(void *));

    unsigned long long int old_data_a = ptrace(PTRACE_PEEKDATA, pid, addr_a, NULL);
    unsigned long long int old_data_b = ptrace(PTRACE_PEEKDATA, pid, addr_b, NULL);

    registers.rax = arg->opti_func_addr;
    registers.rdi = addr_a;
    registers.rsi = addr_b;

    ptrace(PTRACE_SETREGS, pid, NULL, &registers);
    write_indirect_call_at_rip(pid, arg);

    continue_exec(pid, true); // RESTART THE TRACEE

    ptrace(PTRACE_GETREGS, pid, NULL, &registers);
    printf("value of rax right now 0x%llx or %lld\n", registers.rax, registers.rax); // IF THIS IS EQUAL TO 1 IT MEANS WE WON FUCK YEAH

    printf("addr_a: 0x%llx, addr_b: 0x%llx\n", addr_a, addr_b);

    long a_val = ptrace(PTRACE_PEEKDATA, pid, addr_a, NULL);
    long b_val = ptrace(PTRACE_PEEKDATA, pid, addr_b, NULL);

    if (ptrace(PTRACE_POKEDATA, pid, addr_a, old_data_a) == -1) perror("first POKEDATA");
    if (ptrace(PTRACE_POKEDATA, pid, addr_b, old_data_b) == -1) perror("second POKEDATA");

    printf("val_a: %lx, val_b: %lx\n", a_val, b_val);

    ptrace(PTRACE_SETREGS, pid, NULL, &(arg->user_regs));
    restore_mem(pid, arg);

    return;
}


void exec_posix_melalign(pid_t pid, Arg *arg)
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

    printf("\t\t\t\t\tvalue of rip %llx\n", registers.rip);
    printf("\t\t\t\t\tvalue of rdi %lld\n", registers.rdi);
    printf("\t\t\t\t\tvalue of rsi %lld\n", registers.rsi);

    /*
     * Getting the path and offset in mem of libc
     */
    char libc_path[256];
    unsigned long long int libc_addr = 0;

    path_and_start_addr_of_libc(pid, libc_path, &libc_addr);

    printf("\tlibc_path: %s\n", libc_path);
    printf("\tlibc_addr: 0x%llx\n", libc_addr);

    /*
     * Getting the offset in mem of alligend_alloc and mprotect
     */

    unsigned long long int aligned_alloc_address = get_offset_libc_func(libc_path, "aligned_alloc") + libc_addr; // look at README
    unsigned long long int posix_memalign_address= get_offset_libc_func(libc_path, "posix_memalign") + libc_addr; // with libc-2.28 aligned_alloc causes stack_smashing TODO: test wether posix_memalign has the same behavior
    unsigned long long int mprotect_address = get_offset_libc_func(libc_path, "mprotect") + libc_addr; // look at README
    printf("aligned_alloc_address: 0x%llx\n", aligned_alloc_address);
    printf("posix_memalign: 0x%llx\n", posix_memalign_address);
    printf("mprotect_address: 0x%llx\n", mprotect_address);

    /*
     * Changing the registers to the right values:
     * rax -> addr in mem of alligned alloc
     * rdi -> the size of a page
     * rsi -> the size of memory we want !
     * rip -> the addr in memory after 0xCC to 0xFF 0xD0
     */
    /*registers.rax = aligned_alloc_address;
    registers.rdi = pagesize;
    registers.rsi = mem_size;*/

    /*
     * Tests with posix_memalign
     * and since we don't want to use the stack we'll use the heap
     *
     */

    /*
     * TODO: PUT THIS IN A FUNCTION
     *
     * using FILE (stream) is actually more convenient for strings and stuff
     *
     */

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

    /*
     * TODO: END OF PUT THIS IN A FUNCTION
     */

    registers.rax = posix_memalign_address;
    registers.rdi = addr_start_heap;
    registers.rsi = pagesize;
    registers.rdx = mem_size;

    unsigned long long int old_data_heap = ptrace(PTRACE_PEEKDATA, pid, addr_start_heap, NULL);

    /*
     * we set the registers and write the indirect call
     */
    ptrace(PTRACE_SETREGS, pid, NULL, &registers);
    write_indirect_call_at_rip(pid, arg);

    //TODO: check this waitpid
    continue_exec(pid, true); // RESTART THE TRACEE

    ptrace(PTRACE_GETREGS, pid, NULL, &registers);
    // the value of rax should be the address of the memory allocated
    // BUT IT AIN'T WTF IS GOING ON WITH LIBC 2.28
    printf("return value of aligned alloc (or posix_memalign) in rax is: 0x%llx \n", registers.rax);
    unsigned long long int addr_allocated = registers.rax;

    unsigned long long int new_data_heap = ptrace(PTRACE_PEEKDATA, pid, addr_start_heap, NULL);
    if (ptrace(PTRACE_POKEDATA, pid, addr_start_heap, old_data_heap) == -1) perror("first POKEDATA");
    printf("ADDR allocated by posix_memalign %llx\n", new_data_heap);

    /*
     * End of test with posix_memalign
     */

    // restoring everything RIGHT HERE RIGHT NOW !
    ptrace(PTRACE_SETREGS, pid, NULL, &(arg->user_regs));
    restore_mem(pid, arg);


    printf("\t\t\t\tFIRST STEP DONE\n");

    /*
     * SECOND STEP: mprotect
     */

    ptrace(PTRACE_GETREGS, pid, NULL, &(arg->user_regs));
    registers = arg->user_regs;

    registers.rax = mprotect_address;
    registers.rdi = new_data_heap; //or addr_allocated with aligned_alloc
    registers.rsi = mem_size-1;
    registers.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;

    ptrace(PTRACE_SETREGS, pid, NULL, &registers);
    write_indirect_call_at_rip(pid, arg);

    continue_exec(pid, true); // RESTART THE TRACEE

    ptrace(PTRACE_GETREGS, pid, NULL, &registers);
    // the value of rax should be the address of the memory allocated
    printf("value of rax right now 0x%llx \n", registers.rax);

    // restoring everything RIGHT HERE RIGHT NOW !
    ptrace(PTRACE_SETREGS, pid, NULL, &(arg->user_regs));
    restore_mem(pid, arg);

    printf("\t\t\t\tSECOND STEP DONE\n");

    /*
     * THIRD STEP: copy the function code inside the allocated memory
     */

    int fd = open(get_proc_name(getpid()), O_RDONLY);
    printf("\t\tFUNC_SIZE : %lld, OFFSET_FUNC_CHALLENGE %llx, OFFSET_END_FUNC_CHALLENGE %llx\n", func_size, offset_func_c3, offset_func_c3_end);
    unsigned char *code = malloc(sizeof(unsigned char) * func_size);

    lseek(fd, (off_t) offset_func_c3, SEEK_SET);
    read(fd, code, func_size);
    printf("code to be copied: ");
    for (int i = 0; i < func_size ; ++i) {
        printf("%x ",code[i]);
    } printf("\n");

    close(fd);

    fd = open(arg->path_to_mem, O_RDWR);
    lseek(fd, (off_t) new_data_heap, SEEK_SET); //or addr_allocated with aligned_alloc
    write(fd, code, func_size);

    close(fd);

    ptrace(PTRACE_GETREGS, pid, NULL, &(arg->user_regs));
    registers = arg->user_regs;

    registers.rax = new_data_heap; //or addr_allocated with aligned_alloc
    // TODO: for testing purposes, restore old_rsi & old_rdi
    registers.rdi = 4096;
    registers.rsi = 4096;

    ptrace(PTRACE_SETREGS, pid, NULL, &registers);
    write_indirect_call_at_rip(pid, arg);

    continue_exec(pid, true); // RESTART THE TRACEE

    ptrace(PTRACE_GETREGS, pid, NULL, &registers);
    // the value of rax should be the address of the memory allocated
    printf("value of rax right now 0x%llx \n", registers.rax);

    // restoring everything RIGHT HERE RIGHT NOW !
    //TODO: should test what's below
    //arg->user_regs.rip = arg->func_addr;
    ptrace(PTRACE_SETREGS, pid, NULL, &(arg->user_regs));
    // WTF

    //print_registers(&(arg->user_regs));
    //print_registers(&registers);

    restore_mem(pid, arg);

    printf("\t\t\t\tTHIRD STEP DONE\n");

    /*
     * Challenge 4 : TESTING
     */

    union ulli_u { // 8 bytes
        unsigned long long int cont;
        unsigned char each[8];
    };

    union ulli_u test;
    test.cont = addr_allocated;

    unsigned char jump_at_addr_and_ret[16] = { (unsigned char) 0x48, (unsigned char) 0xB8};
    for (int i = 0; i < 8; ++i) jump_at_addr_and_ret[2+i] = test.each[i];
    jump_at_addr_and_ret[10] = (unsigned char)0xFF;
    jump_at_addr_and_ret[11] = (unsigned char)0xE0;
    jump_at_addr_and_ret[12] = (unsigned char)0xC3;
    jump_at_addr_and_ret[13] = (unsigned char)0x90;
    jump_at_addr_and_ret[14] = (unsigned char)0x90;
    jump_at_addr_and_ret[15] = (unsigned char)0x90;



    fd = open(arg->path_to_mem, O_RDWR);
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

	fscanf(fp, "%llx", &offset); //TODO: investigate why the previous method we used had undefined behavior
    /*char read_val[17];
	fread(read_val, sizeof(char), 16, fp);
    offset = strtoull(read_val, NULL, 16);*/
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

    fscanf(fp, "%llx", &offset); //TODO: investigate why the previous method we used had undefined behavior
    pclose(fp);

    printf("offset of the function %s 0x%llx\n", func_name, offset);

    return offset;
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
        /*if (WSTOPSIG(wstatus) == 11) {
            perror("SIGSEGV");
            exit(EXIT_FAILURE);
        }*/
    }


    return;

}

void path_and_start_addr_of_libc(pid_t pid, char *libc_path, unsigned long long int *libc_addr)
{
    /*
     * using FILE (stream) is actually more convenient for this kind of stuff
     */

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
            cp++; // move to first char instead of /
            if ( (strcmp(cp, "libc-2.28.so") == 0) && (strcmp(perms, "r-xp")) == 0 ) { //executable code //TODO: find a method with libc.so.6 to find the path (for portability)
                strcpy(libc_path, path_or_desc);
                *libc_addr = addr_start;
            }
        }
    }

    return;
}


void print_registers(struct user_regs_struct *regs)
{
    printf("*********PRINT_RESGISTER_BEGIN**********\n");
    printf(" r15 : %llx\n", regs->r15);
    printf(" r14 : %llx\n", regs->r14);
    printf(" r13 : %llx\n", regs->r13);
    printf(" r12 : %llx\n", regs->r12);
    printf(" rbp : %llx\n", regs->rbp);
    printf(" rbx : %llx\n", regs->rbx);
    printf(" r11 : %llx\n", regs->r11);
    printf(" r10 : %llx\n", regs->r10);
    printf(" r9 : %llx\n", regs->r9);
    printf(" r8 : %llx\n", regs->r8);
    printf(" rax : %llx\n", regs->rax);
    printf(" rcx : %llx\n", regs->rcx);
    printf(" rdx : %llx\n", regs->rdx);
    printf(" rsi : %llx\n", regs->rsi);
    printf(" rdi : %llx\n", regs->rdi);
    printf(" orig_rax : %llx\n", regs->orig_rax);
    printf(" rip : %llx\n", regs->rip);
    printf(" cs : %llx\n", regs->cs);
    printf(" eflags : %llx\n", regs->eflags);
    printf(" rsp : %llx\n", regs->rsp);
    printf(" ss : %llx\n", regs->ss);
    printf(" fs_base : %llx\n", regs->fs_base);
    printf(" gs_base : %llx\n", regs->gs_base);
    printf(" ds : %llx\n", regs->ds);
    printf(" es : %llx\n", regs->es);
    printf(" fs : %llx\n", regs->fs);
    printf(" gs : %llx\n", regs->gs);
    printf("*********REGISTERS PRINTED_END**********\n");

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
