#include "hotpatchor.h"


pid_t get_pid_from_argv(char *argv1)
{
    pid_t pid;
    FILE *fp;
    char path[64];

    sprintf(path, "pgrep -n %s", argv1);
    fp = popen(path, "r");
    fscanf(fp, "%d", &pid);
    pclose(fp);

    return pid;
}


void hotwait(pid_t pid)
{
    int wstatus;
    waitpid(pid, &wstatus, 0);
    if (WIFSTOPPED(wstatus)) printf("process %d was stopped by signal number %d\n", pid, WSTOPSIG(wstatus));

    return;
}


void init_hotpatchor(pid_t pid, Arg *arg, char *argv1, char *argv2)
{
    char * path_to_ptrace_scope = "/proc/sys/kernel/yama/ptrace_scope";
    uint8_t ptrace_scope_val = 0;
    
    int fd = open(path_to_ptrace_scope, O_RDONLY);
    if(fd == -1) err(EXIT_FAILURE, "open failed");
    ssize_t br = read(fd, &ptrace_scope_val, sizeof(uint8_t));
    if(br == -1) err(EXIT_FAILURE, "read failed");
    close(fd);

    if(ptrace_scope_val != '0') errx(EXIT_FAILURE, "ptrace_scope is %d should be 0\nuse \"echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope\"", ptrace_scope_val);

    sprintf(arg->path_to_mem, "/proc/%d/mem", (int)pid);
    br = readlink("/proc/self/exe", arg->self_prog_path, STR_SIZE);
    if(br == -1) err(EXIT_FAILURE, "readlink failed");

    *((arg->self_prog_path)+br) = '\0'; // readlink() doesnt apppend null byte see: man 2 readlink
    arg->func_addr = get_func_addr(pid, argv1, argv2, false);
    printf("addr of %s : 0x%lx\n", argv2, arg->func_addr);

    return;
}

void init_ptrace_attach(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) err(EXIT_FAILURE, "Ptrace_failed");
    hotwait(pid);

    return;
}

void init_ptrace_seize(pid_t pid)
{
    if (ptrace(PTRACE_SEIZE, pid, NULL, NULL) == -1) err(EXIT_FAILURE, "Ptrace_failed");

    return;
}


void write_trap_only(pid_t pid, Arg *arg)
{

    int fd;
    ssize_t br;
    uint8_t int3 = 0xCC;

    fd = open(arg->path_to_mem, O_RDWR);

    if (lseek(fd, (off_t) arg->func_addr, SEEK_SET) < 0) perror("lseek");
    if (read(fd, &(arg->old_byte), 1) < 0) perror("read");

    if (lseek(fd, (off_t) arg->func_addr, SEEK_SET) < 0) perror("lseek");
    if ( (br = write(fd, &int3, 1)) < 0) perror("write");

    close(fd); // this seals the deal and should send SIGTRAP after we send SIGCONT / or PTRACE_CONT
    printf("%ld byte(s) written at address 0x%lx\n", br, arg->func_addr);

    return;
}


void write_trap_and_syscall(pid_t pid, Arg *arg)
{

    int fd;
    ssize_t br, bw;
    uint8_t buf[4] = { (char)0xCC, (char)0x0F, (char)0x05, (char)0xCC };

    fd = open(arg->path_to_mem, O_RDWR);

    if (lseek(fd, (off_t) arg->func_addr, SEEK_SET) < 0) err(EXIT_FAILURE,"lseek");
    if (read(fd, arg->backup, 4) < 0) err(EXIT_FAILURE,"read");;

    if (lseek(fd, (off_t) arg->func_addr, SEEK_SET) < 0) err(EXIT_FAILURE,"lseek");;
    if ( (br = write(fd, buf, 4)) < 0) err(EXIT_FAILURE,"write");;

    close(fd); // this seals the deal and should send SIGTRAP after we send SIGCONT / or PTRACE_CONT
    printf("%ld byte(s) written at address 0x%lx\n", br, arg->func_addr);


    return;
}


/*
 * Now with syscalls !
 */
void hotpatch(pid_t pid, Arg *arg)
{
    ssize_t br, bw;
    size_t pagesize = (size_t) sysconf(_SC_PAGESIZE);
    uint8_t trampoline[16] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0, 0xC3, 0x90, 0x90, 0x90};

    struct user_regs_struct registers;
    ptrace(PTRACE_GETREGS, pid, NULL, &(arg->user_regs));
    registers = arg->user_regs;

    registers.rax = 9; //system call : mmap
    registers.rdi = 0; // addr
    registers.rsi = pagesize; // length
    registers.rdx = PROT_READ | PROT_WRITE | PROT_EXEC; // prot
    registers.r10 = MAP_PRIVATE | MAP_ANONYMOUS; // flag
    registers.r8 = -1; // fd : -1 or 0xFFFFFFFFFFFFFFFF...
    registers.r9 = 0; //

    ptrace(PTRACE_SETREGS, pid, NULL, &registers);

    ptrace(PTRACE_CONT, pid, NULL, NULL);
    hotwait(pid);

    ptrace(PTRACE_GETREGS, pid, NULL, &registers);
    printf("mmap returns rax : %llx\n", registers.rax);

    arg->allocated_mem = registers.rax;

    // compute size of function instruction code
    uint64_t offset_func_c3 = get_symbol_offset(arg->self_prog_path, "challenge3_func", false);
    uint64_t offset_func_c3_end = get_symbol_offset(arg->self_prog_path, "end_challeng3_func", false);
    uint64_t func_size = offset_func_c3_end - offset_func_c3;

    uint8_t *code = malloc(sizeof(uint8_t) * func_size);

    int fd = open(arg->self_prog_path, O_RDONLY);
    lseek(fd, (off_t) offset_func_c3, SEEK_SET);
    read(fd, code, func_size);
    close(fd);

    // we write the code in mem
    fd = open(arg->path_to_mem, O_RDWR);
    lseek(fd, (off_t) arg->allocated_mem, SEEK_SET);
    bw = write(fd, code, func_size);
    printf("%ld byte(s) written at address 0x%lx\n", bw, arg->allocated_mem);

    // we're going to write the trampoline at the start of the func to be replaced so we have to set rip to its value
    arg->user_regs.rip = arg->func_addr;
    ptrace(PTRACE_SETREGS, pid, NULL, &(arg->user_regs));

    // write the address in the right order
    /*union endian64_u addr;
    addr.val = arg->allocated_mem;
    for (int i = 0; i < 8; ++i) trampoline[2+i] = addr.each[i];*/

    *((uint64_t *) (trampoline+2)) = arg->allocated_mem;

    lseek(fd, (off_t) (arg->func_addr)+4, SEEK_SET);
    br = read(fd, (arg->backup)+4, 12);
    printf("%ld byte(s) read at address 0x%lx\n", br, (arg->func_addr)+4);

    // we write the trampoline here
    lseek(fd, (off_t) arg->func_addr, SEEK_SET);
    bw = write(fd, trampoline, 16);
    printf("%ld byte(s) written at address 0x%lx\n", bw, arg->func_addr);

    close(fd);
    free(code);

    return;
}


void restore_mem(pid_t pid, Arg *arg)
{
    int fd;
    ssize_t br, bw;

    uint8_t buf[4] = { 0xCC, 0x0F, 0x05, 0xCC };

    kill(pid, SIGSTOP);
    hotwait(pid);

    fd = open(arg->path_to_mem, O_RDWR);
    if (lseek(fd, (off_t) arg->func_addr, SEEK_SET) < 0) perror("lseek");
    if ( (br = write(fd, buf, 4)) < 0) perror("write");
    printf("%ld byte(s) written at address 0x%lx\n", br, arg->func_addr);
    close(fd);

    ptrace(PTRACE_CONT, pid, NULL, NULL);
    hotwait(pid);

    ptrace(PTRACE_GETREGS, pid, NULL, &(arg->user_regs));
    struct user_regs_struct registers = arg->user_regs;

    registers.rax = 11; //system call : munmap
    registers.rdi = arg->allocated_mem;
    registers.rsi = (unsigned long long int) sysconf(_SC_PAGESIZE);

    ptrace(PTRACE_SETREGS, pid, NULL, &registers);

    ptrace(PTRACE_CONT, pid, NULL, NULL);
    hotwait(pid);

    //TODO: refactor this code with if() statements

    fd = open(arg->path_to_mem, O_RDWR);

    lseek(fd,(off_t) arg->func_addr, SEEK_SET);
    bw = write(fd, arg->backup, 16);
    printf("%ld byte(s) written at address 0x%lx\n", bw, arg->func_addr);

    arg->user_regs.rip = arg->func_addr;
    ptrace(PTRACE_SETREGS, pid, NULL, &(arg->user_regs));

    close(fd);

    return;
}


/*
 * str is the string to be searched
 * if lib_path is not NULL: return the path to the lib/executable
 * if the return value is zero then there's no match
 */
uint64_t get_addr_from_proc_maps(pid_t pid, char *str, char *lib_path)
{
    char path[64];
    char *line = NULL;
    size_t len = 0;

    sprintf(path, "/proc/%d/maps", pid);

    uint64_t addr_start = 0;
    uint64_t addr_end;
    char perms[5];
    unsigned long int offset;
    short dev_maj;
    short dev_min;
    int inode;
    char path_or_desc[256];

    FILE *fp_maps = fopen(path, "r");

    while (getline(&line, &len, fp_maps) != -1) {

        sscanf(line, "%lx-%lx %s %lx %x:%x %d %s", &addr_start, &addr_end, perms, &offset, (int *) &dev_maj, (int *) &dev_min, &inode, path_or_desc);

        // case of desc
        if(path_or_desc[0] == '[') {
            if (strcmp(str, HEAP) == 0) return addr_start;
            if (strcmp(str, STACK) == 0) return addr_start;
            if (strcmp(str, VVAR) == 0) return addr_start;
            if (strcmp(str, VDSO) == 0) return addr_start;
            if (strcmp(str, VSYSCALL) == 0) return addr_start;
        }

        // case of path
        if(path_or_desc[0] == '/') {
            char * cp = strrchr(path_or_desc, '/');
            cp++; // move to first char instead of '/'
            // strstr is better than strcmp because it works with any libc version
            if ( (strstr(cp, str) != NULL) && (offset == 0) ) {
                strcpy(lib_path, path_or_desc);
                return addr_start;
            }
        }
    }

    // in case of no match
    return addr_start;
}


uint64_t get_symbol_offset(char *exec_path, char * sym_name, bool dynamic)
{
    FILE* fp;
    char exec[128];
    uint64_t offset;

    if(dynamic) sprintf(exec, "/usr/bin/nm -D %s | grep %s | head -n 1 |cut -f 1 -d \" \"", exec_path, sym_name);
    else sprintf(exec, "/usr/bin/nm %s | grep %s | head -n 1 |cut -f 1 -d \" \"", exec_path, sym_name);

    fp = popen(exec,"r");

    if (fp == NULL) {
        perror("popen");
        exit(EXIT_FAILURE);
    }

    fscanf(fp, "%lx", &offset);
    pclose(fp);

    fprintf(stderr, "\toffset of the symbol %s 0x%lx\n", sym_name, offset);

    return offset;
}


/*
 * this func is a wrapper around the two above
 */
uint64_t get_func_addr(pid_t pid, char* lib_or_exec_name, char* func_name, bool dyn)
{
    char path_to_lib[64];
    uint64_t addr_exec_start = get_addr_from_proc_maps(pid, lib_or_exec_name, path_to_lib);

    return addr_exec_start + get_symbol_offset(path_to_lib,func_name, dyn);
}


void tid_buf_and_number(pid_t pid, pid_t **tid_buf, size_t *tid_nb)
{
    char path[64];

    sprintf(path, "/proc/%d/task", pid);

    DIR *d = opendir(path);
    struct dirent *dir;

    if (d) {

        while (readdir(d) != NULL) (*tid_nb)++;
        rewinddir(d);

        *tid_buf = malloc(sizeof(pid_t) * (*tid_nb));

        if (*tid_buf == NULL) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }

        int i = 0;
        while ( (dir = readdir(d)) != NULL) sscanf(dir->d_name, "%d", (*tid_buf)+i++);
        closedir(d);
    }

    /*
     * the first 3 entries are always '. .. [pid]' and then the threads, so if the size is 3 there is no threads
     * knowing this we could change the value of the pointer but then we would have to clean with a func
     * we waste 24 bytes (if long int is in fact 8 byte long), on x86_64
     *
     */

    (*tid_nb)-=3;
    (*tid_buf)+=3;

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
