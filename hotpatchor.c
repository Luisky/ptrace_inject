#include "hotpatchor.h"


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

void init_hotpatchor(pid_t pid, char *func_name, char *path_mem, unsigned long long int *func_addr)
{
    sprintf(path_mem, "/proc/%d/mem", (int)pid);
    *func_addr = get_func_addr((int)pid, func_name);

    return;
}

void init_ptrace_attach(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
        fprintf(stderr, "Ptrace failed\n"); //TODO: check errno
        exit(EXIT_FAILURE);
    }

    continue_exec(pid, true); // RESTART THE TRACEE

    return;
}

void write_trap_at_addr(pid_t pid, Arg *arg)
{
    int fd;
    ssize_t br;
    uint8_t int3 = (char)0xCC;
    static bool first_try = true; //TODO: investigate why on second call the wait() never returns

    //process must be stopped in order to be able to read mem so:
    kill((int)pid, SIGSTOP); // we send another SIGSTOP to be able to write in /proc/[pid]/mem

    fd = open(arg->path_to_mem, O_RDWR);

    if (lseek(fd, (off_t) arg->func_addr, SEEK_SET) < 0) perror("lseek");
    if (read(fd, &(arg->old_byte_bf_cc), 1) < 0) perror("read");

    if (lseek(fd, (off_t) arg->func_addr, SEEK_SET) < 0) perror("lseek");
    if ( (br = write(fd, &int3, 1)) < 0) perror("write");

    close(fd); // this seals the deal and should send SIGTRAP after we send SIGCONT
    printf("%ld byte(s) written at address 0x%llx\n", br, arg->func_addr);

    continue_exec(pid, true); // RESTART THE TRACEE

    return;
}

/*
 * This function is to be executed after a SIGTRAP occured (call to: write_trap_at_addr)
 * don't use this if you don't know whether the traced process has stopped or not
 *
 */
void exec_func_with_val(pid_t pid, Arg *arg)
{
    int fd;
    ssize_t br;
    uint8_t buf[3] = { (char)0xFF, (char)0xD0, (char)0xCC};
    uint8_t buf_r[3];

    // GET and SET the registers
    ptrace(PTRACE_GETREGS, pid, NULL, &(arg->user_regs));

    // this is necessary for restoring the original state of the process
    unsigned long long int old_rax = arg->user_regs.rax;
    unsigned long long int old_rdi = arg->user_regs.rdi;
    unsigned long long int old_rsi = arg->user_regs.rsi;

    arg->user_regs.rax = arg->opti_func_addr;
    arg->user_regs.rsi = 0;
    arg->user_regs.rdi = 1;

    ptrace(PTRACE_SETREGS, pid, NULL, &(arg->user_regs));

    // replace code in memory
    //TODO: refactor this code with if() statements
    fd = open(arg->path_to_mem, O_RDWR);

    lseek(fd, (long) arg->user_regs.rip, SEEK_SET); // SUPER IMPORTANT
    read(fd, buf_r, 3);

    lseek(fd, (long) arg->user_regs.rip, SEEK_SET);
    br = write(fd, buf, 3);

    if (br <= 0) perror("write");
    close(fd);
    printf("%ld byte(s) written at address 0x%llx\n", br, arg->user_regs.rip);

    continue_exec(pid, true); // RESTART THE TRACEE

    //TODO: this is where the code should change, since there is a SIGTRAP we could follow up with another instruction

    // we check if rax has the right value
    struct user_regs_struct SAVING_PRIVATE_RAX_VALUE;
    ptrace(PTRACE_GETREGS, pid, NULL, &SAVING_PRIVATE_RAX_VALUE);

    printf("value of rax right now %llx\n", SAVING_PRIVATE_RAX_VALUE.rax);

    // restoring everything registers and code in memory
    arg->user_regs.rax = old_rax;
    arg->user_regs.rdi = old_rdi;
    arg->user_regs.rsi = old_rsi;
    ptrace(PTRACE_SETREGS, pid, NULL, &(arg->user_regs));

    fd = open(arg->path_to_mem, O_RDWR);

    lseek(fd,(off_t) arg->func_addr, SEEK_SET);
    br = write(fd, &(arg->old_byte_bf_cc), 1);
    printf("%ld byte(s) written\n", br);
    printf("char: %x \n", arg->old_byte_bf_cc);

    lseek(fd, (long) arg->user_regs.rip, SEEK_SET);
    write(fd, buf_r, 3);
    printf("%ld byte(s) written\n", br);
    printf("char: %x %x %x\n", buf_r[0], buf_r[1], buf_r[2]);

    close(fd);

    return;
}

void exec_func_with_ptr(pid_t pid, Arg *arg)
{
    int fd;
    ssize_t br;
    uint8_t buf[3] = { (char)0xFF, (char)0xD0, (char)0xCC};
    uint8_t buf_r[3];

    ptrace(PTRACE_GETREGS, pid, NULL, &(arg->user_regs));

    // this is necessary for restoring the original state of the process
    unsigned long long int old_rax = arg->user_regs.rax;
    unsigned long long int old_rdi = arg->user_regs.rdi;
    unsigned long long int old_rsi = arg->user_regs.rsi;

    arg->user_regs.rax = arg->opti_func_addr;
    arg->user_regs.rdi = arg->user_regs.rsp - (sizeof(void *)); //TODO: check why this works
    arg->user_regs.rsi = arg->user_regs.rsp - 2 * (sizeof(void *));

    ptrace(PTRACE_SETREGS, pid, NULL, &(arg->user_regs));

    fd = open(arg->path_to_mem, O_RDWR);

    lseek(fd, (long) arg->user_regs.rip, SEEK_SET); // SUPER IMPORTANT
    read(fd, buf_r, 3);

    lseek(fd, (long) arg->user_regs.rip, SEEK_SET);
    br = write(fd, buf, 3);

    if (br <= 0) perror("write");
    close(fd);
    printf("%ld byte(s) written at address 0x%llx\n", br, arg->user_regs.rip);

    continue_exec(pid, true); // RESTART THE TRACEE

    struct user_regs_struct SAVING_PRIVATE_RAX_VALUE;
    ptrace(PTRACE_GETREGS, pid, NULL, &SAVING_PRIVATE_RAX_VALUE);

    printf("value of rax right now %llx\n", SAVING_PRIVATE_RAX_VALUE.rax); // IF THIS IS EQUAL TO 1 IT MEANS WE WON FUCK YEAH

    // restoring everything RIGHT HERE RIGHT NOW !
    arg->user_regs.rax = old_rax;
    arg->user_regs.rdi = old_rdi;
    arg->user_regs.rsi = old_rsi;
    ptrace(PTRACE_SETREGS, pid, NULL, &(arg->user_regs));

    fd = open(arg->path_to_mem, O_RDWR);

    lseek(fd, (off_t) arg->func_addr, SEEK_SET);
    br = write(fd, &(arg->old_byte_bf_cc), 1);
    printf("%ld byte(s) written\n", br);
    printf("char: %x \n", arg->old_byte_bf_cc);

    lseek(fd, (long) arg->user_regs.rip, SEEK_SET);
    br = write(fd, buf_r, 3);
    printf("%ld byte(s) written\n", br);
    printf("char: %x %x %x\n", buf_r[0], buf_r[1], buf_r[2]);

    close(fd);

    return;
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
	fclose(fp);

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

void continue_exec(pid_t pid, bool wait) {

    int wstatus;

    ptrace(PTRACE_CONT, pid, NULL, NULL);

    if (wait) waitpid(pid, &wstatus, 0); // this stops the tracing program, can be replaced with: wait()
    else waitpid(pid, &wstatus, WNOHANG);
    if (WIFSTOPPED(wstatus)) printf("process was stopped by signal number %d\n", WSTOPSIG(wstatus));

    return;

}